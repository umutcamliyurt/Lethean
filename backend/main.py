import hashlib
import hmac
import logging
import os
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Depends, HTTPException, UploadFile, Form, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import EncryptedFile
from schemas import FileMetaResponse, UsageResponse
from vault_auth import get_vault_id, require_upload_authorization, UploadAuthorization
import storage
import token_store

logger = logging.getLogger("lethean")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Lethean API", docs_url=None, redoc_url=None)

if os.environ.get("DEV_CORS", "0") == "1":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(5 * 1024**3)))
_READ_CHUNK = 4 * 1024 * 1024

_IV_MAX_LEN = 64
_WRAPPED_KEY_MAX_LEN = 4096
_ENCRYPTED_METADATA_MAX_LEN = 65536

_MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + _ENCRYPTED_METADATA_MAX_LEN + _WRAPPED_KEY_MAX_LEN + (4 * _IV_MAX_LEN) + (64 * 1024)

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "1200"))
_rate_limit_lock = threading.Lock()
_rate_limit_hits: dict[str, deque] = defaultdict(deque)
_rate_limit_last_seen: dict[str, float] = {}
_RATE_LIMIT_MAX_TRACKED_KEYS = 10_000


def _client_ip(request: Request) -> str:
    if os.environ.get("TRUST_PROXY_HEADERS", "0") == "1":
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit(request, call_next):
    key = _client_ip(request)
    now = time.monotonic()
    with _rate_limit_lock:
        hits = _rate_limit_hits[key]
        while hits and now - hits[0] > _RATE_LIMIT_WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= _RATE_LIMIT_MAX_REQUESTS:
            return Response(status_code=429, content="Too many requests")
        hits.append(now)
        _rate_limit_last_seen[key] = now
        if len(_rate_limit_last_seen) > _RATE_LIMIT_MAX_TRACKED_KEYS:
            stale = [k for k, t in _rate_limit_last_seen.items() if now - t > _RATE_LIMIT_WINDOW_SECONDS]
            for k in stale:
                _rate_limit_last_seen.pop(k, None)
                _rate_limit_hits.pop(k, None)
    return await call_next(request)


@app.middleware("http")
async def limit_request_size(request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            return Response(status_code=400, content="Invalid Content-Length")
        if length > _MAX_REQUEST_BYTES:
            return Response(status_code=413, content="Request body too large")
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; media-src 'self' blob:; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
    )
    forwarded_proto = request.headers.get("x-forwarded-proto") if os.environ.get("TRUST_PROXY_HEADERS", "0") == "1" else None
    is_https = request.url.scheme == "https" or forwarded_proto == "https"
    if is_https:
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


_LOCK_STRIPES = 256
_vault_locks = [threading.Lock() for _ in range(_LOCK_STRIPES)]


def _lock_for_vault(vault_id: str) -> threading.Lock:
    idx = int(hashlib.sha256(vault_id.encode("utf-8")).hexdigest(), 16) % _LOCK_STRIPES
    return _vault_locks[idx]


@app.post("/files", response_model=FileMetaResponse, status_code=201)
async def upload_file(
    content_iv: str = Form(..., max_length=_IV_MAX_LEN),
    encrypted_metadata: str = Form(..., max_length=_ENCRYPTED_METADATA_MAX_LEN),
    metadata_iv: str = Form(..., max_length=_IV_MAX_LEN),
    wrapped_file_key: str = Form(..., max_length=_WRAPPED_KEY_MAX_LEN),
    wrap_iv: str = Form(..., max_length=_IV_MAX_LEN),
    blob: UploadFile | None = None,
    db: Session = Depends(get_db),
    auth: UploadAuthorization = Depends(require_upload_authorization),
):
    if blob is None:
        raise HTTPException(status_code=400, detail="Missing file blob")

    vault_id = auth.vault_id

    with _lock_for_vault(vault_id):
        current_usage = db.query(func.coalesce(func.sum(EncryptedFile.size), 0)).filter(
            EncryptedFile.vault_id == vault_id
        ).scalar()
        remaining_quota = auth.quota_bytes - current_usage
        if remaining_quota <= 0:
            raise HTTPException(
                status_code=413,
                detail=f"Storage quota exceeded: {current_usage} of {auth.quota_bytes} bytes",
            )
        stream_limit = min(MAX_UPLOAD_BYTES, remaining_quota)

        record = EncryptedFile(
            vault_id=vault_id,
            encrypted_metadata=encrypted_metadata,
            metadata_iv=metadata_iv,
            content_iv=content_iv,
            wrapped_file_key=wrapped_file_key,
            wrap_iv=wrap_iv,
            storage_path="",
            size=0,
        )
        db.add(record)
        db.flush()

        path = storage.path_for(vault_id, record.id)
        try:
            size = await storage.write_blob_streamed(path, blob, stream_limit, chunk_size=_READ_CHUNK)
        except ValueError:
            db.rollback()
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds allowed size ({stream_limit} bytes remaining under quota/limit)",
            )

        record.storage_path = path
        record.size = size

        db.commit()
        db.refresh(record)
        return record


@app.get("/files", response_model=list[FileMetaResponse])
def list_files(db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    return (
        db.query(EncryptedFile)
        .filter(EncryptedFile.vault_id == vault_id)
        .order_by(EncryptedFile.created_at.desc())
        .all()
    )


@app.get("/usage", response_model=UsageResponse)
def usage(db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    files = db.query(EncryptedFile).filter(EncryptedFile.vault_id == vault_id).all()
    record = token_store.find_by_vault_id(vault_id)
    quota_bytes = token_store.quota_bytes_for(record) if record else None
    return UsageResponse(file_count=len(files), total_bytes=sum(f.size for f in files), quota_bytes=quota_bytes)


@app.get("/files/{file_id}", response_model=FileMetaResponse)
def get_file_meta(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    return _get_owned_file(db, file_id, vault_id)


@app.get("/files/{file_id}/blob")
def get_file_blob(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    record = _get_owned_file(db, file_id, vault_id)

    def _iter_file(path: str, chunk_size: int = _READ_CHUNK):
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    return StreamingResponse(
        _iter_file(record.storage_path),
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "attachment",
            "Content-Length": str(record.size),
        },
    )


@app.delete("/files/{file_id}", status_code=204)
def delete_file(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    record = _get_owned_file(db, file_id, vault_id)
    storage.shred_blob(record.storage_path)
    db.delete(record)
    db.commit()
    return Response(status_code=204)


@app.delete("/vault", status_code=204)
def wipe_vault(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    vault_id: str = Depends(get_vault_id),
):
    files = db.query(EncryptedFile).filter(EncryptedFile.vault_id == vault_id).all()
    file_infos = [(f.id, f.storage_path) for f in files]

    if file_infos:
        db.query(EncryptedFile).filter(EncryptedFile.vault_id == vault_id).delete(synchronize_session=False)
        db.commit()

    background_tasks.add_task(_shred_vault_files, vault_id, file_infos)

    return Response(status_code=204)


def _shred_vault_files(vault_id: str, file_infos: list[tuple[str, str]]) -> None:
    with _lock_for_vault(vault_id):
        for file_id, path in file_infos:
            try:
                storage.shred_blob(path)
            except Exception:
                logger.exception("Failed to shred blob for file %s in vault %s...", file_id, vault_id[:8])


def _get_owned_file(db: Session, file_id: str, vault_id: str) -> EncryptedFile:
    record = db.query(EncryptedFile).filter(EncryptedFile.id == file_id).first()
    if not record or not hmac.compare_digest(record.vault_id, vault_id):
        raise HTTPException(status_code=404, detail="File not found")
    return record


_client_dir = os.path.join(os.path.dirname(__file__), "..", "client")
if os.path.isdir(_client_dir):
    app.mount("/", StaticFiles(directory=_client_dir, html=True), name="client")