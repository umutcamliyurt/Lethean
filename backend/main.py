import asyncio
import hashlib
import hmac
import logging
import os
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import anyio.to_thread
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

_MAX_CONCURRENT_UPLOADS = int(os.environ.get("MAX_CONCURRENT_UPLOADS", "50"))
_upload_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_UPLOADS)


@app.on_event("startup")
async def _configure_thread_capacity():
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=_MAX_CONCURRENT_UPLOADS * 2))

    anyio.to_thread.current_default_thread_limiter().total_tokens = max(100, _MAX_CONCURRENT_UPLOADS * 2)


_ALLOWED_ORIGINS = ["tauri://localhost", "https://tauri.localhost"]
_extra_origins = os.environ.get("EXTRA_CORS_ORIGINS", "")
if _extra_origins:
    _ALLOWED_ORIGINS.extend(o.strip() for o in _extra_origins.split(",") if o.strip())

if os.environ.get("DEV_CORS", "0") == "1":
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "X-Access-Token", "Content-Type"],
        allow_credentials=False,
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
        "img-src 'self' blob: data:; media-src 'self' blob:; frame-src blob:; "
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


_reserved_lock = threading.Lock()
_reserved_bytes: dict[str, int] = defaultdict(int)


def _reserve_upload_slot(
    db: Session,
    vault_id: str,
    quota_bytes: int,
    declared_size: int | None,
    encrypted_metadata: str,
    metadata_iv: str,
    content_iv: str,
    wrapped_file_key: str,
    wrap_iv: str,
) -> tuple[EncryptedFile, int]:
    with _lock_for_vault(vault_id):
        current_usage = db.query(func.coalesce(func.sum(EncryptedFile.size), 0)).filter(
            EncryptedFile.vault_id == vault_id
        ).scalar()
        with _reserved_lock:
            reserved = _reserved_bytes.get(vault_id, 0)
        remaining_quota = quota_bytes - current_usage - reserved
        if remaining_quota <= 0:
            raise HTTPException(
                status_code=413,
                detail=f"Storage quota exceeded: {current_usage + reserved} of {quota_bytes} bytes",
            )
        candidate_limits = [MAX_UPLOAD_BYTES, remaining_quota]
        if declared_size is not None:
            candidate_limits.append(max(declared_size, 1))
        stream_limit = min(candidate_limits)

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

        with _reserved_lock:
            _reserved_bytes[vault_id] = _reserved_bytes.get(vault_id, 0) + stream_limit

        return record, stream_limit


def _release_reservation(vault_id: str, stream_limit: int) -> None:
    with _reserved_lock:
        remaining = _reserved_bytes.get(vault_id, 0) - stream_limit
        if remaining <= 0:
            _reserved_bytes.pop(vault_id, None)
        else:
            _reserved_bytes[vault_id] = remaining


def _discard_upload(db: Session, vault_id: str, stream_limit: int) -> None:
    db.rollback()
    _release_reservation(vault_id, stream_limit)


def _finalize_upload(db: Session, record: EncryptedFile, path: str, size: int, vault_id: str, stream_limit: int) -> EncryptedFile:
    record.storage_path = path
    record.size = size
    db.commit()
    db.refresh(record)
    _release_reservation(vault_id, stream_limit)
    return record


@app.post("/files", response_model=FileMetaResponse, status_code=201)
async def upload_file(
    request: Request,
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

    declared_size: int | None = None
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError:
            declared_size = None

    async with _upload_semaphore:
        record, stream_limit = await asyncio.to_thread(
            _reserve_upload_slot,
            db,
            vault_id,
            auth.quota_bytes,
            declared_size,
            encrypted_metadata,
            metadata_iv,
            content_iv,
            wrapped_file_key,
            wrap_iv,
        )

        path = storage.path_for(vault_id, record.id)
        try:
            size = await storage.write_blob_streamed(path, blob, stream_limit, chunk_size=_READ_CHUNK)
        except ValueError:
            await asyncio.to_thread(_discard_upload, db, vault_id, stream_limit)
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds allowed size ({stream_limit} bytes remaining under quota/limit)",
            )
        except Exception:
            await asyncio.to_thread(_discard_upload, db, vault_id, stream_limit)
            raise

        return await asyncio.to_thread(_finalize_upload, db, record, path, size, vault_id, stream_limit)


@app.get("/files", response_model=list[FileMetaResponse])
def list_files(
    db: Session = Depends(get_db),
    vault_id: str = Depends(get_vault_id),
    offset: int = 0,
    limit: int | None = None,
):
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    if limit is not None and not (1 <= limit <= 500):
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")

    query = (
        db.query(EncryptedFile)
        .filter(EncryptedFile.vault_id == vault_id)
        .order_by(EncryptedFile.created_at.desc(), EncryptedFile.id.asc())
        .offset(offset)
    )
    if limit is not None:
        query = query.limit(limit)
    return query.all()


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