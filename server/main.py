import asyncio
import hashlib
import hmac
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import anyio.to_thread
from fastapi import FastAPI, Depends, HTTPException, UploadFile, Form, BackgroundTasks, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete as sa_delete, func
from sqlalchemy.orm import Session

from database import Base, engine, get_db, run_migrations
from models import EncryptedFile, ShareToken
from schemas import (
    FileMetaResponse, UsageResponse, ShareCreateResponse, ShareFileResponse,
    VaultRotateRequest, VaultRotateResponse,
)
from vault_auth import get_vault_id, require_upload_authorization, UploadAuthorization
import share_store
import storage
import token_store

logger = logging.getLogger("lethean")

Base.metadata.create_all(bind=engine)
run_migrations()

app = FastAPI(title="Lethean API", docs_url=None, redoc_url=None)

_MAX_CONCURRENT_UPLOADS = int(os.environ.get("MAX_CONCURRENT_UPLOADS", "100"))
_upload_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_UPLOADS)

_MAX_CONCURRENT_DOWNLOADS = int(os.environ.get("MAX_CONCURRENT_DOWNLOADS", "100"))
_download_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_DOWNLOADS)

_THREAD_POOL_WORKERS = max(100, (_MAX_CONCURRENT_UPLOADS + _MAX_CONCURRENT_DOWNLOADS) * 2)


@app.on_event("startup")
async def _configure_thread_capacity():
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=_THREAD_POOL_WORKERS))

    anyio.to_thread.current_default_thread_limiter().total_tokens = _THREAD_POOL_WORKERS


_ALLOWED_ORIGINS = ["tauri://localhost", "https://tauri.localhost", "http://tauri.localhost"]
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

@app.middleware("http")
async def _debug_cors(request: Request, call_next):
    if request.method == "OPTIONS" and "access-control-request-method" in request.headers:
        origin = request.headers.get("origin")
        verdict = "ALLOWED" if origin in _ALLOWED_ORIGINS else "REJECTED"
        print(
            f"[DEBUG_CORS] {verdict} origin={origin!r} "
            f"method={request.headers.get('access-control-request-method')!r} "
            f"headers={request.headers.get('access-control-request-headers')!r} "
            f"path={request.url.path} allowed_origins={_ALLOWED_ORIGINS!r}",
            flush=True,
        )
    return await call_next(request)

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(5 * 1024**3)))
_READ_CHUNK = 8 * 1024 * 1024

_DEFAULT_LIST_LIMIT = 1000

_IV_MAX_LEN = 64
_WRAPPED_KEY_MAX_LEN = 4096
_ENCRYPTED_METADATA_MAX_LEN = 65536

_SHARE_LINK_TTL_SECONDS = int(os.environ.get("SHARE_LINK_TTL_SECONDS", str(share_store.DEFAULT_SHARE_TTL_SECONDS)))
_SHARE_LINK_MAX_TTL_SECONDS = int(os.environ.get("SHARE_LINK_MAX_TTL_SECONDS", str(30 * 24 * 3600)))
_SHARE_LINK_MAX_DOWNLOADS_LIMIT = int(os.environ.get("SHARE_LINK_MAX_DOWNLOADS_LIMIT", "100"))
_SHARE_LINKS_MAX_ACTIVE_PER_FILE = int(os.environ.get("SHARE_LINKS_MAX_ACTIVE_PER_FILE", "20"))
_SHARE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")

_MAX_ROTATE_ITEMS = int(os.environ.get("MAX_ROTATE_ITEMS", "50000"))
_VAULT_ID_RE_MAIN = re.compile(r"^[0-9a-f]{64}$")

_MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + _ENCRYPTED_METADATA_MAX_LEN + _WRAPPED_KEY_MAX_LEN + (4 * _IV_MAX_LEN) + (64 * 1024)

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "3000"))
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


app.add_middleware(GZipMiddleware, minimum_size=1024)


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

    effective_limit = limit if limit is not None else _DEFAULT_LIST_LIMIT

    query = (
        db.query(EncryptedFile)
        .filter(EncryptedFile.vault_id == vault_id)
        .order_by(EncryptedFile.created_at.desc(), EncryptedFile.id.asc())
        .offset(offset)
        .limit(effective_limit)
    )
    return query.all()


@app.get("/usage", response_model=UsageResponse)
def usage(db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    file_count, total_bytes = (
        db.query(func.count(EncryptedFile.id), func.coalesce(func.sum(EncryptedFile.size), 0))
        .filter(EncryptedFile.vault_id == vault_id)
        .one()
    )
    record = token_store.find_by_vault_id(vault_id)
    quota_bytes = token_store.quota_bytes_for(record) if record else None
    return UsageResponse(file_count=file_count, total_bytes=total_bytes, quota_bytes=quota_bytes)


@app.get("/files/{file_id}", response_model=FileMetaResponse)
def get_file_meta(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    return _get_owned_file(db, file_id, vault_id)


@app.get("/files/{file_id}/blob")
async def get_file_blob(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    record = _get_owned_file(db, file_id, vault_id)
    storage_path = record.storage_path
    size = record.size

    async def _bounded_stream():
        async with _download_semaphore:
            async for chunk in storage.stream_blob(storage_path, chunk_size=_READ_CHUNK):
                yield chunk

    return StreamingResponse(
        _bounded_stream(),
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "attachment",
            "Content-Length": str(size),
            "Content-Encoding": "identity",
        },
    )


def _delete_record(db: Session, record: EncryptedFile) -> bool:
    result = db.execute(sa_delete(EncryptedFile).where(EncryptedFile.id == record.id))
    db.commit()
    if result.rowcount != 1:
        return False
    storage.shred_blob(record.storage_path)
    return True


@app.post("/files/{file_id}/share", response_model=ShareCreateResponse, status_code=201)
def create_file_share(
    file_id: str,
    max_downloads: int = Query(
        share_store.DEFAULT_MAX_DOWNLOADS,
        ge=1,
        le=_SHARE_LINK_MAX_DOWNLOADS_LIMIT,
        description="How many times this link can be downloaded before it stops working.",
    ),
    expires_in: int | None = Query(
        None,
        ge=60,
        le=_SHARE_LINK_MAX_TTL_SECONDS,
        description="Seconds until the link expires. Omit to use the server default.",
    ),
    allow_delete: bool = Query(
        False,
        description="If true, also mint a separate token that can delete the file. The view/download token never can.",
    ),
    db: Session = Depends(get_db),
    vault_id: str = Depends(get_vault_id),
):
    record = _get_owned_file(db, file_id, vault_id)
    try:
        raw_token, raw_delete_token, expires_at, max_downloads = share_store.create_share(
            db, record.id, vault_id,
            ttl_seconds=expires_in if expires_in is not None else _SHARE_LINK_TTL_SECONDS,
            max_downloads=max_downloads,
            max_active_per_file=_SHARE_LINKS_MAX_ACTIVE_PER_FILE,
            allow_delete=allow_delete,
        )
    except share_store.TooManyActiveSharesError:
        raise HTTPException(
            status_code=429,
            detail=(
                f"This file already has {_SHARE_LINKS_MAX_ACTIVE_PER_FILE} active share link(s). "
                "Revoke one before creating another."
            ),
        )
    return ShareCreateResponse(
        shareToken=raw_token, deleteToken=raw_delete_token, expiresAt=expires_at, maxDownloads=max_downloads,
    )


@app.delete("/files/{file_id}/share", status_code=204)
def revoke_file_share(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    record = _get_owned_file(db, file_id, vault_id)
    share_store.revoke_shares_for_file(db, record.id, vault_id)
    return Response(status_code=204)


@app.delete("/files/{file_id}", status_code=204)
def delete_file(file_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    record = _get_owned_file(db, file_id, vault_id)
    _delete_record(db, record)
    return Response(status_code=204)


@app.get("/share/{share_token}", response_model=ShareFileResponse)
def get_shared_file_meta(share_token: str, db: Session = Depends(get_db)):
    if not _SHARE_TOKEN_RE.match(share_token):
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")
    result = share_store.peek_share(db, share_token)
    if result is None:
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")
    record, share = result
    return ShareFileResponse(
        content_iv=record.content_iv,
        encrypted_metadata=record.encrypted_metadata,
        metadata_iv=record.metadata_iv,
        downloads_used=share.download_count,
        max_downloads=share.max_downloads,
        expires_at=share.expires_at,
        deletable=share.delete_token_hash is not None,
    )


@app.get("/share/{share_token}/blob")
async def get_shared_file_blob(share_token: str, db: Session = Depends(get_db)):
    if not _SHARE_TOKEN_RE.match(share_token):
        raise HTTPException(status_code=404, detail="This link is invalid, has expired, or has no downloads left")

    record = await asyncio.to_thread(share_store.claim_share, db, share_token)
    if record is None:
        raise HTTPException(status_code=404, detail="This link is invalid, has expired, or has no downloads left")

    storage_path = record.storage_path
    size = record.size

    async def _bounded_stream():
        async with _download_semaphore:
            async for chunk in storage.stream_blob(storage_path, chunk_size=_READ_CHUNK):
                yield chunk

    return StreamingResponse(
        _bounded_stream(),
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "attachment",
            "Content-Length": str(size),
            "Content-Encoding": "identity",
        },
    )


@app.delete("/share/{share_token}", status_code=204)
async def delete_shared_file(share_token: str, db: Session = Depends(get_db)):
    if not _SHARE_TOKEN_RE.match(share_token):
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")

    deleted = await asyncio.to_thread(share_store.delete_via_delete_token, db, share_token)
    if not deleted:
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")
    return Response(status_code=204)


@app.delete("/vault", status_code=204)
def wipe_vault(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    vault_id: str = Depends(get_vault_id),
):
    rows = (
        db.query(EncryptedFile.id, EncryptedFile.storage_path)
        .filter(EncryptedFile.vault_id == vault_id)
        .all()
    )
    file_infos = [(row.id, row.storage_path) for row in rows]

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


@app.post("/vault/rotate", response_model=VaultRotateResponse)
def rotate_vault(
    body: VaultRotateRequest,
    db: Session = Depends(get_db),
    auth: UploadAuthorization = Depends(require_upload_authorization),
):
    old_vault_id = auth.vault_id
    new_vault_id = body.new_vault_id.strip().lower()

    if not _VAULT_ID_RE_MAIN.match(new_vault_id):
        raise HTTPException(status_code=400, detail="Malformed new vault id")
    if new_vault_id == old_vault_id:
        raise HTTPException(status_code=400, detail="New vault id must differ from the current one")
    if len(body.rewraps) > _MAX_ROTATE_ITEMS:
        raise HTTPException(status_code=413, detail=f"Too many items for a single rotation (max {_MAX_ROTATE_ITEMS})")

    already_at_target = db.query(func.count(EncryptedFile.id)).filter(
        EncryptedFile.vault_id == new_vault_id
    ).scalar()
    if already_at_target:
        raise HTTPException(status_code=409, detail="Target vault id is already in use")

    owned_ids = {
        row.id for row in db.query(EncryptedFile.id).filter(EncryptedFile.vault_id == old_vault_id).all()
    }
    provided_ids = {item.file_id for item in body.rewraps}
    if owned_ids != provided_ids:
        raise HTTPException(
            status_code=409,
            detail="Vault contents changed since this rotation was prepared — refresh and try again",
        )

    for item in body.rewraps:
        if len(item.wrapped_file_key) > _WRAPPED_KEY_MAX_LEN or len(item.wrap_iv) > _IV_MAX_LEN:
            raise HTTPException(status_code=400, detail=f"Malformed rewrap entry for {item.file_id}")

    with _lock_for_vault(old_vault_id), _lock_for_vault(new_vault_id):
        for item in body.rewraps:
            db.query(EncryptedFile).filter(
                EncryptedFile.id == item.file_id, EncryptedFile.vault_id == old_vault_id,
            ).update(
                {
                    "wrapped_file_key": item.wrapped_file_key,
                    "wrap_iv": item.wrap_iv,
                    "vault_id": new_vault_id,
                },
                synchronize_session=False,
            )

        db.query(ShareToken).filter(ShareToken.vault_id == old_vault_id).update(
            {"vault_id": new_vault_id}, synchronize_session=False,
        )
        db.commit()

    tokens_rebound = token_store.rebind_vault(old_vault_id, new_vault_id)

    return VaultRotateResponse(files_moved=len(body.rewraps), tokens_rebound=tokens_rebound)


def _get_owned_file(db: Session, file_id: str, vault_id: str) -> EncryptedFile:
    record = db.query(EncryptedFile).filter(EncryptedFile.id == file_id).first()
    if not record or not hmac.compare_digest(record.vault_id, vault_id):
        raise HTTPException(status_code=404, detail="File not found")
    return record


_client_dir = os.environ.get(
    "CLIENT_DIST_DIR",
    os.path.join(os.path.dirname(__file__), "..", "client", "dist"),
)
if os.path.isdir(_client_dir):
    app.mount("/", StaticFiles(directory=_client_dir, html=True), name="client")