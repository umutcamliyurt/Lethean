import asyncio
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

import anyio.to_thread
from fastapi import FastAPI, Depends, Header, HTTPException, UploadFile, Form, BackgroundTasks, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete as sa_delete, func
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine, get_db, run_migrations
from models import DuressSlot, EncryptedFile, ShareToken, UploadSession, gen_uuid
from schemas import (
    FileMetaResponse, UsageResponse, ShareCreateResponse, ShareFileResponse,
    VaultRotateRequest, VaultRotateResponse,
    UploadInitRequest, UploadInitResponse, UploadStatusResponse, DuressPutRequest, ShredRequest,
)
from vault_auth import get_vault_id, require_upload_authorization, UploadAuthorization
import admin
import duress_store
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


@app.on_event("startup")
async def _start_admin_panel():
    admin.start_in_background()


@app.on_event("shutdown")
async def _stop_admin_panel():
    admin.stop()


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
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "X-Access-Token", "Content-Type"],
        allow_credentials=False,
    )

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


_MAX_PART_BYTES = int(os.environ.get("MAX_UPLOAD_PART_BYTES", str(64 * 1024 * 1024)))
_MAX_PARTS = 100_000
_UPLOAD_SESSION_TTL_SECONDS = int(os.environ.get("UPLOAD_SESSION_TTL_SECONDS", str(24 * 3600)))
_MAX_ACTIVE_SESSIONS_PER_VAULT = int(os.environ.get("MAX_ACTIVE_UPLOAD_SESSIONS", "32"))
_UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_ACCESS_TOKEN_RE_MAIN = re.compile(r"^[0-9a-f]{64}$")


class _SlidingLimiter:

    def __init__(self, max_hits: int, window: float = 60.0, max_keys: int = 50_000):
        self.max_hits, self.window, self.max_keys = max_hits, window, max_keys
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            if len(self.hits) > self.max_keys:
                for k in [k for k, d in self.hits.items() if not d or now - d[-1] > self.window]:
                    del self.hits[k]
            d = self.hits[key]
            while d and now - d[0] > self.window:
                d.popleft()
            if len(d) >= self.max_hits:
                return False
            d.append(now)
            return True


_duress_read_limiter = _SlidingLimiter(int(os.environ.get("DURESS_READS_PER_MINUTE", "30")))
_shred_limiter = _SlidingLimiter(int(os.environ.get("SHRED_REQUESTS_PER_MINUTE", "60")))


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
        "img-src 'self' blob: data:; media-src 'self' blob:; frame-src 'self' blob:; worker-src 'self'; "
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


def _stripe_for_vault(vault_id: str) -> int:
    return int(hashlib.sha256(vault_id.encode("utf-8")).hexdigest(), 16) % _LOCK_STRIPES


def _lock_for_vault(vault_id: str) -> threading.Lock:
    return _vault_locks[_stripe_for_vault(vault_id)]


def _locks_for(*vault_ids: str) -> list[threading.Lock]:
    return [_vault_locks[i] for i in sorted({_stripe_for_vault(v) for v in vault_ids})]


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
        reserved += _open_session_bytes(db, vault_id)
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
            id=gen_uuid(),
            vault_id=vault_id,
            encrypted_metadata=encrypted_metadata,
            metadata_iv=metadata_iv,
            content_iv=content_iv,
            wrapped_file_key=wrapped_file_key,
            wrap_iv=wrap_iv,
            storage_path="",
            size=0,
        )

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


def _finalize_upload(db: Session, record: EncryptedFile, path: str, size: int, vault_id: str, stream_limit: int) -> EncryptedFile:
    try:
        record.storage_path = path
        record.size = size
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except BaseException:
        db.rollback()
        storage.delete_blob(path)
        raise
    finally:
        _release_reservation(vault_id, stream_limit)


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

        try:
            path = storage.path_for(vault_id, record.id)
            size = await storage.write_blob_streamed(path, blob, stream_limit, chunk_size=_READ_CHUNK)
        except ValueError as exc:
            _release_reservation(vault_id, stream_limit)
            if "stalled" in str(exc):
                raise HTTPException(status_code=408, detail=str(exc))
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds allowed size ({stream_limit} bytes remaining under quota/limit)",
            )
        except BaseException:
            _release_reservation(vault_id, stream_limit)
            raise

        return await asyncio.to_thread(_finalize_upload, db, record, path, size, vault_id, stream_limit)



def _session_cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=_UPLOAD_SESSION_TTL_SECONDS)


def _open_session_bytes(db: Session, vault_id: str) -> int:
    return db.query(func.coalesce(func.sum(UploadSession.total_size), 0)).filter(
        UploadSession.vault_id == vault_id, UploadSession.created_at > _session_cutoff()
    ).scalar() or 0


def _purge_expired_sessions(db: Session) -> None:
    expired = [s.id for s in db.query(UploadSession.id).filter(UploadSession.created_at <= _session_cutoff())]
    if not expired:
        return
    db.query(UploadSession).filter(UploadSession.id.in_(expired)).delete(synchronize_session=False)
    db.commit()
    for sid in expired:
        storage.remove_session(sid)


@app.on_event("startup")
async def _purge_stale_upload_sessions():
    db = SessionLocal()
    try:
        await asyncio.to_thread(_purge_expired_sessions, db)
    finally:
        db.close()


def _part_length(session: UploadSession, index: int) -> int:
    if index == session.part_count - 1:
        return session.total_size - index * session.part_size
    return session.part_size


def _get_owned_session(db: Session, upload_id: str, vault_id: str) -> UploadSession:
    if not _UPLOAD_ID_RE.match(upload_id):
        raise HTTPException(status_code=404, detail="Upload not found")
    session = db.get(UploadSession, upload_id)
    if (
        session is None
        or not hmac.compare_digest(session.vault_id, vault_id)
        or _as_utc(session.created_at) <= _session_cutoff()
    ):
        raise HTTPException(status_code=404, detail="Upload not found")
    return session


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


@app.post("/files/uploads", response_model=UploadInitResponse, status_code=201)
def start_upload(
    body: UploadInitRequest,
    db: Session = Depends(get_db),
    auth: UploadAuthorization = Depends(require_upload_authorization),
):
    vault_id = auth.vault_id
    if body.total_size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the maximum upload size of {MAX_UPLOAD_BYTES} bytes")
    if body.part_size > _MAX_PART_BYTES:
        raise HTTPException(status_code=413, detail=f"Parts may be at most {_MAX_PART_BYTES} bytes")
    if body.part_count > _MAX_PARTS or body.part_count != math.ceil(body.total_size / body.part_size):
        raise HTTPException(status_code=400, detail="part_count doesn't match total_size / part_size")

    _purge_expired_sessions(db)
    with _lock_for_vault(vault_id):
        open_sessions = db.query(func.count(UploadSession.id)).filter(
            UploadSession.vault_id == vault_id, UploadSession.created_at > _session_cutoff()
        ).scalar() or 0
        if open_sessions >= _MAX_ACTIVE_SESSIONS_PER_VAULT:
            raise HTTPException(status_code=429, detail="Too many unfinished uploads; finish or cancel some first")

        current_usage = db.query(func.coalesce(func.sum(EncryptedFile.size), 0)).filter(
            EncryptedFile.vault_id == vault_id
        ).scalar()
        with _reserved_lock:
            reserved = _reserved_bytes.get(vault_id, 0)
        committed = current_usage + reserved + _open_session_bytes(db, vault_id)
        if committed + body.total_size > auth.quota_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Storage quota exceeded: {committed + body.total_size} of {auth.quota_bytes} bytes",
            )

        upload_id = secrets.token_urlsafe(24)
        storage.create_session_file(upload_id, body.total_size)
        db.add(UploadSession(
            id=upload_id,
            vault_id=vault_id,
            encrypted_metadata=body.encrypted_metadata,
            metadata_iv=body.metadata_iv,
            content_iv=body.content_iv,
            wrapped_file_key=body.wrapped_file_key,
            wrap_iv=body.wrap_iv,
            part_count=body.part_count,
            part_size=body.part_size,
            total_size=body.total_size,
        ))
        db.commit()
    return UploadInitResponse(upload_id=upload_id)


@app.put("/files/uploads/{upload_id}/parts/{index}", status_code=204)
async def upload_part(
    upload_id: str,
    index: int,
    request: Request,
    db: Session = Depends(get_db),
    auth: UploadAuthorization = Depends(require_upload_authorization),
):
    session = await asyncio.to_thread(_get_owned_session, db, upload_id, auth.vault_id)
    if not 0 <= index < session.part_count:
        raise HTTPException(status_code=400, detail="Part index out of range")
    expected = _part_length(session, index)
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) != expected:
        raise HTTPException(status_code=400, detail=f"Part {index} must be exactly {expected} bytes")

    async with _upload_semaphore:
        try:
            await storage.write_part_streamed(upload_id, index, index * session.part_size, expected, request.stream())
        except ValueError as exc:
            raise HTTPException(status_code=408 if "stalled" in str(exc) else 400, detail=str(exc))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Upload not found")
    return Response(status_code=204)


@app.get("/files/uploads/{upload_id}", response_model=UploadStatusResponse)
def upload_status(upload_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    _get_owned_session(db, upload_id, vault_id)
    return UploadStatusResponse(received=storage.received_parts(upload_id))


@app.post("/files/uploads/{upload_id}/complete", response_model=FileMetaResponse, status_code=201)
def complete_upload(
    upload_id: str,
    db: Session = Depends(get_db),
    auth: UploadAuthorization = Depends(require_upload_authorization),
):
    vault_id = auth.vault_id
    with _lock_for_vault(vault_id):
        session = _get_owned_session(db, upload_id, vault_id)
        missing = sorted(set(range(session.part_count)) - set(storage.received_parts(upload_id)))
        if missing:
            preview = ", ".join(map(str, missing[:10])) + ("…" if len(missing) > 10 else "")
            raise HTTPException(status_code=409, detail=f"Missing parts: {preview}")

        record = EncryptedFile(
            id=gen_uuid(),
            vault_id=vault_id,
            encrypted_metadata=session.encrypted_metadata,
            metadata_iv=session.metadata_iv,
            content_iv=session.content_iv,
            wrapped_file_key=session.wrapped_file_key,
            wrap_iv=session.wrap_iv,
            storage_path="",
            size=session.total_size,
        )
        path = storage.path_for(vault_id, record.id)
        storage.finalize_session(upload_id, path)
        try:
            record.storage_path = path
            db.add(record)
            db.delete(session)
            db.commit()
            db.refresh(record)
        except BaseException:
            db.rollback()
            storage.delete_blob(path)
            raise
    return record


@app.delete("/files/uploads/{upload_id}", status_code=204)
def abort_upload(upload_id: str, db: Session = Depends(get_db), vault_id: str = Depends(get_vault_id)):
    session = _get_owned_session(db, upload_id, vault_id)
    db.delete(session)
    db.commit()
    storage.remove_session(upload_id)
    return Response(status_code=204)


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
    quota_bytes = token_store.quota_bytes_for(record) if record else token_store.DEFAULT_QUOTA_BYTES
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
    record_id = record.id
    storage_path = record.storage_path
    result = db.execute(sa_delete(EncryptedFile).where(EncryptedFile.id == record_id))
    db.commit()
    if result.rowcount != 1:
        return False
    storage.delete_blob(storage_path)
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
    if token_store.find_by_vault_id(vault_id) is None:
        raise HTTPException(
            status_code=403,
            detail="This vault's access token is no longer active, so new share links can't be created.",
        )
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


def _wipe_vault(db: Session, vault_id: str, background_tasks: BackgroundTasks) -> None:
    rows = (
        db.query(EncryptedFile.id, EncryptedFile.storage_path)
        .filter(EncryptedFile.vault_id == vault_id)
        .all()
    )
    file_infos = [(row.id, row.storage_path) for row in rows]
    session_ids = [s.id for s in db.query(UploadSession.id).filter(UploadSession.vault_id == vault_id)]

    if file_infos:
        db.query(EncryptedFile).filter(EncryptedFile.vault_id == vault_id).delete(synchronize_session=False)
    if session_ids:
        db.query(UploadSession).filter(UploadSession.vault_id == vault_id).delete(synchronize_session=False)
    duress_store.on_vault_wiped(db, vault_id)
    db.commit()

    background_tasks.add_task(_delete_vault_files, vault_id, file_infos)
    for sid in session_ids:
        background_tasks.add_task(storage.remove_session, sid)


@app.delete("/vault", status_code=204)
def wipe_vault(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    vault_id: str = Depends(get_vault_id),
):
    _wipe_vault(db, vault_id, background_tasks)
    return Response(status_code=204)



def _token_hash_from_header(x_access_token: str | None) -> tuple[str, dict]:
    token = (x_access_token or "").strip().lower()
    if not _ACCESS_TOKEN_RE_MAIN.match(token):
        raise HTTPException(status_code=401, detail="Missing or malformed X-Access-Token header")
    record = token_store.get_record(token)
    if record is None:
        raise HTTPException(status_code=403, detail="Invalid access token")
    return token_store.hash_token(token), record


@app.get("/duress")
def get_duress(
    request: Request,
    db: Session = Depends(get_db),
    x_access_token: str | None = Header(default=None, alias="X-Access-Token"),
    authorization: str | None = Header(default=None),
):
    token_hash, record = _token_hash_from_header(x_access_token)
    if not _duress_read_limiter.allow(token_hash):
        raise HTTPException(status_code=429, detail="Too many requests")
    slot = duress_store.get_or_create_slot(db, token_hash)
    out = {"blob": slot.blob}
    if authorization and record.get("vault_id"):
        try:
            caller = get_vault_id(authorization)
        except HTTPException:
            caller = None
        if caller and hmac.compare_digest(caller, record["vault_id"]):
            out["written"] = bool(slot.written)
    return out


@app.put("/duress", status_code=204)
def put_duress(
    body: DuressPutRequest,
    db: Session = Depends(get_db),
    auth: UploadAuthorization = Depends(require_upload_authorization),
    x_access_token: str | None = Header(default=None, alias="X-Access-Token"),
):
    try:
        parsed = json.loads(body.blob)
        ok = isinstance(parsed, dict) and all(isinstance(parsed.get(k), str) for k in ("salt", "verifier", "encVaultId", "iv"))
    except ValueError:
        ok = False
    if not ok:
        raise HTTPException(status_code=400, detail="Malformed duress blob")
    token_hash = token_store.hash_token(x_access_token.strip().lower())
    with _lock_for_vault(auth.vault_id):
        duress_store.write_slot(db, token_hash, body.blob, auth.vault_id, body.shred_hash)
    return Response(status_code=204)


@app.post("/vault/shred", status_code=204)
def shred_vault(body: ShredRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not _shred_limiter.allow(_client_ip(request)):
        return Response(status_code=204)
    background_tasks.add_task(_shred_in_background, body.secret)
    return Response(status_code=204)


def _shred_in_background(secret_b64: str) -> None:
    db = SessionLocal()
    try:
        vault_id = duress_store.vault_for_secret(db, secret_b64)
        if vault_id is None:
            return
        tasks = BackgroundTasks()
        _wipe_vault(db, vault_id, tasks)
        for task in tasks.tasks:
            task.func(*task.args, **task.kwargs)
        logger.info("Duress shred wiped vault %s...", vault_id[:8])
    except Exception:
        logger.exception("duress shred failed")
    finally:
        db.close()


def _delete_vault_files(vault_id: str, file_infos: list[tuple[str, str]]) -> None:
    with _lock_for_vault(vault_id):
        for file_id, path in file_infos:
            try:
                storage.delete_blob(path)
            except Exception:
                logger.exception("Failed to delete blob for file %s in vault %s...", file_id, vault_id[:8])


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

    with ExitStack() as stack:
        for lk in _locks_for(old_vault_id, new_vault_id):
            stack.enter_context(lk)

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
        db.query(UploadSession).filter(UploadSession.vault_id == old_vault_id).update(
            {"vault_id": new_vault_id}, synchronize_session=False,
        )
        duress_store.on_vault_rotated(db, old_vault_id, new_vault_id)
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
