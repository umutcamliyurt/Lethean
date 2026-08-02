import hashlib
import os
import threading

from fastapi import FastAPI, Depends, HTTPException, UploadFile, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import EncryptedFile
from schemas import FileMetaResponse, UsageResponse
from vault_auth import get_vault_id, require_upload_authorization, UploadAuthorization
import storage
import token_store

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Lethean API", docs_url=None, redoc_url=None)

if os.environ.get("DEV_CORS", "0") == "1":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(200 * 1024**2)))
_READ_CHUNK = 1024 * 1024

_IV_MAX_LEN = 64
_WRAPPED_KEY_MAX_LEN = 4096
_ENCRYPTED_METADATA_MAX_LEN = 65536

_LOCK_STRIPES = 256
_vault_locks = [threading.Lock() for _ in range(_LOCK_STRIPES)]


def _lock_for_vault(vault_id: str) -> threading.Lock:
    idx = int(hashlib.sha256(vault_id.encode("utf-8")).hexdigest(), 16) % _LOCK_STRIPES
    return _vault_locks[idx]


async def _read_capped(upload: UploadFile, limit: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = await upload.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail=f"File exceeds max upload size of {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


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
    data = await _read_capped(blob, MAX_UPLOAD_BYTES)

    with _lock_for_vault(vault_id):
        current_usage = db.query(func.coalesce(func.sum(EncryptedFile.size), 0)).filter(
            EncryptedFile.vault_id == vault_id
        ).scalar()
        if current_usage + len(data) > auth.quota_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Storage quota exceeded: {current_usage + len(data)} of {auth.quota_bytes} bytes",
            )

        record = EncryptedFile(
            vault_id=vault_id,
            encrypted_metadata=encrypted_metadata,
            metadata_iv=metadata_iv,
            content_iv=content_iv,
            wrapped_file_key=wrapped_file_key,
            wrap_iv=wrap_iv,
            storage_path="",
            size=len(data),
        )
        db.add(record)
        db.flush()

        path = storage.path_for(vault_id, record.id)
        storage.write_blob(path, data)
        record.storage_path = path

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
    data = storage.read_blob(record.storage_path)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"X-Content-Type-Options": "nosniff"},
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
        for _file_id, path in file_infos:
            try:
                storage.shred_blob(path)
            except Exception:
                pass


def _get_owned_file(db: Session, file_id: str, vault_id: str) -> EncryptedFile:
    record = db.query(EncryptedFile).filter(EncryptedFile.id == file_id).first()
    if not record or record.vault_id != vault_id:
        raise HTTPException(status_code=404, detail="File not found")
    return record


_client_dir = os.path.join(os.path.dirname(__file__), "..", "client")
if os.path.isdir(_client_dir):
    app.mount("/", StaticFiles(directory=_client_dir, html=True), name="client")