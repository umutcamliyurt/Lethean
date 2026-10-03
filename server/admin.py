import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import uvicorn
from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import share_store
import storage
import token_store
from database import get_db
from models import EncryptedFile, ShareToken

logger = logging.getLogger("lethean.admin")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ADMIN_HOST = os.environ.get("ADMIN_HOST", "127.0.0.1")
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8001"))
_SESSION_TTL = int(os.environ.get("ADMIN_SESSION_TTL", str(12 * 3600)))
_LOGIN_MAX_FAILS = int(os.environ.get("ADMIN_LOGIN_MAX_FAILS", "5"))
_LOGIN_LOCKOUT = int(os.environ.get("ADMIN_LOGIN_LOCKOUT", "900"))
_MIN_PASSWORD_LEN = 12

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_HERE, "admin_static")
_COOKIE = "lethean_admin_session"

_TOKEN_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
_SHARE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

GB = 1024**3



_sessions: dict[str, float] = {}
_sessions_lock = threading.Lock()

_login_fails: dict[str, deque] = defaultdict(deque)
_login_lock = threading.Lock()


def _new_session() -> str:
    sid = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _sessions_lock:
        for k in [k for k, exp in _sessions.items() if exp <= now]:
            del _sessions[k]
        _sessions[sid] = now + _SESSION_TTL
    return sid


def _session_valid(sid: str) -> bool:
    now = time.monotonic()
    with _sessions_lock:
        exp = _sessions.get(sid)
        if exp is None:
            return False
        if exp <= now:
            del _sessions[sid]
            return False
        return True


def _end_session(sid: str) -> None:
    with _sessions_lock:
        _sessions.pop(sid, None)


def _client_ip(request: Request) -> str:
    if os.environ.get("TRUST_PROXY_HEADERS", "0") == "1":
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    return (
        os.environ.get("TRUST_PROXY_HEADERS", "0") == "1"
        and request.headers.get("x-forwarded-proto") == "https"
    )


def _locked_out(ip: str) -> bool:
    now = time.monotonic()
    with _login_lock:
        fails = _login_fails[ip]
        while fails and now - fails[0] > _LOGIN_LOCKOUT:
            fails.popleft()
        if not fails:
            _login_fails.pop(ip, None)
            return False
        return len(fails) >= _LOGIN_MAX_FAILS


def _record_fail(ip: str) -> None:
    with _login_lock:
        _login_fails[ip].append(time.monotonic())


def _clear_fails(ip: str) -> None:
    with _login_lock:
        _login_fails.pop(ip, None)


def _csrf_ok(request: Request) -> bool:
    return request.headers.get("x-admin-request") == "1"


def _require_admin(request: Request) -> None:
    sid = request.cookies.get(_COOKIE)
    if not sid or not _session_valid(sid):
        raise HTTPException(status_code=401, detail="Not signed in")
    if request.method not in ("GET", "HEAD") and not _csrf_ok(request):
        raise HTTPException(status_code=403, detail="Missing request header")



admin_app = FastAPI(title="Lethean Admin", docs_url=None, redoc_url=None, openapi_url=None)


@admin_app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'",
    )
    response.headers.setdefault("Cache-Control", "no-store")
    if _is_https(request):
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


class LoginBody(BaseModel):
    password: str = Field(..., max_length=256)


@admin_app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response):
    if not _csrf_ok(request):
        raise HTTPException(status_code=403, detail="Missing request header")

    ip = _client_ip(request)
    if _locked_out(ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    supplied = hashlib.sha256(body.password.encode("utf-8")).digest()
    expected = hashlib.sha256(ADMIN_PASSWORD.encode("utf-8")).digest()
    if not hmac.compare_digest(supplied, expected):
        _record_fail(ip)
        time.sleep(0.5)
        raise HTTPException(status_code=401, detail="Wrong password")

    _clear_fails(ip)
    sid = _new_session()
    response.set_cookie(
        _COOKIE, sid,
        max_age=_SESSION_TTL, httponly=True, samesite="strict",
        secure=_is_https(request), path="/",
    )
    logger.info("admin login from %s", ip)
    return {"ok": True}


@admin_app.post("/api/logout", status_code=204)
def logout(request: Request):
    if not _csrf_ok(request):
        raise HTTPException(status_code=403, detail="Missing request header")
    sid = request.cookies.get(_COOKIE)
    if sid:
        _end_session(sid)
    resp = Response(status_code=204)
    resp.delete_cookie(_COOKIE, path="/")
    return resp


api = APIRouter(prefix="/api", dependencies=[Depends(_require_admin)])


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _vault_usage(db: Session) -> dict[str, tuple[int, int]]:
    rows = (
        db.query(
            EncryptedFile.vault_id,
            func.count(EncryptedFile.id),
            func.coalesce(func.sum(EncryptedFile.size), 0),
        )
        .group_by(EncryptedFile.vault_id)
        .all()
    )
    return {vault_id: (count, total) for vault_id, count, total in rows}


@api.get("/session")
def session():
    return {"ok": True}


@api.get("/overview")
def overview(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    file_count, total_bytes = db.query(
        func.count(EncryptedFile.id), func.coalesce(func.sum(EncryptedFile.size), 0)
    ).one()
    vault_count = db.query(func.count(func.distinct(EncryptedFile.vault_id))).scalar() or 0
    active_shares = db.query(func.count(ShareToken.id)).filter(ShareToken.expires_at > now).scalar() or 0
    expired_shares = db.query(func.count(ShareToken.id)).filter(ShareToken.expires_at <= now).scalar() or 0

    records = list(token_store.list_tokens().values())
    bound = sum(1 for r in records if r.get("vault_id"))

    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "vault_count": vault_count,
        "token_count": len(records),
        "tokens_bound": bound,
        "tokens_unbound": len(records) - bound,
        "active_shares": active_shares,
        "expired_shares": expired_shares,
        "default_quota_bytes": token_store.DEFAULT_QUOTA_BYTES,
    }


@api.get("/tokens")
def list_tokens(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    usage = _vault_usage(db)
    share_rows = (
        db.query(ShareToken.vault_id, func.count(ShareToken.id))
        .filter(ShareToken.expires_at > now)
        .group_by(ShareToken.vault_id)
        .all()
    )
    shares_by_vault = {v: c for v, c in share_rows}

    out = []
    for token_hash, record in list(token_store.list_tokens().items()):
        vault_id = record.get("vault_id")
        file_count, total = usage.get(vault_id, (0, 0)) if vault_id else (0, 0)
        out.append({
            "id": token_hash[:16],
            "label": record.get("label"),
            "bound": bool(vault_id),
            "vault": vault_id[:12] if vault_id else None,
            "quota_bytes": token_store.quota_bytes_for(record),
            "custom_quota": record.get("quota_bytes") is not None,
            "file_count": file_count,
            "total_bytes": total,
            "active_shares": shares_by_vault.get(vault_id, 0) if vault_id else 0,
        })
    out.sort(key=lambda t: ((t["label"] or "~").lower(), t["id"]))
    return out


class CreateTokenBody(BaseModel):
    label: str | None = Field(default=None, max_length=120)
    quota_gb: float | None = Field(default=None, gt=0, le=1_000_000)
    decoy: bool = True


def _clean_label(label: str | None) -> str | None:
    if label is None:
        return None
    label = label.strip()
    return label or None


@api.post("/tokens", status_code=201)
def create_token(body: CreateTokenBody):
    label = _clean_label(body.label)
    quota_bytes = int(body.quota_gb * GB) if body.quota_gb is not None else None

    real = token_store.create_token(label=label, quota_bytes=quota_bytes)
    decoy = None
    if body.decoy:
        decoy_label = f"{label} (decoy)" if label else "(decoy)"
        decoy = token_store.create_token(label=decoy_label, quota_bytes=quota_bytes)

    logger.info("admin created token label=%r decoy=%s", label, body.decoy)
    return {"token": real, "decoy_token": decoy}


class UpdateTokenBody(BaseModel):
    label: str | None = Field(default=None, max_length=120)
    quota_gb: float | None = Field(default=None, gt=0, le=1_000_000)


def _update_token(token_id: str, label: str | None, quota_bytes: int | None) -> bool:
    with token_store._lock:
        data = token_store._load()
        matches = [h for h in data if h.startswith(token_id)]
        if len(matches) != 1:
            return False
        record = data[matches[0]]
        record["label"] = label
        record["quota_bytes"] = quota_bytes
        token_store._write(data)
        return True


@api.patch("/tokens/{token_id}", status_code=204)
def update_token(token_id: str, body: UpdateTokenBody):
    if not _TOKEN_ID_RE.match(token_id):
        raise HTTPException(status_code=404, detail="No such token")
    quota_bytes = int(body.quota_gb * GB) if body.quota_gb is not None else None
    if not _update_token(token_id, _clean_label(body.label), quota_bytes):
        raise HTTPException(status_code=404, detail="No such token")
    logger.info("admin edited token %s", token_id)
    return Response(status_code=204)


def _delete_files(file_infos: list[tuple[str, str]]) -> None:
    for file_id, path in file_infos:
        try:
            storage.delete_blob(path)
        except Exception:
            logger.exception("admin: failed to delete blob for file %s", file_id)


@api.delete("/tokens/{token_id}", status_code=204)
def revoke_token(
    token_id: str,
    background_tasks: BackgroundTasks,
    delete_contents: bool = False,
    db: Session = Depends(get_db),
):
    if not _TOKEN_ID_RE.match(token_id):
        raise HTTPException(status_code=404, detail="No such token")
    matches = [
        record for token_hash, record in list(token_store.list_tokens().items())
        if token_hash.startswith(token_id)
    ]
    if len(matches) != 1:
        raise HTTPException(status_code=404, detail="No such token")
    vault_id = matches[0].get("vault_id")

    if not token_store.revoke_by_id(token_id):
        raise HTTPException(status_code=404, detail="No such token")
    logger.info("admin revoked token %s", token_id)

    if delete_contents and vault_id:
        rows = (
            db.query(EncryptedFile.id, EncryptedFile.storage_path)
            .filter(EncryptedFile.vault_id == vault_id)
            .all()
        )
        file_infos = [(r.id, r.storage_path) for r in rows]
        db.query(ShareToken).filter(ShareToken.vault_id == vault_id).delete(synchronize_session=False)
        db.query(EncryptedFile).filter(EncryptedFile.vault_id == vault_id).delete(synchronize_session=False)
        db.commit()
        background_tasks.add_task(_delete_files, file_infos)
        logger.info("admin deleted %d file(s) of token %s", len(file_infos), token_id)
    return Response(status_code=204)


@api.delete("/tokens/{token_id}/shares")
def revoke_token_shares(token_id: str, db: Session = Depends(get_db)):
    if not _TOKEN_ID_RE.match(token_id):
        raise HTTPException(status_code=404, detail="No such token")
    matches = [
        record for token_hash, record in list(token_store.list_tokens().items())
        if token_hash.startswith(token_id)
    ]
    if len(matches) != 1:
        raise HTTPException(status_code=404, detail="No such token")
    vault_id = matches[0].get("vault_id")
    if not vault_id:
        return {"removed": 0}
    removed = db.query(ShareToken).filter(ShareToken.vault_id == vault_id).delete(synchronize_session=False)
    db.commit()
    logger.info("admin revoked %d share link(s) for token %s", removed, token_id)
    return {"removed": removed}


@api.get("/shares")
def list_shares(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    rows = (
        db.query(ShareToken, EncryptedFile.size)
        .join(EncryptedFile, EncryptedFile.id == ShareToken.file_id)
        .filter(ShareToken.expires_at > now)
        .order_by(ShareToken.created_at.desc())
        .limit(500)
        .all()
    )
    return [
        {
            "id": share.id,
            "file": share.file_id[:8],
            "vault": share.vault_id[:12],
            "size": size,
            "downloads_used": share.download_count,
            "max_downloads": share.max_downloads,
            "created_at": _iso(share.created_at),
            "expires_at": _iso(share.expires_at),
            "deletable": share.delete_token_hash is not None,
        }
        for share, size in rows
    ]


@api.delete("/shares/{share_id}", status_code=204)
def revoke_share(share_id: str, db: Session = Depends(get_db)):
    if not _SHARE_ID_RE.match(share_id):
        raise HTTPException(status_code=404, detail="No such share link")
    deleted = db.query(ShareToken).filter(ShareToken.id == share_id).delete(synchronize_session=False)
    db.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="No such share link")
    logger.info("admin revoked share %s", share_id[:8])
    return Response(status_code=204)


@api.post("/shares/purge-expired")
def purge_expired_shares(db: Session = Depends(get_db)):
    removed = share_store.purge_expired(db)
    logger.info("admin purged %d expired share link(s)", removed)
    return {"removed": removed}


admin_app.include_router(api)



def _client_asset(name: str) -> str | None:
    dirs = []
    env_dir = os.environ.get("CLIENT_DIST_DIR")
    if env_dir:
        dirs.append(env_dir)
    dirs += [
        os.path.join(_HERE, "..", "client", "dist"),
        os.path.join(_HERE, ".."),
    ]
    for d in dirs:
        path = os.path.join(d, name)
        if os.path.isfile(path):
            return path
    return None


_NO_CACHE = {"Cache-Control": "no-store"}

_LOGO_FALLBACK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="100 270 1052 680" fill="#f0f0f0">'
    '<path d="M626 292C540 380 507 450 507 520C507 640 560 740 626 822C692 740 745 640 745 520C745 450 712 380 626 292Z"/>'
    '<path d="M276 430C380 450 450 490 472 525C480 640 520 740 594 830C420 810 280 660 276 430Z"/>'
    '<path d="M976 430C872 450 802 490 780 525C772 640 732 740 658 830C832 810 972 660 976 430Z"/>'
    '<path d="M124 730C200 705 290 700 335 712C400 790 500 830 586 855C480 925 300 930 124 730Z"/>'
    '<path d="M1128 730C1052 705 962 700 917 712C852 790 752 830 666 855C772 925 952 930 1128 730Z"/>'
    "</svg>"
)


@admin_app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"), media_type="text/html", headers=_NO_CACHE)


@admin_app.get("/admin.css", include_in_schema=False)
def admin_css():
    return FileResponse(os.path.join(_STATIC_DIR, "admin.css"), media_type="text/css", headers=_NO_CACHE)


@admin_app.get("/admin.js", include_in_schema=False)
def admin_js():
    return FileResponse(os.path.join(_STATIC_DIR, "admin.js"), media_type="text/javascript", headers=_NO_CACHE)


@admin_app.get("/style.css", include_in_schema=False)
def client_style():
    path = _client_asset("style.css")
    if path is None:
        raise HTTPException(status_code=404, detail="style.css not found; set CLIENT_DIST_DIR")
    return FileResponse(path, media_type="text/css", headers=_NO_CACHE)


@admin_app.get("/logo.png", include_in_schema=False)
def client_logo():
    path = _client_asset("logo.png")
    if path is None:
        return Response(content=_LOGO_FALLBACK_SVG, media_type="image/svg+xml", headers=_NO_CACHE)
    return FileResponse(path, media_type="image/png", headers=_NO_CACHE)



_server: uvicorn.Server | None = None
_thread: threading.Thread | None = None


def start_in_background() -> threading.Thread | None:
    global _server, _thread
    if _thread is not None:
        return _thread
    if not ADMIN_PASSWORD:
        logger.info("Admin panel disabled (ADMIN_PASSWORD not set).")
        return None
    if len(ADMIN_PASSWORD) < _MIN_PASSWORD_LEN:
        logger.error(
            "Admin panel NOT started: ADMIN_PASSWORD must be at least %d characters.", _MIN_PASSWORD_LEN
        )
        return None

    config = uvicorn.Config(admin_app, host=ADMIN_HOST, port=ADMIN_PORT, log_level="info", access_log=False)
    _server = uvicorn.Server(config)
    _thread = threading.Thread(target=_server.run, name="lethean-admin", daemon=True)
    _thread.start()
    logger.info("Admin panel listening on http://%s:%d", ADMIN_HOST, ADMIN_PORT)
    return _thread


def stop() -> None:
    global _server, _thread
    if _server is not None:
        _server.should_exit = True
    if _thread is not None:
        _thread.join(timeout=5)
    _server = None
    _thread = None
