import hmac
import json
import os
import secrets
import threading

TOKENS_PATH = os.environ.get("TOKENS_PATH", os.path.join(os.path.dirname(__file__), "tokens.json"))
DEFAULT_QUOTA_BYTES = int(os.environ.get("DEFAULT_QUOTA_GB", "10")) * 1024**3

_lock = threading.Lock()

_cache: dict | None = None
_cache_mtime: float | None = None


def _load() -> dict:
    global _cache, _cache_mtime
    try:
        mtime = os.path.getmtime(TOKENS_PATH)
    except FileNotFoundError:
        _cache = {}
        _cache_mtime = None
        return {}
    if _cache is not None and mtime == _cache_mtime:
        return _cache
    with open(TOKENS_PATH, "r") as f:
        content = f.read().strip()
        data = json.loads(content) if content else {}
    _cache = data
    _cache_mtime = mtime
    return data


def _save(data: dict) -> None:
    global _cache, _cache_mtime
    tmp_path = TOKENS_PATH + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, TOKENS_PATH)
    os.chmod(TOKENS_PATH, 0o600)
    _cache = data
    _cache_mtime = os.path.getmtime(TOKENS_PATH)


def _find_token(data: dict, token: str) -> str | None:
    match = None
    for existing_token in data:
        if hmac.compare_digest(existing_token, token):
            match = existing_token
    return match


def get_record(token: str) -> dict | None:
    with _lock:
        data = _load()
        matched = _find_token(data, token)
        return data.get(matched) if matched is not None else None


def bind_to_vault(token: str, vault_id: str) -> dict | None:
    with _lock:
        data = _load()
        matched_token = _find_token(data, token)
        record = data.get(matched_token) if matched_token is not None else None
        if record is None:
            return None
        existing_vault_id = record.get("vault_id")
        if existing_vault_id is None:
            record["vault_id"] = vault_id
            data[token] = record
            _save(data)
        elif not hmac.compare_digest(existing_vault_id, vault_id):
            return None
        return record


def quota_bytes_for(record: dict) -> int:
    quota = record.get("quota_bytes")
    return quota if quota is not None else DEFAULT_QUOTA_BYTES


def create_token(label: str | None = None, quota_bytes: int | None = None, vault_id: str | None = None) -> str:
    token = secrets.token_hex(32)
    with _lock:
        data = _load()
        data[token] = {"vault_id": vault_id, "quota_bytes": quota_bytes, "label": label}
        _save(data)
    return token


def revoke_token(token: str) -> bool:
    with _lock:
        data = _load()
        matched_token = _find_token(data, token)
        if matched_token is None:
            return False
        del data[matched_token]
        _save(data)
        return True


def list_tokens() -> dict:
    with _lock:
        return _load()


def find_by_vault_id(vault_id: str) -> dict | None:
    with _lock:
        data = _load()
        for record in data.values():
            existing_vault_id = record.get("vault_id")
            if existing_vault_id is not None and hmac.compare_digest(existing_vault_id, vault_id):
                return record
        return None