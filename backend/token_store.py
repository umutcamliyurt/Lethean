import hashlib
import hmac
import json
import logging
import os
import secrets
import threading

TOKENS_PATH = os.environ.get("TOKENS_PATH", os.path.join(os.path.dirname(__file__), "tokens.json"))
DEFAULT_QUOTA_BYTES = int(os.environ.get("DEFAULT_QUOTA_GB", "10")) * 1024**3

_FORMAT_VERSION = 2

logger = logging.getLogger("lethean.token_store")

_lock = threading.Lock()

_cache: dict | None = None
_cache_mtime: float | None = None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
        raw = json.loads(content) if content else {}

    if raw.get("version") == _FORMAT_VERSION and isinstance(raw.get("tokens"), dict):
        data = raw["tokens"]
    elif "version" not in raw:
        data = {_hash_token(token): record for token, record in raw.items()}
        if raw:
            logger.warning(
                "Migrated %d token(s) in %s to hashed storage. "
                "Raw token values have been overwritten on disk and can no "
                "longer be recovered from this file.",
                len(raw), TOKENS_PATH,
            )
        _write(data)
    else:
        raise RuntimeError(f"{TOKENS_PATH}: unsupported tokens.json format version {raw.get('version')!r}")

    _cache = data
    _cache_mtime = os.path.getmtime(TOKENS_PATH)
    return data


def _write(data: dict) -> None:
    global _cache, _cache_mtime
    tmp_path = TOKENS_PATH + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"version": _FORMAT_VERSION, "tokens": data}, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, TOKENS_PATH)
    os.chmod(TOKENS_PATH, 0o600)
    _cache = data
    _cache_mtime = os.path.getmtime(TOKENS_PATH)


def _find_hash(data: dict, token_hash: str) -> str | None:
    match = None
    for existing_hash in data:
        if hmac.compare_digest(existing_hash, token_hash):
            match = existing_hash
    return match


def get_record(token: str) -> dict | None:
    with _lock:
        data = _load()
        matched = _find_hash(data, _hash_token(token))
        return data.get(matched) if matched is not None else None


def bind_to_vault(token: str, vault_id: str) -> dict | None:
    with _lock:
        data = _load()
        matched_hash = _find_hash(data, _hash_token(token))
        record = data.get(matched_hash) if matched_hash is not None else None
        if record is None:
            return None
        existing_vault_id = record.get("vault_id")
        if existing_vault_id is None:
            record["vault_id"] = vault_id
            data[matched_hash] = record
            _write(data)
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
        data[_hash_token(token)] = {"vault_id": vault_id, "quota_bytes": quota_bytes, "label": label}
        _write(data)
    return token


def revoke_token(token: str) -> bool:
    with _lock:
        data = _load()
        matched_hash = _find_hash(data, _hash_token(token))
        if matched_hash is None:
            return False
        del data[matched_hash]
        _write(data)
        return True


def revoke_by_id(token_id: str) -> bool:
    token_id = token_id.strip().lower()
    if not token_id:
        return False
    with _lock:
        data = _load()
        matches = [h for h in data if h.startswith(token_id)]
        if len(matches) != 1:
            return False
        del data[matches[0]]
        _write(data)
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