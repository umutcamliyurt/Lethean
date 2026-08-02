import hmac
import json
import os
import secrets
import threading

TOKENS_PATH = os.environ.get("TOKENS_PATH", os.path.join(os.path.dirname(__file__), "tokens.json"))
DEFAULT_QUOTA_BYTES = int(os.environ.get("DEFAULT_QUOTA_GB", "10")) * 1024**3

_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(TOKENS_PATH):
        return {}
    with open(TOKENS_PATH, "r") as f:
        content = f.read().strip()
        return json.loads(content) if content else {}


def _save(data: dict) -> None:
    tmp_path = TOKENS_PATH + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, TOKENS_PATH)
    os.chmod(TOKENS_PATH, 0o600)


def get_record(token: str) -> dict | None:
    with _lock:
        return _load().get(token)


def bind_to_vault(token: str, vault_id: str) -> dict | None:
    with _lock:
        data = _load()
        record = data.get(token)
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
        if token not in data:
            return False
        del data[token]
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
