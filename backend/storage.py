import os
import re
import secrets

STORAGE_ROOT = os.environ.get("STORAGE_ROOT", "./blobs")
_VAULT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_FILE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

_SHRED_PASSES = int(os.environ.get("SHRED_PASSES", "3"))


def path_for(vault_id: str, file_id: str) -> str:
    if not _VAULT_ID_RE.match(vault_id):
        raise ValueError("invalid vault_id")
    if not _FILE_ID_RE.match(file_id):
        raise ValueError("invalid file_id")
    d = os.path.join(STORAGE_ROOT, vault_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return os.path.join(d, f"{file_id}.bin")


def write_blob(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def read_blob(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def shred_blob(path: str) -> None:
    try:
        length = os.path.getsize(path)
    except FileNotFoundError:
        return

    try:
        with open(path, "r+b") as f:
            for _ in range(_SHRED_PASSES):
                f.seek(0)
                f.write(secrets.token_bytes(length))
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.write(b"\x00" * length)
            f.flush()
            os.fsync(f.fileno())
    except FileNotFoundError:
        return
    finally:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        dir_path = os.path.dirname(path)
        dir_fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def delete_blob(path: str) -> None:
    shred_blob(path)