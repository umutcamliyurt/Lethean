import asyncio
import os
import queue as _queue
import re
import secrets

STORAGE_ROOT = os.environ.get("STORAGE_ROOT", "./blobs")
_VAULT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_FILE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

_SHRED_PASSES = int(os.environ.get("SHRED_PASSES", "3"))

_READ_STALL_TIMEOUT_SECONDS = float(os.environ.get("UPLOAD_READ_STALL_TIMEOUT", "60"))

_WRITE_BUFFER_CHUNKS = int(os.environ.get("UPLOAD_WRITE_BUFFER_CHUNKS", "4"))


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


async def write_blob_streamed(
    path: str,
    upload,
    limit: int,
    chunk_size: int = 4 * 1024 * 1024,
    read_timeout: float = _READ_STALL_TIMEOUT_SECONDS,
    buffer_chunks: int = _WRITE_BUFFER_CHUNKS,
) -> int:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    f = os.fdopen(fd, "wb")

    write_q: "_queue.Queue[bytes | None]" = _queue.Queue(maxsize=buffer_chunks)
    write_errors: list[BaseException] = []

    def _writer() -> None:
        try:
            while True:
                item = write_q.get()
                if item is None:
                    break
                f.write(item)
            f.flush()
            os.fsync(f.fileno())
        except Exception as exc:
            write_errors.append(exc)
        finally:
            f.close()

    writer_task = asyncio.create_task(asyncio.to_thread(_writer))

    total = 0
    try:
        while True:
            try:
                chunk = await asyncio.wait_for(upload.read(chunk_size), timeout=read_timeout)
            except asyncio.TimeoutError:
                raise ValueError(
                    f"upload stalled: no data received within {read_timeout:.0f}s"
                )

            if not chunk:
                break

            total += len(chunk)
            if total > limit:
                raise ValueError(f"upload exceeds max size of {limit} bytes")

            if write_errors:
                raise write_errors[0]

            await asyncio.to_thread(write_q.put, chunk)

        await asyncio.to_thread(write_q.put, None)
        await writer_task
        if write_errors:
            raise write_errors[0]

    except Exception:
        await asyncio.to_thread(write_q.put, None)
        await writer_task
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        raise

    return total


def read_blob(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


async def stream_blob(path: str, chunk_size: int = 8 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY)
    if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_SEQUENTIAL"):
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
        except OSError:
            pass
    f = os.fdopen(fd, "rb")
    try:
        while True:
            chunk = await asyncio.to_thread(f.read, chunk_size)
            if not chunk:
                break
            yield chunk
    finally:
        await asyncio.to_thread(f.close)


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