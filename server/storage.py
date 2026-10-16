import asyncio
import os
import queue as _queue
import re

STORAGE_ROOT = os.environ.get("STORAGE_ROOT", "./blobs")
_VAULT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_FILE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

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


async def _write_chunks(path: str, chunks, limit: int, buffer_chunks: int) -> int:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    f = os.fdopen(fd, "wb")

    write_q: "_queue.Queue[bytes | None]" = _queue.Queue(maxsize=buffer_chunks)
    write_errors: list[BaseException] = []

    def _writer() -> None:
        failed = False
        try:
            while True:
                item = write_q.get()
                if item is None:
                    break
                if not failed:
                    try:
                        f.write(item)
                    except Exception as exc:
                        write_errors.append(exc)
                        failed = True
            if not failed:
                f.flush()
                os.fsync(f.fileno())
        except Exception as exc:
            write_errors.append(exc)
        finally:
            f.close()

    writer_task = asyncio.create_task(asyncio.to_thread(_writer))

    total = 0
    try:
        async for chunk in chunks:
            if not chunk:
                continue
            total += len(chunk)
            if total > limit:
                raise ValueError(f"upload exceeds max size of {limit} bytes")

            if write_errors:
                raise write_errors[0]

            try:
                write_q.put_nowait(chunk)
            except _queue.Full:
                await asyncio.to_thread(write_q.put, chunk)

        await asyncio.to_thread(write_q.put, None)
        await writer_task
        if write_errors:
            raise write_errors[0]

    except BaseException:
        sentinel_thread = asyncio.get_running_loop().run_in_executor(None, write_q.put, None)
        try:
            await asyncio.shield(sentinel_thread)
            await asyncio.shield(writer_task)
        except BaseException:
            pass
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        raise

    return total


async def write_blob_streamed(
    path: str,
    upload,
    limit: int,
    chunk_size: int = 4 * 1024 * 1024,
    read_timeout: float = _READ_STALL_TIMEOUT_SECONDS,
    buffer_chunks: int = _WRITE_BUFFER_CHUNKS,
) -> int:
    async def _read():
        while True:
            try:
                chunk = await asyncio.wait_for(upload.read(chunk_size), timeout=read_timeout)
            except asyncio.TimeoutError:
                raise ValueError(
                    f"upload stalled: no data received within {read_timeout:.0f}s"
                )
            if not chunk:
                return
            yield chunk

    return await _write_chunks(path, _read(), limit, buffer_chunks)


class UploadFormError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


_FORM_MAX_FIELD_BYTES = 256 * 1024
_FORM_MAX_PARTS = 32
_FLUSH_BYTES = 4 * 1024 * 1024


async def write_multipart_blob(
    path: str,
    body,
    boundary: bytes,
    limit: int,
    field_limits: dict[str, int],
    blob_field: str = "blob",
    read_timeout: float = _READ_STALL_TIMEOUT_SECONDS,
    buffer_chunks: int = _WRITE_BUFFER_CHUNKS,
) -> tuple[dict[str, str], int]:
    from multipart.exceptions import MultipartParseError
    from multipart.multipart import MultipartParser, parse_options_header

    fields: dict[str, str] = {}
    pending = bytearray()
    st = {"name": None, "is_blob": False, "blob_seen": False, "ended": False, "parts": 0, "field_bytes": 0,
          "header_field": bytearray(), "header_value": bytearray(), "headers": {}, "value": bytearray()}

    def on_part_begin():
        st["parts"] += 1
        if st["parts"] > _FORM_MAX_PARTS:
            raise UploadFormError(400, "Too many form parts")
        st["headers"] = {}
        st["value"] = bytearray()
        st["name"] = None
        st["is_blob"] = False

    def on_header_field(data, start, end):
        st["header_field"] += data[start:end]

    def on_header_value(data, start, end):
        st["header_value"] += data[start:end]

    def on_header_end():
        st["headers"][bytes(st["header_field"]).lower()] = bytes(st["header_value"])
        st["header_field"] = bytearray()
        st["header_value"] = bytearray()

    def on_headers_finished():
        _, options = parse_options_header(st["headers"].get(b"content-disposition", b""))
        name = options.get(b"name")
        if name is None:
            raise UploadFormError(400, "Form part without a name")
        st["name"] = name.decode("utf-8", "replace")
        if st["name"] == blob_field:
            if st["blob_seen"]:
                raise UploadFormError(400, "More than one file blob")
            st["blob_seen"] = True
            st["is_blob"] = True

    def on_part_data(data, start, end):
        if st["is_blob"]:
            pending.extend(data[start:end])
            return
        st["field_bytes"] += end - start
        if st["field_bytes"] > _FORM_MAX_FIELD_BYTES:
            raise UploadFormError(413, "Form fields too large")
        st["value"] += data[start:end]

    def on_part_end():
        if st["is_blob"]:
            return
        name = st["name"]
        value = bytes(st["value"]).decode("utf-8", "replace")
        cap = field_limits.get(name)
        if cap is not None and len(value) > cap:
            raise UploadFormError(422, f"{name} is too long")
        fields[name] = value

    def on_end():
        st["ended"] = True

    parser = MultipartParser(boundary, {
        "on_part_begin": on_part_begin,
        "on_part_data": on_part_data,
        "on_part_end": on_part_end,
        "on_header_field": on_header_field,
        "on_header_value": on_header_value,
        "on_header_end": on_header_end,
        "on_headers_finished": on_headers_finished,
        "on_end": on_end,
    })

    async def _blob_chunks():
        iterator = body.__aiter__()
        while True:
            try:
                chunk = await asyncio.wait_for(iterator.__anext__(), timeout=read_timeout)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                raise ValueError(f"upload stalled: no data received within {read_timeout:.0f}s")
            if chunk:
                try:
                    parser.write(chunk)
                except MultipartParseError:
                    raise UploadFormError(400, "Malformed multipart body")
            if len(pending) >= _FLUSH_BYTES:
                out = bytes(pending)
                pending.clear()
                yield out
        try:
            parser.finalize()
        except MultipartParseError:
            raise UploadFormError(400, "Malformed multipart body")
        if pending:
            out = bytes(pending)
            pending.clear()
            yield out
        if not st["ended"]:
            raise UploadFormError(400, "Incomplete multipart body")
        if not st["blob_seen"]:
            raise UploadFormError(400, "Missing file blob")

    size = await _write_chunks(path, _blob_chunks(), limit, buffer_chunks)
    return fields, size


def read_blob(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


async def stream_blob(path: str, chunk_size: int = 8 * 1024 * 1024, offset: int = 0, length: int | None = None):
    fd = os.open(path, os.O_RDONLY)
    if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_SEQUENTIAL"):
        try:
            os.posix_fadvise(fd, offset, length or 0, os.POSIX_FADV_SEQUENTIAL)
        except OSError:
            pass
    try:
        pos = offset
        remaining = length
        while remaining is None or remaining > 0:
            want = chunk_size if remaining is None else min(chunk_size, remaining)
            chunk = await asyncio.to_thread(os.pread, fd, want, pos)
            if not chunk:
                break
            pos += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)
            yield chunk
    finally:
        await asyncio.to_thread(os.close, fd)


def delete_blob(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass

import shutil

_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_UPLOADS_DIR = "_uploads"


def _session_dir(session_id: str) -> str:
    if not _SESSION_ID_RE.match(session_id):
        raise ValueError("invalid upload session id")
    return os.path.join(STORAGE_ROOT, _UPLOADS_DIR, session_id)


def create_session_file(session_id: str, total_size: int) -> None:
    d = _session_dir(session_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(d, "data.bin"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.ftruncate(fd, total_size)
    finally:
        os.close(fd)


def _pwrite_all(fd: int, data: bytes, offset: int) -> None:
    view = memoryview(data)
    while view:
        n = os.pwrite(fd, view, offset)
        view = view[n:]
        offset += n


async def write_part_streamed(
    session_id: str,
    index: int,
    offset: int,
    expected_len: int,
    chunks,
    read_timeout: float = _READ_STALL_TIMEOUT_SECONDS,
) -> None:
    d = _session_dir(session_id)
    marker = os.path.join(d, f"{index}.done")
    try:
        os.remove(marker)
    except FileNotFoundError:
        pass

    fd = os.open(os.path.join(d, "data.bin"), os.O_WRONLY)
    try:
        written = 0
        flushed = 0
        buf = bytearray()
        iterator = chunks.__aiter__()
        while True:
            try:
                chunk = await asyncio.wait_for(iterator.__anext__(), timeout=read_timeout)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                raise ValueError(f"upload stalled: no data received within {read_timeout:.0f}s")
            if not chunk:
                continue
            if written + len(chunk) > expected_len:
                raise ValueError(f"part {index} is larger than {expected_len} bytes")
            buf += chunk
            written += len(chunk)
            if len(buf) >= _FLUSH_BYTES:
                await asyncio.to_thread(_pwrite_all, fd, bytes(buf), offset + flushed)
                flushed += len(buf)
                buf.clear()
        if buf:
            await asyncio.to_thread(_pwrite_all, fd, bytes(buf), offset + flushed)
            flushed += len(buf)
        if written != expected_len:
            raise ValueError(f"part {index} must be exactly {expected_len} bytes, got {written}")
        await asyncio.to_thread(os.fsync, fd)
    finally:
        os.close(fd)

    with open(marker, "wb"):
        pass


def received_parts(session_id: str) -> list[int]:
    try:
        names = os.listdir(_session_dir(session_id))
    except FileNotFoundError:
        return []
    return sorted(int(n[:-5]) for n in names if n.endswith(".done") and n[:-5].isdigit())


def finalize_session(session_id: str, final_path: str) -> None:
    d = _session_dir(session_id)
    os.replace(os.path.join(d, "data.bin"), final_path)
    shutil.rmtree(d, ignore_errors=True)


def remove_session(session_id: str) -> None:
    try:
        shutil.rmtree(_session_dir(session_id), ignore_errors=True)
    except ValueError:
        pass
