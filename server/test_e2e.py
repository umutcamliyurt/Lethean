import os, sys, tempfile, threading, time, hashlib

tmp = tempfile.mkdtemp()
os.environ["STORAGE_ROOT"] = os.path.join(tmp, "blobs")
os.environ["TOKENS_PATH"] = os.path.join(tmp, "tokens.json")
os.environ["CLIENT_DIST_DIR"] = os.path.join(tmp, "nodist")
os.chdir(tmp)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
import main, token_store, storage
from models import EncryptedFile

client = TestClient(main.app)
VAULT = "a" * 64
VAULT2 = "b" * 64
passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"PASS {name}")
    else:
        failed += 1
        print(f"FAIL {name} {extra}")


def hdr(v=VAULT, tok=None):
    h = {"Authorization": f"Bearer {v}"}
    if tok:
        h["X-Access-Token"] = tok
    return h


FORM = dict(content_iv="iv", encrypted_metadata="meta", metadata_iv="miv", wrapped_file_key="wk", wrap_iv="wiv")


def upload(tok, data=b"hello world" * 1000, v=VAULT):
    return client.post("/files", data=FORM, files={"blob": ("b", data)}, headers=hdr(v, tok))


tok = token_store.create_token(label="t1", quota_bytes=10 * 1024 * 1024)

r = client.post("/files", data=FORM, files={"blob": ("b", b"x")}, headers=hdr())
check("upload without token = 401", r.status_code == 401, r.text)

payload = os.urandom(300_000)
r = upload(tok, payload)
check("upload 201", r.status_code == 201, r.text)
fid = r.json()["id"]
check("created_at has tz", r.json()["created_at"].endswith(("Z", "+00:00")), r.json()["created_at"])

r = client.get("/files", headers=hdr())
check("list has 1", r.status_code == 200 and len(r.json()) == 1, r.text)
r = client.get(f"/files/{fid}", headers=hdr())
check("meta ok", r.status_code == 200, r.text)
r = client.get("/usage", headers=hdr())
check("usage", r.status_code == 200 and r.json()["total_bytes"] == len(payload), r.text)

r = client.get(f"/files/{fid}/blob", headers=hdr())
check("download matches", r.status_code == 200 and r.content == payload, str(r.status_code))

r = client.get(f"/files/{fid}", headers=hdr(VAULT2))
check("other vault 404", r.status_code == 404)

r = client.post(f"/files/{fid}/share?max_downloads=2&allow_delete=true", headers=hdr())
check("share create 201", r.status_code == 201, r.text)
st, dt = r.json()["shareToken"], r.json()["deleteToken"]
check("share expiresAt has tz", r.json()["expiresAt"].endswith(("Z", "+00:00")), r.json()["expiresAt"])
r = client.get(f"/share/{st}")
check("share meta 200", r.status_code == 200, r.text)
check("share meta expires tz", r.json()["expires_at"].endswith(("Z", "+00:00")), r.json().get("expires_at"))
check("share deletable", r.json()["deletable"] is True)
r1 = client.get(f"/share/{st}/blob")
r2 = client.get(f"/share/{st}/blob")
r3 = client.get(f"/share/{st}/blob")
check("share downloads 2 then 404", (r1.status_code, r2.status_code, r3.status_code) == (200, 200, 404),
      (r1.status_code, r2.status_code, r3.status_code))
check("share content ok", r1.content == payload)

blob_path = None
db = main.SessionLocal() if hasattr(main, "SessionLocal") else None
from database import SessionLocal
db = SessionLocal()
blob_path = db.query(EncryptedFile).filter(EncryptedFile.id == fid).first().storage_path
db.close()
check("blob exists on disk", os.path.exists(blob_path))
r = client.delete(f"/files/{fid}", headers=hdr())
check("DELETE /files/{id} = 204", r.status_code == 204, f"{r.status_code} {r.text}")
check("blob deleted from disk", not os.path.exists(blob_path))
r = client.get(f"/files/{fid}", headers=hdr())
check("deleted file 404", r.status_code == 404)

r = upload(tok, b"abc" * 100)
fid2 = r.json()["id"]
r = client.post(f"/files/{fid2}/share?allow_delete=true", headers=hdr())
dt2 = r.json()["deleteToken"]
r = client.delete(f"/share/{dt2}")
check("delete via delete token 204", r.status_code == 204, r.text)
r = client.get(f"/files/{fid2}", headers=hdr())
check("file gone after delete token", r.status_code == 404)

small = token_store.create_token(label="small", quota_bytes=1000)
r = upload(small, b"x" * 5000, v=VAULT2)
check("over-quota upload rejected 413", r.status_code == 413, f"{r.status_code} {r.text}")
check("reservation released after reject", not main._reserved_bytes.get(VAULT2))
r = upload(small, b"x" * 500, v=VAULT2)
check("within-quota upload ok", r.status_code == 201, r.text)
check("reservation released after success", not main._reserved_bytes.get(VAULT2))

import io, socket


class SlowBody(io.RawIOBase):
    pass

import httpx, uvicorn

port = 18765
config = uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error")
server = uvicorn.Server(config)
th = threading.Thread(target=server.run, daemon=True)
th.start()
for _ in range(50):
    if server.started:
        break
    time.sleep(0.1)

tok3 = token_store.create_token(label="slow", quota_bytes=50 * 1024 * 1024)
V3 = "c" * 64
seed = httpx.post(f"http://127.0.0.1:{port}/files", data=FORM, files={"blob": ("b", b"seed")}, headers=hdr(V3, tok3))
seed_id = seed.json()["id"]


def slow_gen():
    yield b"--B\r\nContent-Disposition: form-data; name=\"content_iv\"\r\n\r\niv\r\n"
    for n, val in (("encrypted_metadata", "m"), ("metadata_iv", "i"), ("wrapped_file_key", "k"), ("wrap_iv", "w")):
        yield f"--B\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{val}\r\n".encode()
    yield b"--B\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"b\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    for _ in range(6):
        yield b"z" * 50_000
        time.sleep(0.5)
    yield b"\r\n--B--\r\n"


result = {}


def do_slow():
    h = hdr(V3, tok3)
    h["Content-Type"] = "multipart/form-data; boundary=B"
    try:
        r = httpx.post(f"http://127.0.0.1:{port}/files", content=slow_gen(), headers=h, timeout=60)
        result["slow"] = (r.status_code, r.text[:200])
    except Exception as e:
        result["slow"] = ("exc", repr(e))


t = threading.Thread(target=do_slow)
t.start()
time.sleep(1.0)
t0 = time.time()
r = httpx.post(f"http://127.0.0.1:{port}/files/{seed_id}/share", headers=hdr(V3), timeout=40)
dt_share = time.time() - t0
check("share creation not blocked by in-flight upload", r.status_code == 201 and dt_share < 3,
      f"status={r.status_code} took={dt_share:.1f}s {r.text[:100]}")
t.join()
check("slow upload completed", result.get("slow", (None,))[0] == 201, result.get("slow"))
check("reservation cleared after slow upload", not main._reserved_bytes.get(V3))

def drop():
    s = socket.create_connection(("127.0.0.1", port))
    body_head = b"--B\r\nContent-Disposition: form-data; name=\"content_iv\"\r\n\r\niv\r\n"
    for n, val in (("encrypted_metadata", "m"), ("metadata_iv", "i"), ("wrapped_file_key", "k"), ("wrap_iv", "w")):
        body_head += f"--B\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{val}\r\n".encode()
    body_head += b"--B\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"b\"\r\nContent-Type: application/octet-stream\r\n\r\n" + b"q" * 20000
    req = (f"POST /files HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {V3}\r\nX-Access-Token: {tok3}\r\n"
           f"Content-Type: multipart/form-data; boundary=B\r\nContent-Length: {len(body_head) + 100000}\r\n\r\n").encode()
    s.sendall(req + body_head)
    time.sleep(0.5)
    s.close()

drop()
time.sleep(3)
check("reservation released after client disconnect", not main._reserved_bytes.get(V3), dict(main._reserved_bytes))
leftovers = [f for f in os.listdir(os.path.join(os.environ["STORAGE_ROOT"], V3))]
db = SessionLocal()
db_ids = {r_.id + ".bin" for r_ in db.query(EncryptedFile).filter(EncryptedFile.vault_id == V3)}
db.close()
check("no orphan blob after disconnect", set(leftovers) <= db_ids, (leftovers, db_ids))

def find_same_stripe():
    base = "d" * 64
    s0 = main._stripe_for_vault(base)
    for i in range(100000):
        cand = hashlib.sha256(str(i).encode()).hexdigest()
        if cand != base and main._stripe_for_vault(cand) == s0:
            return base, cand

old, new = find_same_stripe()
tok4 = token_store.create_token(label="rot", quota_bytes=10 * 1024 * 1024)
r = upload(tok4, b"rot" * 100, v=old)
rid = r.json()["id"]
res = {}


def do_rotate():
    res["r"] = client.post("/vault/rotate", json={"new_vault_id": new, "rewraps": [{"file_id": rid, "wrapped_file_key": "nk", "wrap_iv": "niv"}]},
                           headers=hdr(old, tok4))

rt = threading.Thread(target=do_rotate, daemon=True)
rt.start()
rt.join(10)
check("rotate with same-stripe ids does not deadlock", not rt.is_alive())
if "r" in res:
    check("rotate 200", res["r"].status_code == 200 and res["r"].json()["files_moved"] == 1, res["r"].text)
    r = client.get(f"/files/{rid}", headers=hdr(new))
    check("file visible under new vault", r.status_code == 200 and r.json()["wrapped_file_key"] == "nk", r.text)
    r = client.get(f"/files/{rid}/blob", headers=hdr(new))
    check("blob readable after rotate", r.status_code == 200 and r.content == b"rot" * 100)

r = client.delete("/vault", headers=hdr(new))
check("wipe 204", r.status_code == 204)
r = client.get("/files", headers=hdr(new))
check("vault empty after wipe", r.json() == [])

p = os.path.join(tmp, "big.bin")
with open(p, "wb") as f:
    f.write(os.urandom(9 * 1024 * 1024 + 7))
import resource
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
storage.delete_blob(p)
check("delete removes file", not os.path.exists(p))
storage.delete_blob(p)
check("delete on missing file is no-op", True)

import asyncio


class FakeUpload:
    def __init__(self, n):
        self.n = n
    async def read(self, size):
        if self.n <= 0:
            return b""
        self.n -= 1
        return b"x" * 1000


async def writer_fail():
    path = os.path.join(tmp, "wf.bin")
    real_fdopen = os.fdopen

    def bad_fdopen(fd, mode):
        f = real_fdopen(fd, mode)
        class W:
            def write(self, b): raise OSError("disk full")
            def flush(self): pass
            def fileno(self): return f.fileno()
            def close(self): f.close()
        return W()
    os.fdopen = bad_fdopen
    try:
        await asyncio.wait_for(storage.write_blob_streamed(path, FakeUpload(50), 10**9, chunk_size=1000, buffer_chunks=2), 10)
        return "no error"
    except OSError:
        return "oserror"
    except asyncio.TimeoutError:
        return "DEADLOCK"
    finally:
        os.fdopen = real_fdopen

check("writer failure surfaces error, no deadlock", asyncio.run(writer_fail()) == "oserror")

server.should_exit = True
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
