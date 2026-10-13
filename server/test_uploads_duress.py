import base64, hashlib, json, math, os, sys, tempfile, time

tmp = tempfile.mkdtemp()
os.environ["STORAGE_ROOT"] = os.path.join(tmp, "blobs")
os.environ["TOKENS_PATH"] = os.path.join(tmp, "tokens.json")
os.environ["CLIENT_DIST_DIR"] = os.path.join(tmp, "nodist")
os.environ["MAX_UPLOAD_PART_BYTES"] = str(1024 * 1024)
os.chdir(tmp)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
import main, token_store, storage
from database import SessionLocal
from models import DuressSlot, ShredHash, UploadSession

client = TestClient(main.app)
passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1; print(f"PASS {name}")
    else:
        failed += 1; print(f"FAIL {name} {extra}")


def hdr(v, tok=None):
    h = {"Authorization": f"Bearer {v}"}
    if tok: h["X-Access-Token"] = tok
    return h


META = dict(content_iv="civ", encrypted_metadata="meta", metadata_iv="miv", wrapped_file_key="wk", wrap_iv="wiv")

V = "1" * 64
tok = token_store.create_token(label="up", quota_bytes=20 * 1024 * 1024)
PART = 512 * 1024
data = os.urandom(5 * PART + 12345)
n = math.ceil(len(data) / PART)
parts = [data[i * PART:(i + 1) * PART] for i in range(n)]


def init(total=len(data), part=PART, count=n, v=V, t=tok):
    return client.post("/files/uploads", json=dict(META, part_count=count, part_size=part, total_size=total), headers=hdr(v, t))


r = init()
check("init 201", r.status_code == 201, r.text)
uid = r.json()["upload_id"]
check("init binds token like an upload", token_store.get_record(tok)["vault_id"] == V)

r = client.post("/files/uploads", json=dict(META, part_count=n, part_size=PART, total_size=len(data)), headers=hdr(V))
check("init without token 401", r.status_code == 401, r.status_code)
r = init(count=n + 1)
check("inconsistent part_count 400", r.status_code == 400, r.text)
r = init(part=2 * 1024 * 1024, count=math.ceil(len(data) / (2 * 1024 * 1024)))
check("part larger than MAX_UPLOAD_PART_BYTES 413", r.status_code == 413, r.text)

for i in [3, 0, 5, 1]:
    r = client.put(f"/files/uploads/{uid}/parts/{i}", content=parts[i], headers=hdr(V, tok))
    check(f"part {i} 204", r.status_code == 204, r.text)
r = client.put(f"/files/uploads/{uid}/parts/1", content=parts[1], headers=hdr(V, tok))
check("re-sent part is idempotent", r.status_code == 204)
r = client.put(f"/files/uploads/{uid}/parts/2", content=parts[2][:-1], headers=hdr(V, tok))
check("short part rejected 400", r.status_code == 400, r.text)
r = client.put(f"/files/uploads/{uid}/parts/9", content=b"x", headers=hdr(V, tok))
check("index out of range 400", r.status_code == 400)

r = client.get(f"/files/uploads/{uid}", headers=hdr(V))
check("status lists received parts (resume)", r.status_code == 200 and r.json()["received"] == [0, 1, 3, 5], r.text)
r = client.get(f"/files/uploads/{uid}", headers=hdr("2" * 64))
check("other vault can't see session 404", r.status_code == 404)

r = client.post(f"/files/uploads/{uid}/complete", headers=hdr(V, tok))
check("complete with missing parts 409", r.status_code == 409 and "2" in r.json()["detail"] and "4" in r.json()["detail"], r.text)

for i in [2, 4]:
    client.put(f"/files/uploads/{uid}/parts/{i}", content=parts[i], headers=hdr(V, tok))
r = client.post(f"/files/uploads/{uid}/complete", headers=hdr(V, tok))
check("complete 201", r.status_code == 201, r.text)
rec = r.json()
check("record has size + client fields", rec["size"] == len(data) and rec["content_iv"] == "civ", rec)
check("created_at has tz", rec["created_at"].endswith(("Z", "+00:00")), rec["created_at"])
r = client.get(f"/files/{rec['id']}/blob", headers=hdr(V))
check("download equals concatenated parts", r.status_code == 200 and r.content == data)
check("session dir cleaned", not os.path.exists(os.path.join(os.environ["STORAGE_ROOT"], "_uploads", uid)))
r = client.post(f"/files/uploads/{uid}/complete", headers=hdr(V, tok))
check("complete twice 404", r.status_code == 404)

r = init(total=12 * 1024 * 1024, part=1024 * 1024, count=12)
check("open session reserves quota", r.status_code == 201, r.text)
r = init(total=6 * 1024 * 1024, part=1024 * 1024, count=6)
check("second session over quota (incl. reserved) 413", r.status_code == 413, r.text)
big = r
r = client.post("/files", data=META, files={"blob": ("b", os.urandom(6 * 1024 * 1024))}, headers=hdr(V, tok))
check("single-request upload also sees reservation 413", r.status_code == 413, r.status_code)

uid2 = init(total=12 * 1024 * 1024, part=1024 * 1024, count=12)
db = SessionLocal(); open_ids = [s.id for s in db.query(UploadSession)]; db.close()
for sid in open_ids:
    r = client.delete(f"/files/uploads/{sid}", headers=hdr(V))
check("abort 204", r.status_code == 204)
r = init(total=4 * 1024 * 1024, part=1024 * 1024, count=4)
check("quota available again after abort", r.status_code == 201, r.text)
check("aborted session dirs removed", all(not os.path.exists(os.path.join(os.environ["STORAGE_ROOT"], "_uploads", s)) for s in open_ids))

db = SessionLocal()
sid = r.json()["upload_id"]
s = db.get(UploadSession, sid); s.created_at = s.created_at.replace(year=2000); db.commit(); db.close()
r = client.get(f"/files/uploads/{sid}", headers=hdr(V))
check("expired session 404", r.status_code == 404)

uid3 = init(total=PART, part=PART, count=1).json()["upload_id"]
V2 = "3" * 64
files = client.get("/files", headers=hdr(V)).json()
r = client.post("/vault/rotate", json={"new_vault_id": V2, "rewraps": [{"file_id": f["id"], "wrapped_file_key": "k", "wrap_iv": "i"} for f in files]}, headers=hdr(V, tok))
check("rotate 200", r.status_code == 200, r.text)
r = client.put(f"/files/uploads/{uid3}/parts/0", content=parts[0], headers=hdr(V2, tok))
check("open upload continues under the new vault id", r.status_code == 204, r.text)
check("complete after rotate", client.post(f"/files/uploads/{uid3}/complete", headers=hdr(V2, tok)).status_code == 201)

A = "a" * 64
A_DECOY = "d" * 64
ta = token_store.create_token(label="duress")
other = token_store.create_token(label="other")

r = client.get("/duress", headers={"X-Access-Token": "f" * 64})
check("unknown token 403", r.status_code == 403, r.status_code)
r = client.get("/duress")
check("no token 401", r.status_code == 401)

r1 = client.get("/duress", headers={"X-Access-Token": ta})
r2 = client.get("/duress", headers={"X-Access-Token": ta})
check("first read creates a decoy, then stable", r1.status_code == 200 and r1.json() == r2.json(), r1.text)
blob0 = json.loads(r1.json()["blob"])
check("decoy shape: same fields/lengths as a client blob",
      list(blob0) == ["salt", "verifier", "encVaultId", "iv", "kdfVersion"]
      and len(base64.b64decode(blob0["encVaultId"])) == 80 and len(blob0["verifier"]) == 64, blob0)
check("unauthenticated read has no 'written'", "written" not in r1.json())

r = client.get("/duress", headers=hdr(A, ta))
check("unbound token: no 'written' even with bearer", "written" not in r.json())

client_blob = json.dumps({"salt": "c2FsdA==", "verifier": "ab" * 32, "encVaultId": base64.b64encode(os.urandom(80)).decode(), "iv": "aXY=", "kdfVersion": 2}, separators=(",", ":"))
secret = os.urandom(32)
shred_hash = hashlib.sha256(secret).hexdigest()
r = client.put("/duress", json={"blob": client_blob, "shred_hash": shred_hash}, headers=hdr(A, ta))
check("owner PUT 204 (binds the unbound token)", r.status_code == 204 and token_store.get_record(ta)["vault_id"] == A, r.text)
r = client.put("/duress", json={"blob": client_blob, "shred_hash": None}, headers=hdr(A_DECOY, ta))
check("decoy vault can't overwrite 403", r.status_code == 403, r.status_code)
r = client.put("/duress", json={"blob": "not json"}, headers=hdr(A, ta))
check("malformed blob 400", r.status_code == 400)

r = client.get("/duress", headers=hdr(A, ta))
check("owner sees written=true", r.json().get("written") is True and r.json()["blob"] == client_blob, r.text)
r = client.get("/duress", headers=hdr(A_DECOY, ta))
check("non-owner bearer: no 'written'", "written" not in r.json())

client.post("/files", data=META, files={"blob": ("b", b"precious")}, headers=hdr(A, ta))
r = client.post("/vault/shred", json={"secret": base64.b64encode(os.urandom(32)).decode()})
check("random shred -> 204", r.status_code == 204)
r = client.post("/vault/shred", json={"secret": "garbage!!"})
check("malformed shred -> 204 (no oracle)", r.status_code == 204)
check("vault untouched", len(client.get("/files", headers=hdr(A)).json()) == 1)

A2 = "b" * 64
fs = client.get("/files", headers=hdr(A)).json()
r = client.post("/vault/rotate", json={"new_vault_id": A2, "rewraps": [{"file_id": f["id"], "wrapped_file_key": "k", "wrap_iv": "i"} for f in fs]}, headers=hdr(A, ta))
check("rotate ok", r.status_code == 200, r.text)
db = SessionLocal(); row = db.get(ShredHash, A2); db.close()
check("shred hash moved to new vault id", row is not None and row.shred_hash == shred_hash)

r = client.post("/vault/shred", json={"secret": base64.b64encode(secret).decode()})
check("matching shred -> 204", r.status_code == 204)
check("vault wiped", client.get("/files", headers=hdr(A2)).json() == [])
r = client.get("/duress", headers=hdr(A2, ta))
check("blob replaced by a fresh decoy after wipe", r.json()["blob"] != client_blob and len(base64.b64decode(json.loads(r.json()["blob"])["encVaultId"])) == 80)
check("'written' unchanged after wipe (not a tell)", r.json().get("written") is True)
db = SessionLocal(); check("shred hash removed", db.get(ShredHash, A2) is None); db.close()
r = client.post("/vault/shred", json={"secret": base64.b64encode(secret).decode()})
check("replaying the secret does nothing", r.status_code == 204)

tb = token_store.create_token(label="legacy")
B = "e" * 64
client.put("/duress", json={"blob": client_blob, "shred_hash": hashlib.sha256(b"x" * 32).hexdigest()}, headers=hdr(B, tb))
client.delete("/vault", headers=hdr(B))
r = client.get("/duress", headers=hdr(B, tb))
check("DELETE /vault resets blob", r.json()["blob"] != client_blob)
db = SessionLocal(); check("DELETE /vault drops shred hash", db.get(ShredHash, B) is None); db.close()

tc = token_store.create_token(label="c"); C_ = "c" * 64
td = token_store.create_token(label="d"); D_ = "9" * 64
h = hashlib.sha256(b"y" * 32).hexdigest()
client.put("/duress", json={"blob": client_blob, "shred_hash": h}, headers=hdr(C_, tc))
client.put("/duress", json={"blob": client_blob, "shred_hash": h}, headers=hdr(D_, td))
db = SessionLocal(); check("shred hash stays with its first vault", db.get(ShredHash, C_) is not None and db.get(ShredHash, D_) is None); db.close()

main._duress_read_limiter.hits.clear()
codes = [client.get("/duress", headers={"X-Access-Token": other}).status_code for _ in range(35)]
check("duress reads rate-limited per token", codes[:30] == [200] * 30 and 429 in codes[30:], codes[-6:])

import admin
db = SessionLocal()
admin.revoke_token(token_store.hash_token(tc)[:16], admin.BackgroundTasks(), delete_contents=True, db=db)
check("admin revoke deletes the token's slot", db.get(DuressSlot, token_store.hash_token(tc)) is None)
check("admin delete-contents drops shred hash", db.get(ShredHash, C_) is None)
db.close()

csp = client.get("/usage", headers=hdr(V2)).headers["content-security-policy"]
check("CSP frame-src allows same-origin", "frame-src 'self' blob:" in csp, csp)
check("CSP worker-src self", "worker-src 'self'" in csp, csp)
r = client.options("/files/uploads/x/parts/0", headers={"Origin": "tauri://localhost", "Access-Control-Request-Method": "PUT"})
check("CORS preflight allows PUT", r.status_code == 200 and "PUT" in r.headers.get("access-control-allow-methods", ""), r.headers)

r = client.get("/usage", headers=hdr("7" * 64))
check("unbound (decoy) vault reports the default quota like any other", r.json()["quota_bytes"] == token_store.DEFAULT_QUOTA_BYTES, r.text)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
