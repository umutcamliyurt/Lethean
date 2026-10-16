# Server Configuration

## Run

```bash
cd client && npm install && npm run build
cd ../server
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app
```

- Serves the API and the web client on `127.0.0.1:8000`.
- Start it from `server/`: the database is `./lethean.db` and blobs default to `./blobs`, both relative to the working directory.
- Run a single process (no `--workers`). Quotas, locks, rate limits and admin sessions are held in memory.
- On startup the server creates missing tables, applies migrations and removes expired upload sessions.

## Access tokens

Tokens are created in identical pairs, one for the vault and one for its decoy; nothing records which is which. A token binds to the first vault that writes with it. Only its SHA-256 hash is stored.

```bash
python manage_tokens.py create --label alice --quota-gb 15
python manage_tokens.py list
python manage_tokens.py revoke <token-or-id>
python manage_tokens.py migrate [--yes]
python manage_tokens.py strip-decoy-labels
```

Use the same `TOKENS_PATH` as the server. Revoking a token blocks uploads, password changes and new share links. It does not delete the files.

## Reverse proxy

Use HTTPS and keep uvicorn on `127.0.0.1`. Then set `TRUST_PROXY_HEADERS=1`.

```nginx
server {
    listen 443 ssl;
    server_name vault.example.com;
    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;

    client_max_body_size 99M;
    proxy_request_buffering off;
    proxy_read_timeout 300s;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

If `MAX_UPLOAD_PART_BYTES` exceeds about 99 MB, raise `client_max_body_size` to match.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `STORAGE_ROOT` | `./blobs` | Blob and upload-part directory |
| `TOKENS_PATH` | `<server dir>/tokens.json` | Token store |
| `CLIENT_DIST_DIR` | `../client/dist` | Web client served at `/` |
| `MAX_UPLOAD_BYTES` | `5368709120` | Largest stored ciphertext, bytes |
| `MAX_UPLOAD_PART_BYTES` | `67108864` | Largest upload part, bytes |
| `UPLOAD_SESSION_TTL_SECONDS` | `86400` | Lifetime of an unfinished multipart upload |
| `MAX_ACTIVE_UPLOAD_SESSIONS` | `32` | Unfinished multipart uploads per vault |
| `UPLOAD_READ_STALL_TIMEOUT` | `60` | Seconds without data before an upload is dropped |
| `UPLOAD_WRITE_BUFFER_CHUNKS` | `4` | Chunks queued between network and disk |
| `MAX_CONCURRENT_UPLOADS` | `100` | Uploads in progress at once |
| `MAX_CONCURRENT_DOWNLOADS` | `100` | Downloads in progress at once |
| `DEFAULT_QUOTA_GB` | `10` | Quota for tokens created without one (integer, GiB of stored ciphertext) |
| `MAX_ROTATE_ITEMS` | `50000` | Most items per password change |
| `SHARE_LINK_TTL_SECONDS` | `604800` | Default share link expiry |
| `SHARE_LINK_MAX_TTL_SECONDS` | `2592000` | Longest share link expiry |
| `SHARE_LINK_MAX_DOWNLOADS_LIMIT` | `100` | Highest download limit per link |
| `SHARE_LINKS_MAX_ACTIVE_PER_FILE` | `20` | Active links per file |
| `RATE_LIMIT_PER_MINUTE` | `3000` | Requests per client address (over the limit: `429`) |
| `DURESS_READS_PER_MINUTE` | `30` | Duress reads per token |
| `SHRED_REQUESTS_PER_MINUTE` | `60` | Wipe requests per address (excess is silently ignored) |
| `TRUST_PROXY_HEADERS` | `0` | `1` reads `X-Forwarded-For` and `X-Forwarded-Proto`. Set it only behind a proxy |
| `EXTRA_CORS_ORIGINS` | *(empty)* | Comma-separated extra allowed origins |
| `DEV_CORS` | `0` | `1` allows all origins (development only) |
| `ADMIN_PASSWORD` | *(empty)* | Enables the admin panel (at least 12 characters) |
| `ADMIN_HOST` | `127.0.0.1` | Admin panel address |
| `ADMIN_PORT` | `8001` | Admin panel port |
| `ADMIN_SESSION_TTL` | `43200` | Admin session lifetime, seconds |
| `ADMIN_LOGIN_MAX_FAILS` | `5` | Failed logins before lockout |
| `ADMIN_LOGIN_LOCKOUT` | `900` | Lockout, seconds |

## Admin panel

The panel manages tokens, quotas, share links and vault deletion. Don't expose it publicly; reach it through a tunnel:

```bash
ssh -L 8001:127.0.0.1:8001 user@vault.example.com
```

## Data

| Path | Contents |
|---|---|
| `lethean.db` (+ `-wal`, `-shm`) | File records (encrypted metadata, wrapped keys, IVs, ciphertext length), hashed share tokens, upload sessions, duress records, shred-secret hashes |
| `STORAGE_ROOT/<vault>/<file>.bin` | Encrypted file contents (`0600`; directories `0700`) |
| `STORAGE_ROOT/_uploads/<session>/` | Unfinished upload parts |
| `TOKENS_PATH` | Hashed tokens with labels, quotas and bound vault IDs (`0600`) |

Names, folder structure, contents and true file sizes are encrypted; stored lengths are padded ciphertext. What is visible: vault IDs, item counts, upload times and share link limits.

To back up, stop the server and copy all of it. Alternatively, while it runs, copy the database with `sqlite3 lethean.db ".backup backup.db"` and copy the other files alongside.