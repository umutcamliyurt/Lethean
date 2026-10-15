<div align="center">

<img src="logo.png" width="75" />

## Zero-Knowledge Encrypted Cloud Storage

</div>

Lethean is a zero-knowledge encrypted storage accountless web app. Your chosen password and an access token, issued by whoever operates the server, are the only credentials required to access your personal vault. Your password never leaves the browser; the access token is hashed locally into your vault's cryptographic salt and is also sent to the server as your upload credential. You can upload files and archives of any size, including photos or videos, which you can browse and play (decrypted on your device). By design and for maximum security, the server only ever sees encrypted data, while only you hold the key.

> The name comes from the **River of Forgetfulness** in Greek mythology. In the Underworld, souls who drink from the river would lose all memory of their past lives before reincarnation.

## Features

- Built-in minimalist markdown editor
- FUSE client for mounting vault as a network drive
- Elegant and customizable UI
- AES-256-GCM for client-side encryption
- Ciphertext padding to hide file size metadata
- Argon2id for key derivation
- Minimum 12-character password, checked against a common-password list locally
- Duress code for wiping the vault under coercion, with an optional decoy vault
- Desktop and mobile apps (Tauri-based)
- Optional web admin panel on a separate port for managing access tokens and share links

## Screenshots

<table align="center">
<tr>
<td align="center"><img src="screenshot_desktop.png" width="1000" /><br/><sub>Desktop</sub></td>
<td align="center"><img src="screenshot_mobile.png" width="250" /><br/><sub>Mobile</sub></td>
</tr>
</table>

## How It Works

1. User types their password and access token.
2. The access token is hashed locally into a cryptographic salt, and combined with the password.
3. **That process produces one `masterKey`**, which is then split into two separate keys with two separate jobs:

| Key | What it does | Where it lives |
|---|---|---|
| `vaultId` | Acts like a "key card", user shows it to the server to prove they can access a vault. Think of it like an unguessable link: possession is access. | Sent to the server on every request |
| `wrappingKey` | Locks and unlocks the individual encryption key for each file user uploads. | Stays in the browser |

Each file gets its own random key, wrapped by `wrappingKey`. Separate keys for the file's name and its contents are derived from that file key. Files up to 32 MiB are encrypted as one AES-256-GCM message (gzip-compressed first when that helps). Larger files are split into 32 MiB chunks, each sealed separately with its position and an "is last chunk" flag bound in, so chunks can't be reordered, dropped or truncated without detection. That lets them be uploaded in parts and decrypted as a stream.

For the full design, see [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md).

### Upgrading older vaults

Items created before this format still open, but a malicious server can tamper with them. **Settings → Upgrade Vault** re-encrypts them in the current format, keeping names, contents and folders, and checks each copy before deleting the original. It uploads every old item again, and share links to upgraded items stop working. Afterwards, the device refuses old-format items for that vault. Clients that predate this format, including older FUSE builds, can't open new items; update every device. The FUSE client upgrades with `lethean-fuse upgrade`.

## Access Tokens

An access token, issued by whoever operates the server, is required both to unlock your vault (it's hashed locally into your vault's cryptographic salt) and to upload files (it's sent to the server as a bearer credential). Each token comes with a default 10 GB quota, and it's a one-time pairing, the first vault it's used with (on its first upload, or when the vault first saves its duress settings) is the only vault it will ever work with.

Tokens are always issued in identical pairs, one pair per person. The person signs in with either one, and keeps the other for their decoy vault (see [Duress Code](#duress-code)). Nothing records which is which: both have the same label and quota, and everyone gets a pair, so holding a decoy token says nothing about whether someone uses a duress code.

Tokens are hashed (SHA-256) before they're written to disk, so a leaked `tokens.json` doesn't hand out upload tokens.

Server operators manage these tokens from the command line, or from the [web admin panel](#admin-panel):

```bash
cd server
python manage_tokens.py create --label alice --quota-gb 15   # prints a pair of tokens
python manage_tokens.py list
python manage_tokens.py revoke <token-or-id>
```

## Setup

```bash
git clone https://github.com/umutcamliyurt/Lethean.git
cd Lethean/client
npm install
npm run build
```

Then run the server:

```bash
cd ../server
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Serves the API and client at `http://localhost:8000`.

### Behind a reverse proxy

No request carries more than 32 MiB of file data: anything larger is sent as separate, resumable parts. So any proxy body limit of about 33 MB or more works. For large uploads, turning off request buffering and allowing time per part helps:

```nginx
client_max_body_size 99M;
proxy_request_buffering off;
proxy_read_timeout 300s;
proxy_send_timeout 300s;
```

The body limit only applies to uploads; downloads stream in a single response.

### Server settings

| Variable | Default | Purpose |
|---|---|---|
| `MAX_UPLOAD_BYTES` | `5368709120` (5 GiB) | Largest single file (after padding). Raise it to allow bigger files |
| `MAX_UPLOAD_PART_BYTES` | `67108864` (64 MiB) | Largest part the server accepts. The client sends 32 MiB parts |
| `UPLOAD_SESSION_TTL_SECONDS` | `86400` | Unfinished uploads are discarded (and their space freed) after this long |
| `MAX_ACTIVE_UPLOAD_SESSIONS` | `32` | Unfinished uploads allowed per vault |
| `DURESS_READS_PER_MINUTE` | `30` | Reads of a token's duress settings, per token |
| `SHRED_REQUESTS_PER_MINUTE` | `60` | Duress wipe requests, per IP |
| `DEFAULT_QUOTA_GB` | `10` | Quota for tokens without their own |
| `RATE_LIMIT_PER_MINUTE` | `3000` | Requests per IP across the whole API |

Unfinished uploads count against the vault's quota until they complete, are cancelled, or expire.

## Admin Panel

An optional web UI for server operators, served on its own port. It is disabled unless `ADMIN_PASSWORD` is set.

```bash
cd server
ADMIN_PASSWORD='a password of 12+ characters' uvicorn main:app
```

Then open `http://127.0.0.1:8001`. From there you can:

- See total storage, file and vault counts, token counts, and active/expired share links
- Create access tokens (a pair per person), edit a token's label or quota, and revoke tokens. The raw tokens are shown once, at creation
- See each token's bound vault (truncated), usage and quota
- Revoke individual share links and purge expired ones

Revoking a token blocks further uploads and vault rotation with it, and deletes its stored duress settings. It does not delete stored files unless you choose to; deleting them also removes the vault's duress registration.

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | unset (panel disabled) | Admin password, minimum 12 characters |
| `ADMIN_HOST` | `127.0.0.1` | Bind address |
| `ADMIN_PORT` | `8001` | Port |
| `ADMIN_SESSION_TTL` | `43200` | Session lifetime in seconds |
| `ADMIN_LOGIN_MAX_FAILS` | `5` | Failed logins per IP before lockout |
| `ADMIN_LOGIN_LOCKOUT` | `900` | Lockout window in seconds |
| `TRUST_PROXY_HEADERS` | `0` | Set to `1` behind a reverse proxy to honor `X-Forwarded-For` / `X-Forwarded-Proto` |

It binds to localhost by default and should stay there. To reach it remotely, use an SSH tunnel (`ssh -L 8001:127.0.0.1:8001 host`) or put it behind an HTTPS reverse proxy, rather than exposing the port directly.

## Duress Code

A second password, typing it at the unlock screen, on any device that uses the same access token, wipes the real vault and opens a decoy vault instead. The decoy vault is empty unless you add files to it, using the second token of your pair.

- **Synced across devices.** The duress settings are stored on the server, encrypted with a key derived from the duress password, one entry per access token. A device fetches them as soon as the token is known, and uses its last copy if the server is unreachable.
- **What's stored can only wipe.** It holds a random wipe secret, of which the server keeps only a hash. It does not contain the vault ID (the vault's access credential), so cracking it never gives access to your files, and password or token changes don't break it.
- **Indistinguishable.** Every vault has duress settings of the same size from its first unlock, real or random, and setting a code looks the same as resetting one. Every unlock sends the same wipe request, carrying random values when it isn't the duress password, and the server answers identically either way.
- **No trace afterwards.** When the duress password is used, the server wipes the vault, deletes the wipe secret, and replaces the duress settings with random ones, on the server and on that device. Trying the duress password again later shows nothing.

## Desktop & Mobile Apps

The desktop and mobile apps are [Tauri](https://v2.tauri.app) wrappers around the same
`client/` code as the web app.

One-time setup (needs [Rust](https://www.rust-lang.org/tools/install) installed):

```bash
scripts/setup-tauri.sh
scripts/setup-tauri-android.sh
```

After that:

```bash
cd client
npm run tauri:build          # desktop
npm run tauri:android:build  # android
```

The release APK lands under `client/src-tauri/gen/android/app/build/outputs/apk/`.

The apps only connect to an `https://` server URL (`http://` is allowed for `localhost`).

## Threat Model

### Defends against:
- **Passive server compromise**: the adversary can read stored server data but cannot alter server responses, observe live operations, or control server behavior. Only encrypted data and encrypted metadata are stored, and file sizes remain hidden: files up to 32 MiB are padded to size buckets (16 KiB up to 64 MiB), larger files to a multiple of 32 MiB.
- Offline brute-force attacks against a stolen database
- Coerced unlock: the duress path is indistinguishable from the normal path at the network, storage, and UI levels, works from any of your devices, and leaves nothing that proves a duress code existed
- Passive network eavesdropping during unlock attempts
- **Active server compromise, for the desktop and mobile apps**: an adversary who controls the server, its responses and its stored data. The apps' code ships in the build rather than being loaded from the server, and every secret stays on the device, so even full control of the server yields:
  - **No passwords, keys or plaintext.** The server only ever receives the vault ID and ciphertext, and it already holds both.
  - **No undetected tampering.** Every key, metadata record and file is authenticated encryption, and chunked files bind each chunk's position, so altered, swapped, reordered or truncated data fails to decrypt instead of being shown. The server also can't move items between folders or change a file's format. Items not yet upgraded are the exception (see [Upgrading older vaults](#upgrading-older-vaults)).
  - **No forged duress settings.** Without the duress password the server can't create settings that match it, or learn anything from the ones it stores.

### Does not defend against:
- **Active server compromise, for the web app**: the web app's JavaScript is delivered by the server, so a compromised server can serve modified code that captures passwords and keys. The same applies to share links, which recipients open in the web page even when the sender uses an app. Use the desktop or mobile apps if you don't trust the server operator.
- **Availability under active server compromise**, for any client: a server in someone else's control can refuse service, withhold or delete files, show files you deleted again, ignore a duress wipe request, or replace the duress settings with random ones so the duress password stops wiping. It can't read anything in the process.
- A compromised client, including a malicious browser, extension, or tampered JavaScript
- Weak or reused passwords, including a weak duress password: anyone holding your access token can fetch the encrypted duress settings and try to guess the duress password offline (Argon2id-hardened, rate-limited online). A guessed duress password lets them wipe the vault, not read it
- Sustained forensic analysis of server-side metadata, including timing and access patterns. For example, the server sees when duress settings are written after a vault's first unlock (which in practice suggests a duress code was set, though it can't tell setting from removing one), when the second token of a pair starts being used (which suggests decoy files were added), and the 32 MiB padding steps of large files.
- A compromised admin password: whoever holds it can create, edit and revoke access tokens and revoke share links, though not read any vault contents.

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full terms.