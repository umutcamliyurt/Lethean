# Lethean

## Anonymous Zero-Knowledge Encrypted Cloud Storage

Lethean is a zero-knowledge encrypted storage app with no accounts, no email. Password is the only credential and never leaves the browser. Upload photos and videos, browse them in a gallery, and play them fully decrypted in memory, the server only ever sees ciphertext.

![screenshot](screenshot.png)

## Features

- No user account required
- Elegant and customizable UI
- AES-256-GCM for client-side encryption
- Ciphertext padding to hide file size metadata
- Argon2id for key derivation with per-vault salt
- Minimum 12-character password, checked against a common-password list locally
- Duress code for wiping the vault under coercion

## How It Works

A password, together with a salt, is run through Argon2id to derive a `masterKey`, which produces:

| Key | Purpose |
|---|---|
| `vaultId` | Sent to the server as a bearer capability on every request. Never validated against a database, possession of it is access, the same trust model as an unguessable share link. |
| `wrappingKey` | Stays in the browser and wraps each file's content key. |

The salt isn't secret by itself, but it's required together with the password to re-derive the same `masterKey`, so two vaults that happen to share a password don't also share a salt.

Because `vaultId` is only derived after the Argon2id step, an attacker with the server's storage must pay full Argon2id cost per guess, there's no cheaper path.

## Duress Code

A second password wipes the real vault and opens an empty decoy in its place. Real password, duress code, or a wrong guess all produce identical derivation steps, network requests, including sending the same `DELETE /vault` request shape regardless of outcome, so no observer can tell which occurred, or whether a duress code even exists.

## Access Tokens

Browsing requires only a `vaultId`. Uploading also requires an operator-issued token (10 GB default quota), which binds permanently to the first vault it's used with:

```bash
cd backend
python manage_tokens.py create --label alice --quota-gb 15
python manage_tokens.py list
python manage_tokens.py revoke <token>
```

## Setup

```bash
git clone https://github.com/umutcamliyurt/Lethean.git
cd Lethean/client
npm install
npm run build
```

Then run the backend:

```bash
cd ../backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Serves the API and client at `http://localhost:8000`.

## Threat Model

**Defends against:**
- Server compromise, only ciphertext, random `vaultId`s, and wrapped keys are ever stored
- Offline brute-force of a stolen database, every guess pays full Argon2id cost
- Coerced unlock, duress path is indistinguishable at the network, storage, and UI level
- Passive network eavesdropping of unlock attempts

**Does not defend against:**
- A compromised client (malicious browser, extension, or tampered JS)
- Weak or reused passwords
- Sustained forensic analysis of server-side metadata (timing, access patterns)

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full terms.