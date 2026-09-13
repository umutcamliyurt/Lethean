<div align="center">

<img src="logo.jpg" width="100" />

## Anonymous Zero-Knowledge Encrypted Cloud Storage

</div>

Lethean is a zero-knowledge encrypted storage accountless web app. Your chosen password and the salt are the only credentials required to access your personal vault. These credentials never leave the browser. You can upload files and archives, including photos or videos, which you can browse and play (decrypted in memory). By design and for maximum security, the server only ever sees encrypted data, while only you hold the key.

> The name comes from the **River of Forgetfulness** in Greek mythology. In the Underworld, souls who drink from the river would lose all memory of their past lives before reincarnation.

## Features

- No user account required
- Elegant and customizable UI
- AES-256-GCM for client-side encryption
- Ciphertext padding to hide file size metadata
- Argon2id for key derivation with per-vault salt
- Minimum 12-character password, checked against a common-password list locally
- Duress code for wiping the vault under coercion, with an optional decoy vault

## Screenshots

<table align="center">
<tr>
<td align="center"><img src="screenshot_desktop.png" width="1000" /><br/><sub>Desktop</sub></td>
<td align="center"><img src="screenshot_mobile.png" width="250" /><br/><sub>Mobile</sub></td>
</tr>
</table>

## How It Works

1. User types their password.
2. It's combined with a cryptographic salt.
3. **That process produces one `masterKey`**, which is then split into two separate keys with two separate jobs:

| Key | What it does | Where it lives |
|---|---|---|
| `vaultId` | Acts like a "key card", user shows it to the server to prove they can access a vault. Think of it like an unguessable link: possession is access. | Sent to the server on every request |
| `wrappingKey` | Locks and unlocks the individual encryption key for each file user uploads. | Stays in the browser |

**Why the salt matters:** the salt itself doesn't need to be secret, but without it, the same password won't produce the same `masterKey`. So if two people happen to pick the same password, their vaults still end up completely unrelated, different salt, different keys.

**Why this resists brute-forcing:** because `vaultId` only exists after the Argon2id step, someone who steals the server's data can't shortcut anything. Every single password guess still has to pay the full Argon2id cost, there's no faster path in.

## Duress Code

Think of the duress code as a second, secret password that opens a decoy vault instead of the real one, and silently destroys the real one in the process.

Here's what makes it safe to use under coercion: if someone forces user to "unlock their vault," there's no way for them to tell which of these three things actually happened:

- **User entered their real password --> real vault opens normally**
- **User entered their duress code --> real vault is wiped, a decoy opens instead**
- **User entered the wrong password --> nothing happens, an empty vault opens instead**

All three cases look identical from the outside, same derivation steps happen in the browser, same network requests go out, even the exact same `DELETE /vault` request shape gets sent to the server every time. Nothing about the traffic, timing, or server behavior reveals which one occurred.

## Access Tokens

Uploading files requires an access token, issued by whoever operates the server. Each token comes with a default 10 GB quota, and it's a one-time pairing, the first vault it's used with is the only vault it will ever work with.

Tokens are hashed (SHA-256) before they're written to disk, so a leaked `tokens.json` doesn't hand out upload tokens.

Server operators manage these tokens from the command line:

```bash
cd backend
python manage_tokens.py create --label alice --quota-gb 15     # issue a real token + a matching decoy token
python manage_tokens.py list                                   # see all tokens
python manage_tokens.py revoke <token-or-id>                   # disable a token
python manage_tokens.py migrate                                # migration to hashed storage
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
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Serves the API and client at `http://localhost:8000`.

## Threat Model

### Defends against:
- **Passive server compromise**: the adversary can read stored server data but cannot alter server responses, observe live operations, or control server behavior. Only encrypted data and encrypted metadata are stored, and file sizes remain hidden.
- Offline brute-force attacks against a stolen database
- Coerced unlock: the duress path is indistinguishable from the normal path at the network, storage, and UI levels
- Passive network eavesdropping during unlock attempts

### Does not defend against:
- **Active server compromise**: an adversary who can modify server-side data, tamper with responses, alter application behavior, or control the server. This includes replacing or modifying JavaScript delivered to the client, allowing the adversary to capture passwords and encryption keys.
- A compromised client, including a malicious browser, extension, or tampered JavaScript
- Weak or reused passwords
- Sustained forensic analysis of server-side metadata, including timing and access patterns.

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full terms.