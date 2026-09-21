# Cryptography of Lethean

This document specifies the zero-knowledge encryption design: the key
hierarchy, algorithms, and per-operation data flow. It is implementation-
agnostic and applies to any compliant client.

**Invariant:** the server stores and serves only ciphertext, wrapped keys,
and opaque identifiers. It never receives a plaintext password, file
content, file name, or any key capable of independent decryption.

## 1. Key hierarchy

| # | Key / value | Derived from | Method | Scope |
|---|---|---|---|---|
| 1 | Salt | Access token | `H(fixed-label \|\| access_token)` | Public, deterministic |
| 2 | Master key | Password + salt | Argon2id (versioned params) | Transient, discarded after step 3 |
| 3a | Vault ID | Master key | HKDF-SHA256, label `vault-id` | Sent to server (bearer credential) |
| 3b | Wrapping key | Master key | HKDF-SHA256, label `wrap` | Client-side only, never transmitted |
| 4 | Per-file key | Random (CSPRNG) | Generated fresh per file/folder | Wrapped under 3b before leaving client |
| 5 | File content / metadata | Per-file key | AES-256-GCM | Encrypted under 4, stored server-side |

Each row's output is the next row's input except row 4, which is
independent randomness rather than a derivation; it is only *protected*
by row 3b, not derived from it. Rows 1-3 collapse into a single local
computation at unlock; row 4 keys are created once per file and persist
(wrapped) for that file's lifetime.

## 2. Key derivation

**Salt.** Deterministic: `H(fixed-label || access_token)`. No stored
per-user salt; any client re-derives it from public inputs.

**Master key.** `Argon2id(password, salt, params[kdf_version])` → 32 bytes.
Parameter sets (memory/iterations/parallelism) are versioned so newer
vaults can adopt stronger work factors without invalidating older ones; a
vault records the version used at creation, and unlock replays it. An
unrecognized version is a hard failure, not a silent fallback.

**Sub-keys.** `HKDF-SHA256(master_key, info=label)` with two distinct
labels yields the vault ID and the wrapping key. Domain separation ensures
compromise of one (the vault ID, sent on every request) gives no leverage
on the other. The master key is discarded immediately after derivation;
it is a transient intermediate, never persisted or reused.

**Unlock.** A pure local function: `(password, access_token, kdf_version)
→ (vault_id, wrapping_key)`. No network round-trip, no password
transmission or storage. The password is the root secret; there is no
recovery path if it is lost.

**Password policy.** Strength requirements (minimum length, character
diversity or extra length, no trivial sequences, no repetition) are
enforced only when a new password is chosen (e.g. rotation), never on
unlock: unlock must honor whatever policy was active at creation time.

## 3. Symmetric primitive

AES-256-GCM, used uniformly for key-wrapping, metadata, and content:

- 256-bit keys throughout.
- A fresh CSPRNG 96-bit nonce per encryption call, with no reuse across
  any operation.
- No AAD; binding of ciphertext to record is structural: a ciphertext is
  only ever decrypted with the key resolved for its own record.
- Decryption failures (bad key, tampering, truncation) return one generic
  error, denying an attacker a distinguishing oracle.

## 4. Envelope encryption per file

Each file/folder receives a random 256-bit file key at creation. This key,
not the wrapping key, encrypts that item's content and metadata (name,
MIME type, parent folder, size, folder flag). The file key is wrapped
under the wrapping key before leaving the client.

Server-side state per record: wrapped file key + IV, encrypted metadata +
IV, encrypted content + IV (empty for folders). Decryption reverses the
chain: wrapping key to file key to metadata/content. Since parent-folder
references live inside encrypted metadata, directory structure itself is
confidential; clients reconstruct the tree locally after decrypting each
record.

Rationale for per-file keys over direct use of the wrapping key:

1. **Cheap rotation**: changing the password re-wraps small per-file keys
   only; content and metadata, which dominate storage, are untouched (§7).
2. **Blast-radius containment**: no single key decrypts more than one
   file; the wrapping key never touches content directly.

## 5. Size-hiding: padding and compression

Ciphertext length leaks approximate plaintext length even under strong
encryption. Two padding schemes mitigate this, applied pre-encryption:

- **Content** is padded to the next of a fixed, exponentially growing set
  of size buckets. True length is stored inside encrypted metadata and
  used to strip padding post-decryption.
- **Metadata** is length-prefixed and padded to a separate, smaller bucket
  set, preventing file-name length from being inferable from ciphertext
  size.

**Compression** is applied opportunistically pre-padding, kept only if it
reduces size, with the outcome flagged in encrypted metadata. Order is
fixed: **compress, then pad, then encrypt.** Reversing any step is
ineffective: post-encryption data is incompressible, and padding is
deliberately incompressible filler.

## 6. Encoding

Binary fields in JSON/form payloads (IVs, wrapped keys, encrypted
metadata) are base64. The vault ID is hex (used directly as a bearer
token). Raw content ciphertext is transmitted as a binary blob to avoid
base64 overhead on large payloads.

## 7. Password rotation

1. Unlock with the old password; every file's key is now held unwrapped
   in memory.
2. Derive new master key / vault ID / wrapping key from the new password
   under the current KDF version (opportunistically upgrading legacy
   vaults).
3. Verify the new vault ID differs from the old one.
4. Re-wrap each unchanged file key under the new wrapping key.
5. Submit all new wrapped-key/IV pairs in one atomic operation that also
   swaps the account to the new vault ID.
6. Adopt the new wrapping key; discard the old one.

Cost scales with file count, not data volume. Rotation is a genuine
invalidation of the old password: no wrapped file key remains decryptable
under the wrapping key the old password derives.

## 8. Rename / move

Only metadata changes (name and/or parent folder); the file key is
unchanged. Metadata is re-encrypted under the same key; content
ciphertext, its IV, and the wrapped file key are carried over unmodified.

## 9. Sharing

The server issues a share token (and, if delete is permitted, a delete
token) for a file, subject to expiry/download-count constraints. It never
receives the file key.

The client embeds the share token, file key, and delete token in the URL
fragment (`#...`), which browsers never transmit to a server. The
recipient's page fetches ciphertext by token and decrypts locally using
the key from the fragment; the server enforces the access constraints but
never handles plaintext or key material.

The link, fragment included, is therefore the decryption capability
itself, not merely an access handle. Its confidentiality is the sole
control on the shared file.

## 10. Key material hygiene

Master key, passwords, per-file keys, the wrapping key, and cached
plaintext are zeroized as soon as they are no longer needed, rather than
left for garbage collection. This does not change the protocol's
guarantees but reduces the exposure window in memory.

## 11. Threat model

| Scenario | Exposure |
|---|---|
| Full server compromise | Opaque IDs, padded AES-256-GCM ciphertext, wrapped keys. No plaintext, names, directory structure, wrapping key, or master key. Decryption still requires the password. |
| Traffic analysis | Size bucket only, not exact length. |
| Nonce reuse | Precluded structurally: fresh nonce per call, no reuse path. |
| KDF weakening over time | Mitigated via versioned parameters; new vaults/rotations adopt stronger settings without breaking older ones. |
| Share link exposure | The file key travels in the URL fragment. Anyone who obtains the full link (fragment included) can decrypt that one file; the server alone cannot, since it never receives the fragment. |