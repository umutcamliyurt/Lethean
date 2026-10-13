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

The duress code (§12) has its own, separate derivation and never touches
this hierarchy.

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
transmission or storage. (Separately, the client fetches the duress blob
with the access token before checking the typed password against it, §12;
that check is also local.) The password is the root secret; there is no
recovery path if it is lost.

**Password policy.** Strength requirements (minimum length, character
diversity or extra length, no trivial sequences, no repetition) are
enforced only when a new password is chosen (e.g. rotation), never on
unlock: unlock must honor whatever policy was active at creation time.

## 3. Symmetric primitive

AES-256-GCM, used uniformly for key-wrapping, metadata, and content:

- 256-bit keys throughout, 128-bit authentication tags.
- 96-bit nonces. Every single-message encryption (wrapped keys, metadata,
  small-file content, duress blobs) uses a fresh CSPRNG nonce. Chunked
  content (§6) uses a per-file random prefix plus a chunk counter, so
  nonces never repeat across chunks or files.
- No AAD for single-message encryption; binding of ciphertext to record
  is structural: a ciphertext is only ever decrypted with the key resolved
  for its own record. Chunked content binds each chunk's position and
  "last chunk" flag as AAD (§6).
- Decryption failures (bad key, tampering, truncation) return one generic
  error, denying an attacker a distinguishing oracle.

## 4. Envelope encryption per file

Each file/folder receives a random 256-bit file key at creation. This key,
not the wrapping key, encrypts that item's content and metadata (name,
MIME type, parent folder, true size, folder flag, compression flag, and
for chunked files the chunk size). The file key is wrapped under the
wrapping key before leaving the client.

Server-side state per record: wrapped file key + IV, encrypted metadata +
IV, encrypted content + IV (empty for folders). Decryption reverses the
chain: wrapping key to file key to metadata/content. Since parent-folder
references live inside encrypted metadata, directory structure itself is
confidential; clients reconstruct the tree locally after decrypting each
record.

Rationale for per-file keys over direct use of the wrapping key:

1. **Cheap rotation**: changing the password re-wraps small per-file keys
   only; content and metadata, which dominate storage, are untouched (§8).
2. **Blast-radius containment**: no single key decrypts more than one
   file; the wrapping key never touches content directly.

## 5. Size-hiding: padding and compression

Ciphertext length leaks approximate plaintext length even under strong
encryption. Padding is applied pre-encryption; the true length is stored
inside encrypted metadata and used to strip padding after decryption.

- **Small-file content** (32 MiB or less, §6) is padded to the next of a
  fixed, exponentially growing set of size buckets: 16 KiB, 64 KiB,
  256 KiB, 1 MiB, 4 MiB, 16 MiB, 64 MiB.
- **Chunked content** (larger than 32 MiB) is padded with zeros to a
  whole number of 32 MiB chunks, so its size is revealed only to the
  nearest 32 MiB.
- **Metadata** is length-prefixed and padded to a separate, smaller bucket
  set (64 bytes to 4 KiB, then 4 KiB steps), preventing file-name length
  from being inferable from ciphertext size.

**Compression** is applied opportunistically to small-file content only,
pre-padding, kept only if it reduces size, with the outcome flagged in
encrypted metadata. Order is fixed: **compress, then pad, then encrypt.**
Reversing any step is ineffective: post-encryption data is
incompressible, and padding is deliberately incompressible filler.
Chunked content is not compressed, so it can be encrypted and decrypted
as a stream.

## 6. Content formats

A file's format is determined by its encrypted metadata: if it carries a
chunk size, the content is chunked; otherwise it is a single message.
Folders and existing files keep their original format; clients must read
both.

**Single message** (files of 32 MiB or less, and every file written
before chunking existed). The padded, optionally compressed content is
one AES-256-GCM message under the file key with a fresh random nonce,
stored as the record's content IV.

**Chunked** (files larger than 32 MiB). The padded content is split into
`n = max(1, ceil(true_size / 32 MiB))` chunks of exactly 32 MiB. Each
chunk `i` is sealed independently under the file key:

- **Nonce:** `prefix || uint32_be(i)`, where `prefix` is 8 random bytes
  chosen once per file and stored (base64) as the record's content IV.
  This allows up to 2³² chunks per file with no nonce repetition.
- **AAD:** `uint32_be(i) || last`, where `last` is `0x01` for chunk
  `n − 1` and `0x00` otherwise.
- **Stored ciphertext:** the concatenation of all sealed chunks, each
  32 MiB + 16-byte tag.

On decryption the client derives `n` from the true size in metadata,
requires the ciphertext to be exactly `n × (32 MiB + 16)` bytes, and opens
chunks in order. Because position and the "last" flag are authenticated,
reordering, duplicating, dropping, or truncating chunks, or appending
data after the last one, all fail as authentication errors. Chunks can be
decrypted as they arrive, so memory use stays at about one chunk
regardless of file size.

**Determinism and retries.** Chunk `i` is always encrypted under the same
key and nonce. A retried or resumed upload re-reads the same bytes and so
reproduces identical ciphertext, which reveals nothing new. A compliant
client must never re-encrypt a chunk from changed input. Web clients rely
on the browser refusing to read a selected file that was modified on
disk after selection; a client without that guarantee must snapshot the
input or abandon the file's key and prefix when the source changes.

**Upload transport.** Chunked ciphertext is sent in parts that match the
chunks, so each request stays under reverse-proxy body limits, and a
failed upload resumes from the parts the server already holds. Transport
is not cryptographic: the server joins the parts into the same single
ciphertext described above, and nothing about the parts is trusted on
download.

## 7. Encoding

Binary fields in JSON/form payloads (IVs, wrapped keys, encrypted
metadata, duress blobs) are base64. The vault ID is hex (used directly as
a bearer token). Raw content ciphertext is transmitted as a binary blob to
avoid base64 overhead on large payloads. The content IV is 12 bytes for
single-message files and an 8-byte nonce prefix for chunked files.

## 8. Password rotation

1. Unlock with the old password; every file's key is now held unwrapped
   in memory.
2. Derive new master key / vault ID / wrapping key from the new password
   under the current KDF version (opportunistically upgrading legacy
   vaults).
3. Verify the new vault ID differs from the old one.
4. Re-wrap each unchanged file key under the new wrapping key.
5. Submit all new wrapped-key/IV pairs in one atomic operation that also
   swaps the account to the new vault ID. The vault's duress registration
   (§12) moves with it.
6. Adopt the new wrapping key; discard the old one.

Cost scales with file count, not data volume. Rotation is a genuine
invalidation of the old password: no wrapped file key remains decryptable
under the wrapping key the old password derives.

Changing the access token follows the same steps, since the token feeds
the salt. Afterwards the client republishes the duress blob under the new
token; the blob itself does not depend on the token or vault ID.

## 9. Rename / move

Only metadata changes (name and/or parent folder); the file key is
unchanged. Metadata is re-encrypted under the same key; content
ciphertext, its IV, and the wrapped file key are carried over unmodified.

## 10. Sharing

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

## 11. Streaming decryption on the client

To keep large files out of memory, web clients may decrypt in a
same-origin service worker (for downloads) or a dedicated worker (for
thumbnails) instead of the page. Only the single file's key, its content
IV, and the request needed to fetch its ciphertext are handed over; the
wrapping key and master key never reach these workers. A service worker
job is single-use: it is removed from the worker's job table when its
download starts and is held only by that download until it ends, and an
unclaimed job expires after 60 seconds. Plaintext is passed straight to
the browser's download manager or downscaled in place; it is never stored
by the worker.

## 12. Duress code

A second password that, typed at unlock, wipes the vault instead of
opening it. Its design goal is that nothing stored on the device or the
server, and nothing in the unlock traffic, distinguishes a vault with a
duress code from one without, before or after it is used. Activity over
time is not fully hidden from the server operator (see "Sync" and §14).

**Derivation.** Independent of the key hierarchy. A random 16-byte salt
`s` is chosen when the code is set. Two Argon2id derivations of the duress
password, with the current KDF parameters and domain-separated salts
`SHA-256(label || s)`, give:

- a **verifier**, labelled `duress-verifier`, which recognizes the code;
- a **sealing key**, labelled `duress-wrap`, an AES-256-GCM key.

**Blob.** The sealing key encrypts a 64-byte payload:

- `"DRS2" || shred_secret || 28 random bytes`, where `shred_secret` is 32
  random bytes. This is the current format.
- Legacy format: the real vault ID (64 hex characters). It is still
  honored, and current clients create it only when the server doesn't
  support sync.

The blob `{salt, verifier, ciphertext, iv, kdf_version}` therefore always
has an 80-byte ciphertext. Every vault that has no duress code has a blob
of exactly the same shape filled with random bytes, and resetting a code
writes a new random one. Real and decoy blobs cannot be told apart
without the duress password.

**What it can do.** The server stores `SHA-256(shred_secret)` for the
vault. Presenting the secret wipes that vault, and nothing else: the blob
holds no vault ID, wrapping key, or file key, so recovering the duress
password (§13) grants the ability to wipe, not to read. Because the blob
doesn't depend on the vault ID or token, password and token changes don't
invalidate it.

**Sync.** The blob is stored on the server, one per access token, and is
readable with the token alone, since a device needs it before it can
derive anything. Only the vault the token is bound to can replace it.
Every vault writes its blob and a hash on its first unlock with a
syncing client, whether or not a code is ever set, so the stored state
doesn't reveal which users use the feature. Later writes happen only when
the user sets or resets a code; the server can't tell which, but an
operator watching over time can see that one happened. Devices cache the
blob and fall back to the cache when the server is unreachable.

**Unlock.** On every unlock attempt the client:

1. Runs both Argon2id derivations against the blob (and against a
   pre-sync local blob, if the device still holds a different one),
   whether or not the verifier matches, and compares the verifier in
   constant time.
2. Sends one shred request carrying a secret and one legacy wipe request
   carrying a vault ID. On a match these carry the real secret or legacy
   vault ID; otherwise they carry random values of the same shape. The
   server gives the same empty response either way, and does the
   secret-based wipe after responding.
3. Proceeds to derive the vault from the typed password as usual. A
   duress password derives a different, decoy vault.

**Decoy vault.** The vault opened by the duress password is an ordinary
vault: its keys are derived exactly as in §2, from the duress password and
the same access token. Files are added to it ahead of time, using the
second token of the user's pair. Tokens are always issued in identical
pairs with no record of which one the user signs in with, so holding or
binding a second token doesn't by itself mark anyone as having a duress
code, though the server can see when a second token starts being used.

**After use.** The server wipes the vault, deletes its shred hash, and
replaces the token's blob with a fresh random one; the device does the
same to its cached copy. Typing the duress password again afterwards
matches nothing, so the blob can't be used to show that a duress code or
a real vault existed.

## 13. Key material hygiene

Clients keep key material and plaintext in memory only while it is
needed. The master key is a transient intermediate; per-file keys,
metadata, cached plaintext and the wrapping key are dropped when the
vault is locked, and keys handed to workers are dropped when their job
ends (§11). The web and app clients run in JavaScript, which can't
guarantee that memory is overwritten, so this limits how long secrets are
reachable rather than erasing them. It does not change the protocol's
guarantees.

## 14. Threat model

| Scenario | Exposure |
|---|---|
| Passive server compromise (stored data) | Opaque IDs, padded AES-256-GCM ciphertext, wrapped keys, duress blobs and shred-secret hashes. No plaintext, names, directory structure, wrapping key, or master key. Decryption still requires the password. |
| Active server compromise, desktop/mobile apps | The apps' code ships with them and every secret stays on the device, so the server learns nothing beyond the stored data above. Altered, swapped or truncated ciphertext fails authentication instead of being shown, and the server can't forge a duress blob that matches the user's duress password. |
| Active server compromise, web app and share page | The server delivers the JavaScript, so it can serve code that captures passwords and keys, including the key in a share link's fragment. Not defended. |
| Server availability | Any compromised server can refuse service, withhold or delete files, show deleted files again, skip a requested wipe, or replace duress blobs with random ones so the duress password stops wiping. None of this reveals plaintext. |
| Traffic analysis | Size bucket only, not exact length: up to 64 MiB for small files, to the nearest 32 MiB for larger ones. |
| Nonce reuse | Precluded structurally: fresh random nonce per single-message encryption; per-file random prefix plus counter for chunks. A chunk is only ever re-encrypted from identical input (§6). |
| Chunk tampering | Reordering, dropping, duplicating, truncating, or appending chunks fails authentication (position and last-chunk flag are AAD). |
| KDF weakening over time | Mitigated via versioned parameters; new vaults/rotations adopt stronger settings without breaking older ones. |
| Share link exposure | The file key travels in the URL fragment. Anyone who obtains the full link (fragment included) can decrypt that one file; the server alone cannot, since it never receives the fragment. |
| Duress blob exposure | Anyone holding the access token can fetch the blob and try to guess the duress password offline, at Argon2id cost per guess. Success lets them wipe the vault, not read it. Whether a code is set stays hidden. |
| Server observing duress use | The request pattern at unlock and all stored state are identical with or without a code. An operator watching over time sees writes after a vault's first unlock (which suggest a code was set, though setting and removing look alike) and when a second token of a pair starts being used (which suggests decoy files were added). |