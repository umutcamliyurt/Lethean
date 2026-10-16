# Cryptography of Lethean

This document specifies Lethean's end-to-end encryption design: the key hierarchy, primitives, storage formats and per-operation data flow. It applies to every compliant client: web, desktop and mobile apps, and the FUSE client.

**Invariant.** The server stores and serves only ciphertext, wrapped keys and opaque identifiers. It never receives a password, file content, a file name, a directory structure, or any key capable of decryption.

**Notation.** `||` is concatenation. `H` is SHA-256. `HKDF(k, info)` is HKDF-SHA256 with an empty salt and a 32-byte output. Byte strings in quotes are UTF-8. `uint32_be(i)` is the 4-byte big-endian encoding of `i`. KiB and MiB are binary units.

## 1. Key hierarchy

| # | Value | Input | Derivation | Handling |
|---|---|---|---|---|
| 1 | Salt | Access token | `H("e2ee-vault\|salt\|v1\|" \|\| access_token)` | Public, deterministic |
| 2 | Master key | Password, salt | Argon2id (§2) | Transient; discarded after step 3 |
| 3a | Vault ID | Master key | `HKDF(master_key, "e2ee-vault\|vault-id\|v1")`, hex-encoded | Sent to the server as a bearer credential |
| 3b | Wrapping key | Master key | `HKDF(master_key, "e2ee-vault\|wrap\|v1")` | Client only; never transmitted |
| 4 | Item key | CSPRNG | 32 random bytes per file or folder | Wrapped under 3b before leaving the client |
| 5 | Metadata and content keys | Item key | Format 2: HKDF sub-keys (§4.1); legacy: the item key itself | Never stored |

Rows 1–3 are computed locally at every unlock. Row 4 is independent randomness: it is protected by row 3b, not derived from it, and persists in wrapped form for the item's lifetime.

The duress code (§12) has a separate derivation and does not interact with this hierarchy.

## 2. Key derivation

**Salt.** The salt is derived deterministically from the access token (§1, row 1). No per-user salt is stored; any client recomputes it.

**Master key.** `Argon2id(password, salt, params[kdf_version])`, version 0x13, 32-byte output.

| `kdf_version` | Memory | Iterations | Parallelism |
|---|---|---|---|
| 1 | 96 MiB | 4 | 1 |
| 2 (current) | 256 MiB | 6 | 1 |

Parameter sets are versioned so new vaults and rotations can adopt stronger work factors without invalidating existing vaults. The client records the version in use, and unlock replays it. An unrecognized version is a hard failure; there is no fallback.

**Sub-keys.** The vault ID and wrapping key are derived with distinct HKDF labels (§1). Domain separation ensures the vault ID, which is sent with every request, gives no information about the wrapping key. The master key is discarded immediately after both are derived.

**Unlock** is a local function `(password, access_token, kdf_version) → (vault_id, wrapping_key)`. It involves no network round trip and no transmission or storage of the password. Separately, the client fetches the duress settings using the access token and checks the password against them locally (§12). The password is the root secret; there is no recovery mechanism.

**Password policy.** Strength requirements apply only when a password is chosen: setup, rotation, and duress-code setup. They are:
- at least 12 characters (at most 256);
- at least three character classes, or at least 20 characters;
- no run of five sequential or keyboard-adjacent characters;
- no single character making up more than half the password;
- in the web and app clients, rejection of common or breached passwords and of passwords consisting mostly of dictionary words.

Unlock never enforces the policy, so vaults created under an earlier policy remain accessible.

## 3. Symmetric primitive

AES-256-GCM is used for key wrapping, metadata and content:

- 256-bit keys and 128-bit authentication tags throughout.
- 96-bit nonces. Every single-message encryption (wrapped keys, metadata, single-message content, duress payloads) uses a fresh CSPRNG nonce. Chunked content (§6) uses a random per-file prefix and a chunk counter, so nonces never repeat within or across files.
- Associated data: format-2 metadata, content and chunks each carry a distinct label (§4.1); chunks additionally bind their index and end-of-file flag (§6). Wrapped keys, duress payloads, and legacy metadata and single-message content use no associated data.
- All decryption failures (wrong key, tampering, truncation) produce one generic error, so an attacker learns nothing from which check failed.

## 4. Envelope encryption

Each file and folder receives a random 256-bit item key at creation. The item key, not the wrapping key, protects the item's content and metadata. Metadata holds the name, MIME type, parent folder, true size, folder flag, compression flag and, for chunked files, the chunk size. The item key is wrapped under the wrapping key before it leaves the client.

Server-side state per record is: wrapped item key and IV, encrypted metadata and IV, and encrypted content and IV (an empty message for folders). Decryption follows the chain wrapping key → item key → metadata and content. Parent references are inside the encrypted metadata, so the directory structure is confidential. Clients reconstruct the tree locally.

Per-item keys are used instead of the wrapping key directly because they give:

1. **Inexpensive rotation.** A password change re-wraps 32–52-byte item keys only. Content and metadata, which dominate storage, are untouched (§8).
2. **Containment.** No key except the wrapping key decrypts more than one item, and the wrapping key never encrypts content or metadata directly.

### 4.1 File formats

New items use **format 2**. The wrapped plaintext is `"LTH2" || item_key (32 bytes) || binding (16 bytes)`, where `binding` is random per record revision (§9). The item key is never used directly as an encryption key:

| Use | Key | Associated data |
|---|---|---|
| Metadata | `HKDF(item_key, "lethean\|file-metadata\|v2")` | `"lethean\|metadata\|v2\|" \|\| binding` |
| Content | `HKDF(item_key, "lethean\|file-content\|v2")` | `"lethean\|content\|v2"`, or the chunk AAD (§6) |
| Node reference | First 16 bytes of `HKDF(item_key, "lethean\|node-ref\|v2")`, base64url without padding (22 characters) | n/a |

Metadata and content therefore cannot be substituted for each other, and metadata cannot be combined with another record's or another revision's wrapped key.

**Format selection.** The format is determined solely by the unwrapped plaintext, which the wrapping key authenticates:
- 32 bytes: legacy;
- 52 bytes beginning with `"LTH2"`: format 2;
- anything else: rejected.

Share links carry the format explicitly (§10). No data is ever encrypted under the raw bytes of a format-2 key, nor under keys derived from a legacy key, so reading an item in the wrong format fails authentication.

**Folders.** A format-2 item identifies its parent by the parent's node reference (`pref`) as well as its server-assigned record ID (`parentId`). Clients place the item according to `pref`. If no folder matches, the item is hidden rather than misplaced.

**Canonical form.** Clients reject format-2 data they would not have produced themselves:

- metadata that fails the schema. The schema requires:
  - correct field types;
  - a non-empty name of at most 4,096 UTF-16 code units and a MIME type of at most 255;
  - `size` equal to the true size;
  - `chunkSize`, if present, exactly 32 MiB;
  - `pref` present exactly when `parentId` is;
  - for folders, no size, compression or chunk fields.
- metadata padding that is not the exact bucket size or not zero-filled;
- content padding that is not the exact bucket size or not zero-filled, including the filler in the final chunk;
- compressed content that does not inflate to exactly `size` bytes (inflation stops at `size + 1`).

**Legacy (format 1).** The wrapped plaintext is the bare item key, which encrypts metadata and content directly, without associated data. A malicious server can therefore serve a legacy item's metadata ciphertext as its content, or move legacy items between folders by rewriting record IDs. Clients that predate format 2 reject format-2 keys and display those items as unreadable.

### 4.2 Upgrading legacy items

**Upgrade Vault** (or `lethean-fuse upgrade`) re-encrypts each legacy item under a new format-2 key:

1. Folders are recreated, parents first.
2. Each file is uploaded, then downloaded and fully decrypted, before its legacy copy is deleted.
3. Old folders are deleted last, once empty.

Each replacement records the legacy item's node reference in its `from` field. An interrupted upgrade therefore resumes without creating duplicates, and items still referencing an old folder resolve to its replacement. Legacy items keep their existing folder arrangement.

**Strict mode.** When a device lists a vault completely and finds no legacy items, it marks the vault *legacy-free*. From then on it refuses legacy records for that vault. Refused records are hidden unless the user includes them in an upgrade. They are still re-wrapped during rotation (§8), and the mark carries over to the new vault ID. The mark is stored as `H("e2ee-vault|legacy-free-marker|v1|" || vault_id)`. It replaces the device's existing `confirmed` marker for that vault, which is a hash under a different label, so the stored marker list does not reveal which vaults have been opened on the device. The FUSE client stores only legacy-free marks, and never records one for a duress unlock.

## 5. Size hiding: padding and compression

Ciphertext length reveals approximate plaintext length. Padding is applied before encryption; the true length is stored in the encrypted metadata and used to remove padding after decryption.

- **Single-message content** (files of 32 MiB or less, §6) is zero-padded to the next bucket of 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB or 64 MiB.
- **Chunked content** (files larger than 32 MiB) is zero-padded to a whole number of 32 MiB chunks, so its size is revealed only to the nearest 32 MiB.
- **Metadata** is prefixed with a 4-byte big-endian length and zero-padded to 64, 128, 256, 512, 1,024, 2,048 or 4,096 bytes, then to multiples of 4,096 bytes. This prevents inference of name length from ciphertext size.

**Compression** (gzip) is applied opportunistically to single-message content only. It is kept only when it reduces size, and the result is recorded in the encrypted metadata. The order is fixed: **compress, pad, encrypt**. Any other order is ineffective: ciphertext does not compress, and padding is not meant to compress. Chunked content is not compressed, so it can be encrypted and decrypted as a stream.

## 6. Content formats

A file's content format is determined by its encrypted metadata: if `chunkSize` is present, the content is chunked; otherwise it is a single message. Existing files keep their original format; clients must read both.

Below, *content key* means the item key (legacy) or the derived content key (format 2, §4.1).

**Single message** (files of 32 MiB or less, and all files written before chunking existed). The padded, optionally compressed content is one AES-256-GCM message under the content key with a fresh random 12-byte nonce, stored as the record's content IV.

**Chunked** (files larger than 32 MiB). The padded content is divided into `n = max(1, ceil(true_size / 32 MiB))` chunks of exactly 32 MiB. Chunk `i` is sealed independently under the content key:

- **Nonce:** `prefix || uint32_be(i)`. `prefix` is 8 random bytes chosen once per file and stored, base64-encoded, as the record's content IV. This permits 2³² chunks per file without nonce repetition.
- **AAD:** `uint32_be(i) || last`, where `last` is `0x01` for chunk `n − 1` and `0x00` otherwise. Format 2 prepends `"lethean|chunk|v2|"`.
- **Stored ciphertext:** the concatenation of all sealed chunks, each 32 MiB plus a 16-byte tag.

To decrypt, the client derives `n` from the true size in the metadata and requires the ciphertext to be exactly `n × (32 MiB + 16)` bytes. Because the index and end-of-file flag are authenticated, reordering, duplicating, removing or truncating chunks, or appending data after the last chunk, all fail authentication. Chunks are independently verifiable, so a client can decrypt a stream with memory bounded by one chunk, or fetch a single chunk by HTTP range request (§11.2).

**Determinism and retries.** Chunk `i` is always encrypted under the same key and nonce. A retried or resumed upload re-reads the same input and reproduces identical ciphertext, which reveals nothing new. A compliant client must never re-encrypt a chunk from changed input:
- Web clients rely on the browser refusing to read a selected file that has been modified on disk since selection.
- The FUSE client fails the upload if its source ends early.
- Any other client must snapshot its input, or discard the file's key and prefix when the source changes.

**Upload transport.** Chunked ciphertext is sent in parts aligned to chunks, so each request stays under reverse-proxy body limits and a failed upload can resume from the parts the server already holds. Clients may upload several parts concurrently; the FUSE client keeps at most three in flight. The transport is not cryptographically significant: the server concatenates the parts into the single ciphertext described above, and nothing about the parts is trusted on download.

## 7. Encoding and transport

- Binary fields in JSON and form payloads (IVs, wrapped keys, encrypted metadata, duress payloads) are base64.
- The vault ID is hex and is sent as a bearer token.
- Content ciphertext is transmitted as raw binary to avoid base64 overhead.
- The content IV is 12 bytes for single-message files and an 8-byte prefix for chunked files.
- The web client refuses to run outside a secure context, except for local development.
- The desktop, mobile and FUSE clients accept only `https://` server URLs, except `http://` for loopback addresses. They reject URLs containing credentials, a query or a fragment.

## 8. Password rotation

1. Unlock with the current password. Every item key is now held unwrapped in memory.
2. Ensure the client has loaded the complete record list. Rotation is refused otherwise, because an item left out would remain wrapped under the old key and become unreadable.
3. Derive the new master key, vault ID and wrapping key from the new password under the current KDF version. This also upgrades vaults created under older parameters.
4. Verify that the new vault ID differs from the old one.
5. Re-wrap each item key under the new wrapping key, keeping its format and binding.
6. Submit all new wrapped keys and IVs in one atomic request that also moves the vault to the new vault ID. The vault's duress registration (§12) moves with it.
7. Adopt the new wrapping key and discard the old one.

Cost scales with the number of items, not the volume of data. Rotation fully invalidates the old password: no wrapped item key remains decryptable under the wrapping key it derives.

Changing the access token follows the same procedure, because the token determines the salt. Afterwards the client republishes the duress payload under the new token; the payload does not depend on the token or the vault ID.

## 9. Rename and move

Only the metadata changes (name, parent folder, or both); the item key, content ciphertext and content IV are unchanged. For format 2, the item key is re-wrapped with a fresh binding and the metadata is resealed to it, so the previous revision's metadata no longer authenticates. Legacy items keep their existing wrap.

## 10. Sharing

The server issues a share token, plus a delete token if deletion is permitted, subject to expiry and download-count limits. It never receives the item key.

The client places the share token, item key and optional delete token in the URL fragment (`#…`), which browsers never send to a server. The recipient's page fetches the ciphertext by share token and decrypts it locally. The server enforces the access limits but never handles plaintext or key material.

For format-2 files, the fragment also carries `v=2` and the binding `b`. The recipient determines the format from `v` alone: absence means legacy, and any other value is rejected.

The complete link, including the fragment, is therefore the decryption capability itself, not merely an access handle. Its confidentiality is the only control on the shared file.

## 11. Client-side decryption pipelines

### 11.1 Web, desktop and mobile clients

To keep large files out of page memory, the web client may decrypt in a same-origin service worker (downloads) or a dedicated worker (thumbnails). These workers receive only:
- the file's content key (§6);
- its format;
- its content IV;
- the request needed to fetch its ciphertext.

The wrapping key, the master key and format-2 item keys never reach them.

A service-worker job is single-use. It is removed from the worker's job table when its download begins and is held only by that download until it ends. Unclaimed jobs are purged after 60 seconds, the page cancels jobs it no longer needs, and locking the vault clears all jobs. Plaintext is passed directly to the browser's download manager, or downscaled in place for thumbnails; the worker never stores it. Responses carry `Content-Disposition: attachment` and a sandboxing Content Security Policy.

File names from decrypted metadata are untrusted. Before a name is used for a download or a native save dialog, it is reduced to a single path component: path separators, control characters and bidirectional-override characters are removed.

### 11.2 FUSE client

The FUSE client reads chunked files at chunk granularity. To serve a read, it fetches the sealed chunks that cover the requested range by HTTP range request. Each chunk's authentication tag is verified before any of its plaintext is served. A chunk that fails authentication is discarded, never returned. Single-message files are decrypted and verified in full before any byte is served. Sequential reads trigger read-ahead of up to three following chunks; read-ahead attempts each chunk at most once.

Plaintext buffered by the FUSE client (read caches and files being written) is held in memory up to a configurable budget (64 MiB by default). Beyond that, it is spilled to disk in 64 KiB blocks, each sealed with AES-256-GCM:
- **Key:** random per buffer, held only in memory;
- **Nonce:** a 4-byte random prefix followed by an 8-byte counter;
- **Associated data:** the block index, so blocks cannot be swapped.

On Unix the spill file is unlinked immediately after it is created, in a directory with mode `0700`. A spilled block that fails authentication is reported as an I/O error.

## 12. Duress code

A duress code is a second password that, entered at unlock, wipes the vault instead of opening it. The design goal is that nothing stored on the device or the server, and nothing in the unlock traffic, distinguishes a vault with a duress code from one without, before or after use. Activity over time is not fully hidden from the server operator (see **Synchronization** and §14).

**Derivation.** Independent of the key hierarchy. When a code is set, a random 16-byte salt `s` is chosen. Two Argon2id derivations of the duress password use the current KDF parameters and the domain-separated salts `H(label || s)`:

- a **verifier**, label `"e2ee-vault|duress-verifier|v1"`, which recognizes the code;
- a **sealing key**, label `"e2ee-vault|duress-wrap|v1"`, used as an AES-256-GCM key.

**Payload.** The sealing key encrypts a 64-byte payload:

- Current format: `"DRS2" || shred_secret (32 bytes) || 28 random bytes`.
- Legacy format: the real vault ID (64 hex characters). It is still honored, and current clients create it only when the server does not support synchronization.

The stored record is `{salt, verifier, ciphertext, iv, kdf_version}`; the ciphertext is always 80 bytes. A vault without a duress code holds a record of identical shape filled with random bytes, and resetting a code writes a new random one. Real and random records cannot be distinguished without the duress password.

**Capability.** The server stores `H(shred_secret)` for the vault. Presenting the secret wipes that vault and does nothing else. The payload contains no vault ID, wrapping key or item key, so recovering the duress password (§14) grants the ability to wipe, not to read. The payload depends on neither the vault ID nor the token, so password and token changes do not invalidate it.

**Synchronization.** The record is stored on the server, one per access token. It is readable with the token alone, because a device needs it before it can derive anything; only the vault bound to the token can replace it.

Every vault writes a record and a hash on its first unlock with a synchronizing client, whether or not a code is ever set, so stored state does not reveal who uses the feature. Later writes occur only when the user sets or resets a code. The server cannot tell which of the two occurred, but an operator observing over time can see that a write happened. Devices cache the record and use the cache when the server is unreachable.

**Unlock.** On every unlock attempt, the client:

1. Runs both Argon2id derivations against the record, regardless of whether the verifier matches. It also runs them against an older local record if the device still holds a different one from before synchronization. The verifier is compared in constant time.
2. Sends one shred request carrying a secret and one legacy wipe request carrying a vault ID. On a match these carry the real values; otherwise, random values of the same shape. The server returns the same empty response in both cases, and performs the secret-based wipe after responding.
3. Derives the vault from the entered password as usual. A duress password derives a different vault: the decoy.

**Decoy vault.** The decoy is an ordinary vault whose keys are derived as in §2 from the duress password and the same access token. Files are added to it in advance using the second token of the user's pair. Tokens are always issued in identical pairs, with no record of which one the user signs in with. Holding or binding a second token therefore does not by itself indicate a duress code, although the server can observe when a pair's second token is first used.

**After use.** The server wipes the vault, deletes its shred hash, and replaces the token's record with a random one; the device replaces its cached copy the same way. Entering the duress password again matches nothing, so the record cannot later demonstrate that a duress code or a real vault existed.

## 13. Key material hygiene

Clients hold key material and plaintext only while needed:
- The master key is transient.
- Item keys, decrypted metadata, cached plaintext and the wrapping key are discarded when the vault is locked.
- Keys given to workers are discarded when their job ends (§11.1).
- Locking also closes open previews and clears pending download jobs.

The web and app clients run JavaScript, which cannot guarantee that memory is overwritten; there, these measures limit how long secrets remain reachable rather than erasing them. The FUSE client zeroizes keys, passwords and plaintext buffers when they are released. None of this changes the protocol's guarantees.

## 14. Threat analysis

| Scenario | Exposure |
|---|---|
| Passive server compromise (stored data) | Opaque IDs, padded AES-256-GCM ciphertext, wrapped keys, duress records and shred-secret hashes. No plaintext, names, directory structure, wrapping key or master key. Decryption still requires the password. |
| Active server compromise: desktop, mobile and FUSE clients | Client code ships with the build and all secrets stay on the device, so the server learns nothing beyond stored data. Altered, swapped or truncated ciphertext fails authentication and is never presented. The server cannot forge a duress record that matches the user's duress password. For legacy items not yet upgraded, it can serve metadata as content and move items between folders (§4.1). |
| Active server compromise: web app and share page | The server delivers the JavaScript and can serve code that captures passwords and keys, including the key in a share link's fragment. Not defended. |
| Hostile item names or server responses | Names are untrusted input. They are rendered as text, reduced to a single path component before saving (§11.1), mapped to valid path components in the FUSE mount, and escaped before terminal output. Server error text is sanitized before display. |
| Framing of the web client | The client refuses to run inside a frame. |
| Format downgrade | Reading an item in the other format fails authentication. The format comes only from the authenticated wrap or the share link (§4.1). |
| Reintroduced legacy items | Devices that have seen a vault legacy-free refuse legacy records for it (§4.2). Other devices accept them until they do. |
| Server availability | A compromised server can refuse service, withhold or delete files, or restore deleted files or an earlier revision. It can also skip a requested wipe, or replace duress records with random ones so that the duress password no longer wipes. None of this reveals plaintext. |
| Traffic analysis | Sizes are revealed only to the padding bucket: up to 64 MiB for single-message files, the nearest 32 MiB for chunked files. |
| Nonce reuse | Precluded structurally: a fresh random nonce per single-message encryption, and a random per-file prefix with a counter for chunks. A chunk is re-encrypted only from identical input (§6). |
| Chunk tampering | Reordering, removing, duplicating, truncating or appending chunks fails authentication, because index and end-of-file flag are associated data. |
| Unauthenticated plaintext | No client presents plaintext from a chunk or message whose tag has not verified (§11.2). |
| Local disk (FUSE client) | Buffered plaintext spilled to disk is encrypted and authenticated under keys held only in memory (§11.2). The mount is accessible only to its owner and root. The configuration file, which contains the access token, has mode `0600`. |
| KDF weakening over time | Mitigated by versioned parameters (§2). New vaults and rotations adopt stronger settings without breaking older vaults. |
| Share link exposure | The item key travels in the URL fragment. Anyone holding the complete link can decrypt that one file; the server alone cannot, because it never receives the fragment. |
| Duress record exposure | Anyone holding the access token can fetch the record and guess the duress password offline, at Argon2id cost per guess. Success allows wiping the vault, not reading it. Whether a code is set remains hidden. |
| Server observing duress use | Unlock traffic and stored state are identical with and without a code. An operator observing over time sees writes after a vault's first unlock (suggesting a code was set; setting and removing are indistinguishable), and the first use of a pair's second token (suggesting decoy files). |
