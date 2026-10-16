# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 3.1.x | Yes |
| < 3.1 | No |

Security fixes are released only for the latest release on `main`. Reproduce reported issues against the latest release before submitting.

## Reporting a Vulnerability

Do not open public issues for security vulnerabilities. Report them privately through either channel:

- **GitHub:** use **Report a vulnerability** under the repository's **Security** tab
- **Email:** [9r39hhxp@addy.io](mailto:9r39hhxp@addy.io), with a subject line beginning `[Lethean Security]`

A report should include:

- the affected component (server, web client, desktop or mobile app, FUSE client, or admin panel) and version
- a description of the vulnerability and its impact
- steps to reproduce, or a proof of concept
- the attacker position assumed (for example: malicious server, holder of stored data, network observer, holder of an access token, or another local user)

## Response Process

| Stage | Target |
|---|---|
| Acknowledgement | within 7 days |
| Initial assessment | within 14 days |
| Fix | prioritized by severity |

Reporters are credited unless they request otherwise. Allow a reasonable period for a fix to be released before public disclosure.

## Scope

### Cryptography and confidentiality

- Flaws in the design or implementation specified in [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)
- Any way for the server, or an attacker holding its stored data, to learn plaintext, passwords, keys, file names, directory structure, or sizes more precisely than the padding buckets allow
- Nonce reuse, or any condition under which a client re-encrypts a chunk from different input under the same key and nonce

### Integrity and format handling

- Undetected reordering, removal, duplication, truncation or splicing of chunks
- Causing a client to read a format-2 item as legacy, accept non-canonical format-2 data, or place a format-2 item in the wrong folder
- Causing any client to present unauthenticated plaintext as a file's content
- Data loss during a vault upgrade, or acceptance of legacy records by a device that has marked the vault legacy-free

### Authentication and authorization

- Authentication or authorization bypass, including access-token binding and quota enforcement
- Quota or authorization bypass through multipart uploads, and access to another vault's upload sessions
- Admin panel and share-link vulnerabilities

### Duress code

- Any observable difference between the duress path and a normal unlock, in synchronized duress settings, their write pattern, or the wipe requests
- Determining from stored data alone whether a vault has a duress code, or which token of a pair is the decoy
- Recovering a vault ID or file key from duress settings
- Wiping a vault without its duress secret, or modifying another vault's duress settings

### Clients

- Vulnerabilities in the web, desktop, mobile or FUSE clients
- Any way for a malicious or compromised server to obtain passwords, keys or plaintext from desktop, mobile or FUSE users, or to have tampered data accepted by any client
- Script injection through file names, file content, Markdown, previews or server responses
- Service-worker or worker issues, such as exposing one file's plaintext to another origin, or keys or credentials outliving the job they were issued for
- Framing (clickjacking) of the web client
- Path traversal or unsafe file names in downloads and native save dialogs
- FUSE client: exposure of decrypted files, buffers or credentials to other unprivileged local users; data loss through file-system operations (rename, truncate, unlink); and server-controlled input that crashes the client or makes directories unreadable

### Server

- Injection, path traversal or remote code execution

## Out of Scope

These cases are documented in the [threat model](README.md#threat-model) and are not treated as vulnerabilities:

- A malicious server serving modified JavaScript to the web client or the share-link page
- Denial of service by the server: withholding, deleting or restoring files, or ignoring wipe requests
- A compromised device, operating system, root account, browser or extension
- Weak or reused passwords
- Metadata visible by design: padded size buckets (including the 32 MiB granularity of large files), record counts, access patterns, the timing of duress-settings writes, and whether the second token of a pair is in use
- Offline guessing of a weak duress password by a holder of the access token (duress settings are readable with the token by design, so devices can fetch them before unlocking)
- A compromised admin password
- Any holder of a complete share link, which is the decryption capability for that file
- Documented weaknesses of legacy-format items that have not yet been upgraded
- Volumetric denial of service, and issues in third-party dependencies without an exploitable path in Lethean (report those upstream)

## Safe Harbor

Good-faith research that follows this policy, avoids harm to other users' data, and is performed only against instances you own or operate will not be met with legal action.
