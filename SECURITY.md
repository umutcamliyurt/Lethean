# Security Policy

## Supported Versions

Security fixes are applied to the latest release on `main`. Please update before reporting.

## Reporting a Vulnerability

Please do not open a public issue for security vulnerabilities. Report privately through either channel:

- **GitHub:** use "Report a vulnerability" under the repository's **Security** tab
- **Email:** [9r39hhxp@addy.io](mailto:9r39hhxp@addy.io), with a subject starting `[Lethean Security]`

Include a description of the issue, steps to reproduce, the affected component and version, and its impact.

You can expect an acknowledgement within 7 days and an initial assessment within 14 days. Fixes are released as quickly as severity warrants, and reporters are credited unless they prefer otherwise. Please allow a reasonable window for a fix before public disclosure.

## Scope

In scope:

- Flaws in the cryptographic design or implementation described in [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)
- Any way for the server, or an attacker with its stored data, to learn plaintext, passwords, keys, file names, directory structure, or exact file sizes
- Authentication or authorization bypass, including access token and quota handling
- Duress code or decoy vault behavior that is distinguishable from the normal unlock path, including through the synced duress settings, their write pattern, or the wipe request
- Any way to learn whether a vault has a duress code, or which token of a pair is the decoy, from stored data alone, or to recover a vault ID or file keys from the duress settings
- Any way to wipe a vault without its duress secret, or to change another vault's duress settings
- Attacks on chunked files: reordering, dropping, truncating or splicing chunks without detection
- Making a client read a format-2 file as legacy, accept non-canonical format-2 data, or place a format-2 item in the wrong folder
- Data loss during a vault upgrade, or legacy records accepted by a device that has seen the vault legacy-free
- Quota or authorization bypass through multi-part uploads, and access to another vault's upload sessions
- Issues in the download service worker or thumbnail workers, such as serving one file's plaintext to another origin, or keys or credentials outliving the download they were given for
- Admin panel and share link vulnerabilities
- Injection, path traversal, or remote code execution in the server
- Vulnerabilities in the web, desktop, mobile, or FUSE clients
- Any way for a malicious or compromised server to learn passwords, keys or plaintext from desktop or mobile app users, or to get tampered data accepted by any client

Out of scope, as documented in the [threat model](README.md#threat-model):

- A malicious server serving modified JavaScript to the web client or the share-link page, and a server denying service (withholding, deleting or restoring files, ignoring wipe requests)
- A compromised client device, browser, or extension
- Weak or reused passwords
- Metadata visible by design: padded size buckets (including the 32 MiB steps of large files), record counts, access patterns, when duress settings are written, and whether the second token of a pair is in use
- Offline guessing of a weak duress password by someone who holds your access token (the duress settings are readable with the token by design, so devices can fetch them before unlocking)
- A compromised admin password
- Anyone holding a complete share link, which is the decryption key for that file
- Documented weaknesses of legacy-format items that haven't been upgraded yet
- Volumetric denial of service, and third-party dependency issues with no exploitable path (report those upstream)

## Safe Harbor

Good-faith research that follows this policy, avoids harm to other users' data, and is performed only against your own instance will not be met with legal action.