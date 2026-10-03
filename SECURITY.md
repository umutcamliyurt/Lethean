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
- Duress code or decoy vault behavior that is distinguishable from the normal unlock path
- Admin panel and share link vulnerabilities
- Injection, path traversal, or remote code execution in the server
- Vulnerabilities in the web, desktop, mobile, or FUSE clients

Out of scope, as documented in the [threat model](README.md#threat-model):

- Active server compromise, including a malicious operator serving modified JavaScript to the web client
- A compromised client device, browser, or extension
- Weak or reused passwords
- Metadata visible by design: padded size buckets, record counts, and access patterns
- A compromised admin password
- Anyone holding a complete share link, which is the decryption key for that file
- Volumetric denial of service, and third-party dependency issues with no exploitable path (report those upstream)

## Safe Harbor

Good-faith research that follows this policy, avoids harm to other users' data, and is performed only against your own instance will not be met with legal action.