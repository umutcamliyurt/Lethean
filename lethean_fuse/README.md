# lethean-fuse

## A minimal FUSE client for Lethean

This tool mounts the decrypted vault as a network drive, so any program on the machine can open, edit and save files in it directly. Everything is encrypted and decrypted on your machine, in the same formats as the web and desktop apps, so files and settings move freely between them.

## Building

Requires a Rust toolchain and `libfuse3-dev` (Debian) or `macFUSE` (macOS).

```sh
sudo apt install libfuse3-dev   # Debian/Ubuntu
cargo build --release
```

## Usage

```sh
# Save the server URL
lethean-fuse config set-server https://vault.example.com

# Save the operator-provided access token (prompts for the token)
lethean-fuse config set-token

# Mount the vault (prompts for the password)
lethean-fuse mount ~/Vault

# Headless commands
lethean-fuse tree
lethean-fuse usage
lethean-fuse rotate-password
lethean-fuse upgrade
lethean-fuse share <file-id> --max-downloads 5 --expires-in-seconds 3600
lethean-fuse unshare <file-id>

# Duress code
lethean-fuse duress set
lethean-fuse duress reset
lethean-fuse duress add-decoy-files notes.txt photo.jpg
```

## Formats

New items use format 2 (see [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md#41-file-formats)). Older items stay readable; `lethean-fuse upgrade` re-encrypts them and checks each copy before deleting the original. Once this device has seen a vault with no older items, it refuses them for that vault.