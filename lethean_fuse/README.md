# lethean-fuse

## A minimal FUSE client for Lethean

This tool mounts the decrypted vault as a network drive, so any program on the machine can open, edit and save files in it directly.

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
lethean-fuse share <file-id> --max-downloads 5 --expires-in-seconds 3600
lethean-fuse unshare <file-id>
```