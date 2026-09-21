
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as OsCommand;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use lethean_fuse_lib::api::{self, ApiClient};
use lethean_fuse_lib::config::Config;
use lethean_fuse_lib::crypto::kdf;
use lethean_fuse_lib::fuse_fs;
use lethean_fuse_lib::vault::Vault;

#[derive(Parser)]
#[command(name = "lethean-cli", version, about = "Mount an e2ee-vault as a local filesystem, or drive it headlessly")]
struct Cli {
    #[arg(long, global = true)]
    server: Option<String>,

    #[arg(long, global = true)]
    access_token: Option<String>,

    #[arg(long, global = true, default_value_t = kdf::CURRENT_KDF_VERSION)]
    kdf_version: u32,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Mount {
        mountpoint: PathBuf,
        #[arg(long)]
        allow_other: bool,
    },
    Usage,
    Tree,
    RotatePassword,
    Share {
        file_id: String,
        #[arg(long)]
        max_downloads: Option<u64>,
        #[arg(long)]
        expires_in_seconds: Option<u64>,
        #[arg(long)]
        allow_delete: bool,
    },
    Unshare { file_id: String },
}

#[derive(Subcommand)]
enum ConfigAction {
    SetServer { url: String },
    SetToken,
    Show,
}

fn prompt_hidden(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = io::stdin().as_raw_fd();
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        let got = unsafe { libc::tcgetattr(fd, &mut term) };
        let echo_was_supported = got == 0;
        let original = term;
        if echo_was_supported {
            term.c_lflag &= !(libc::ECHO);
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
        }
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match io::stdin().read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    if byte[0] != b'\r' {
                        buf.push(byte[0]);
                    }
                }
                Err(e) => {
                    if echo_was_supported {
                        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
                    }
                    buf.zeroize();
                    return Err(e.into());
                }
            }
        }
        if echo_was_supported {
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
        }
        println!();
        let result = String::from_utf8_lossy(&buf).to_string();
        buf.zeroize();
        Ok(result)
    }
    #[cfg(not(unix))]
    {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let result = line.trim_end_matches(['\n', '\r']).to_string();
        line.zeroize();
        Ok(result)
    }
}

fn resolve_server(cli: &Cli, config: &Config) -> Result<String> {
    cli.server.clone().or_else(|| config.server_url.clone()).context("no server URL configured — pass --server or run `lethean-cli config set-server <url>`")
}

fn resolve_access_token(cli: &Cli, config: &Config) -> Option<String> {
    cli.access_token.clone().or_else(|| config.access_token.clone()).filter(|t| !t.is_empty())
}

fn unlock_session(cli: &Cli, config: &Config) -> Result<Vault> {
    let server = resolve_server(cli, config)?;
    let access_token = resolve_access_token(cli, config);

    let mut password = prompt_hidden("Vault password: ")?;
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    let unlocked = kdf::unlock_vault(&password, access_token.as_deref(), cli.kdf_version)?;
    password.zeroize();

    let api = ApiClient::new(server)?;
    api.set_vault_id(Some(unlocked.vault_id));
    api.set_access_token(access_token);

    let vault = Vault::new(api, unlocked.wrapping_key_raw);
    eprintln!("Fetching file index…");
    vault.refresh_all().context("could not list vault files (wrong password/access token, or server unreachable?)")?;
    eprintln!("Loaded {} item(s).", vault.all_entries().len());
    Ok(vault)
}

fn cmd_config(action: ConfigAction) -> Result<()> {
    let mut config = Config::load()?;
    match action {
        ConfigAction::SetServer { url } => {
            config.server_url = Some(url.trim_end_matches('/').to_string());
            config.save()?;
            println!("Saved server URL.");
        }
        ConfigAction::SetToken => {
            let token = prompt_hidden("Access token: ")?;
            config.access_token = if token.is_empty() { None } else { Some(token) };
            config.save()?;
            println!("Saved access token.");
        }
        ConfigAction::Show => {
            println!("server_url  = {}", config.server_url.as_deref().unwrap_or("(none)"));
            println!("access_token = {}", if config.access_token.is_some() { "(set)" } else { "(none)" });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_stale_mount(path: &Path) -> Result<()> {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let is_mounted = mounts.lines().any(|line| line.split_whitespace().nth(1) == Some(canon.to_string_lossy().as_ref()));
    if !is_mounted {
        return Ok(());
    }

    eprintln!("Found a stale mount at {} (likely left behind by a previous run that didn't exit cleanly) — unmounting it first…", path.display());
    let unmounted = ["fusermount3", "fusermount", "umount"].iter().any(|cmd| OsCommand::new(cmd).arg("-u").arg(path).status().map(|s| s.success()).unwrap_or(false));
    if !unmounted {
        bail!(
            "Could not automatically clear the stale mount at {}. Run `fusermount -u {}` (or `umount {}`) yourself, then try again.",
            path.display(),
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cleanup_stale_mount(_path: &Path) -> Result<()> {
    Ok(())
}

fn cmd_mount(cli: &Cli, config: &Config, mountpoint: PathBuf, allow_other: bool) -> Result<()> {
    cleanup_stale_mount(&mountpoint)?;

    let vault = unlock_session(cli, config)?;
    let mut fs = fuse_fs::VaultFs::new(vault);
    fs.refresh()?;

    let mut options = vec![fuser::MountOption::FSName("e2ee-vault".to_string()), fuser::MountOption::DefaultPermissions];
    if allow_other {
        options.push(fuser::MountOption::AllowOther);
    }

    println!("Mounted at {} — Ctrl+C to unmount.", mountpoint.display());
    fuser::mount2(fs, &mountpoint, &options).context("FUSE mount failed — if this persists, try `fusermount -u <mountpoint>` first")?;
    Ok(())
}

fn cmd_usage(cli: &Cli, config: &Config) -> Result<()> {
    let vault = unlock_session(cli, config)?;
    let usage = vault.api.get_usage(None)?;
    match usage.quota_bytes {
        Some(quota) => println!("{} used / {} quota · {} item(s)", format_bytes(usage.total_bytes), format_bytes(quota), usage.file_count),
        None => println!("{} used · {} item(s)", format_bytes(usage.total_bytes), usage.file_count),
    }
    vault.close();
    Ok(())
}

fn format_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut n = n as f64;
    let mut i = 0;
    while n >= 1024.0 && i < units.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n:.0} {}", units[i])
    } else {
        format!("{n:.1} {}", units[i])
    }
}

fn cmd_tree(cli: &Cli, config: &Config) -> Result<()> {
    let vault = unlock_session(cli, config)?;
    fn walk(vault: &Vault, parent_id: Option<&str>, depth: usize) {
        for entry in vault.children_of(parent_id) {
            let indent = "  ".repeat(depth);
            if entry.is_folder() {
                println!("{indent}{}/  [{}]", entry.name(), entry.record.id);
                walk(vault, Some(&entry.record.id), depth + 1);
            } else {
                println!("{indent}{}  ({}, id {})", entry.name(), format_bytes(entry.size()), entry.record.id);
            }
        }
    }
    walk(&vault, None, 0);
    vault.close();
    Ok(())
}

fn cmd_rotate_password(cli: &Cli, config: &Config) -> Result<()> {
    let server = resolve_server(cli, config)?;
    let access_token = resolve_access_token(cli, config);

    let mut old_password = prompt_hidden("Current vault password: ")?;
    let unlocked = kdf::unlock_vault(&old_password, access_token.as_deref(), cli.kdf_version)?;
    old_password.zeroize();

    let api = ApiClient::new(server)?;
    api.set_vault_id(Some(unlocked.vault_id.clone()));
    api.set_access_token(access_token.clone());
    let vault = Vault::new(api, unlocked.wrapping_key_raw);
    eprintln!("Fetching file index…");
    vault.refresh_all()?;

    let mut new_password = prompt_hidden("New vault password: ")?;
    let mut confirm = prompt_hidden("Confirm new password: ")?;
    if new_password != confirm {
        new_password.zeroize();
        confirm.zeroize();
        vault.close();
        bail!("passwords did not match");
    }
    confirm.zeroize();
    let strength = kdf::validate_password_strength(&new_password);
    if !strength.valid {
        for e in &strength.errors {
            eprintln!("- {e}");
        }
        new_password.zeroize();
        vault.close();
        bail!("new password is too weak");
    }

    let new_kdf_version = kdf::CURRENT_KDF_VERSION;
    let mut new_unlocked = kdf::unlock_vault(&new_password, access_token.as_deref(), new_kdf_version)?;
    new_password.zeroize();
    if new_unlocked.vault_id == unlocked.vault_id {
        new_unlocked.wrapping_key_raw.zeroize();
        vault.close();
        bail!("new password must be different from the current one");
    }

    let files_moved = vault.rotate_password(&new_unlocked.vault_id, &new_unlocked.wrapping_key_raw)?;
    new_unlocked.wrapping_key_raw.zeroize();
    println!("Password changed. {files_moved} file(s) re-wrapped under the new key.");
    println!("(Remember: the vault password itself is never stored anywhere — only you know it.)");
    vault.close();
    Ok(())
}

fn cmd_share(cli: &Cli, config: &Config, file_id: String, max_downloads: Option<u64>, expires_in_seconds: Option<u64>, allow_delete: bool) -> Result<()> {
    let vault = unlock_session(cli, config)?;
    let opts = api::CreateShareOptions { max_downloads, expires_in_seconds, allow_delete };
    let share = vault.api.create_file_share(&file_id, &opts)?;
    println!("share_token = {}", share.share_token);
    if let Some(exp) = share.expires_at {
        println!("expires_at  = {exp}");
    }
    println!("max_downloads = {}", share.max_downloads);
    vault.close();
    Ok(())
}

fn cmd_unshare(cli: &Cli, config: &Config, file_id: String) -> Result<()> {
    let vault = unlock_session(cli, config)?;
    vault.api.revoke_file_share(&file_id)?;
    println!("Share link revoked.");
    vault.close();
    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let cli = Cli::parse();
    let config = Config::load()?;

    match cli.command {
        Command::Config { action } => cmd_config(action),
        Command::Mount { ref mountpoint, allow_other } => cmd_mount(&cli, &config, mountpoint.clone(), allow_other),
        Command::Usage => cmd_usage(&cli, &config),
        Command::Tree => cmd_tree(&cli, &config),
        Command::RotatePassword => cmd_rotate_password(&cli, &config),
        Command::Share { ref file_id, max_downloads, expires_in_seconds, allow_delete } => cmd_share(&cli, &config, file_id.clone(), max_downloads, expires_in_seconds, allow_delete),
        Command::Unshare { ref file_id } => cmd_unshare(&cli, &config, file_id.clone()),
    }
}
