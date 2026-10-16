
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duress_blob: Option<String>,
    #[serde(default)]
    pub duress_synced: bool,
    #[serde(default)]
    pub duress_conflict_noticed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_free_markers: Vec<String>,
}

const MAX_LEGACY_FREE_MARKERS: usize = 50;

pub fn legacy_free_marker(vault_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("e2ee-vault|legacy-free-marker|v1|{vault_id}").as_bytes()))
}

pub fn is_vault_legacy_free(vault_id: &str) -> bool {
    let marker = legacy_free_marker(vault_id);
    Config::load().map(|c| c.legacy_free_markers.contains(&marker)).unwrap_or(false)
}

pub fn mark_vault_legacy_free(vault_id: &str) {
    let marker = legacy_free_marker(vault_id);
    let Ok(mut c) = Config::load() else { return };
    if c.legacy_free_markers.contains(&marker) {
        return;
    }
    c.legacy_free_markers.push(marker);
    while c.legacy_free_markers.len() > MAX_LEGACY_FREE_MARKERS {
        c.legacy_free_markers.remove(0);
    }
    let _ = c.save();
}

impl Drop for Config {
    fn drop(&mut self) {
        if let Some(t) = self.access_token.as_mut() {
            t.zeroize();
        }
    }
}

fn config_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("could not determine config directory")?.join("lethean-cli");
    Ok(dir.join("config.json"))
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    pub fn save(&self) -> Result<()> {
        save_private(&config_path()?, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

fn save_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("config path has no parent directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(parent)?;

    let mut suffix = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
    let tmp = parent.join(format!(".config.json.{}.tmp", hex::encode(suffix)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

pub struct ConfigDuressCache;

impl crate::duress::DuressCache for ConfigDuressCache {
    fn load(&self) -> crate::duress::LocalDuress {
        let c = Config::load().unwrap_or_default();
        crate::duress::LocalDuress { config: c.duress_blob.as_deref().and_then(crate::crypto::duress::DuressConfig::from_json), synced: c.duress_synced }
    }

    fn save(&self, config: &crate::crypto::duress::DuressConfig, synced: bool) {
        let mut c = Config::load().unwrap_or_default();
        c.duress_blob = Some(config.to_json());
        c.duress_synced = synced;
        if synced {
            c.duress_conflict_noticed = false;
        }
        let _ = c.save();
    }

    fn conflict_noticed(&self) -> bool {
        Config::load().map(|c| c.duress_conflict_noticed).unwrap_or(false)
    }

    fn set_conflict_noticed(&self) {
        let mut c = Config::load().unwrap_or_default();
        c.duress_conflict_noticed = true;
        let _ = c.save();
    }
}
