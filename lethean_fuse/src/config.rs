
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
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
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
