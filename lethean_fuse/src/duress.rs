
use anyhow::{bail, Result};

use crate::api::{is_missing_endpoint, ApiClient};
use crate::crypto::aead::random_bytes;
use crate::crypto::duress::{self, decoy_config, sha256_hex, DuressConfig, DuressMatch, SHRED_SECRET_LEN};

#[derive(Clone, Debug, Default)]
pub struct LocalDuress {
    pub config: Option<DuressConfig>,
    pub synced: bool,
}

pub trait DuressCache {
    fn load(&self) -> LocalDuress;
    fn save(&self, config: &DuressConfig, synced: bool);
    fn conflict_noticed(&self) -> bool;
    fn set_conflict_noticed(&self);
}

#[derive(Debug, PartialEq, Eq)]
pub enum SaveScope {
    AllDevices,
    ThisDeviceOnly,
}

fn valid(c: &DuressConfig) -> bool {
    !c.salt.is_empty() && !c.verifier.is_empty() && !c.enc_vault_id.is_empty() && !c.iv.is_empty()
}

fn fetch(api: &ApiClient, token: &str, vault_id: Option<&str>) -> Result<(DuressConfig, Option<bool>)> {
    let remote = api.get_duress(token, vault_id)?;
    match DuressConfig::from_json(&remote.blob) {
        Some(c) if valid(&c) => Ok((c, remote.written)),
        _ => bail!("malformed duress settings from server"),
    }
}

pub fn configs_to_check(api: &ApiClient, token: Option<&str>, cache: &dyn DuressCache) -> Vec<DuressConfig> {
    let local = cache.load();
    let remote = token.and_then(|t| fetch(api, t, None).ok()).map(|(c, _)| c);
    match (remote, local.config) {
        (Some(r), Some(l)) if !local.synced && l != r => vec![r, l],
        (Some(r), Some(_)) if !local.synced => vec![r],
        (Some(r), _) => {
            cache.save(&r, true);
            vec![r]
        }
        (None, Some(l)) => vec![l],
        (None, None) => {
            let d = decoy_config();
            cache.save(&d, true);
            vec![d]
        }
    }
}

pub fn check_and_signal(api: &ApiClient, token: Option<&str>, password: &str, cache: &dyn DuressCache) -> bool {
    let configs = configs_to_check(api, token, cache);
    let mut matched: Option<DuressMatch> = None;
    for cfg in &configs {
        let m = duress::check_duress(password, cfg);
        if matched.is_none() {
            matched = m;
        }
    }
    let (secret_b64, vault_id) = duress::shred_payloads(matched.as_ref());
    let _ = api.shred_by_secret(&secret_b64);
    let _ = api.send_shred_signal(&vault_id);
    if matched.is_some() {
        cache.save(&decoy_config(), true);
        return true;
    }
    false
}

pub fn reconcile(api: &ApiClient, vault_id: &str, token: Option<&str>, cache: &dyn DuressCache) -> bool {
    let Some(token) = token else { return false };
    let Ok((remote, written)) = fetch(api, token, Some(vault_id)) else { return false };
    let local = cache.load();

    let Some(written) = written else {
        if local.synced || local.config.is_none() {
            cache.save(&remote, true);
        }
        return false;
    };

    if !written {
        let config = match local.config {
            Some(c) if !local.synced => c,
            _ => decoy_config(),
        };
        let hash = sha256_hex(&random_bytes(SHRED_SECRET_LEN));
        if api.put_duress(&config.to_json(), Some(&hash), vault_id, token).is_ok() {
            cache.save(&config, true);
        }
        return false;
    }

    match local.config {
        Some(l) if !local.synced && l != remote => {
            if cache.conflict_noticed() {
                return false;
            }
            cache.set_conflict_noticed();
            true
        }
        _ => {
            cache.save(&remote, true);
            false
        }
    }
}

pub fn save_code(api: &ApiClient, code: &str, vault_id: &str, token: &str, cache: &dyn DuressCache) -> Result<SaveScope> {
    let (config, secret) = duress::setup_duress(code)?;
    match api.put_duress(&config.to_json(), Some(&sha256_hex(&secret)), vault_id, token) {
        Ok(()) => {
            cache.save(&config, true);
            Ok(SaveScope::AllDevices)
        }
        Err(e) if is_missing_endpoint(&e) => {
            cache.save(&duress::setup_legacy_duress(code, vault_id)?, false);
            Ok(SaveScope::ThisDeviceOnly)
        }
        Err(e) => Err(e),
    }
}

pub fn reset_code(api: &ApiClient, vault_id: &str, token: &str, cache: &dyn DuressCache) -> Result<SaveScope> {
    let config = decoy_config();
    match api.put_duress(&config.to_json(), Some(&sha256_hex(&random_bytes(SHRED_SECRET_LEN))), vault_id, token) {
        Ok(()) => {
            cache.save(&config, true);
            Ok(SaveScope::AllDevices)
        }
        Err(e) if is_missing_endpoint(&e) => {
            cache.save(&config, false);
            Ok(SaveScope::ThisDeviceOnly)
        }
        Err(e) => Err(e),
    }
}

pub fn is_duress_code(api: &ApiClient, token: Option<&str>, code: &str, cache: &dyn DuressCache) -> bool {
    configs_to_check(api, token, cache).iter().any(|c| duress::check_duress(code, c).is_some())
}

#[derive(Default)]
pub struct MemoryCache {
    inner: std::sync::Mutex<(LocalDuress, bool)>,
}

impl DuressCache for MemoryCache {
    fn load(&self) -> LocalDuress {
        self.inner.lock().unwrap().0.clone()
    }
    fn save(&self, config: &DuressConfig, synced: bool) {
        self.inner.lock().unwrap().0 = LocalDuress { config: Some(config.clone()), synced };
    }
    fn conflict_noticed(&self) -> bool {
        self.inner.lock().unwrap().1
    }
    fn set_conflict_noticed(&self) {
        self.inner.lock().unwrap().1 = true;
    }
}
