
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{aes_gcm_decrypt, aes_gcm_encrypt, from_base64, random_bytes, to_base64, to_hex};
use crate::crypto::kdf::{kdf_params, CURRENT_KDF_VERSION, DEFAULT_LEGACY_KDF_VERSION};

const V2_MAGIC: &[u8; 4] = b"DRS2";
const PAYLOAD_LEN: usize = 64;
pub const SHRED_SECRET_LEN: usize = 32;
const LABEL_VERIFIER: &str = "e2ee-vault|duress-verifier|v1";
const LABEL_WRAP: &str = "e2ee-vault|duress-wrap|v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuressConfig {
    pub salt: String,
    pub verifier: String,
    #[serde(rename = "encVaultId")]
    pub enc_vault_id: String,
    pub iv: String,
    #[serde(rename = "kdfVersion", default, skip_serializing_if = "Option::is_none")]
    pub kdf_version: Option<u32>,
}

impl DuressConfig {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain struct serializes")
    }

    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}

pub enum DuressMatch {
    Secret(Zeroizing<Vec<u8>>),
    LegacyVault(String),
}

fn derive(input: &str, salt: &[u8], label: &str, kdf_version: u32) -> Result<Zeroizing<Vec<u8>>> {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update(salt);
    let domain_salt = h.finalize();
    let p = kdf_params(kdf_version)?;
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(p.hash_len)).map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
    let mut out = Zeroizing::new(vec![0u8; p.hash_len]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(input.as_bytes(), &domain_salt, &mut out).map_err(|e| anyhow!("argon2 hashing failed: {e}"))?;
    Ok(out)
}

fn seal(code: &str, payload: &[u8]) -> Result<DuressConfig> {
    let salt = random_bytes(16);
    let verifier = derive(code, &salt, LABEL_VERIFIER, CURRENT_KDF_VERSION)?;
    let wrap = derive(code, &salt, LABEL_WRAP, CURRENT_KDF_VERSION)?;
    let enc = aes_gcm_encrypt(&wrap, payload)?;
    Ok(DuressConfig { salt: to_base64(&salt), verifier: to_hex(&verifier), enc_vault_id: to_base64(&enc.ciphertext), iv: to_base64(&enc.iv), kdf_version: Some(CURRENT_KDF_VERSION) })
}

pub fn setup_duress(code: &str) -> Result<(DuressConfig, Zeroizing<Vec<u8>>)> {
    let secret = Zeroizing::new(random_bytes(SHRED_SECRET_LEN));
    let mut payload = Zeroizing::new(random_bytes(PAYLOAD_LEN));
    payload[..4].copy_from_slice(V2_MAGIC);
    payload[4..4 + SHRED_SECRET_LEN].copy_from_slice(&secret);
    Ok((seal(code, &payload)?, secret))
}

pub fn setup_legacy_duress(code: &str, real_vault_id: &str) -> Result<DuressConfig> {
    seal(code, real_vault_id.as_bytes())
}

pub fn decoy_config() -> DuressConfig {
    DuressConfig {
        salt: to_base64(&random_bytes(16)),
        verifier: to_hex(&random_bytes(32)),
        enc_vault_id: to_base64(&random_bytes(PAYLOAD_LEN + 16)),
        iv: to_base64(&random_bytes(12)),
        kdf_version: Some(CURRENT_KDF_VERSION),
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn check_duress(input: &str, cfg: &DuressConfig) -> Option<DuressMatch> {
    let kdf_version = cfg.kdf_version.unwrap_or(DEFAULT_LEGACY_KDF_VERSION);
    let salt = from_base64(&cfg.salt).ok()?;
    let verifier = derive(input, &salt, LABEL_VERIFIER, kdf_version).ok()?;
    let matches = ct_eq(to_hex(&verifier).as_bytes(), cfg.verifier.as_bytes());

    let wrap = derive(input, &salt, LABEL_WRAP, kdf_version).ok()?;
    let payload = (|| -> Result<Vec<u8>> { aes_gcm_decrypt(&wrap, &from_base64(&cfg.iv)?, &from_base64(&cfg.enc_vault_id)?) })().ok();
    let mut payload = Zeroizing::new(payload?);
    if !matches {
        return None;
    }
    if payload.len() == PAYLOAD_LEN && &payload[..4] == V2_MAGIC {
        return Some(DuressMatch::Secret(Zeroizing::new(payload[4..4 + SHRED_SECRET_LEN].to_vec())));
    }
    let vault_id = String::from_utf8(payload.to_vec()).ok();
    payload.zeroize();
    vault_id.map(DuressMatch::LegacyVault)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

pub fn shred_payloads(m: Option<&DuressMatch>) -> (String, String) {
    let secret = match m {
        Some(DuressMatch::Secret(s)) => to_base64(s),
        _ => to_base64(&random_bytes(SHRED_SECRET_LEN)),
    };
    let vault_id = match m {
        Some(DuressMatch::LegacyVault(v)) => v.clone(),
        _ => to_hex(&random_bytes(32)),
    };
    (secret, vault_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_and_decoy_blobs_have_the_same_shape() {
        let (real, _) = setup_duress("duress password one").unwrap();
        let legacy = setup_legacy_duress("duress password one", &"ab".repeat(32)).unwrap();
        let decoy = decoy_config();
        let lens = |c: &DuressConfig| (c.salt.len(), c.verifier.len(), c.enc_vault_id.len(), c.iv.len(), c.kdf_version);
        assert_eq!(lens(&real), lens(&decoy));
        assert_eq!(lens(&legacy), lens(&decoy));
        assert!(real.to_json().starts_with("{\"salt\":"), "{}", real.to_json());
        assert_eq!(DuressConfig::from_json(&real.to_json()).unwrap(), real);
    }

    #[test]
    fn matches_only_the_right_password_and_returns_the_payload() {
        let (cfg, secret) = setup_duress("correct duress words").unwrap();
        match check_duress("correct duress words", &cfg) {
            Some(DuressMatch::Secret(s)) => assert_eq!(&s[..], &secret[..]),
            _ => panic!("no match"),
        }
        assert!(check_duress("wrong duress words!", &cfg).is_none());
        assert!(check_duress("correct duress words", &decoy_config()).is_none());

        let vid = "cd".repeat(32);
        match check_duress("legacy words here", &setup_legacy_duress("legacy words here", &vid).unwrap()) {
            Some(DuressMatch::LegacyVault(v)) => assert_eq!(v, vid),
            _ => panic!("legacy not matched"),
        }
    }
}
