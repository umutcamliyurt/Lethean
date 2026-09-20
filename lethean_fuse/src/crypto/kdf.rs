
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::crypto::aead::to_hex;
use crate::types::UnlockResult;

#[derive(Clone, Copy)]
pub struct Argon2Params {
    pub parallelism: u32,
    pub iterations: u32,
    pub memory_kib: u32,
    pub hash_len: usize,
}

pub const CURRENT_KDF_VERSION: u32 = 2;
pub const DEFAULT_LEGACY_KDF_VERSION: u32 = 1;

pub fn kdf_params(version: u32) -> Result<Argon2Params> {
    match version {
        1 => Ok(Argon2Params { parallelism: 1, iterations: 4, memory_kib: 98304, hash_len: 32 }),
        2 => Ok(Argon2Params { parallelism: 1, iterations: 6, memory_kib: 262144, hash_len: 32 }),
        v => bail!("Unknown KDF version: {v}. This vault may need a client update."),
    }
}

fn derive_salt(access_token: Option<&str>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"e2ee-vault|salt|v1|");
    hasher.update(access_token.unwrap_or("").as_bytes());
    hasher.finalize().to_vec()
}

pub fn derive_master_key(password: &str, access_token: Option<&str>, kdf_version: u32) -> Result<Vec<u8>> {
    let salt = derive_salt(access_token);
    let p = kdf_params(kdf_version)?;
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(p.hash_len))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; p.hash_len];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;
    Ok(out)
}

fn hkdf_derive(master_key: &[u8], info: &str, length: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(&[]), master_key);
    let mut okm = vec![0u8; length];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(okm)
}

pub fn derive_vault_id(master_key: &[u8]) -> Result<String> {
    let bytes = hkdf_derive(master_key, "e2ee-vault|vault-id|v1", 32)?;
    Ok(to_hex(&bytes))
}

pub fn derive_wrapping_key(master_key: &[u8]) -> Result<Vec<u8>> {
    hkdf_derive(master_key, "e2ee-vault|wrap|v1", 32)
}

pub fn derive_confirm_marker(vault_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"e2ee-vault|confirmed-marker|v1|");
    hasher.update(vault_id.as_bytes());
    to_hex(&hasher.finalize())
}

pub fn unlock_vault(password: &str, access_token: Option<&str>, kdf_version: u32) -> Result<UnlockResult> {
    let master_key = derive_master_key(password, access_token, kdf_version)?;
    let vault_id = derive_vault_id(&master_key)?;
    let wrapping_key_raw = derive_wrapping_key(&master_key)?;
    Ok(UnlockResult { vault_id, wrapping_key_raw })
}

pub struct PasswordValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

fn has_sequential_run(password: &str, run_length: usize) -> bool {
    let lower = password.to_lowercase();
    let sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
    for seq in sequences {
        let seq_chars: Vec<char> = seq.chars().collect();
        if seq_chars.len() < run_length {
            continue;
        }
        for i in 0..=(seq_chars.len() - run_length) {
            let fwd: String = seq_chars[i..i + run_length].iter().collect();
            let rev: String = fwd.chars().rev().collect();
            if lower.contains(&fwd) || lower.contains(&rev) {
                return true;
            }
        }
    }
    false
}

fn is_mostly_repeated_chars(password: &str) -> bool {
    use std::collections::HashMap;
    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in password.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let max_count = counts.values().copied().max().unwrap_or(0);
    let len = password.chars().count();
    len > 3 && (max_count as f64) / (len as f64) > 0.5
}

pub fn validate_password_strength(password: &str) -> PasswordValidationResult {
    let mut errors = Vec::new();

    if password.chars().count() < 12 {
        errors.push("Use at least 12 characters (longer passwords are safer than short complex ones).".to_string());
    }
    if password.chars().count() > 256 {
        errors.push("Password is unreasonably long (max 256 characters).".to_string());
    }

    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();

    if password.chars().count() < 20 && classes < 3 {
        errors.push("Mix at least 3 of: lowercase, uppercase, numbers, symbols — or use a longer password (20+ characters).".to_string());
    }
    if has_sequential_run(password, 5) {
        errors.push("Avoid simple sequences like \"abcdef\" or \"12345\".".to_string());
    }
    if is_mostly_repeated_chars(password) {
        errors.push("Avoid passwords made mostly of one repeated character.".to_string());
    }

    PasswordValidationResult { valid: errors.is_empty(), errors }
}
