use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use std::io::{Read, Write};

use crate::types::{EncryptedFilePayload, FileMeta, FOLDER_MIME};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    let normalized: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let normalized = normalized.replace('-', "+").replace('_', "/");
    base64::engine::general_purpose::STANDARD
        .decode(normalized.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(normalized.as_bytes()))
        .map_err(|_| anyhow!("Invalid base64 string"))
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn compress_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

pub fn decompress_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

pub fn maybe_compress(bytes: &[u8]) -> Result<(Vec<u8>, bool)> {
    match compress_bytes(bytes) {
        Ok(compressed) if compressed.len() < bytes.len() => Ok((compressed, true)),
        _ => Ok((bytes.to_vec(), false)),
    }
}

pub const PADDING_BUCKETS: &[u64] = &[
    16 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024,
    64 * 1024 * 1024,
    256 * 1024 * 1024,
    1024 * 1024 * 1024,
];
pub const PADDING_STEP_BEYOND_MAX: u64 = 256 * 1024 * 1024;

pub fn padded_size(n: u64) -> u64 {
    for &bucket in PADDING_BUCKETS {
        if n <= bucket {
            return bucket;
        }
    }
    n.div_ceil(PADDING_STEP_BEYOND_MAX) * PADDING_STEP_BEYOND_MAX
}

pub fn pad_to_bucket(bytes: &[u8]) -> Vec<u8> {
    let target = padded_size(bytes.len() as u64) as usize;
    if target == bytes.len() {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; target];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

pub fn strip_padding(bytes: &[u8], real_length: Option<u64>) -> Vec<u8> {
    match real_length {
        Some(len) if (len as usize) <= bytes.len() => bytes[..len as usize].to_vec(),
        _ => bytes.to_vec(),
    }
}

pub const METADATA_PADDING_BUCKETS: &[u64] = &[64, 128, 256, 512, 1024, 2048, 4096];

pub fn padded_metadata_size(n: u64) -> u64 {
    for &bucket in METADATA_PADDING_BUCKETS {
        if n <= bucket {
            return bucket;
        }
    }
    let step = *METADATA_PADDING_BUCKETS.last().unwrap();
    n.div_ceil(step) * step
}

pub fn pad_metadata_bytes(bytes: &[u8]) -> Vec<u8> {
    let target = padded_metadata_size(bytes.len() as u64 + 4) as usize;
    let mut out = vec![0u8; target];
    out[0..4].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    out[4..4 + bytes.len()].copy_from_slice(bytes);
    out
}

pub fn unpad_metadata_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 4 {
        return bytes.to_vec();
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > bytes.len() - 4 {
        return bytes[4..].to_vec();
    }
    bytes[4..4 + len].to_vec()
}

pub fn generate_aes_key_raw() -> Vec<u8> {
    random_bytes(32)
}

fn key_from_bytes(raw: &[u8]) -> Result<&Key<Aes256Gcm>> {
    if raw.len() != 32 {
        bail!("AES-256 key must be 32 bytes, got {}", raw.len());
    }
    Ok(Key::<Aes256Gcm>::from_slice(raw))
}

pub struct AesGcmEncryptResult {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn aes_gcm_encrypt(key_raw: &[u8], plaintext: &[u8]) -> Result<AesGcmEncryptResult> {
    let key = key_from_bytes(key_raw)?;
    let cipher = Aes256Gcm::new(key);
    let iv = random_bytes(12);
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &[] })
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    Ok(AesGcmEncryptResult { iv, ciphertext })
}

pub fn aes_gcm_decrypt(key_raw: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = key_from_bytes(key_raw)?;
    let cipher = Aes256Gcm::new(key);
    if iv.len() != 12 {
        bail!("invalid AES-GCM nonce: expected 12 bytes, got {} (corrupted or malformed record)", iv.len());
    }
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: &[] })
        .map_err(|_| anyhow!("AES-GCM decryption failed (wrong key, or corrupted/tampered data)"))
}

pub fn unwrap_file_key(wrapping_key_raw: &[u8], wrapped_file_key_b64: &str, wrap_iv_b64: &str) -> Result<Vec<u8>> {
    let wrap_iv = from_base64(wrap_iv_b64)?;
    let wrapped = from_base64(wrapped_file_key_b64)?;
    aes_gcm_decrypt(wrapping_key_raw, &wrap_iv, &wrapped).context("Could not unwrap file key")
}

pub fn decrypt_metadata(file_key_raw: &[u8], encrypted_metadata_b64: &str, metadata_iv_b64: &str) -> Result<FileMeta> {
    let iv = from_base64(metadata_iv_b64)?;
    let ct = from_base64(encrypted_metadata_b64)?;
    let padded = aes_gcm_decrypt(file_key_raw, &iv, &ct)?;
    let raw = unpad_metadata_bytes(&padded);
    serde_json::from_slice(&raw).context("Could not parse decrypted metadata JSON")
}

pub fn decrypt_content(
    file_key_raw: &[u8],
    content_iv_b64: &str,
    ciphertext: &[u8],
    compressed: bool,
    unpadded_size: Option<u64>,
) -> Result<Vec<u8>> {
    let iv = from_base64(content_iv_b64)?;
    let padded = aes_gcm_decrypt(file_key_raw, &iv, ciphertext)?;
    let bytes = strip_padding(&padded, unpadded_size);
    if compressed {
        decompress_bytes(&bytes)
    } else {
        Ok(bytes)
    }
}

pub fn encrypt_file(
    wrapping_key_raw: &[u8],
    name: &str,
    mime: &str,
    contents: &[u8],
    parent_id: Option<&str>,
) -> Result<EncryptedFilePayload> {
    let file_key_raw = generate_aes_key_raw();

    let (content_bytes, compressed) = maybe_compress(contents)?;
    let unpadded_size = content_bytes.len() as u64;
    let padded_content = pad_to_bucket(&content_bytes);

    let meta = FileMeta::new_file(name.to_string(), mime.to_string(), compressed, unpadded_size, parent_id.map(|s| s.to_string()));
    let metadata_json = serde_json::to_vec(&meta)?;
    let metadata_bytes = pad_metadata_bytes(&metadata_json);
    let meta_enc = aes_gcm_encrypt(&file_key_raw, &metadata_bytes)?;

    let content_enc = aes_gcm_encrypt(&file_key_raw, &padded_content)?;

    let key_wrap = aes_gcm_encrypt(wrapping_key_raw, &file_key_raw)?;

    Ok(EncryptedFilePayload {
        ciphertext: content_enc.ciphertext,
        content_iv: to_base64(&content_enc.iv),
        encrypted_metadata: to_base64(&meta_enc.ciphertext),
        metadata_iv: to_base64(&meta_enc.iv),
        wrapped_file_key: to_base64(&key_wrap.ciphertext),
        wrap_iv: to_base64(&key_wrap.iv),
    })
}

pub fn encrypt_folder(wrapping_key_raw: &[u8], name: &str, parent_id: Option<&str>) -> Result<EncryptedFilePayload> {
    let file_key_raw = generate_aes_key_raw();

    let meta = FileMeta::new_folder(name.to_string(), parent_id.map(|s| s.to_string()));
    let metadata_json = serde_json::to_vec(&meta)?;
    let metadata_bytes = pad_metadata_bytes(&metadata_json);
    let meta_enc = aes_gcm_encrypt(&file_key_raw, &metadata_bytes)?;

    let content_enc = aes_gcm_encrypt(&file_key_raw, &[])?;

    let key_wrap = aes_gcm_encrypt(wrapping_key_raw, &file_key_raw)?;

    Ok(EncryptedFilePayload {
        ciphertext: content_enc.ciphertext,
        content_iv: to_base64(&content_enc.iv),
        encrypted_metadata: to_base64(&meta_enc.ciphertext),
        metadata_iv: to_base64(&meta_enc.iv),
        wrapped_file_key: to_base64(&key_wrap.ciphertext),
        wrap_iv: to_base64(&key_wrap.iv),
    })
}

pub fn reencrypt_metadata(file_key_raw: &[u8], meta: &FileMeta) -> Result<(String, String)> {
    let metadata_json = serde_json::to_vec(meta)?;
    let metadata_bytes = pad_metadata_bytes(&metadata_json);
    let enc = aes_gcm_encrypt(file_key_raw, &metadata_bytes)?;
    Ok((to_base64(&enc.ciphertext), to_base64(&enc.iv)))
}

pub fn is_folder_mime(mime: &str) -> bool {
    mime == FOLDER_MIME
}