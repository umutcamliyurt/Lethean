use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use std::io::{self, Read, Write};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::format::{is_node_ref, is_record_id, ContentKey, FileKey, FileFormat, ParentRef};
use crate::types::{EncryptedFilePayload, FileMeta, FOLDER_MIME};

pub use crate::crypto::format::{unwrap_file_key, wrap_file_key};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) {
        return Ok(v);
    }
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
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

pub fn decompress_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

pub fn maybe_compress(bytes: &[u8]) -> Result<(Vec<u8>, bool)> {
    match compress_bytes(bytes) {
        Ok(compressed) if compressed.len() < bytes.len() => Ok((compressed, true)),
        _ => Ok((bytes.to_vec(), false)),
    }
}

pub fn is_incompressible_mime(mime: &str) -> bool {
    let m = mime.to_ascii_lowercase();
    if m.starts_with("video/") {
        return true;
    }
    if m.starts_with("audio/") {
        return !matches!(m.as_str(), "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/aiff" | "audio/x-aiff");
    }
    if m.starts_with("image/") {
        return matches!(m.as_str(), "image/png" | "image/jpeg" | "image/jpg" | "image/gif" | "image/webp" | "image/avif" | "image/heic" | "image/heif");
    }
    matches!(
        m.as_str(),
        "application/zip"
            | "application/gzip"
            | "application/x-gzip"
            | "application/x-7z-compressed"
            | "application/x-xz"
            | "application/x-bzip2"
            | "application/zstd"
            | "application/x-rar-compressed"
            | "application/vnd.rar"
            | "application/java-archive"
    ) || m.starts_with("application/vnd.openxmlformats-officedocument.")
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

fn pad_owned_for_encryption(mut bytes: Vec<u8>) -> Vec<u8> {
    let target = padded_size(bytes.len() as u64) as usize;
    bytes.reserve_exact(target.saturating_sub(bytes.len()) + 16);
    bytes.resize(target, 0);
    bytes
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
    aes_gcm_encrypt_aad(key_raw, plaintext, &[])
}

pub fn aes_gcm_encrypt_aad(key_raw: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<AesGcmEncryptResult> {
    let key = key_from_bytes(key_raw)?;
    let cipher = Aes256Gcm::new(key);
    let iv = random_bytes(12);
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    Ok(AesGcmEncryptResult { iv, ciphertext })
}

pub fn aes_gcm_encrypt_in_place(key_raw: &[u8], buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    aes_gcm_encrypt_in_place_aad(key_raw, buf, &[])
}

pub fn aes_gcm_encrypt_in_place_aad(key_raw: &[u8], buf: &mut Vec<u8>, aad: &[u8]) -> Result<Vec<u8>> {
    let key = key_from_bytes(key_raw)?;
    let cipher = Aes256Gcm::new(key);
    let iv = random_bytes(12);
    let nonce = Nonce::from_slice(&iv);
    cipher.encrypt_in_place(nonce, aad, buf).map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    Ok(iv)
}

pub fn aes_gcm_decrypt(key_raw: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    aes_gcm_decrypt_aad(key_raw, iv, ciphertext, &[])
}

pub fn aes_gcm_decrypt_aad(key_raw: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = key_from_bytes(key_raw)?;
    let cipher = Aes256Gcm::new(key);
    if iv.len() != 12 {
        bail!("invalid AES-GCM nonce: expected 12 bytes, got {} (corrupted or malformed record)", iv.len());
    }
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("AES-GCM decryption failed (wrong key, or corrupted/tampered data)"))
}

pub fn aes_gcm_decrypt_in_place_aad(key_raw: &[u8], iv: &[u8], buf: &mut Vec<u8>, aad: &[u8]) -> Result<()> {
    let key = key_from_bytes(key_raw)?;
    let cipher = Aes256Gcm::new(key);
    if iv.len() != 12 {
        bail!("invalid AES-GCM nonce: expected 12 bytes, got {} (corrupted or malformed record)", iv.len());
    }
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt_in_place(nonce, aad, buf)
        .map_err(|_| anyhow!("AES-GCM decryption failed (wrong key, or corrupted/tampered data)"))
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn validate_v2_meta(meta: &FileMeta) -> Result<()> {
    let bad = |why: &str| -> Result<()> { bail!("Corrupt file metadata ({why})") };
    if meta.name.is_empty() || utf16_len(&meta.name) > 4096 {
        return bad("name");
    }
    if utf16_len(&meta.mime) > 255 {
        return bad("mime");
    }
    match &meta.parent_id {
        None => {
            if meta.pref.is_some() {
                return bad("pref without parent");
            }
        }
        Some(id) => {
            if !is_record_id(id) {
                return bad("parentId");
            }
            if !meta.pref.as_deref().map(is_node_ref).unwrap_or(false) {
                return bad("pref");
            }
        }
    }
    if let Some(from) = &meta.from {
        if !is_node_ref(from) {
            return bad("from");
        }
    }
    if meta.is_folder {
        if meta.mime != FOLDER_MIME {
            return bad("folder mime");
        }
        if meta.compressed || meta.chunk_size.is_some() || meta.unpadded_size.is_some() || meta.size.is_some() {
            return bad("folder fields");
        }
        return Ok(());
    }
    let Some(size) = meta.size else { return bad("size") };
    let Some(unpadded) = meta.unpadded_size else { return bad("unpaddedSize") };
    const MAX_SAFE: u64 = (1u64 << 53) - 1;
    if size > MAX_SAFE || unpadded > MAX_SAFE {
        return bad("size");
    }
    if let Some(cs) = meta.chunk_size {
        if cs != crate::crypto::chunked::CHUNK_SIZE {
            return bad("chunkSize");
        }
        if meta.compressed {
            return bad("compressed chunked file");
        }
        if unpadded != size {
            return bad("chunked size");
        }
        if size.div_ceil(cs) > u32::MAX as u64 {
            return bad("too many chunks");
        }
    } else if !meta.compressed && unpadded != size {
        return bad("uncompressed size");
    }
    Ok(())
}

fn unpad_metadata_strict(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() < 4 {
        bail!("Corrupt file metadata (padding)");
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > bytes.len() - 4 || bytes.len() as u64 != padded_metadata_size(len as u64 + 4) || bytes[4 + len..].iter().any(|&b| b != 0) {
        bail!("Corrupt file metadata (padding)");
    }
    Ok(&bytes[4..4 + len])
}

pub fn decrypt_metadata(file_key: &FileKey, encrypted_metadata_b64: &str, metadata_iv_b64: &str) -> Result<FileMeta> {
    let iv = from_base64(metadata_iv_b64)?;
    let ct = from_base64(encrypted_metadata_b64)?;
    let (key, aad) = file_key.metadata_key();
    let padded = Zeroizing::new(aes_gcm_decrypt_aad(&key, &iv, &ct, &aad)?);
    if file_key.is_v2() {
        let meta: FileMeta = serde_json::from_slice(unpad_metadata_strict(&padded)?).context("Corrupt file metadata (JSON)")?;
        validate_v2_meta(&meta)?;
        return Ok(meta);
    }
    let raw = Zeroizing::new(unpad_metadata_bytes(&padded));
    serde_json::from_slice(&raw).context("Could not parse decrypted metadata JSON")
}

pub fn encrypt_metadata(file_key: &FileKey, meta: &FileMeta) -> Result<(String, String)> {
    if file_key.is_v2() {
        validate_v2_meta(meta)?;
    }
    let (key, aad) = file_key.metadata_key();
    let metadata_json = Zeroizing::new(serde_json::to_vec(meta)?);
    let metadata_bytes = Zeroizing::new(pad_metadata_bytes(&metadata_json));
    let enc = aes_gcm_encrypt_aad(&key, &metadata_bytes, &aad)?;
    Ok((to_base64(&enc.ciphertext), to_base64(&enc.iv)))
}

pub fn decompress_exactly(bytes: &[u8], expected: u64) -> Result<Vec<u8>> {
    use flate2::bufread::GzDecoder;
    let mut decoder = GzDecoder::new(io::Cursor::new(bytes));
    let mut out = Vec::with_capacity(expected.min(64 * 1024 * 1024) as usize);
    let read = (&mut decoder).take(expected.saturating_add(1)).read_to_end(&mut out)?;
    if read as u64 != expected {
        out.zeroize();
        bail!("File is corrupt (decompressed size mismatch)");
    }
    let mut probe = [0u8; 1];
    let extra = decoder.read(&mut probe)?;
    let consumed = decoder.into_inner().position();
    if extra != 0 || consumed != bytes.len() as u64 {
        out.zeroize();
        bail!("File is corrupt (decompressed size mismatch)");
    }
    Ok(out)
}

fn finish_single_content(ck: &ContentKey, mut padded: Vec<u8>, meta: &FileMeta) -> Result<Vec<u8>> {
    if ck.format == FileFormat::Legacy {
        if let Some(len) = meta.unpadded_size {
            if (len as usize) <= padded.len() {
                padded.truncate(len as usize);
            }
        }
        if meta.compressed {
            let out = decompress_bytes(&padded);
            padded.zeroize();
            return out;
        }
        return Ok(padded);
    }
    let Some(unpadded) = meta.unpadded_size else {
        if !padded.is_empty() {
            padded.zeroize();
            bail!("File is corrupt (padding)");
        }
        return Ok(padded);
    };
    if padded.len() as u64 != padded_size(unpadded) || padded[unpadded as usize..].iter().any(|&b| b != 0) {
        padded.zeroize();
        bail!("File is corrupt (padding)");
    }
    padded.truncate(unpadded as usize);
    if !meta.compressed {
        return Ok(padded);
    }
    let size = meta.size.context("Corrupt file metadata (size)")?;
    let out = decompress_exactly(&padded, size);
    padded.zeroize();
    out
}

pub fn decrypt_content(ck: &ContentKey, content_iv_b64: &str, ciphertext: &[u8], meta: &FileMeta) -> Result<Vec<u8>> {
    decrypt_content_owned(ck, content_iv_b64, ciphertext.to_vec(), meta)
}

pub fn decrypt_content_owned(ck: &ContentKey, content_iv_b64: &str, mut buf: Vec<u8>, meta: &FileMeta) -> Result<Vec<u8>> {
    let iv = from_base64(content_iv_b64)?;
    aes_gcm_decrypt_in_place_aad(&ck.key, &iv, &mut buf, ck.single_aad())?;
    finish_single_content(ck, buf, meta)
}

fn safe_mime(mime: &str) -> String {
    if mime.is_empty() || utf16_len(mime) > 255 {
        "application/octet-stream".to_string()
    } else {
        mime.to_string()
    }
}

fn safe_name(name: &str) -> String {
    if name.is_empty() {
        return "Untitled".to_string();
    }
    if utf16_len(name) <= 4096 {
        return name.to_string();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in name.chars() {
        units += c.len_utf16();
        if units > 4096 {
            break;
        }
        out.push(c);
    }
    out
}

pub fn encrypt_file(wrapping_key_raw: &[u8], name: &str, mime: &str, contents: &[u8], parent: Option<&ParentRef>) -> Result<EncryptedFilePayload> {
    encrypt_file_ext(wrapping_key_raw, name, mime, contents, parent, None)
}

pub fn encrypt_file_ext(
    wrapping_key_raw: &[u8],
    name: &str,
    mime: &str,
    contents: &[u8],
    parent: Option<&ParentRef>,
    from: Option<&str>,
) -> Result<EncryptedFilePayload> {
    let file_key = FileKey::new_v2();
    let mime = safe_mime(mime);

    let compressed_copy = if is_incompressible_mime(&mime) {
        None
    } else {
        match compress_bytes(contents) {
            Ok(c) if c.len() < contents.len() => Some(c),
            _ => None,
        }
    };
    let (compressed, content_bytes) = match compressed_copy {
        Some(c) => (true, c),
        None => (false, contents.to_vec()),
    };
    let unpadded_size = content_bytes.len() as u64;
    let mut padded_content = Zeroizing::new(pad_owned_for_encryption(content_bytes));

    let mut meta = FileMeta::new_file(safe_name(name), mime, compressed, unpadded_size, parent);
    meta.size = Some(contents.len() as u64);
    meta.from = from.map(|s| s.to_string());
    let (encrypted_metadata, metadata_iv) = encrypt_metadata(&file_key, &meta)?;

    let ck = file_key.content_key();
    let content_iv = aes_gcm_encrypt_in_place_aad(&ck.key, &mut padded_content, ck.single_aad())?;
    let ciphertext = std::mem::take(&mut *padded_content);

    let (wrapped_file_key, wrap_iv) = wrap_file_key(wrapping_key_raw, &file_key)?;

    Ok(EncryptedFilePayload { ciphertext, content_iv: to_base64(&content_iv), encrypted_metadata, metadata_iv, wrapped_file_key, wrap_iv })
}

pub struct StreamUploadPlan {
    pub content_key: ContentKey,
    pub iv: Vec<u8>,
    pub padded_len: u64,
    pub header: crate::types::EncryptedHeader,
}

impl StreamUploadPlan {
    pub fn body_len(&self) -> u64 {
        crate::crypto::gcm_stream::GcmEncryptReader::<std::io::Empty>::encrypted_len(self.padded_len)
    }
}

pub fn plan_stream_upload(wrapping_key_raw: &[u8], name: &str, mime: &str, plain_size: u64, parent: Option<&ParentRef>, from: Option<&str>) -> Result<StreamUploadPlan> {
    let file_key = FileKey::new_v2();
    let iv = random_bytes(12);
    let padded_len = padded_size(plain_size);

    let mut meta = FileMeta::new_file(safe_name(name), safe_mime(mime), false, plain_size, parent);
    meta.size = Some(plain_size);
    meta.from = from.map(|s| s.to_string());
    let (encrypted_metadata, metadata_iv) = encrypt_metadata(&file_key, &meta)?;
    let (wrapped_file_key, wrap_iv) = wrap_file_key(wrapping_key_raw, &file_key)?;

    Ok(StreamUploadPlan {
        header: crate::types::EncryptedHeader { content_iv: to_base64(&iv), encrypted_metadata, metadata_iv, wrapped_file_key, wrap_iv },
        content_key: file_key.content_key(),
        iv,
        padded_len,
    })
}

pub fn encrypt_folder(wrapping_key_raw: &[u8], name: &str, parent: Option<&ParentRef>) -> Result<EncryptedFilePayload> {
    encrypt_folder_ext(wrapping_key_raw, name, parent, None)
}

pub fn encrypt_folder_ext(wrapping_key_raw: &[u8], name: &str, parent: Option<&ParentRef>, from: Option<&str>) -> Result<EncryptedFilePayload> {
    let file_key = FileKey::new_v2();

    let mut meta = FileMeta::new_folder(safe_name(name), parent);
    meta.from = from.map(|s| s.to_string());
    let (encrypted_metadata, metadata_iv) = encrypt_metadata(&file_key, &meta)?;

    let ck = file_key.content_key();
    let content_enc = aes_gcm_encrypt_aad(&ck.key, &[], ck.single_aad())?;

    let (wrapped_file_key, wrap_iv) = wrap_file_key(wrapping_key_raw, &file_key)?;

    Ok(EncryptedFilePayload {
        ciphertext: content_enc.ciphertext,
        content_iv: to_base64(&content_enc.iv),
        encrypted_metadata,
        metadata_iv,
        wrapped_file_key,
        wrap_iv,
    })
}

pub fn is_folder_mime(mime: &str) -> bool {
    mime == FOLDER_MIME
}
