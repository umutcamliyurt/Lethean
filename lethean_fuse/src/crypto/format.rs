
use anyhow::{bail, Result};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::aead::{aes_gcm_decrypt, aes_gcm_encrypt, from_base64, random_bytes, to_base64};

pub const FILE_KEY_LEN: usize = 32;
pub const BINDING_LEN: usize = 16;
const NODE_REF_LEN: usize = 16;
const WRAP_V2_MAGIC: &[u8; 4] = b"LTH2";
const WRAP_V2_LEN: usize = 4 + FILE_KEY_LEN + BINDING_LEN;

const HKDF_INFO_METADATA_V2: &str = "lethean|file-metadata|v2";
const HKDF_INFO_CONTENT_V2: &str = "lethean|file-content|v2";
const HKDF_INFO_NODE_REF_V2: &str = "lethean|node-ref|v2";
pub const AAD_METADATA_V2: &[u8] = b"lethean|metadata|v2|";
pub const AAD_CONTENT_V2: &[u8] = b"lethean|content|v2";
pub const AAD_CHUNK_V2: &[u8] = b"lethean|chunk|v2|";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileFormat {
    Legacy,
    V2,
}

#[derive(Clone)]
pub struct FileKey {
    raw: Zeroizing<Vec<u8>>,
    format: FileFormat,
    binding: Option<[u8; BINDING_LEN]>,
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey").field("format", &self.format).finish_non_exhaustive()
    }
}

impl FileKey {
    pub fn new_v2() -> Self {
        let mut binding = [0u8; BINDING_LEN];
        binding.copy_from_slice(&random_bytes(BINDING_LEN));
        Self { raw: Zeroizing::new(random_bytes(FILE_KEY_LEN)), format: FileFormat::V2, binding: Some(binding) }
    }

    pub fn legacy(raw: Vec<u8>) -> Result<Self> {
        if raw.len() != FILE_KEY_LEN {
            bail!("file key must be {FILE_KEY_LEN} bytes");
        }
        Ok(Self { raw: Zeroizing::new(raw), format: FileFormat::Legacy, binding: None })
    }

    pub fn v2(raw: Vec<u8>, binding: [u8; BINDING_LEN]) -> Result<Self> {
        if raw.len() != FILE_KEY_LEN {
            bail!("file key must be {FILE_KEY_LEN} bytes");
        }
        Ok(Self { raw: Zeroizing::new(raw), format: FileFormat::V2, binding: Some(binding) })
    }

    pub fn format(&self) -> FileFormat {
        self.format
    }

    pub fn is_v2(&self) -> bool {
        self.format == FileFormat::V2
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn binding(&self) -> Option<&[u8; BINDING_LEN]> {
        self.binding.as_ref()
    }

    pub fn rebind(&self) -> Self {
        match self.format {
            FileFormat::Legacy => self.clone(),
            FileFormat::V2 => {
                let mut binding = [0u8; BINDING_LEN];
                binding.copy_from_slice(&random_bytes(BINDING_LEN));
                Self { raw: self.raw.clone(), format: FileFormat::V2, binding: Some(binding) }
            }
        }
    }

    fn wrap_plaintext(&self) -> Zeroizing<Vec<u8>> {
        match self.format {
            FileFormat::Legacy => self.raw.clone(),
            FileFormat::V2 => {
                let mut v = Zeroizing::new(Vec::with_capacity(WRAP_V2_LEN));
                v.extend_from_slice(WRAP_V2_MAGIC);
                v.extend_from_slice(&self.raw);
                v.extend_from_slice(self.binding.as_ref().expect("v2 keys carry a binding"));
                v
            }
        }
    }

    pub fn content_key(&self) -> ContentKey {
        let key = match self.format {
            FileFormat::Legacy => self.raw.clone(),
            FileFormat::V2 => hkdf32(&self.raw, HKDF_INFO_CONTENT_V2),
        };
        ContentKey { key, format: self.format }
    }

    pub fn metadata_key(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        match self.format {
            FileFormat::Legacy => (self.raw.clone(), Vec::new()),
            FileFormat::V2 => {
                let mut aad = AAD_METADATA_V2.to_vec();
                aad.extend_from_slice(self.binding.as_ref().expect("v2 keys carry a binding"));
                (hkdf32(&self.raw, HKDF_INFO_METADATA_V2), aad)
            }
        }
    }

    pub fn node_ref(&self) -> String {
        let full = hkdf32(&self.raw, HKDF_INFO_NODE_REF_V2);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&full[..NODE_REF_LEN])
    }
}

#[derive(Clone)]
pub struct ContentKey {
    pub key: Zeroizing<Vec<u8>>,
    pub format: FileFormat,
}

impl ContentKey {
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    pub fn single_aad(&self) -> &'static [u8] {
        match self.format {
            FileFormat::Legacy => &[],
            FileFormat::V2 => AAD_CONTENT_V2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ParentRef {
    pub id: String,
    pub node_ref: String,
}

fn hkdf32(ikm: &[u8], info: &str) -> Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(&[]), ikm);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    hk.expand(info.as_bytes(), &mut out).expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

pub fn wrap_file_key(wrapping_key: &[u8], key: &FileKey) -> Result<(String, String)> {
    let enc = aes_gcm_encrypt(wrapping_key, &key.wrap_plaintext())?;
    Ok((to_base64(&enc.ciphertext), to_base64(&enc.iv)))
}

pub fn unwrap_file_key(wrapping_key: &[u8], wrapped_b64: &str, iv_b64: &str) -> Result<FileKey> {
    let iv = from_base64(iv_b64)?;
    let wrapped = from_base64(wrapped_b64)?;
    let pt = Zeroizing::new(aes_gcm_decrypt(wrapping_key, &iv, &wrapped).map_err(|e| e.context("Could not unwrap file key"))?);
    if pt.len() == FILE_KEY_LEN {
        return FileKey::legacy(pt.to_vec());
    }
    if pt.len() == WRAP_V2_LEN && &pt[..4] == WRAP_V2_MAGIC {
        let mut binding = [0u8; BINDING_LEN];
        binding.copy_from_slice(&pt[4 + FILE_KEY_LEN..]);
        return FileKey::v2(pt[4..4 + FILE_KEY_LEN].to_vec(), binding);
    }
    bail!("Unsupported file key format")
}

pub fn is_node_ref(s: &str) -> bool {
    s.len() == 22 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn is_record_id(s: &str) -> bool {
    (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_round_trip_in_their_own_format() {
        let wk = random_bytes(32);
        let v2 = FileKey::new_v2();
        let (w, iv) = wrap_file_key(&wk, &v2).unwrap();
        let back = unwrap_file_key(&wk, &w, &iv).unwrap();
        assert!(back.is_v2() && back.raw() == v2.raw() && back.binding() == v2.binding());

        let legacy = FileKey::legacy(random_bytes(32)).unwrap();
        let (w, iv) = wrap_file_key(&wk, &legacy).unwrap();
        let back = unwrap_file_key(&wk, &w, &iv).unwrap();
        assert!(!back.is_v2() && back.raw() == legacy.raw());
    }

    #[test]
    fn odd_wrap_plaintexts_are_rejected() {
        let wk = random_bytes(32);
        for pt in [random_bytes(16), random_bytes(36), random_bytes(52)] {
            let enc = aes_gcm_encrypt(&wk, &pt).unwrap();
            assert!(unwrap_file_key(&wk, &to_base64(&enc.ciphertext), &to_base64(&enc.iv)).is_err());
        }
    }

    #[test]
    fn rebind_keeps_the_key_and_changes_the_binding() {
        let k = FileKey::new_v2();
        let r = k.rebind();
        assert_eq!(k.raw(), r.raw());
        assert_ne!(k.binding(), r.binding());
        assert_eq!(k.node_ref(), r.node_ref());
        assert!(is_node_ref(&k.node_ref()));
    }

    #[test]
    fn subkeys_are_distinct_from_the_file_key() {
        let k = FileKey::new_v2();
        let ck = k.content_key();
        let (mk, _) = k.metadata_key();
        assert_ne!(&ck.key[..], k.raw());
        assert_ne!(&mk[..], k.raw());
        assert_ne!(&mk[..], &ck.key[..]);
    }
}
