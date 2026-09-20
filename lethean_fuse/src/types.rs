
use serde::{Deserialize, Serialize};

pub const FOLDER_MIME: &str = "application/x-lethean-folder";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMeta {
    pub name: String,
    pub mime: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compressed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpadded_size: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_folder: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

impl FileMeta {
    pub fn new_file(name: String, mime: String, compressed: bool, unpadded_size: u64, parent_id: Option<String>) -> Self {
        Self {
            name,
            mime,
            compressed,
            unpadded_size: Some(unpadded_size),
            is_folder: false,
            parent_id,
        }
    }

    pub fn new_folder(name: String, parent_id: Option<String>) -> Self {
        Self {
            name,
            mime: FOLDER_MIME.to_string(),
            compressed: false,
            unpadded_size: None,
            is_folder: true,
            parent_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: String,
    pub content_iv: String,
    pub encrypted_metadata: String,
    pub metadata_iv: String,
    pub wrapped_file_key: String,
    pub wrap_iv: String,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EncryptedFilePayload {
    pub ciphertext: Vec<u8>,
    pub content_iv: String,
    pub encrypted_metadata: String,
    pub metadata_iv: String,
    pub wrapped_file_key: String,
    pub wrap_iv: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageResponse {
    pub file_count: u64,
    pub total_bytes: u64,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

pub struct UnlockResult {
    pub vault_id: String,
    pub wrapping_key_raw: Vec<u8>,
}
