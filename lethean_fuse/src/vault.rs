
use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use crate::api::{ApiClient, RewrapEntry};
use crate::crypto::aead;
use crate::types::{FileMeta, FileRecord};

const PAGE_SIZE: u64 = 200;

#[derive(Clone)]
pub struct Entry {
    pub record: FileRecord,
    pub meta: FileMeta,
    pub file_key: Vec<u8>,
}

impl Entry {
    pub fn is_folder(&self) -> bool {
        self.meta.is_folder
    }

    pub fn parent_id(&self) -> Option<&str> {
        self.meta.parent_id.as_deref()
    }

    pub fn name(&self) -> &str {
        &self.meta.name
    }

    pub fn size(&self) -> u64 {
        self.meta.unpadded_size.unwrap_or_else(|| self.record.size.unwrap_or(0))
    }
}

pub struct Vault {
    pub api: ApiClient,
    pub wrapping_key_raw: Vec<u8>,
    entries: HashMap<String, Entry>,
}

impl Vault {
    pub fn new(api: ApiClient, wrapping_key_raw: Vec<u8>) -> Self {
        Self { api, wrapping_key_raw, entries: HashMap::new() }
    }

    fn ingest_record(&mut self, record: FileRecord) {
        if self.entries.contains_key(&record.id) {
            return;
        }
        let decoded = (|| -> Result<Entry> {
            let file_key = aead::unwrap_file_key(&self.wrapping_key_raw, &record.wrapped_file_key, &record.wrap_iv)?;
            let meta = aead::decrypt_metadata(&file_key, &record.encrypted_metadata, &record.metadata_iv)?;
            Ok(Entry { record: record.clone(), meta, file_key })
        })();

        let entry = match decoded {
            Ok(e) => e,
            Err(_) => Entry {
                record: record.clone(),
                meta: FileMeta {
                    name: "Unreadable item".to_string(),
                    mime: "application/octet-stream".to_string(),
                    compressed: false,
                    unpadded_size: None,
                    is_folder: false,
                    parent_id: None,
                },
                file_key: Vec::new(),
            },
        };
        self.entries.insert(record.id, entry);
    }

    pub fn refresh_all(&mut self) -> Result<()> {
        self.entries.clear();
        let mut offset = 0u64;
        loop {
            let page = self.api.list_files(offset, Some(PAGE_SIZE))?;
            let got = page.len() as u64;
            for record in page {
                self.ingest_record(record);
            }
            if got < PAGE_SIZE {
                break;
            }
            offset += got;
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    pub fn all_entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn children_of(&self, parent_id: Option<&str>) -> Vec<&Entry> {
        let mut kids: Vec<&Entry> = self.entries.values().filter(|e| e.parent_id() == parent_id).collect();
        kids.sort_by(|a, b| match (a.is_folder(), b.is_folder()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name().cmp(b.name()),
        });
        kids
    }

    pub fn find_child_by_name(&self, parent_id: Option<&str>, name: &str) -> Option<&Entry> {
        self.entries.values().find(|e| e.parent_id() == parent_id && e.name() == name)
    }

    pub fn descendant_ids(&self, folder_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut visited: std::collections::HashSet<String> = [folder_id.to_string()].into_iter().collect();
        let mut stack = vec![folder_id.to_string()];
        while let Some(id) = stack.pop() {
            for e in self.entries.values() {
                if e.parent_id() == Some(id.as_str()) && !visited.contains(&e.record.id) {
                    visited.insert(e.record.id.clone());
                    result.push(e.record.id.clone());
                    if e.is_folder() {
                        stack.push(e.record.id.clone());
                    }
                }
            }
        }
        result
    }

    pub fn create_file(&mut self, name: &str, mime: &str, contents: &[u8], parent_id: Option<&str>) -> Result<Entry> {
        let payload = aead::encrypt_file(&self.wrapping_key_raw, name, mime, contents, parent_id)?;
        let record = self.api.upload_file(&payload, None, None).context("upload failed")?;
        self.ingest_record(record.clone());
        Ok(self.entries.get(&record.id).cloned().expect("just inserted"))
    }

    pub fn create_folder(&mut self, name: &str, parent_id: Option<&str>) -> Result<Entry> {
        let payload = aead::encrypt_folder(&self.wrapping_key_raw, name, parent_id)?;
        let record = self.api.upload_file(&payload, None, None).context("folder creation failed")?;
        self.ingest_record(record.clone());
        Ok(self.entries.get(&record.id).cloned().expect("just inserted"))
    }

    pub fn delete_one(&mut self, id: &str) -> Result<()> {
        self.api.delete_file(id, None)?;
        self.entries.remove(id);
        Ok(())
    }

    pub fn download_decrypted(&self, id: &str) -> Result<Vec<u8>> {
        let entry = self.entries.get(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }
        let ciphertext = self.api.download_content(id)?;
        aead::decrypt_content(&entry.file_key, &entry.record.content_iv, &ciphertext, entry.meta.compressed, entry.meta.unpadded_size)
    }

    pub fn replace_content(&mut self, id: &str, new_contents: &[u8]) -> Result<Entry> {
        let old = self.entries.get(id).context("unknown file")?.clone();
        let new_entry = self.create_file(old.name(), &old.meta.mime, new_contents, old.parent_id())?;
        self.delete_one(id)?;
        Ok(new_entry)
    }

    pub fn rename_or_move(&mut self, id: &str, new_name: Option<&str>, new_parent_id: Option<Option<&str>>) -> Result<Entry> {
        let old = self.entries.get(id).context("unknown file")?.clone();
        let mut new_meta = old.meta.clone();
        if let Some(name) = new_name {
            new_meta.name = name.to_string();
        }
        if let Some(parent) = new_parent_id {
            new_meta.parent_id = parent.map(|s| s.to_string());
        }

        if old.is_folder() {
            let new_folder = self.reupload_with_metadata(&old, &new_meta)?;
            let child_ids: Vec<String> = self.entries.values().filter(|e| e.parent_id() == Some(id)).map(|e| e.record.id.clone()).collect();
            for child_id in child_ids {
                self.rename_or_move(&child_id, None, Some(Some(new_folder.record.id.as_str())))?;
            }
            self.delete_one(id)?;
            Ok(new_folder)
        } else {
            let new_file = self.reupload_with_metadata(&old, &new_meta)?;
            self.delete_one(id)?;
            Ok(new_file)
        }
    }

    fn reupload_with_metadata(&mut self, old: &Entry, new_meta: &FileMeta) -> Result<Entry> {
        let (encrypted_metadata, metadata_iv) = aead::reencrypt_metadata(&old.file_key, new_meta)?;
        let ciphertext = if old.is_folder() { Vec::new() } else { self.api.download_content(&old.record.id)? };
        let payload = crate::types::EncryptedFilePayload {
            ciphertext,
            content_iv: old.record.content_iv.clone(),
            encrypted_metadata,
            metadata_iv,
            wrapped_file_key: old.record.wrapped_file_key.clone(),
            wrap_iv: old.record.wrap_iv.clone(),
        };
        let record = self.api.upload_file(&payload, None, None)?;
        self.ingest_record(record.clone());
        Ok(self.entries.get(&record.id).cloned().expect("just inserted"))
    }

    pub fn rotate_password(&mut self, new_vault_id: &str, new_wrapping_key_raw: &[u8]) -> Result<u64> {
        let mut rewraps = Vec::with_capacity(self.entries.len());
        for entry in self.entries.values() {
            if entry.file_key.is_empty() {
                bail!("\"{}\" isn't fully loaded yet — refresh and try again.", entry.name());
            }
            let wrap = aead::aes_gcm_encrypt(new_wrapping_key_raw, &entry.file_key)?;
            rewraps.push(RewrapEntry { file_id: entry.record.id.clone(), wrapped_file_key: aead::to_base64(&wrap.ciphertext), wrap_iv: aead::to_base64(&wrap.iv) });
        }

        let result = self.api.rotate_vault(new_vault_id, &rewraps)?;
        self.api.set_vault_id(Some(new_vault_id.to_string()));
        self.wrapping_key_raw = new_wrapping_key_raw.to_vec();
        Ok(result.files_moved)
    }
}
