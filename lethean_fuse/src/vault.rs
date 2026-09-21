use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::api::{ApiClient, RewrapEntry};
use crate::crypto::aead;
use crate::types::{FileMeta, FileRecord};

const PAGE_SIZE: u64 = 200;

const CONTENT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

const CONTENT_CACHE_MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Entry {
    pub record: FileRecord,
    pub meta: FileMeta,
    pub file_key: Zeroizing<Vec<u8>>,
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

fn parent_key(parent_id: Option<&str>) -> &str {
    parent_id.unwrap_or("")
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct VaultIndex {
    entries: HashMap<String, Entry>,
    children_by_parent: HashMap<String, Vec<String>>,
}

struct ContentCache {
    entries: HashMap<String, Arc<Zeroizing<Vec<u8>>>>,
    order: VecDeque<String>,
    total_bytes: u64,
}

impl ContentCache {
    fn new() -> Self {
        Self { entries: HashMap::new(), order: VecDeque::new(), total_bytes: 0 }
    }

    fn touch(&mut self, id: &str) {
        if let Some(pos) = self.order.iter().position(|x| x == id) {
            let id = self.order.remove(pos).expect("position just found");
            self.order.push_back(id);
        }
    }

    fn get(&mut self, id: &str) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let hit = self.entries.get(id).cloned();
        if hit.is_some() {
            self.touch(id);
        }
        hit
    }

    fn insert(&mut self, id: String, bytes: Arc<Zeroizing<Vec<u8>>>) {
        let size = bytes.len() as u64;
        if size > CONTENT_CACHE_MAX_ENTRY_BYTES {
            return;
        }
        self.remove(&id);
        self.total_bytes += size;
        self.entries.insert(id.clone(), bytes);
        self.order.push_back(id);
        while self.total_bytes > CONTENT_CACHE_MAX_BYTES {
            let Some(oldest) = self.order.pop_front() else { break };
            if let Some(evicted) = self.entries.remove(&oldest) {
                self.total_bytes -= evicted.len() as u64;
            }
        }
    }

    fn rekey(&mut self, old_id: &str, new_id: &str) {
        if let Some(bytes) = self.entries.remove(old_id) {
            if let Some(pos) = self.order.iter().position(|x| x == old_id) {
                self.order.remove(pos);
            }
            self.entries.insert(new_id.to_string(), bytes);
            self.order.push_back(new_id.to_string());
        }
    }

    fn remove(&mut self, id: &str) {
        if let Some(evicted) = self.entries.remove(id) {
            self.total_bytes -= evicted.len() as u64;
        }
        if let Some(pos) = self.order.iter().position(|x| x == id) {
            self.order.remove(pos);
        }
    }

    fn wipe(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.total_bytes = 0;
    }
}

fn lock_cache(cache: &Mutex<ContentCache>) -> MutexGuard<'_, ContentCache> {
    cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct Vault {
    pub api: ApiClient,
    wrapping_key_raw: RwLock<Zeroizing<Vec<u8>>>,
    index: RwLock<VaultIndex>,
    content_cache: Mutex<ContentCache>,
}

impl Vault {
    pub fn new(api: ApiClient, wrapping_key_raw: Vec<u8>) -> Self {
        Self {
            api,
            wrapping_key_raw: RwLock::new(Zeroizing::new(wrapping_key_raw)),
            index: RwLock::new(VaultIndex { entries: HashMap::new(), children_by_parent: HashMap::new() }),
            content_cache: Mutex::new(ContentCache::new()),
        }
    }

    fn wrapping_key(&self) -> Zeroizing<Vec<u8>> {
        read_lock(&self.wrapping_key_raw).clone()
    }

    pub fn close(&self) {
        *write_lock(&self.wrapping_key_raw) = Zeroizing::new(Vec::new());
        {
            let mut index = write_lock(&self.index);
            index.entries.clear();
            index.children_by_parent.clear();
        }
        lock_cache(&self.content_cache).wipe();
    }

    fn index_insert(index: &mut VaultIndex, id: String, parent_id: Option<&str>) {
        index.children_by_parent.entry(parent_key(parent_id).to_string()).or_default().push(id);
    }

    fn index_remove(index: &mut VaultIndex, id: &str, parent_id: Option<&str>) {
        if let Some(v) = index.children_by_parent.get_mut(parent_key(parent_id)) {
            if let Some(pos) = v.iter().position(|x| x == id) {
                v.swap_remove(pos);
            }
        }
    }

    fn ingest_record(&self, record: FileRecord) {
        let wrapping_key = self.wrapping_key();
        let decoded = (|| -> Result<(FileMeta, Zeroizing<Vec<u8>>)> {
            let file_key = Zeroizing::new(aead::unwrap_file_key(&wrapping_key, &record.wrapped_file_key, &record.wrap_iv)?);
            let meta = aead::decrypt_metadata(&file_key, &record.encrypted_metadata, &record.metadata_iv)?;
            Ok((meta, file_key))
        })();

        let (meta, file_key) = match decoded {
            Ok(v) => v,
            Err(_) => (
                FileMeta {
                    name: "Unreadable item".to_string(),
                    mime: "application/octet-stream".to_string(),
                    compressed: false,
                    unpadded_size: None,
                    is_folder: false,
                    parent_id: None,
                },
                Zeroizing::new(Vec::new()),
            ),
        };

        let id = record.id.clone();
        let parent_id = meta.parent_id.clone();
        let mut index = write_lock(&self.index);
        if index.entries.contains_key(&id) {
            return;
        }
        index.entries.insert(id.clone(), Entry { record, meta, file_key });
        Self::index_insert(&mut index, id, parent_id.as_deref());
    }

    pub fn refresh_all(&self) -> Result<()> {
        {
            let mut index = write_lock(&self.index);
            index.entries.clear();
            index.children_by_parent.clear();
        }
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

    pub fn get(&self, id: &str) -> Option<Entry> {
        read_lock(&self.index).entries.get(id).cloned()
    }

    pub fn all_entries(&self) -> Vec<Entry> {
        read_lock(&self.index).entries.values().cloned().collect()
    }

    pub fn children_of(&self, parent_id: Option<&str>) -> Vec<Entry> {
        let index = read_lock(&self.index);
        let mut kids: Vec<Entry> = match index.children_by_parent.get(parent_key(parent_id)) {
            Some(ids) => ids.iter().filter_map(|id| index.entries.get(id).cloned()).collect(),
            None => Vec::new(),
        };
        drop(index);
        kids.sort_by(|a, b| match (a.is_folder(), b.is_folder()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name().cmp(b.name()),
        });
        kids
    }

    pub fn find_child_by_name(&self, parent_id: Option<&str>, name: &str) -> Option<Entry> {
        let index = read_lock(&self.index);
        let ids = index.children_by_parent.get(parent_key(parent_id))?;
        ids.iter().find_map(|id| index.entries.get(id).filter(|e| e.name() == name).cloned())
    }

    pub fn descendant_ids(&self, folder_id: &str) -> Vec<String> {
        let index = read_lock(&self.index);
        let mut result = Vec::new();
        let mut visited: std::collections::HashSet<String> = [folder_id.to_string()].into_iter().collect();
        let mut stack = vec![folder_id.to_string()];
        while let Some(id) = stack.pop() {
            let Some(children) = index.children_by_parent.get(id.as_str()) else { continue };
            for child_id in children {
                if visited.insert(child_id.clone()) {
                    result.push(child_id.clone());
                    if index.entries.get(child_id).map(|e| e.is_folder()).unwrap_or(false) {
                        stack.push(child_id.clone());
                    }
                }
            }
        }
        result
    }

    pub fn create_file(&self, name: &str, mime: &str, contents: &[u8], parent_id: Option<&str>) -> Result<Entry> {
        let wrapping_key = self.wrapping_key();
        let payload = aead::encrypt_file(&wrapping_key, name, mime, contents, parent_id)?;
        let record = self.api.upload_file(&payload, None, None).context("upload failed")?;
        let id = record.id.clone();
        self.ingest_record(record);
        lock_cache(&self.content_cache).insert(id.clone(), Arc::new(Zeroizing::new(contents.to_vec())));
        self.get(&id).context("upload succeeded but the new entry vanished (likely deleted concurrently)")
    }

    pub fn create_folder(&self, name: &str, parent_id: Option<&str>) -> Result<Entry> {
        let wrapping_key = self.wrapping_key();
        let payload = aead::encrypt_folder(&wrapping_key, name, parent_id)?;
        let record = self.api.upload_file(&payload, None, None).context("folder creation failed")?;
        let id = record.id.clone();
        self.ingest_record(record);
        self.get(&id).context("folder creation succeeded but the new entry vanished (likely deleted concurrently)")
    }

    pub fn delete_one(&self, id: &str) -> Result<()> {
        self.api.delete_file(id, None)?;
        let mut index = write_lock(&self.index);
        if let Some(entry) = index.entries.remove(id) {
            Self::index_remove(&mut index, id, entry.parent_id());
        }
        drop(index);
        lock_cache(&self.content_cache).remove(id);
        Ok(())
    }

    pub fn download_decrypted(&self, id: &str) -> Result<Vec<u8>> {
        if let Some(cached) = lock_cache(&self.content_cache).get(id) {
            return Ok(cached.to_vec());
        }

        let entry = self.get(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }
        let ciphertext = self.api.download_content(id)?;
        let bytes = aead::decrypt_content(&entry.file_key, &entry.record.content_iv, &ciphertext, entry.meta.compressed, entry.meta.unpadded_size)?;
        lock_cache(&self.content_cache).insert(id.to_string(), Arc::new(Zeroizing::new(bytes.clone())));
        Ok(bytes)
    }

    pub fn replace_content(&self, id: &str, new_contents: &[u8]) -> Result<Entry> {
        let old = self.get(id).context("unknown file")?;
        let new_entry = self.create_file(old.name(), &old.meta.mime, new_contents, old.parent_id())?;
        self.delete_one(id)?;
        Ok(new_entry)
    }

    pub fn rename_or_move(&self, id: &str, new_name: Option<&str>, new_parent_id: Option<Option<&str>>) -> Result<Entry> {
        let old = self.get(id).context("unknown file")?;
        let mut new_meta = old.meta.clone();
        if let Some(name) = new_name {
            new_meta.name = name.to_string();
        }
        if let Some(parent) = new_parent_id {
            new_meta.parent_id = parent.map(|s| s.to_string());
        }

        if old.is_folder() {
            let new_folder = self.reupload_with_metadata(&old, &new_meta)?;
            let child_ids: Vec<String> = read_lock(&self.index).children_by_parent.get(id).cloned().unwrap_or_default();
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

    fn reupload_with_metadata(&self, old: &Entry, new_meta: &FileMeta) -> Result<Entry> {
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
        let id = record.id.clone();
        self.ingest_record(record);
        lock_cache(&self.content_cache).rekey(&old.record.id, &id);
        self.get(&id).context("reupload succeeded but the new entry vanished (likely deleted concurrently)")
    }

    pub fn rotate_password(&self, new_vault_id: &str, new_wrapping_key_raw: &[u8]) -> Result<u64> {
        let entries = self.all_entries();
        let mut rewraps = Vec::with_capacity(entries.len());
        for entry in &entries {
            if entry.file_key.is_empty() {
                bail!("\"{}\" isn't fully loaded yet — refresh and try again.", entry.name());
            }
            let wrap = aead::aes_gcm_encrypt(new_wrapping_key_raw, &entry.file_key)?;
            rewraps.push(RewrapEntry { file_id: entry.record.id.clone(), wrapped_file_key: aead::to_base64(&wrap.ciphertext), wrap_iv: aead::to_base64(&wrap.iv) });
        }

        let result = self.api.rotate_vault(new_vault_id, &rewraps)?;
        self.api.set_vault_id(Some(new_vault_id.to_string()));
        *write_lock(&self.wrapping_key_raw) = Zeroizing::new(new_wrapping_key_raw.to_vec());
        Ok(result.files_moved)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod content_cache_tests {
    use super::*;

    #[test]
    fn hit_returns_bytes_and_promotes_recency() {
        let mut cache = ContentCache::new();
        cache.insert("a".to_string(), Arc::new(Zeroizing::new(vec![1, 2, 3])));
        assert_eq!(cache.get("a").map(|v| v.to_vec()), Some(vec![1u8, 2, 3]));
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn evicts_least_recently_used_once_over_budget() {
        let mut cache = ContentCache::new();
        let chunk_size = (CONTENT_CACHE_MAX_BYTES / 5) as usize;
        let chunk = vec![0u8; chunk_size];
        for name in ["a", "b", "c", "d", "e", "f"] {
            cache.insert(name.to_string(), Arc::new(Zeroizing::new(chunk.clone())));
        }

        assert!(cache.get("a").is_none(), "oldest entry should have been evicted to stay under budget");
        assert!(cache.entries.contains_key("f"), "most recently inserted entry should survive");
        assert!(cache.total_bytes <= CONTENT_CACHE_MAX_BYTES);

        assert!(cache.get("b").is_some());
        cache.insert("g".to_string(), Arc::new(Zeroizing::new(chunk)));
        assert!(cache.entries.contains_key("b"), "recently touched entry should survive a further eviction round");
    }

    #[test]
    fn entries_larger_than_the_single_entry_cap_are_never_cached() {
        let mut cache = ContentCache::new();
        let huge = vec![0u8; (CONTENT_CACHE_MAX_ENTRY_BYTES + 1) as usize];
        cache.insert("huge".to_string(), Arc::new(Zeroizing::new(huge)));
        assert!(cache.get("huge").is_none());
        assert_eq!(cache.total_bytes, 0);
    }

    #[test]
    fn remove_clears_bytes_and_recency_entry() {
        let mut cache = ContentCache::new();
        cache.insert("a".to_string(), Arc::new(Zeroizing::new(vec![1, 2, 3])));
        cache.remove("a");
        assert!(cache.get("a").is_none());
        assert_eq!(cache.total_bytes, 0);
        assert!(cache.order.is_empty());
    }

    #[test]
    fn rekey_moves_bytes_to_the_new_id_without_a_redundant_fetch() {
        let mut cache = ContentCache::new();
        cache.insert("old-id".to_string(), Arc::new(Zeroizing::new(vec![9, 9, 9])));
        cache.rekey("old-id", "new-id");
        assert!(cache.get("old-id").is_none());
        assert_eq!(cache.get("new-id").map(|v| v.to_vec()), Some(vec![9u8, 9, 9]));
    }

    #[test]
    fn wipe_clears_everything_the_cache_is_holding() {
        let mut cache = ContentCache::new();
        cache.insert("a".to_string(), Arc::new(Zeroizing::new(vec![1, 2, 3])));
        cache.insert("b".to_string(), Arc::new(Zeroizing::new(vec![4, 5, 6])));
        cache.wipe();
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_none());
        assert_eq!(cache.total_bytes, 0);
        assert!(cache.order.is_empty());
    }

    #[test]
    fn closing_the_vault_scrubs_wrapping_key_file_keys_and_cache() {
        let wrapping_key = aead::generate_aes_key_raw();
        let payload = aead::encrypt_file(&wrapping_key, "secret.txt", "text/plain", b"top secret source material", None).unwrap();
        let record = FileRecord {
            id: "closetest0000000000000000000000".to_string(),
            content_iv: payload.content_iv.clone(),
            encrypted_metadata: payload.encrypted_metadata.clone(),
            metadata_iv: payload.metadata_iv.clone(),
            wrapped_file_key: payload.wrapped_file_key.clone(),
            wrap_iv: payload.wrap_iv.clone(),
            size: None,
        };
        let id = record.id.clone();

        let api = ApiClient::new("http://127.0.0.1:0".to_string()).expect("client");
        let vault = Vault::new(api, wrapping_key);
        vault.ingest_record(record);
        assert!(vault.get(&id).is_some(), "entry should be present before close");

        vault.close();

        assert!(vault.get(&id).is_none(), "index should be empty after close");
        assert!(read_lock(&vault.wrapping_key_raw).is_empty(), "wrapping key should be wiped after close");
        assert_eq!(lock_cache(&vault.content_cache).entries.len(), 0, "content cache should be empty after close");
    }
}