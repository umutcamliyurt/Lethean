use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::api::{ApiClient, RewrapEntry};
use crate::crypto::aead;
use crate::crypto::gcm_stream::{GcmDecryptReader, GcmEncryptReader, AUTH_FAILED, STREAM_THRESHOLD};
use crate::scratch::{self, Scratch, ScratchPool, ScratchWriter, DEFAULT_POOL_BYTES};
use crate::types::{EncryptedHeader, FileMeta, FileRecord};

const PAGE_SIZE: u64 = 200;

const CONTENT_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024;

const CONTENT_CACHE_MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;

pub const IN_MEMORY_READ_MAX: u64 = 8 * 1024 * 1024;

const LARGE_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const LARGE_LOAD_ATTEMPTS: u32 = 3;

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

#[derive(Clone, Debug)]
pub struct ChildInfo {
    pub id: String,
    pub name: String,
    pub is_folder: bool,
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
    name_index: HashMap<String, HashMap<String, String>>,
}

impl VaultIndex {
    fn new() -> Self {
        Self { entries: HashMap::new(), children_by_parent: HashMap::new(), name_index: HashMap::new() }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.children_by_parent.clear();
        self.name_index.clear();
    }
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

pub struct LargeFile {
    scratch: Mutex<Scratch>,
    len: u64,
}

impl LargeFile {
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let want = len.min((self.len - offset) as usize);
        let mut out = vec![0u8; want];
        let mut s = self.scratch.lock().unwrap_or_else(|p| p.into_inner());
        let mut got = 0;
        while got < want {
            let n = s.read_at(offset + got as u64, &mut out[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        out.truncate(got);
        Ok(out)
    }
}

struct LargeCache {
    map: HashMap<String, Arc<LargeFile>>,
    order: VecDeque<String>,
    total_bytes: u64,
    max_bytes: u64,
}

impl LargeCache {
    fn new(max_bytes: u64) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), total_bytes: 0, max_bytes }
    }

    fn touch(&mut self, id: &str) {
        if let Some(pos) = self.order.iter().position(|x| x == id) {
            let k = self.order.remove(pos).expect("position just found");
            self.order.push_back(k);
        }
    }

    fn get(&mut self, id: &str) -> Option<Arc<LargeFile>> {
        let hit = self.map.get(id).cloned();
        if hit.is_some() {
            self.touch(id);
        }
        hit
    }

    fn insert(&mut self, id: &str, file: Arc<LargeFile>) {
        self.remove(id);
        self.total_bytes += file.len;
        self.map.insert(id.to_string(), file);
        self.order.push_back(id.to_string());
        while self.total_bytes > self.max_bytes && self.order.len() > 1 {
            if let Some(old) = self.order.pop_front() {
                if let Some(f) = self.map.remove(&old) {
                    self.total_bytes -= f.len;
                }
            }
        }
    }

    fn remove(&mut self, id: &str) {
        if let Some(f) = self.map.remove(id) {
            self.total_bytes -= f.len;
            self.order.retain(|k| k != id);
        }
    }

    fn rekey(&mut self, old_id: &str, new_id: &str) {
        if let Some(f) = self.map.remove(old_id) {
            for k in self.order.iter_mut() {
                if k == old_id {
                    *k = new_id.to_string();
                }
            }
            self.map.insert(new_id.to_string(), f);
        }
    }

    fn wipe(&mut self) {
        self.map.clear();
        self.order.clear();
        self.total_bytes = 0;
    }
}

fn lock_large(cache: &Mutex<LargeCache>) -> MutexGuard<'_, LargeCache> {
    cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ClaimGuard<'a> {
    vault: &'a Vault,
    id: String,
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        let mut set = self.vault.loading.lock().unwrap_or_else(|p| p.into_inner());
        set.remove(&self.id);
        drop(set);
        self.vault.load_done.notify_all();
    }
}

pub struct Vault {
    pub api: ApiClient,
    wrapping_key_raw: RwLock<Zeroizing<Vec<u8>>>,
    index: RwLock<VaultIndex>,
    content_cache: Mutex<ContentCache>,
    large_cache: Mutex<LargeCache>,
    loading: Mutex<HashSet<String>>,
    load_done: Condvar,
    pool: Arc<ScratchPool>,
}

#[derive(Clone, Copy, Debug)]
pub struct ReadInfo {
    pub size: u64,
    pub large: bool,
}

impl Vault {
    pub fn new(api: ApiClient, wrapping_key_raw: Vec<u8>) -> Self {
        Self {
            api,
            wrapping_key_raw: RwLock::new(Zeroizing::new(wrapping_key_raw)),
            index: RwLock::new(VaultIndex::new()),
            content_cache: Mutex::new(ContentCache::new()),
            large_cache: Mutex::new(LargeCache::new(LARGE_CACHE_MAX_BYTES)),
            loading: Mutex::new(HashSet::new()),
            load_done: Condvar::new(),
            pool: ScratchPool::new(DEFAULT_POOL_BYTES, scratch::default_dir()),
        }
    }

    pub fn set_scratch_pool(&mut self, pool: Arc<ScratchPool>) {
        self.pool = pool;
    }

    pub fn set_scratch_dir(&mut self, dir: PathBuf, ram_bytes: u64) {
        self.pool = ScratchPool::new(ram_bytes, dir);
    }

    fn wrapping_key(&self) -> Zeroizing<Vec<u8>> {
        read_lock(&self.wrapping_key_raw).clone()
    }

    pub fn close(&self) {
        *write_lock(&self.wrapping_key_raw) = Zeroizing::new(Vec::new());
        write_lock(&self.index).clear();
        lock_cache(&self.content_cache).wipe();
        lock_large(&self.large_cache).wipe();
    }

    fn index_insert(index: &mut VaultIndex, id: String, parent_id: Option<&str>, name: &str) {
        let pk = parent_key(parent_id).to_string();
        index.name_index.entry(pk.clone()).or_default().entry(name.to_string()).or_insert_with(|| id.clone());
        index.children_by_parent.entry(pk).or_default().push(id);
    }

    fn index_remove(index: &mut VaultIndex, id: &str, parent_id: Option<&str>, name: &str) {
        let pk = parent_key(parent_id);
        if let Some(v) = index.children_by_parent.get_mut(pk) {
            if let Some(pos) = v.iter().position(|x| x == id) {
                v.swap_remove(pos);
            }
        }
        let owned_name_slot = index.name_index.get(pk).and_then(|m| m.get(name)).map(|cur| cur == id).unwrap_or(false);
        if owned_name_slot {
            if let Some(m) = index.name_index.get_mut(pk) {
                m.remove(name);
            }
            let replacement = index.children_by_parent.get(pk).and_then(|sibs| sibs.iter().find(|sid| index.entries.get(*sid).map(|e| e.name() == name).unwrap_or(false)).cloned());
            if let Some(rid) = replacement {
                index.name_index.entry(pk.to_string()).or_default().insert(name.to_string(), rid);
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
        let name = meta.name.clone();
        index.entries.insert(id.clone(), Entry { record, meta, file_key });
        Self::index_insert(&mut index, id, parent_id.as_deref(), &name);
    }

    pub fn refresh_all(&self) -> Result<()> {
        write_lock(&self.index).clear();
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
        let id = index.name_index.get(parent_key(parent_id))?.get(name)?;
        index.entries.get(id).cloned()
    }

    pub fn list_children(&self, parent_id: Option<&str>) -> Vec<ChildInfo> {
        let index = read_lock(&self.index);
        let mut kids: Vec<ChildInfo> = match index.children_by_parent.get(parent_key(parent_id)) {
            Some(ids) => ids.iter().filter_map(|id| index.entries.get(id).map(|e| ChildInfo { id: id.clone(), name: e.name().to_string(), is_folder: e.is_folder() })).collect(),
            None => Vec::new(),
        };
        drop(index);
        kids.sort_by(|a, b| match (a.is_folder, b.is_folder) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });
        kids
    }

    pub fn has_children(&self, parent_id: &str) -> bool {
        read_lock(&self.index).children_by_parent.get(parent_id).map(|v| !v.is_empty()).unwrap_or(false)
    }

    pub fn read_info(&self, id: &str) -> Option<ReadInfo> {
        let index = read_lock(&self.index);
        let e = index.entries.get(id)?;
        if e.is_folder() {
            return None;
        }
        Some(ReadInfo { size: e.size(), large: Self::is_large(e) })
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


    pub fn create_file<'a>(&self, name: &str, mime: &str, contents: &'a [u8], parent_id: Option<&str>) -> Result<Entry> {
        self.create_file_streaming(name, mime, contents.len() as u64, parent_id, || {
            let r: Box<dyn Read + 'a> = Box::new(io::Cursor::new(contents));
            Ok(r)
        })
    }

    pub fn create_file_streaming<'a, F>(&self, name: &str, mime: &str, size: u64, parent_id: Option<&str>, mut factory: F) -> Result<Entry>
    where
        F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
    {
        let wrapping_key = self.wrapping_key();

        if size < STREAM_THRESHOLD {
            let mut buf = Zeroizing::new(Vec::with_capacity(size as usize));
            let mut reader = factory().context("could not read the file to upload")?;
            reader.by_ref().take(size).read_to_end(&mut buf).context("could not read the file to upload")?;
            if buf.len() as u64 != size {
                bail!("the file changed while it was being uploaded (expected {size} bytes, read {})", buf.len());
            }
            drop(reader);
            let payload = aead::encrypt_file(&wrapping_key, name, mime, &buf, parent_id)?;
            let record = self.api.upload_file(&payload, None, None).context("upload failed")?;
            let id = record.id.clone();
            self.ingest_record(record);
            lock_cache(&self.content_cache).insert(id.clone(), Arc::new(buf));
            return self.get(&id).context("upload succeeded but the new entry vanished (likely deleted concurrently)");
        }

        let plan = aead::plan_stream_upload(&wrapping_key, name, mime, size, parent_id)?;
        let record = self
            .api
            .upload_stream(
                &plan.header,
                plan.body_len(),
                || {
                    let src = factory()?;
                    let enc = GcmEncryptReader::new(src, &plan.file_key, &plan.iv, size, plan.padded_len).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:#}")))?;
                    let body: Box<dyn Read + 'a> = Box::new(enc);
                    Ok(body)
                },
                None,
                None,
            )
            .context("upload failed")?;
        let id = record.id.clone();
        self.ingest_record(record);
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
        {
            let mut index = write_lock(&self.index);
            if let Some(entry) = index.entries.remove(id) {
                let parent = entry.parent_id().map(|s| s.to_string());
                Self::index_remove(&mut index, id, parent.as_deref(), entry.name());
            }
        }
        lock_cache(&self.content_cache).remove(id);
        lock_large(&self.large_cache).remove(id);
        Ok(())
    }


    fn is_large(entry: &Entry) -> bool {
        entry.size().max(entry.record.size.unwrap_or(0)) > IN_MEMORY_READ_MAX
    }

    fn stream_decrypted(&self, entry: &Entry, w: &mut dyn Write) -> Result<u64> {
        if entry.file_key.is_empty() {
            bail!("\"{}\" could not be decrypted (wrong vault password, or a corrupted item)", entry.name());
        }
        let iv = aead::from_base64(&entry.record.content_iv)?;
        let (body, _len) = self.api.open_blob(&entry.record.id)?;
        let mut dec = GcmDecryptReader::new(body, &entry.file_key, &iv)?;
        let limit = entry.meta.unpadded_size.unwrap_or(u64::MAX);

        let written = if entry.meta.compressed {
            let mut gz = flate2::read::GzDecoder::new((&mut dec).take(limit));
            io::copy(&mut gz, w)?
        } else {
            io::copy(&mut (&mut dec).take(limit), w)?
        };
        io::copy(&mut dec, &mut io::sink())?;
        Ok(written)
    }

    fn download_large(&self, id: &str) -> Result<Arc<LargeFile>> {
        let entry = self.get(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }
        let mut last_err = None;
        for attempt in 0..LARGE_LOAD_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500 * (1 << attempt)));
            }
            let mut scratch = self.pool.new_scratch();
            let result = self.stream_decrypted(&entry, &mut ScratchWriter::new(&mut scratch));
            match result {
                Ok(_) => {
                    let len = scratch.len();
                    return Ok(Arc::new(LargeFile { scratch: Mutex::new(scratch), len }));
                }
                Err(e) if is_transient_stream_error(&e) => {
                    log::warn!("[lethean-cli] download of \"{}\" was interrupted ({e:#}); retrying", entry.name());
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.expect("loop ran at least once"))
    }

    pub fn load_large(&self, id: &str) -> Result<Arc<LargeFile>> {
        loop {
            if let Some(f) = lock_large(&self.large_cache).get(id) {
                return Ok(f);
            }
            {
                let mut set = self.loading.lock().unwrap_or_else(|p| p.into_inner());
                if set.contains(id) {
                    while set.contains(id) {
                        set = self.load_done.wait(set).unwrap_or_else(|p| p.into_inner());
                    }
                    continue;
                }
                set.insert(id.to_string());
            }
            let _claim = ClaimGuard { vault: self, id: id.to_string() };
            if let Some(f) = lock_large(&self.large_cache).get(id) {
                return Ok(f);
            }
            let file = self.download_large(id)?;
            if self.get(id).is_some() {
                lock_large(&self.large_cache).insert(id, Arc::clone(&file));
            }
            return Ok(file);
        }
    }

    pub fn read_range(&self, id: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let entry = self.get(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }
        if Self::is_large(&entry) {
            let f = self.load_large(id)?;
            return Ok(f.read_at(offset, len)?);
        }
        let data = self.download_arc(id)?;
        Ok(slice_of(&data, offset, len))
    }

    pub fn try_read_cached(&self, id: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        if let Some(data) = lock_cache(&self.content_cache).get(id) {
            return Some(slice_of(&data, offset, len));
        }
        let f = lock_large(&self.large_cache).get(id)?;
        f.read_at(offset, len).ok()
    }

    pub fn download_arc(&self, id: &str) -> Result<Arc<Zeroizing<Vec<u8>>>> {
        if let Some(cached) = lock_cache(&self.content_cache).get(id) {
            return Ok(cached);
        }

        let entry = self.get(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }

        if Self::is_large(&entry) {
            let mut out = Zeroizing::new(Vec::with_capacity(entry.size() as usize));
            self.stream_decrypted(&entry, &mut *out)?;
            return Ok(Arc::new(out));
        }

        let ciphertext = self.api.download_content(id)?;
        let bytes = aead::decrypt_content_owned(&entry.file_key, &entry.record.content_iv, ciphertext, entry.meta.compressed, entry.meta.unpadded_size)?;
        let shared = Arc::new(Zeroizing::new(bytes));
        lock_cache(&self.content_cache).insert(id.to_string(), Arc::clone(&shared));
        Ok(shared)
    }

    pub fn download_decrypted(&self, id: &str) -> Result<Vec<u8>> {
        Ok(self.download_arc(id)?.to_vec())
    }

    pub fn stream_plaintext(&self, id: &str, w: &mut dyn Write) -> Result<u64> {
        let entry = self.get(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }
        if !Self::is_large(&entry) {
            let data = self.download_arc(id)?;
            w.write_all(&data)?;
            return Ok(data.len() as u64);
        }
        let cached = lock_large(&self.large_cache).get(id);
        if let Some(f) = cached {
            let mut pos = 0u64;
            while pos < f.len() {
                let part = f.read_at(pos, 1024 * 1024)?;
                if part.is_empty() {
                    break;
                }
                w.write_all(&part)?;
                pos += part.len() as u64;
            }
            return Ok(pos);
        }
        self.stream_decrypted(&entry, w)
    }


    pub fn replace_content(&self, id: &str, new_contents: &[u8]) -> Result<Entry> {
        self.replace_content_streaming(id, new_contents.len() as u64, || {
            let r: Box<dyn Read + '_> = Box::new(io::Cursor::new(new_contents));
            Ok(r)
        })
    }

    pub fn replace_content_streaming<'a, F>(&self, id: &str, size: u64, factory: F) -> Result<Entry>
    where
        F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
    {
        let old = self.get(id).context("unknown file")?;
        let new_entry = self.create_file_streaming(old.name(), &old.meta.mime, size, old.parent_id(), factory)?;
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
        let header = EncryptedHeader {
            content_iv: old.record.content_iv.clone(),
            encrypted_metadata,
            metadata_iv,
            wrapped_file_key: old.record.wrapped_file_key.clone(),
            wrap_iv: old.record.wrap_iv.clone(),
        };

        let record = if old.is_folder() {
            self.api.upload_stream(
                &header,
                0,
                || {
                    let r: Box<dyn Read> = Box::new(io::empty());
                    Ok(r)
                },
                None,
                None,
            )?
        } else {
            let old_id = old.record.id.as_str();
            let (first, len) = self.api.open_blob(old_id)?;
            match len {
                Some(total) => {
                    let mut first = Some(first);
                    self.api.upload_stream(
                        &header,
                        total,
                        || {
                            let r: Box<dyn Read + '_> = match first.take() {
                                Some(r) => Box::new(r),
                                None => {
                                    let (r, _) = self.api.open_blob(old_id).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:#}")))?;
                                    Box::new(r)
                                }
                            };
                            Ok(r)
                        },
                        None,
                        None,
                    )?
                }
                None => {
                    drop(first);
                    let ciphertext = self.api.download_content(old_id)?;
                    self.api.upload_stream(
                        &header,
                        ciphertext.len() as u64,
                        || {
                            let r: Box<dyn Read + '_> = Box::new(io::Cursor::new(&ciphertext[..]));
                            Ok(r)
                        },
                        None,
                        None,
                    )?
                }
            }
        };

        let id = record.id.clone();
        self.ingest_record(record);
        lock_cache(&self.content_cache).rekey(&old.record.id, &id);
        lock_large(&self.large_cache).rekey(&old.record.id, &id);
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

fn slice_of(data: &[u8], offset: u64, len: usize) -> Vec<u8> {
    let start = (offset as usize).min(data.len());
    let end = start.saturating_add(len).min(data.len());
    data[start..end].to_vec()
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

fn is_transient_stream_error(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<io::Error>()
            .map(|io_err| {
                if io_err.kind() == io::ErrorKind::InvalidData && io_err.to_string() == AUTH_FAILED {
                    return false;
                }
                matches!(
                    io_err.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::TimedOut | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected
                )
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod large_cache_tests {
    use super::*;

    fn file(len: u64) -> Arc<LargeFile> {
        let pool = ScratchPool::new(1024 * 1024, std::env::temp_dir());
        Arc::new(LargeFile { scratch: Mutex::new(pool.new_scratch()), len })
    }

    #[test]
    fn evicts_least_recently_used_but_always_keeps_the_newest() {
        let mut cache = LargeCache::new(100);
        cache.insert("a", file(40));
        cache.insert("b", file(40));
        assert!(cache.get("a").is_some(), "touch a so b is the oldest");
        cache.insert("c", file(40));
        assert!(cache.get("b").is_none());
        assert!(cache.get("a").is_some() && cache.get("c").is_some());
        assert!(cache.total_bytes <= 100);

        cache.insert("huge", file(500));
        assert!(cache.get("huge").is_some());
        assert_eq!(cache.order.len(), 1);
    }

    #[test]
    fn remove_and_rekey_only_touch_that_file() {
        let mut cache = LargeCache::new(1000);
        cache.insert("a", file(10));
        cache.insert("b", file(10));
        cache.rekey("a", "a2");
        assert!(cache.get("a").is_none());
        assert!(cache.get("a2").is_some());
        cache.remove("a2");
        assert!(cache.get("a2").is_none());
        assert_eq!(cache.total_bytes, 10);
        assert_eq!(cache.order.len(), 1);
    }

    #[test]
    fn transient_errors_are_retried_but_authentication_failures_are_not() {
        let timeout = anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "slow")).context("download");
        assert!(is_transient_stream_error(&timeout));
        let tampered = anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED));
        assert!(!is_transient_stream_error(&tampered));
        let disk = anyhow::Error::new(io::Error::new(io::ErrorKind::Other, "no space"));
        assert!(!is_transient_stream_error(&disk));
    }
}
