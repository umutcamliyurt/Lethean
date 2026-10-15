use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::api::{ApiClient, RewrapEntry};
use crate::crypto::aead;
use crate::crypto::chunked::{self, ChunkedEncryptReader, CHUNK_SIZE};
use crate::crypto::format::{ContentKey, FileFormat, FileKey, ParentRef};
use crate::crypto::gcm_stream::{GcmDecryptReader, GcmEncryptReader, AUTH_FAILED, STREAM_THRESHOLD};
use crate::scratch::{self, Scratch, ScratchPool, ScratchWriter, DEFAULT_POOL_BYTES};
use crate::types::{EncryptedHeader, FileMeta, FileRecord};

const PAGE_SIZE: u64 = 200;

const REFRESH_PARALLELISM: usize = 8;

const CONTENT_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024;

const CONTENT_CACHE_MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;

pub const IN_MEMORY_READ_MAX: u64 = 8 * 1024 * 1024;

const LARGE_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const LARGE_LOAD_ATTEMPTS: u32 = 3;

const MAX_CONCURRENT_CHUNK_FETCHES: usize = 4;

const CHUNK_READAHEAD: u64 = 3;

const SIZE_UNKNOWN: u64 = u64::MAX;

#[derive(Clone)]
pub struct Entry {
    pub record: FileRecord,
    pub meta: FileMeta,
    pub file_key: Option<FileKey>,
    pub content: ContentKey,
    pub node_ref: Option<String>,
    pub readable: bool,
    learned_size: Arc<AtomicU64>,
}

impl Entry {
    fn new(record: FileRecord, meta: FileMeta, file_key: Option<FileKey>) -> Self {
        let content = file_key.as_ref().map(|k| k.content_key()).unwrap_or(ContentKey { key: Zeroizing::new(Vec::new()), format: FileFormat::Legacy });
        let node_ref = file_key.as_ref().map(|k| k.node_ref());
        Self { record, meta, file_key, content, node_ref, readable: true, learned_size: Arc::new(AtomicU64::new(SIZE_UNKNOWN)) }
    }

    fn unreadable(record: FileRecord, file_key: Option<FileKey>) -> Self {
        let mut e = Self::new(record, FileMeta::unreadable(), file_key);
        e.readable = false;
        e
    }

    pub fn is_folder(&self) -> bool {
        self.meta.is_folder
    }

    pub fn is_v2(&self) -> bool {
        self.file_key.as_ref().map(|k| k.is_v2()).unwrap_or(false)
    }

    pub fn is_legacy(&self) -> bool {
        self.file_key.as_ref().map(|k| !k.is_v2()).unwrap_or(false)
    }

    pub fn name(&self) -> &str {
        &self.meta.name
    }

    fn stored_size(&self) -> u64 {
        self.meta.size.or(self.meta.unpadded_size).unwrap_or_else(|| self.record.size.unwrap_or(0))
    }

    pub fn size(&self) -> u64 {
        if self.meta.size.is_some() {
            return self.stored_size();
        }
        if self.meta.compressed {
            let n = self.learned_size.load(Ordering::Acquire);
            if n != SIZE_UNKNOWN {
                return n;
            }
        }
        self.stored_size()
    }

    pub fn size_is_exact(&self) -> bool {
        self.meta.size.is_some() || !self.meta.compressed || self.learned_size.load(Ordering::Acquire) != SIZE_UNKNOWN
    }

    fn learn_size(&self, plain_len: u64) {
        if self.meta.compressed {
            self.learned_size.store(plain_len, Ordering::Release);
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChildInfo {
    pub id: String,
    pub name: String,
    pub is_folder: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub is_folder: bool,
    pub size: u64,
    pub size_is_exact: bool,
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

fn lock_plain<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub const UNRESOLVED_PARENT: &str = "\u{0}unresolved";

struct VaultIndex {
    entries: HashMap<String, Arc<Entry>>,
    children_by_parent: HashMap<String, Vec<String>>,
    name_index: HashMap<String, HashMap<String, String>>,
    placed: HashMap<String, String>,
    folders_by_ref: HashMap<String, BTreeSet<String>>,
    folders_by_from: HashMap<String, BTreeSet<String>>,
    dependents: HashMap<String, BTreeSet<String>>,
}

impl VaultIndex {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            children_by_parent: HashMap::new(),
            name_index: HashMap::new(),
            placed: HashMap::new(),
            folders_by_ref: HashMap::new(),
            folders_by_from: HashMap::new(),
            dependents: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn resolve(&self, entry: &Entry) -> String {
        let declared = entry.meta.parent_id.as_deref();
        if !entry.is_v2() {
            return parent_key(declared).to_string();
        }
        let Some(declared) = declared else { return String::new() };
        let Some(pref) = entry.meta.pref.as_deref() else { return UNRESOLVED_PARENT.to_string() };
        let me = entry.record.id.as_str();
        let pick = |set: Option<&BTreeSet<String>>| -> Option<String> {
            let set = set?;
            if set.contains(declared) && declared != me {
                return Some(declared.to_string());
            }
            set.iter().find(|id| id.as_str() != me).cloned()
        };
        pick(self.folders_by_ref.get(pref)).or_else(|| pick(self.folders_by_from.get(pref))).unwrap_or_else(|| UNRESOLVED_PARENT.to_string())
    }

    fn attach(&mut self, id: &str) {
        let Some(entry) = self.entries.get(id).cloned() else { return };
        let pk = self.resolve(&entry);
        self.name_index.entry(pk.clone()).or_default().entry(entry.name().to_string()).or_insert_with(|| id.to_string());
        self.children_by_parent.entry(pk.clone()).or_default().push(id.to_string());
        self.placed.insert(id.to_string(), pk);
    }

    fn detach(&mut self, id: &str) {
        let Some(pk) = self.placed.remove(id) else { return };
        let name = self.entries.get(id).map(|e| e.name().to_string()).unwrap_or_default();
        if let Some(v) = self.children_by_parent.get_mut(&pk) {
            if let Some(pos) = v.iter().position(|x| x == id) {
                v.swap_remove(pos);
            }
        }
        let owned_name_slot = self.name_index.get(&pk).and_then(|m| m.get(&name)).map(|cur| cur == id).unwrap_or(false);
        if owned_name_slot {
            if let Some(m) = self.name_index.get_mut(&pk) {
                m.remove(&name);
            }
            let replacement = self.children_by_parent.get(&pk).and_then(|sibs| sibs.iter().find(|sid| self.entries.get(*sid).map(|e| e.name() == name).unwrap_or(false)).cloned());
            if let Some(rid) = replacement {
                self.name_index.entry(pk).or_default().insert(name, rid);
            }
        }
    }

    fn reattach_dependents(&mut self, keys: &[Option<String>]) {
        let mut ids = BTreeSet::new();
        for key in keys.iter().flatten() {
            if let Some(d) = self.dependents.get(key) {
                ids.extend(d.iter().cloned());
            }
        }
        for id in ids {
            if self.entries.contains_key(&id) {
                self.detach(&id);
                self.attach(&id);
            }
        }
    }

    fn folder_keys(entry: &Entry) -> [Option<String>; 2] {
        if !entry.is_folder() {
            return [None, None];
        }
        let from = if entry.is_v2() { entry.meta.from.clone() } else { None };
        [entry.node_ref.clone(), from]
    }

    fn insert(&mut self, entry: Entry) -> Option<Arc<Entry>> {
        if self.entries.contains_key(&entry.record.id) {
            return None;
        }
        let id = entry.record.id.clone();
        let [node_ref, from] = Self::folder_keys(&entry);
        if let Some(r) = &node_ref {
            self.folders_by_ref.entry(r.clone()).or_default().insert(id.clone());
        }
        if let Some(f) = &from {
            self.folders_by_from.entry(f.clone()).or_default().insert(id.clone());
        }
        if entry.is_v2() {
            if let Some(pref) = &entry.meta.pref {
                self.dependents.entry(pref.clone()).or_default().insert(id.clone());
            }
        }
        let entry = Arc::new(entry);
        self.entries.insert(id.clone(), Arc::clone(&entry));
        self.attach(&id);
        if node_ref.is_some() || from.is_some() {
            self.reattach_dependents(&[node_ref, from]);
        }
        Some(entry)
    }

    fn remove(&mut self, id: &str) -> Option<Arc<Entry>> {
        self.detach(id);
        let entry = self.entries.remove(id)?;
        let [node_ref, from] = Self::folder_keys(&entry);
        let unregister = |map: &mut HashMap<String, BTreeSet<String>>, key: &Option<String>| {
            if let Some(k) = key {
                if let Some(set) = map.get_mut(k) {
                    set.remove(id);
                    if set.is_empty() {
                        map.remove(k);
                    }
                }
            }
        };
        unregister(&mut self.folders_by_ref, &node_ref);
        unregister(&mut self.folders_by_from, &from);
        unregister(&mut self.dependents, &entry.meta.pref);
        if node_ref.is_some() || from.is_some() {
            self.reattach_dependents(&[node_ref, from]);
        }
        Some(entry)
    }

    fn parent_of(&self, id: &str) -> Option<Option<String>> {
        let pk = self.placed.get(id)?;
        Some(if pk.is_empty() { None } else { Some(pk.clone()) })
    }
}

type SharedPlaintext = Arc<Zeroizing<Vec<u8>>>;

struct ContentCache {
    entries: HashMap<String, (SharedPlaintext, u64)>,
    order: BTreeMap<u64, String>,
    next_stamp: u64,
    total_bytes: u64,
}

impl ContentCache {
    fn new() -> Self {
        Self { entries: HashMap::new(), order: BTreeMap::new(), next_stamp: 0, total_bytes: 0 }
    }

    fn stamp(&mut self) -> u64 {
        self.next_stamp += 1;
        self.next_stamp
    }

    fn get(&mut self, id: &str) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let new_stamp = self.next_stamp + 1;
        let (data, stamp) = self.entries.get_mut(id)?;
        let old = std::mem::replace(stamp, new_stamp);
        let data = Arc::clone(data);
        self.next_stamp = new_stamp;
        if let Some(key) = self.order.remove(&old) {
            self.order.insert(new_stamp, key);
        }
        Some(data)
    }

    fn insert(&mut self, id: String, bytes: Arc<Zeroizing<Vec<u8>>>) {
        let size = bytes.len() as u64;
        if size > CONTENT_CACHE_MAX_ENTRY_BYTES {
            return;
        }
        self.remove(&id);
        let stamp = self.stamp();
        self.total_bytes += size;
        self.entries.insert(id.clone(), (bytes, stamp));
        self.order.insert(stamp, id);
        while self.total_bytes > CONTENT_CACHE_MAX_BYTES {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            if let Some((evicted, _)) = self.entries.remove(&oldest) {
                self.total_bytes -= evicted.len() as u64;
            }
        }
    }

    fn rekey(&mut self, old_id: &str, new_id: &str) {
        if let Some((bytes, stamp)) = self.entries.remove(old_id) {
            self.order.remove(&stamp);
            let stamp = self.stamp();
            self.entries.insert(new_id.to_string(), (bytes, stamp));
            self.order.insert(stamp, new_id.to_string());
        }
    }

    fn remove(&mut self, id: &str) {
        if let Some((evicted, stamp)) = self.entries.remove(id) {
            self.total_bytes -= evicted.len() as u64;
            self.order.remove(&stamp);
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

struct Slots {
    free: Mutex<usize>,
    changed: Condvar,
}

struct SlotGuard<'a>(&'a Slots);

impl Slots {
    fn new(n: usize) -> Self {
        Self { free: Mutex::new(n), changed: Condvar::new() }
    }

    fn acquire(&self) -> SlotGuard<'_> {
        let mut free = lock_plain(&self.free);
        while *free == 0 {
            free = self.changed.wait(free).unwrap_or_else(|p| p.into_inner());
        }
        *free -= 1;
        SlotGuard(self)
    }
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        *lock_plain(&self.0.free) += 1;
        self.0.changed.notify_one();
    }
}

const CHUNK_MISSING: u8 = 0;
const CHUNK_LOADING: u8 = 1;
const CHUNK_READY: u8 = 2;

struct ChunkedSource {
    api: Arc<ApiClient>,
    id: String,
    content: ContentKey,
    prefix: Vec<u8>,
    chunk_size: u64,
    count: u64,
    sealed_total: u64,
    scratch: Mutex<Scratch>,
    states: Mutex<Vec<u8>>,
    changed: Condvar,
    resident: AtomicU64,
    slots: Arc<Slots>,
}

enum Backing {
    Whole(Mutex<Scratch>),
    Chunked(ChunkedSource),
}

pub struct LargeFile {
    len: u64,
    backing: Backing,
}

fn other_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn is_transient_io(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::InvalidData && e.to_string() == AUTH_FAILED {
        return false;
    }
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::TimedOut | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected
    )
}

fn read_scratch(scratch: &Mutex<Scratch>, offset: u64, want: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; want];
    let mut s = lock_plain(scratch);
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

impl LargeFile {
    fn whole(scratch: Scratch, len: u64) -> Self {
        Self { len, backing: Backing::Whole(Mutex::new(scratch)) }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn resident_bytes(&self) -> u64 {
        match &self.backing {
            Backing::Whole(_) => self.len,
            Backing::Chunked(c) => c.resident.load(Ordering::Relaxed),
        }
    }

    fn clamp(&self, offset: u64, len: usize) -> usize {
        if offset >= self.len || len == 0 {
            0
        } else {
            len.min((self.len - offset) as usize)
        }
    }

    pub fn read_at(self: &Arc<Self>, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let want = self.clamp(offset, len);
        if want == 0 {
            return Ok(Vec::new());
        }
        match &self.backing {
            Backing::Whole(s) => read_scratch(s, offset, want),
            Backing::Chunked(c) => {
                let first = offset / c.chunk_size;
                let last = (offset + want as u64 - 1) / c.chunk_size;
                for i in first..=last {
                    c.ensure(i, self.len)?;
                }
                let end_in_chunk = (offset + want as u64 - 1) % c.chunk_size;
                if end_in_chunk >= c.chunk_size / 8 {
                    for next in last + 1..=(last + CHUNK_READAHEAD).min(c.count - 1) {
                        if c.state(next) == CHUNK_MISSING {
                            let me = Arc::clone(self);
                            std::thread::spawn(move || {
                                if let Backing::Chunked(c) = &me.backing {
                                    if let Err(e) = c.ensure(next, me.len) {
                                        log::debug!("[lethean-cli] read-ahead of chunk {next} failed: {e}");
                                    }
                                }
                            });
                        }
                    }
                }
                read_scratch(&c.scratch, offset, want)
            }
        }
    }

    pub fn read_if_resident(&self, offset: u64, len: usize) -> Option<io::Result<Vec<u8>>> {
        let want = self.clamp(offset, len);
        if want == 0 {
            return Some(Ok(Vec::new()));
        }
        match &self.backing {
            Backing::Whole(s) => Some(read_scratch(s, offset, want)),
            Backing::Chunked(c) => {
                let first = offset / c.chunk_size;
                let last = (offset + want as u64 - 1) / c.chunk_size;
                if (first..=last).all(|i| c.state(i) == CHUNK_READY) {
                    Some(read_scratch(&c.scratch, offset, want))
                } else {
                    None
                }
            }
        }
    }
}

struct LoadingReset<'a> {
    src: &'a ChunkedSource,
    index: usize,
    done: bool,
}

impl Drop for LoadingReset<'_> {
    fn drop(&mut self) {
        let mut st = lock_plain(&self.src.states);
        st[self.index] = if self.done { CHUNK_READY } else { CHUNK_MISSING };
        drop(st);
        self.src.changed.notify_all();
    }
}

impl ChunkedSource {
    fn state(&self, i: u64) -> u8 {
        lock_plain(&self.states).get(i as usize).copied().unwrap_or(CHUNK_READY)
    }

    fn ensure(&self, i: u64, file_len: u64) -> io::Result<()> {
        let index = i as usize;
        {
            let mut st = lock_plain(&self.states);
            loop {
                match st.get(index).copied() {
                    None | Some(CHUNK_READY) => return Ok(()),
                    Some(CHUNK_LOADING) => st = self.changed.wait(st).unwrap_or_else(|p| p.into_inner()),
                    Some(_) => {
                        st[index] = CHUNK_LOADING;
                        break;
                    }
                }
            }
        }
        let mut reset = LoadingReset { src: self, index, done: false };
        let take = (file_len - i * self.chunk_size).min(self.chunk_size);
        let _slot = self.slots.acquire();
        let mut last_err = None;
        for attempt in 0..LARGE_LOAD_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500 * (1 << attempt)));
            }
            match self.fetch(i, take) {
                Ok(()) => {
                    self.resident.fetch_add(take, Ordering::Relaxed);
                    reset.done = true;
                    return Ok(());
                }
                Err(e) if is_transient_io(&e) => {
                    log::warn!("[lethean-cli] download of chunk {i} was interrupted ({e}); retrying");
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.expect("loop ran at least once"))
    }

    fn fetch(&self, i: u64, take: u64) -> io::Result<()> {
        let sealed = self.chunk_size + chunked::TAG_LEN;
        let start = i * sealed;
        let (body, total) = self.api.open_blob_range(&self.id, start, start + sealed - 1).map_err(|e| other_io(format!("{e:#}")))?;
        if total != self.sealed_total {
            return Err(io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED));
        }
        let nonce = chunked::nonce_for(&self.prefix, i)?;
        let aad = chunked::aad_for(self.content.format, i, i == self.count - 1);
        let mut dec = GcmDecryptReader::with_aad(body, &self.content.key, &nonce, &aad).map_err(other_io)?;
        let base = i * self.chunk_size;
        let mut buf = Zeroizing::new(vec![0u8; 256 * 1024]);
        let mut got = 0u64;
        loop {
            let n = chunked::read_full(&mut dec, &mut buf)?;
            if n == 0 {
                break;
            }
            let keep = take.saturating_sub(got).min(n as u64) as usize;
            if keep > 0 {
                lock_plain(&self.scratch).write_at(base + got, &buf[..keep])?;
            }
            chunked::check_filler(self.content.format, &buf[keep..n])?;
            got += n as u64;
        }
        if got != self.chunk_size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk ended early"));
        }
        Ok(())
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
        if self.order.back().map(|k| k == id).unwrap_or(false) {
            return;
        }
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

    fn enforce(&mut self) {
        self.total_bytes = self.map.values().map(|f| f.resident_bytes()).sum();
        while self.total_bytes > self.max_bytes && self.order.len() > 1 {
            if let Some(old) = self.order.pop_front() {
                if let Some(f) = self.map.remove(&old) {
                    self.total_bytes -= f.resident_bytes().min(self.total_bytes);
                }
            }
        }
    }

    fn insert(&mut self, id: &str, file: Arc<LargeFile>) {
        self.remove(id);
        self.map.insert(id.to_string(), file);
        self.order.push_back(id.to_string());
        self.enforce();
    }

    fn remove(&mut self, id: &str) {
        if let Some(f) = self.map.remove(id) {
            self.total_bytes -= f.resident_bytes().min(self.total_bytes);
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

#[derive(Clone)]
pub struct Quarantined {
    pub record: FileRecord,
    pub file_key: FileKey,
}

pub struct Vault {
    pub api: Arc<ApiClient>,
    wrapping_key_raw: RwLock<Zeroizing<Vec<u8>>>,
    index: RwLock<VaultIndex>,
    strict: std::sync::atomic::AtomicBool,
    quarantined: RwLock<Vec<Quarantined>>,
    content_cache: Mutex<ContentCache>,
    large_cache: Mutex<LargeCache>,
    loading: Mutex<HashSet<String>>,
    load_done: Condvar,
    pool: Arc<ScratchPool>,
    chunk_slots: Arc<Slots>,
}

#[derive(Clone, Copy, Debug)]
pub struct ReadInfo {
    pub size: u64,
    pub large: bool,
}

#[allow(clippy::large_enum_variant)]
enum Decoded {
    Entry(Entry),
    Quarantined(Quarantined),
}

impl Vault {
    pub fn new(api: ApiClient, wrapping_key_raw: Vec<u8>) -> Self {
        Self {
            api: Arc::new(api),
            wrapping_key_raw: RwLock::new(Zeroizing::new(wrapping_key_raw)),
            index: RwLock::new(VaultIndex::new()),
            strict: std::sync::atomic::AtomicBool::new(false),
            quarantined: RwLock::new(Vec::new()),
            content_cache: Mutex::new(ContentCache::new()),
            large_cache: Mutex::new(LargeCache::new(LARGE_CACHE_MAX_BYTES)),
            loading: Mutex::new(HashSet::new()),
            load_done: Condvar::new(),
            pool: ScratchPool::new(DEFAULT_POOL_BYTES, scratch::default_dir()),
            chunk_slots: Arc::new(Slots::new(MAX_CONCURRENT_CHUNK_FETCHES)),
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
        write_lock(&self.quarantined).clear();
        lock_cache(&self.content_cache).wipe();
        lock_large(&self.large_cache).wipe();
    }

    pub fn set_strict(&self, strict: bool) {
        self.strict.store(strict, Ordering::Release);
    }

    pub fn is_strict(&self) -> bool {
        self.strict.load(Ordering::Acquire)
    }

    fn decode_record(wrapping_key: &[u8], mut record: FileRecord, strict: bool) -> Decoded {
        let file_key = match aead::unwrap_file_key(wrapping_key, &record.wrapped_file_key, &record.wrap_iv) {
            Ok(k) => k,
            Err(_) => return Decoded::Entry(Entry::unreadable(Self::scrub(record), None)),
        };
        if strict && !file_key.is_v2() {
            return Decoded::Quarantined(Quarantined { record, file_key });
        }
        match aead::decrypt_metadata(&file_key, &record.encrypted_metadata, &record.metadata_iv) {
            Ok(meta) => {
                record = Self::scrub(record);
                Decoded::Entry(Entry::new(record, meta, Some(file_key)))
            }
            Err(_) => Decoded::Entry(Entry::unreadable(Self::scrub(record), Some(file_key))),
        }
    }

    fn scrub(mut record: FileRecord) -> FileRecord {
        record.encrypted_metadata = String::new();
        record.metadata_iv = String::new();
        record
    }

    fn ingest_record(&self, record: FileRecord) -> Option<Arc<Entry>> {
        match Self::decode_record(&self.wrapping_key(), record, self.is_strict()) {
            Decoded::Entry(entry) => write_lock(&self.index).insert(entry),
            Decoded::Quarantined(q) => {
                write_lock(&self.quarantined).push(q);
                None
            }
        }
    }

    pub fn refresh_all(&self) -> Result<()> {
        let wrapping_key = self.wrapping_key();
        let strict = self.is_strict();
        let mut fresh = VaultIndex::new();
        let mut quarantined = Vec::new();
        let mut offset = 0u64;
        let mut add = |fresh: &mut VaultIndex, d: Decoded| match d {
            Decoded::Entry(e) => {
                fresh.insert(e);
            }
            Decoded::Quarantined(q) => quarantined.push(q),
        };

        let first = self.api.list_files(0, Some(PAGE_SIZE))?;
        let mut last_page_full = first.len() as u64 >= PAGE_SIZE;
        offset += first.len() as u64;
        for record in first {
            add(&mut fresh, Self::decode_record(&wrapping_key, record, strict));
        }
        let expected = if last_page_full { self.api.get_usage(None).ok().map(|u| u.file_count).unwrap_or(0) } else { 0 };
        let pages = expected.div_ceil(PAGE_SIZE);
        if pages > 1 {
            let next_page = AtomicU64::new(1);
            let results: Mutex<Vec<(u64, Result<Vec<Decoded>>)>> = Mutex::new(Vec::new());
            std::thread::scope(|s| {
                for _ in 0..REFRESH_PARALLELISM.min(pages as usize - 1) {
                    s.spawn(|| loop {
                        let page = next_page.fetch_add(1, Ordering::Relaxed);
                        if page >= pages {
                            break;
                        }
                        let result = self.api.list_files(page * PAGE_SIZE, Some(PAGE_SIZE)).map(|records| records.into_iter().map(|r| Self::decode_record(&wrapping_key, r, strict)).collect::<Vec<_>>());
                        let failed = result.is_err();
                        lock_plain(&results).push((page, result));
                        if failed {
                            break;
                        }
                    });
                }
            });
            let mut results = results.into_inner().unwrap_or_else(|p| p.into_inner());
            results.sort_by_key(|(page, _)| *page);
            for (_, result) in results {
                let entries = result?;
                last_page_full = entries.len() as u64 == PAGE_SIZE;
                offset += entries.len() as u64;
                for e in entries {
                    add(&mut fresh, e);
                }
                if !last_page_full {
                    break;
                }
            }
        }

        while last_page_full {
            let page = self.api.list_files(offset, Some(PAGE_SIZE))?;
            let got = page.len() as u64;
            for record in page {
                add(&mut fresh, Self::decode_record(&wrapping_key, record, strict));
            }
            last_page_full = got >= PAGE_SIZE;
            offset += got;
        }

        *write_lock(&self.index) = fresh;
        *write_lock(&self.quarantined) = quarantined;
        Ok(())
    }

    pub fn legacy_entries(&self) -> Vec<Entry> {
        read_lock(&self.index).entries.values().filter(|e| e.is_legacy()).map(|e| (**e).clone()).collect()
    }

    pub fn quarantined_count(&self) -> usize {
        read_lock(&self.quarantined).len()
    }

    pub fn admit_quarantined(&self) {
        let items = std::mem::take(&mut *write_lock(&self.quarantined));
        let mut index = write_lock(&self.index);
        for q in items {
            let entry = match aead::decrypt_metadata(&q.file_key, &q.record.encrypted_metadata, &q.record.metadata_iv) {
                Ok(meta) => Entry::new(Self::scrub(q.record), meta, Some(q.file_key)),
                Err(_) => Entry::unreadable(Self::scrub(q.record), Some(q.file_key)),
            };
            index.insert(entry);
        }
    }

    pub fn plaintext_to_scratch(&self, id: &str) -> Result<(Arc<Mutex<Scratch>>, u64)> {
        let mut scratch = self.pool.new_scratch();
        let n = self.stream_plaintext(id, &mut ScratchWriter::new(&mut scratch))?;
        Ok((Arc::new(Mutex::new(scratch)), n))
    }

    pub fn verify_record(&self, id: &str) -> Result<()> {
        let entry = self.entry(id).context("record vanished")?;
        if !entry.readable || entry.content.is_empty() {
            bail!("record could not be decrypted");
        }
        if entry.is_folder() {
            let ct = self.api.download_content(id)?;
            let pt = aead::decrypt_content_owned(&entry.content, &entry.record.content_iv, ct, &entry.meta)?;
            if !pt.is_empty() {
                bail!("folder has content");
            }
            return Ok(());
        }
        let n = self.stream_decrypted(&entry, &mut io::sink())?;
        if let Some(size) = entry.meta.size {
            if n != size {
                bail!("record did not read back completely");
            }
        }
        Ok(())
    }

    pub fn parent_of(&self, id: &str) -> Option<Option<String>> {
        read_lock(&self.index).parent_of(id)
    }

    pub fn parent_ref(&self, folder_id: Option<&str>) -> Result<Option<ParentRef>> {
        let Some(id) = folder_id else { return Ok(None) };
        let index = read_lock(&self.index);
        let entry = index.entries.get(id).context("that folder isn't in the vault (refresh and try again)")?;
        if !entry.is_folder() {
            bail!("not a folder");
        }
        let node_ref = entry.node_ref.clone().context("that folder couldn't be decrypted")?;
        Ok(Some(ParentRef { id: id.to_string(), node_ref }))
    }

    pub fn get(&self, id: &str) -> Option<Entry> {
        read_lock(&self.index).entries.get(id).map(|e| (**e).clone())
    }

    pub fn entry(&self, id: &str) -> Option<Arc<Entry>> {
        read_lock(&self.index).entries.get(id).cloned()
    }

    pub fn stat(&self, id: &str) -> Option<Stat> {
        let index = read_lock(&self.index);
        let e = index.entries.get(id)?;
        Some(Stat { is_folder: e.is_folder(), size: e.size(), size_is_exact: e.size_is_exact() })
    }

    pub fn entry_count(&self) -> usize {
        read_lock(&self.index).entries.len()
    }

    pub fn all_entries(&self) -> Vec<Entry> {
        read_lock(&self.index).entries.values().map(|e| (**e).clone()).collect()
    }

    pub fn children_of(&self, parent_id: Option<&str>) -> Vec<Entry> {
        let index = read_lock(&self.index);
        let mut kids: Vec<Entry> = match index.children_by_parent.get(parent_key(parent_id)) {
            Some(ids) => ids.iter().filter_map(|id| index.entries.get(id).map(|e| (**e).clone())).collect(),
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

    pub fn find_child(&self, parent_id: Option<&str>, name: &str) -> Option<Arc<Entry>> {
        let index = read_lock(&self.index);
        let id = index.name_index.get(parent_key(parent_id))?.get(name)?;
        index.entries.get(id).cloned()
    }

    pub fn find_child_by_name(&self, parent_id: Option<&str>, name: &str) -> Option<Entry> {
        self.find_child(parent_id, name).map(|e| (*e).clone())
    }

    pub fn list_children(&self, parent_id: Option<&str>) -> Vec<ChildInfo> {
        let index = read_lock(&self.index);
        let mut kids: Vec<ChildInfo> = match index.children_by_parent.get(parent_key(parent_id)) {
            Some(ids) => ids.iter().filter_map(|id| index.entries.get(id).map(|e| ChildInfo { id: id.clone(), name: e.name().to_string(), is_folder: e.is_folder() })).collect(),
            None => Vec::new(),
        };
        drop(index);
        kids.sort_unstable_by(|a, b| match (a.is_folder, b.is_folder) {
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

    pub fn create_file_streaming<'a, F>(&self, name: &str, mime: &str, size: u64, parent_id: Option<&str>, factory: F) -> Result<Entry>
    where
        F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
    {
        self.create_file_streaming_ext(name, mime, size, parent_id, None, factory)
    }

    pub fn create_file_streaming_ext<'a, F>(&self, name: &str, mime: &str, size: u64, parent_id: Option<&str>, from: Option<&str>, mut factory: F) -> Result<Entry>
    where
        F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
    {
        let wrapping_key = self.wrapping_key();
        let parent = self.parent_ref(parent_id)?;
        let parent = parent.as_ref();

        if size < STREAM_THRESHOLD {
            let mut buf = Zeroizing::new(Vec::with_capacity(size as usize));
            let mut reader = factory().context("could not read the file to upload")?;
            reader.by_ref().take(size).read_to_end(&mut buf).context("could not read the file to upload")?;
            if buf.len() as u64 != size {
                bail!("the file changed while it was being uploaded (expected {size} bytes, read {})", buf.len());
            }
            drop(reader);
            let payload = aead::encrypt_file_ext(&wrapping_key, name, mime, &buf, parent, from)?;
            let record = self.api.upload_file(&payload, None, None).context("upload failed")?;
            drop(payload);
            let id = record.id.clone();
            if let Some(entry) = self.ingest_record(record) {
                entry.learn_size(buf.len() as u64);
            }
            lock_cache(&self.content_cache).insert(id.clone(), Arc::new(buf));
            return self.get(&id).context("upload succeeded but the new entry vanished (likely deleted concurrently)");
        }

        if size > CHUNK_SIZE {
            let plan = chunked::plan_chunked_upload(&wrapping_key, name, mime, size, parent, from)?;
            let record = self
                .api
                .upload_in_parts(
                    &plan.header,
                    plan.body_len(),
                    || {
                        let src = factory()?;
                        let body: Box<dyn Read + 'a> = Box::new(ChunkedEncryptReader::new(src, &plan.content_key, &plan.prefix, size));
                        Ok(body)
                    },
                    None,
                    None,
                )
                .context("upload failed")?;
            let id = record.id.clone();
            self.ingest_record(record);
            return self.get(&id).context("upload succeeded but the new entry vanished (likely deleted concurrently)");
        }

        let plan = aead::plan_stream_upload(&wrapping_key, name, mime, size, parent, from)?;
        let record = self
            .api
            .upload_stream(
                &plan.header,
                plan.body_len(),
                || {
                    let src = factory()?;
                    let enc = GcmEncryptReader::with_aad(src, &plan.content_key.key, &plan.iv, plan.content_key.single_aad(), size, plan.padded_len).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:#}")))?;
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
        self.create_folder_ext(name, parent_id, None)
    }

    pub fn create_folder_ext(&self, name: &str, parent_id: Option<&str>, from: Option<&str>) -> Result<Entry> {
        let wrapping_key = self.wrapping_key();
        let parent = self.parent_ref(parent_id)?;
        let payload = aead::encrypt_folder_ext(&wrapping_key, name, parent.as_ref(), from)?;
        let record = self.api.upload_file(&payload, None, None).context("folder creation failed")?;
        let id = record.id.clone();
        self.ingest_record(record);
        self.get(&id).context("folder creation succeeded but the new entry vanished (likely deleted concurrently)")
    }

    pub fn delete_one(&self, id: &str) -> Result<()> {
        self.api.delete_file(id, None)?;
        write_lock(&self.index).remove(id);
        lock_cache(&self.content_cache).remove(id);
        lock_large(&self.large_cache).remove(id);
        Ok(())
    }


    fn is_large(entry: &Entry) -> bool {
        entry.meta.chunk_size.is_some() || entry.stored_size().max(entry.record.size.unwrap_or(0)) > IN_MEMORY_READ_MAX
    }

    fn stream_decrypted(&self, entry: &Entry, w: &mut dyn Write) -> Result<u64> {
        if entry.content.is_empty() {
            bail!("\"{}\" could not be decrypted (wrong vault password, or a corrupted item)", entry.name());
        }
        let iv = aead::from_base64(&entry.record.content_iv)?;
        if let Some(chunk_size) = entry.meta.chunk_size {
            let true_size = entry.meta.unpadded_size.context("chunked file without a size in its metadata")?;
            let (body, _len) = self.api.open_blob(&entry.record.id)?;
            return Ok(chunked::decrypt_chunked(body, &entry.content, &iv, chunk_size, true_size, w)?);
        }
        let (body, _len) = self.api.open_blob(&entry.record.id)?;
        let mut dec = GcmDecryptReader::with_aad(body, &entry.content.key, &iv, entry.content.single_aad())?;
        if entry.content.format == FileFormat::V2 {
            let written = stream_v2_single(&mut dec, &entry.meta, w)?;
            entry.learn_size(written);
            return Ok(written);
        }
        let limit = entry.meta.unpadded_size.unwrap_or(u64::MAX);

        let written = if entry.meta.compressed {
            let mut gz = flate2::read::GzDecoder::new((&mut dec).take(limit));
            copy_in_blocks(&mut gz, w)?
        } else {
            copy_in_blocks(&mut (&mut dec).take(limit), w)?
        };
        io::copy(&mut dec, &mut io::sink())?;
        entry.learn_size(written);
        Ok(written)
    }

    fn download_large(&self, entry: &Entry) -> Result<Arc<LargeFile>> {
        let mut last_err = None;
        for attempt in 0..LARGE_LOAD_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500 * (1 << attempt)));
            }
            let mut scratch = self.pool.new_scratch();
            let result = self.stream_decrypted(entry, &mut ScratchWriter::new(&mut scratch));
            match result {
                Ok(_) => {
                    let len = scratch.len();
                    return Ok(Arc::new(LargeFile::whole(scratch, len)));
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

    fn open_chunked(&self, entry: &Entry, chunk_size: u64) -> Result<Arc<LargeFile>> {
        if entry.content.is_empty() {
            bail!("\"{}\" could not be decrypted (wrong vault password, or a corrupted item)", entry.name());
        }
        if !(chunked::MIN_CHUNK..=chunked::MAX_CHUNK).contains(&chunk_size) {
            bail!("unsupported chunk size {chunk_size}");
        }
        let true_size = entry.meta.unpadded_size.context("chunked file without a size in its metadata")?;
        let prefix = aead::from_base64(&entry.record.content_iv)?;
        if prefix.len() != chunked::PREFIX_LEN {
            bail!("chunked file has a {}-byte nonce prefix, expected {}", prefix.len(), chunked::PREFIX_LEN);
        }
        let count = chunked::chunk_count(true_size, chunk_size);
        let mut scratch = self.pool.new_scratch();
        scratch.set_len(true_size)?;
        Ok(Arc::new(LargeFile {
            len: true_size,
            backing: Backing::Chunked(ChunkedSource {
                api: Arc::clone(&self.api),
                id: entry.record.id.clone(),
                content: entry.content.clone(),
                prefix,
                chunk_size,
                count,
                sealed_total: chunked::sealed_len(true_size, chunk_size),
                scratch: Mutex::new(scratch),
                states: Mutex::new(vec![CHUNK_MISSING; count as usize]),
                changed: Condvar::new(),
                resident: AtomicU64::new(0),
                slots: Arc::clone(&self.chunk_slots),
            }),
        }))
    }

    fn single_flight<T>(&self, id: &str, cached: impl Fn() -> Option<T>, work: impl FnOnce() -> Result<T>) -> Result<T> {
        loop {
            if let Some(v) = cached() {
                return Ok(v);
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
            if let Some(v) = cached() {
                return Ok(v);
            }
            return work();
        }
    }

    pub fn load_large(&self, id: &str) -> Result<Arc<LargeFile>> {
        self.single_flight(
            id,
            || lock_large(&self.large_cache).get(id),
            || {
                let entry = self.entry(id).context("unknown file")?;
                if entry.is_folder() {
                    bail!("cannot read a folder's content");
                }
                let file = match entry.meta.chunk_size {
                    Some(cs) if self.api.supports_ranges(id).unwrap_or(false) => self.open_chunked(&entry, cs)?,
                    _ => self.download_large(&entry)?,
                };
                if self.entry(id).is_some() {
                    lock_large(&self.large_cache).insert(id, Arc::clone(&file));
                }
                Ok(file)
            },
        )
    }

    pub fn read_large(&self, file: &Arc<LargeFile>, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let before = file.resident_bytes();
        let out = file.read_at(offset, len)?;
        if file.resident_bytes() != before {
            lock_large(&self.large_cache).enforce();
        }
        Ok(out)
    }

    pub fn read_range(&self, id: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let entry = self.entry(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }
        if Self::is_large(&entry) {
            let f = self.load_large(id)?;
            return Ok(self.read_large(&f, offset, len)?);
        }
        let data = self.download_arc(id)?;
        Ok(slice_of(&data, offset, len))
    }

    pub fn try_read_cached(&self, id: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        if let Some(data) = lock_cache(&self.content_cache).get(id) {
            return Some(slice_of(&data, offset, len));
        }
        let f = lock_large(&self.large_cache).get(id)?;
        f.read_if_resident(offset, len)?.ok()
    }

    pub fn cached_small(&self, id: &str) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        lock_cache(&self.content_cache).get(id)
    }

    pub fn download_arc(&self, id: &str) -> Result<Arc<Zeroizing<Vec<u8>>>> {
        if let Some(cached) = lock_cache(&self.content_cache).get(id) {
            return Ok(cached);
        }

        let entry = self.entry(id).context("unknown file")?;
        if entry.is_folder() {
            bail!("cannot read a folder's content");
        }

        if Self::is_large(&entry) {
            let mut out = Zeroizing::new(Vec::with_capacity(entry.size() as usize));
            self.stream_decrypted(&entry, &mut *out)?;
            return Ok(Arc::new(out));
        }

        self.single_flight(
            id,
            || lock_cache(&self.content_cache).get(id),
            || {
                let ciphertext = self.api.download_content(id)?;
                if entry.content.is_empty() {
                    bail!("\"{}\" could not be decrypted (wrong vault password, or a corrupted item)", entry.name());
                }
                let bytes = aead::decrypt_content_owned(&entry.content, &entry.record.content_iv, ciphertext, &entry.meta)?;
                entry.learn_size(bytes.len() as u64);
                let shared = Arc::new(Zeroizing::new(bytes));
                lock_cache(&self.content_cache).insert(id.to_string(), Arc::clone(&shared));
                Ok(shared)
            },
        )
    }

    pub fn download_decrypted(&self, id: &str) -> Result<Vec<u8>> {
        Ok(self.download_arc(id)?.to_vec())
    }

    pub fn stream_plaintext(&self, id: &str, w: &mut dyn Write) -> Result<u64> {
        let entry = self.entry(id).context("unknown file")?;
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
                let part = self.read_large(&f, pos, 1024 * 1024)?;
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
        let parent = match self.parent_of(id) {
            Some(Some(p)) if p == UNRESOLVED_PARENT => bail!("this file's folder couldn't be verified, so it can't be saved there"),
            Some(p) => p,
            None => bail!("unknown file"),
        };
        let new_entry = self.create_file_streaming(old.name(), &old.meta.mime, size, parent.as_deref(), factory)?;
        self.delete_one(id)?;
        Ok(new_entry)
    }

    pub fn rename_or_move(&self, id: &str, new_name: Option<&str>, new_parent_id: Option<Option<&str>>) -> Result<Entry> {
        let old = self.get(id).context("unknown file")?;
        let old_key = old.file_key.clone().with_context(|| format!("\"{}\" could not be decrypted, so it can't be moved", old.name()))?;
        let new_key = old_key.rebind();
        let mut new_meta = old.meta.clone();
        if let Some(name) = new_name {
            new_meta.name = name.to_string();
        }
        let target = match new_parent_id {
            Some(p) => p.map(|s| s.to_string()),
            None => match self.parent_of(id) {
                Some(Some(p)) if p == UNRESOLVED_PARENT => bail!("this item's folder couldn't be verified; move it to a folder explicitly"),
                Some(p) => p,
                None => old.meta.parent_id.clone(),
            },
        };
        if new_key.is_v2() {
            let parent = self.parent_ref(target.as_deref())?;
            new_meta.set_parent(parent.as_ref());
        } else {
            new_meta.parent_id = target;
            new_meta.pref = None;
        }

        if old.is_folder() {
            let new_folder = self.reupload_with_metadata(&old, &new_key, &new_meta)?;
            let legacy_children: Vec<String> = {
                let index = read_lock(&self.index);
                index.children_by_parent.get(id).map(|v| v.iter().filter(|c| index.entries.get(*c).map(|e| !e.is_v2()).unwrap_or(true)).cloned().collect()).unwrap_or_default()
            };
            for child_id in legacy_children {
                self.rename_or_move(&child_id, None, Some(Some(new_folder.record.id.as_str())))?;
            }
            self.delete_one(id)?;
            Ok(self.get(&new_folder.record.id).unwrap_or(new_folder))
        } else {
            let new_file = self.reupload_with_metadata(&old, &new_key, &new_meta)?;
            self.delete_one(id)?;
            Ok(new_file)
        }
    }

    fn reupload_with_metadata(&self, old: &Entry, new_key: &FileKey, new_meta: &FileMeta) -> Result<Entry> {
        let (encrypted_metadata, metadata_iv) = aead::encrypt_metadata(new_key, new_meta)?;
        let (wrapped_file_key, wrap_iv) = if new_key.is_v2() {
            aead::wrap_file_key(&self.wrapping_key(), new_key)?
        } else {
            (old.record.wrapped_file_key.clone(), old.record.wrap_iv.clone())
        };
        let header = EncryptedHeader { content_iv: old.record.content_iv.clone(), encrypted_metadata, metadata_iv, wrapped_file_key, wrap_iv };

        let record = if old.is_folder() {
            let ciphertext = self.api.download_content(&old.record.id)?;
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
        } else {
            let old_id = old.record.id.as_str();
            let (first, len) = self.api.open_blob(old_id)?;
            match len {
                Some(total) => {
                    let mut first = Some(first);
                    self.api.upload_in_parts(
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
                    self.api.upload_in_parts(
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
        if let Some(new_entry) = self.ingest_record(record) {
            if old.meta.compressed && old.size_is_exact() {
                new_entry.learn_size(old.size());
            }
        }
        lock_cache(&self.content_cache).rekey(&old.record.id, &id);
        lock_large(&self.large_cache).rekey(&old.record.id, &id);
        self.get(&id).context("reupload succeeded but the new entry vanished (likely deleted concurrently)")
    }

    pub fn rotate_password(&self, new_vault_id: &str, new_wrapping_key_raw: &[u8]) -> Result<u64> {
        let entries = self.all_entries();
        let quarantined = read_lock(&self.quarantined).clone();
        let mut rewraps = Vec::with_capacity(entries.len() + quarantined.len());
        for entry in &entries {
            let Some(key) = &entry.file_key else {
                bail!("\"{}\" isn't fully loaded yet — refresh and try again.", entry.name());
            };
            let (wrapped_file_key, wrap_iv) = aead::wrap_file_key(new_wrapping_key_raw, key)?;
            rewraps.push(RewrapEntry { file_id: entry.record.id.clone(), wrapped_file_key, wrap_iv });
        }
        for q in &quarantined {
            let (wrapped_file_key, wrap_iv) = aead::wrap_file_key(new_wrapping_key_raw, &q.file_key)?;
            rewraps.push(RewrapEntry { file_id: q.record.id.clone(), wrapped_file_key, wrap_iv });
        }

        let result = self.api.rotate_vault(new_vault_id, &rewraps)?;
        self.api.set_vault_id(Some(new_vault_id.to_string()));
        *write_lock(&self.wrapping_key_raw) = Zeroizing::new(new_wrapping_key_raw.to_vec());
        Ok(result.files_moved)
    }
}

fn stream_v2_single(dec: &mut dyn Read, meta: &FileMeta, w: &mut dyn Write) -> Result<u64> {
    let corrupt = || io::Error::new(io::ErrorKind::InvalidData, "File is corrupt (padding)");
    let unpadded = meta.unpadded_size.context("Corrupt file metadata (unpaddedSize)")?;
    let mut counted = CountingReader { inner: dec, count: 0 };
    let written = {
        let mut body = io::BufReader::new((&mut counted).take(unpadded));
        let written = if meta.compressed {
            let size = meta.size.context("Corrupt file metadata (size)")?;
            let mut gz = flate2::bufread::GzDecoder::new(&mut body);
            let n = copy_in_blocks(&mut (&mut gz).take(size.saturating_add(1)), w)?;
            if n != size {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "File is corrupt (decompressed size mismatch)").into());
            }
            n
        } else {
            copy_in_blocks(&mut body, w)?
        };
        if io::copy(&mut body, &mut io::sink())? != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "File is corrupt (decompressed size mismatch)").into());
        }
        written
    };
    if counted.count != unpadded {
        return Err(corrupt().into());
    }
    let mut buf = Zeroizing::new(vec![0u8; 256 * 1024]);
    loop {
        let n = chunked::read_full(&mut counted, &mut buf)?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Err(corrupt().into());
        }
    }
    if counted.count != aead::padded_size(unpadded) {
        return Err(corrupt().into());
    }
    Ok(written)
}

struct CountingReader<'a> {
    inner: &'a mut dyn Read,
    count: u64,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

fn copy_in_blocks(r: &mut impl Read, w: &mut dyn Write) -> io::Result<u64> {
    let mut buf = Zeroizing::new(vec![0u8; 256 * 1024]);
    let mut total = 0u64;
    loop {
        let n = chunked::read_full(r, &mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        w.write_all(&buf[..n])?;
        total += n as u64;
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
        Arc::new(LargeFile::whole(pool.new_scratch(), len))
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
