use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::api::{ApiClient, HttpError, RewrapEntry};
use crate::heal::{self, HealItem, HealKind};
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

const FS_NAME_MAX: usize = 255;

pub fn kernel_safe_name(name: &str) -> std::borrow::Cow<'_, str> {
    let needs_fix = name.is_empty() || name == "." || name == ".." || name.len() > FS_NAME_MAX || name.contains(['/', '\0']);
    if !needs_fix {
        return std::borrow::Cow::Borrowed(name);
    }
    let mut out: String = name.chars().map(|c| match c {
        '/' => '\u{2215}',
        '\0' => '\u{FFFD}',
        c => c,
    }).collect();
    if out.is_empty() {
        out = "Untitled".to_string();
    } else if out == "." || out == ".." {
        out = out.replace('.', "\u{2024}");
    }
    if out.len() > FS_NAME_MAX {
        let mut cut = FS_NAME_MAX;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    std::borrow::Cow::Owned(out)
}

#[derive(Clone)]
pub struct Entry {
    pub record: FileRecord,
    pub meta: FileMeta,
    pub file_key: Option<FileKey>,
    pub content: ContentKey,
    pub node_ref: Option<String>,
    pub readable: bool,
    fs_name: Arc<str>,
    learned_size: Arc<AtomicU64>,
    fingerprint: [u8; 32],
}

fn record_fingerprint(r: &FileRecord) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for field in [&r.content_iv, &r.encrypted_metadata, &r.metadata_iv, &r.wrapped_file_key, &r.wrap_iv] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.finalize().into()
}

impl Entry {
    fn new(record: FileRecord, meta: FileMeta, file_key: Option<FileKey>) -> Self {
        let content = file_key.as_ref().map(|k| k.content_key()).unwrap_or(ContentKey { key: Zeroizing::new(Vec::new()), format: FileFormat::Legacy });
        let node_ref = file_key.as_ref().map(|k| k.node_ref());
        let fs_name = Arc::from(kernel_safe_name(&meta.name).as_ref());
        Self { record, meta, file_key, content, node_ref, readable: true, fs_name, learned_size: Arc::new(AtomicU64::new(SIZE_UNKNOWN)), fingerprint: [0; 32] }
    }

    fn with_fingerprint(mut self, fingerprint: [u8; 32]) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    pub fn fs_name(&self) -> &str {
        &self.fs_name
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
    display: HashMap<String, (Arc<str>, usize)>,
    aliased_in: HashMap<String, usize>,
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

fn numbered_name(base: &str, n: usize) -> String {
    let (stem, ext) = split_ext(base);
    let suffix = format!(" ({n}){ext}");
    let mut cut = stem.len().min(FS_NAME_MAX.saturating_sub(suffix.len()));
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}", &stem[..cut])
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
            display: HashMap::new(),
            aliased_in: HashMap::new(),
        }
    }

    fn shown_name(&self, id: &str) -> Option<Arc<str>> {
        if let Some((name, _)) = self.display.get(id) {
            return Some(Arc::clone(name));
        }
        self.entries.get(id).map(|e| Arc::clone(&e.fs_name))
    }

    fn set_alias(&mut self, pk: &str, id: &str, alias: Option<(Arc<str>, usize)>) {
        let had = match alias {
            Some(a) => self.display.insert(id.to_string(), a).is_some(),
            None => {
                let had = self.display.remove(id).is_some();
                if had {
                    if let Some(n) = self.aliased_in.get_mut(pk) {
                        *n = n.saturating_sub(1);
                    }
                }
                return;
            }
        };
        if !had {
            *self.aliased_in.entry(pk.to_string()).or_default() += 1;
        }
    }

    fn place_name(&mut self, pk: &str, id: &str) {
        let Some(base) = self.entries.get(id).map(|e| Arc::clone(&e.fs_name)) else { return };
        let holder = self.name_index.get(pk).and_then(|m| m.get(&*base)).cloned();
        match holder {
            None => {
                self.name_index.entry(pk.to_string()).or_default().insert(base.to_string(), id.to_string());
                self.set_alias(pk, id, None);
            }
            Some(h) if h != id && self.display.contains_key(&h) => {
                self.name_index.entry(pk.to_string()).or_default().insert(base.to_string(), id.to_string());
                self.set_alias(pk, id, None);
                self.place_name(pk, &h);
            }
            Some(_) => {
                let slots = self.name_index.entry(pk.to_string()).or_default();
                let (name, n) = (2..).map(|n| (numbered_name(&base, n), n)).find(|(name, _)| !slots.contains_key(name)).expect("unbounded");
                slots.insert(name.clone(), id.to_string());
                self.set_alias(pk, id, Some((Arc::from(name.as_str()), n)));
            }
        }
    }

    fn compact(&mut self, pk: &str, base: &str) {
        let Some(siblings) = self.children_by_parent.get(pk) else { return };
        let mut members: Vec<(usize, String)> = siblings
            .iter()
            .filter(|sid| self.entries.get(*sid).map(|e| &*e.fs_name == base).unwrap_or(false))
            .map(|sid| (self.display.get(sid).map(|(_, n)| *n).unwrap_or(1), sid.clone()))
            .collect();
        if members.is_empty() {
            return;
        }
        members.sort();
        for (_, sid) in &members {
            if let Some(name) = self.shown_name(sid) {
                if let Some(m) = self.name_index.get_mut(pk) {
                    if m.get(&*name) == Some(sid) {
                        m.remove(&*name);
                    }
                }
            }
            self.set_alias(pk, sid, None);
        }
        for (_, sid) in &members {
            self.place_name(pk, sid);
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
        self.children_by_parent.entry(pk.clone()).or_default().push(id.to_string());
        self.placed.insert(id.to_string(), pk.clone());
        self.place_name(&pk, id);
    }

    fn detach(&mut self, id: &str) {
        let Some(pk) = self.placed.remove(id) else { return };
        let shown = self.shown_name(id);
        let was_alias = self.display.contains_key(id);
        self.set_alias(&pk, id, None);
        if let Some(v) = self.children_by_parent.get_mut(&pk) {
            if let Some(pos) = v.iter().position(|x| x == id) {
                v.swap_remove(pos);
            }
        }
        let Some(shown) = shown else { return };
        if let Some(m) = self.name_index.get_mut(&pk) {
            if m.get(&*shown).map(|cur| cur == id).unwrap_or(false) {
                m.remove(&*shown);
            }
        }
        if !was_alias && self.aliased_in.get(&pk).copied().unwrap_or(0) == 0 {
            return;
        }
        if let Some(base) = self.entries.get(id).map(|e| Arc::clone(&e.fs_name)) {
            self.compact(&pk, &base);
        }
        if self.name_index.get(&pk).map(|m| !m.contains_key(&*shown)).unwrap_or(true) {
            self.compact(&pk, &shown);
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

type PageMap<'a, T> = dyn Fn(Vec<FileRecord>) -> Vec<T> + Sync + 'a;

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
    scratches: Vec<Mutex<Option<Box<Scratch>>>>,
    pool: Arc<ScratchPool>,
    prefetched: Mutex<Vec<bool>>,
    states: Mutex<Vec<u8>>,
    changed: Condvar,
    resident: AtomicU64,
    slots: Arc<Slots>,
    last_end: AtomicU64,
}

const SEQUENTIAL_WINDOW: u64 = 8 * 1024 * 1024;

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
                let prev_end = c.last_end.swap(offset + want as u64, Ordering::Relaxed);
                let sequential = offset.abs_diff(prev_end) <= SEQUENTIAL_WINDOW;
                for i in first..=last {
                    c.ensure(i, self.len)?;
                }
                let end_in_chunk = (offset + want as u64 - 1) % c.chunk_size;
                if sequential && end_in_chunk >= c.chunk_size / 8 {
                    for next in last + 1..=(last + CHUNK_READAHEAD).min(c.count - 1) {
                        if c.try_claim(next) {
                            let me = Arc::clone(self);
                            let spawned = std::thread::Builder::new().name("lethean-readahead".into()).spawn(move || {
                                if let Backing::Chunked(c) = &me.backing {
                                    if let Err(e) = c.load_claimed(next, me.len) {
                                        log::debug!("[lethean-cli] read-ahead of chunk {next} failed: {e}");
                                    }
                                }
                            });
                            if spawned.is_err() {
                                c.release_claim(next);
                            }
                        }
                    }
                }
                c.read_resident(offset, want)
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
                    Some(c.read_resident(offset, want))
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
    fn read_resident(&self, offset: u64, want: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(want);
        let end = offset + want as u64;
        let mut pos = offset;
        while pos < end {
            let index = pos / self.chunk_size;
            let within = pos % self.chunk_size;
            let n = (self.chunk_size - within).min(end - pos) as usize;
            let slot = self.scratches.get(index as usize).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read past the last chunk"))?;
            let mut guard = lock_plain(slot);
            let scratch = guard.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "chunk is not loaded"))?;
            let start = out.len();
            out.resize(start + n, 0);
            let mut got = 0;
            while got < n {
                let k = scratch.read_at(within + got as u64, &mut out[start + got..start + n])?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            out.truncate(start + got);
            if got < n {
                break;
            }
            pos += n as u64;
        }
        Ok(out)
    }

    fn state(&self, i: u64) -> u8 {
        lock_plain(&self.states).get(i as usize).copied().unwrap_or(CHUNK_READY)
    }

    fn try_claim(&self, i: u64) -> bool {
        {
            let mut tried = lock_plain(&self.prefetched);
            match tried.get_mut(i as usize) {
                Some(t) if !*t => *t = true,
                _ => return false,
            }
        }
        let mut st = lock_plain(&self.states);
        match st.get_mut(i as usize) {
            Some(s) if *s == CHUNK_MISSING => {
                *s = CHUNK_LOADING;
                true
            }
            _ => false,
        }
    }

    fn release_claim(&self, i: u64) {
        drop(LoadingReset { src: self, index: i as usize, done: false });
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
        self.load_claimed(i, file_len)
    }

    fn load_claimed(&self, i: u64, file_len: u64) -> io::Result<()> {
        let index = i as usize;
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
        let mut slot = lock_plain(&self.scratches[i as usize]);
        let scratch = slot.get_or_insert_with(|| Box::new(self.pool.new_scratch()));
        scratch.set_len(0)?;
        let result = (|| -> io::Result<()> {
            let mut buf = Zeroizing::new(vec![0u8; 256 * 1024]);
            let mut got = 0u64;
            loop {
                let n = chunked::read_full(&mut dec, &mut buf)?;
                if n == 0 {
                    break;
                }
                let keep = take.saturating_sub(got).min(n as u64) as usize;
                if keep > 0 {
                    scratch.write_at(got, &buf[..keep])?;
                }
                chunked::check_filler(self.content.format, &buf[keep..n])?;
                got += n as u64;
            }
            if got != self.chunk_size {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk ended early"));
            }
            Ok(())
        })();
        if result.is_err() {
            *slot = None;
        }
        result
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

#[derive(Default)]
struct Journal {
    seq: AtomicU64,
    touched: Mutex<HashMap<String, u64>>,
    hidden: Mutex<HashSet<String>>,
}

impl Journal {
    fn now(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    fn touch(&self, id: &str) {
        let s = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        lock_plain(&self.touched).insert(id.to_string(), s);
    }

    fn touched_after(&self, id: &str, seq0: u64) -> bool {
        lock_plain(&self.touched).get(id).map(|s| *s > seq0).unwrap_or(false)
    }

    fn prune(&self, seq0: u64) {
        lock_plain(&self.touched).retain(|_, s| *s > seq0);
    }

    fn is_hidden(&self, id: &str) -> bool {
        lock_plain(&self.hidden).contains(id)
    }
}

const DEFERRED_DELETE_ATTEMPTS: u32 = 4;
const DELETE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[derive(Default)]
struct DeleteQueueState {
    items: VecDeque<(String, u32)>,
    running: bool,
}

#[derive(Default)]
struct DeleteQueue {
    state: Mutex<DeleteQueueState>,
    idle: Condvar,
}

impl DeleteQueue {
    fn enqueue(self: &Arc<Self>, api: &Arc<ApiClient>, journal: &Arc<Journal>, id: String) {
        let mut st = lock_plain(&self.state);
        st.items.push_back((id, 0));
        if st.running {
            return;
        }
        st.running = true;
        drop(st);
        let (queue, api, journal) = (Arc::clone(self), Arc::clone(api), Arc::clone(journal));
        let spawned = std::thread::Builder::new().name("lethean-delete".into()).spawn(move || queue.work(&api, &journal));
        if let Err(e) = spawned {
            log::error!("[lethean-cli] could not start the background delete thread: {e}");
            lock_plain(&self.state).running = false;
        }
    }

    fn work(&self, api: &ApiClient, journal: &Journal) {
        loop {
            let next = {
                let mut st = lock_plain(&self.state);
                match st.items.pop_front() {
                    Some(item) => item,
                    None => {
                        st.running = false;
                        drop(st);
                        self.idle.notify_all();
                        return;
                    }
                }
            };
            let (id, attempts) = next;
            match api.delete_file(&id, None) {
                Ok(()) => {
                    journal.touch(&id);
                    lock_plain(&journal.hidden).remove(&id);
                }
                Err(e) if crate::api::is_missing_endpoint(&e) => {
                    journal.touch(&id);
                    lock_plain(&journal.hidden).remove(&id);
                }
                Err(e) if attempts + 1 < DEFERRED_DELETE_ATTEMPTS => {
                    log::warn!("[lethean-cli] could not remove an old copy yet ({e:#}); will retry");
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    lock_plain(&self.state).items.push_back((id, attempts + 1));
                }
                Err(e) => {
                    log::warn!("[lethean-cli] an old copy of a saved file could not be removed from the server and stays hidden for this session: {e:#}");
                }
            }
        }
    }

    fn drain(&self, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        let mut st = lock_plain(&self.state);
        while st.running || !st.items.is_empty() {
            let now = std::time::Instant::now();
            if now >= deadline {
                log::warn!("[lethean-cli] {} old cop(ies) were not removed from the server before exit", st.items.len() + usize::from(st.running));
                return;
            }
            st = self.idle.wait_timeout(st, deadline - now).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub removed: Vec<String>,
    pub aliases: Vec<(String, String, bool)>,
    pub modified: Vec<String>,
    pub added: usize,
    pub touched_names: Vec<(String, String)>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.aliases.is_empty() && self.modified.is_empty() && self.added == 0 && self.touched_names.is_empty()
    }
}

struct StaleItem {
    entry: Arc<Entry>,
    successor: String,
    kind: HealKind,
    hidden: bool,
}

#[derive(Default)]
struct HealState {
    stale: HashMap<String, StaleItem>,
    keep: HashSet<String>,
    hashed: HashMap<String, [u8; 32]>,
    hash_bytes_used: u64,
}

const HEAL_HASH_BUDGET: u64 = 256 * 1024 * 1024;

fn is_retryable(e: &anyhow::Error) -> bool {
    if is_transient_stream_error(e) {
        return true;
    }
    e.chain().any(|c| {
        if let Some(h) = c.downcast_ref::<HttpError>() {
            return h.status >= 500 || h.status == 429 || h.status == 408;
        }
        let msg = c.to_string();
        msg.contains("network error") || msg.contains("connection dropped")
    })
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<HttpError>().map(|h| h.status == 404).unwrap_or(false))
}

fn index_snapshot(index: &VaultIndex) -> HashMap<String, (String, Arc<str>)> {
    index.placed.iter().filter_map(|(id, pk)| index.shown_name(id).map(|name| (id.clone(), (pk.clone(), name)))).collect()
}

fn touched_between(before: &HashMap<String, (String, Arc<str>)>, after: &HashMap<String, (String, Arc<str>)>) -> Vec<(String, String)> {
    let mut touched: HashSet<(String, String)> = HashSet::new();
    for (id, v) in before {
        if after.get(id) != Some(v) {
            touched.insert((v.0.clone(), v.1.to_string()));
        }
    }
    for (id, v) in after {
        if before.get(id) != Some(v) {
            touched.insert((v.0.clone(), v.1.to_string()));
        }
    }
    touched.into_iter().filter(|(pk, _)| pk != UNRESOLVED_PARENT).collect()
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
    journal: Arc<Journal>,
    deletes: Arc<DeleteQueue>,
    defer_deletes: std::sync::atomic::AtomicBool,
    closed: std::sync::atomic::AtomicBool,
    sync_lock: Mutex<()>,
    last_listing_ms: AtomicU64,
    heal: Mutex<HealState>,
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
            journal: Arc::new(Journal::default()),
            deletes: Arc::new(DeleteQueue::default()),
            defer_deletes: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
            sync_lock: Mutex::new(()),
            last_listing_ms: AtomicU64::new(0),
            heal: Mutex::new(HealState::default()),
        }
    }

    pub fn set_deferred_deletes(&self, on: bool) {
        self.defer_deletes.store(on, Ordering::Release);
    }

    pub fn flush_pending_deletes(&self) {
        self.deletes.drain(DELETE_DRAIN_TIMEOUT);
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
        self.closed.store(true, Ordering::SeqCst);
        self.deletes.drain(DELETE_DRAIN_TIMEOUT);
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
        let fp = record_fingerprint(&record);
        let file_key = match aead::unwrap_file_key(wrapping_key, &record.wrapped_file_key, &record.wrap_iv) {
            Ok(k) => k,
            Err(_) => return Decoded::Entry(Entry::unreadable(Self::scrub(record), None).with_fingerprint(fp)),
        };
        if strict && !file_key.is_v2() {
            return Decoded::Quarantined(Quarantined { record, file_key });
        }
        match aead::decrypt_metadata(&file_key, &record.encrypted_metadata, &record.metadata_iv) {
            Ok(meta) => {
                record = Self::scrub(record);
                Decoded::Entry(Entry::new(record, meta, Some(file_key)).with_fingerprint(fp))
            }
            Err(_) => Decoded::Entry(Entry::unreadable(Self::scrub(record), Some(file_key)).with_fingerprint(fp)),
        }
    }

    fn decode_many(wrapping_key: &[u8], records: Vec<FileRecord>, strict: bool) -> Vec<Decoded> {
        const PER_THREAD_MIN: usize = 256;
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(REFRESH_PARALLELISM).min(records.len().div_ceil(PER_THREAD_MIN)).max(1);
        if threads <= 1 {
            return records.into_iter().map(|r| Self::decode_record(wrapping_key, r, strict)).collect();
        }
        let per = records.len().div_ceil(threads);
        let mut chunks: Vec<Vec<FileRecord>> = Vec::with_capacity(threads);
        let mut it = records.into_iter();
        loop {
            let c: Vec<FileRecord> = it.by_ref().take(per).collect();
            if c.is_empty() {
                break;
            }
            chunks.push(c);
        }
        std::thread::scope(|s| {
            let handles: Vec<_> = chunks.into_iter().map(|c| s.spawn(move || c.into_iter().map(|r| Self::decode_record(wrapping_key, r, strict)).collect::<Vec<_>>())).collect();
            handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        })
    }

    fn scrub(mut record: FileRecord) -> FileRecord {
        record.encrypted_metadata = String::new();
        record.metadata_iv = String::new();
        record
    }

    fn ingest_record(&self, record: FileRecord) -> Option<Arc<Entry>> {
        self.journal.touch(&record.id);
        match Self::decode_record(&self.wrapping_key(), record, self.is_strict()) {
            Decoded::Entry(entry) => write_lock(&self.index).insert(entry),
            Decoded::Quarantined(q) => {
                write_lock(&self.quarantined).push(q);
                None
            }
        }
    }

    fn fetch_pages<T: Send>(&self, from: u64, count: u64, map: &PageMap<'_, T>) -> Result<Vec<(usize, Vec<T>)>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let fetch = |page: u64| -> Result<(usize, Vec<T>)> {
            let records = self.api.list_files(page * PAGE_SIZE, Some(PAGE_SIZE))?;
            Ok((records.len(), map(records)))
        };
        if count == 1 {
            return Ok(vec![fetch(from)?]);
        }
        let next = AtomicU64::new(0);
        let failed = std::sync::atomic::AtomicBool::new(false);
        type Slot<T> = Mutex<Option<Result<(usize, Vec<T>)>>>;
        let slots: Vec<Slot<T>> = (0..count).map(|_| Mutex::new(None)).collect();
        std::thread::scope(|s| {
            for _ in 0..REFRESH_PARALLELISM.min(count as usize) {
                s.spawn(|| loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= count {
                        break;
                    }
                    let result = fetch(from + i);
                    if result.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    *lock_plain(&slots[i as usize]) = Some(result);
                });
            }
        });
        let mut out = Vec::with_capacity(count as usize);
        for slot in slots {
            match slot.into_inner().unwrap_or_else(|p| p.into_inner()) {
                Some(r) => out.push(r?),
                None => break,
            }
        }
        Ok(out)
    }

    fn fetch_all<T: Send>(&self, hint: u64, map: &PageMap<'_, T>) -> Result<Vec<T>> {
        let started = std::time::Instant::now();
        let mut out = Vec::new();
        let mut next_page;
        let mut batch;
        if hint > 0 {
            next_page = 0;
            batch = (hint + 1).div_ceil(PAGE_SIZE).max(1);
        } else {
            let (n, first) = self.fetch_pages(0, 1, map)?.pop().unwrap_or_default();
            out.extend(first);
            if (n as u64) < PAGE_SIZE {
                self.last_listing_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                return Ok(out);
            }
            let expected = self.api.get_usage(None).ok().map(|u| u.file_count).unwrap_or(0);
            next_page = 1;
            batch = expected.div_ceil(PAGE_SIZE).saturating_sub(1).max(REFRESH_PARALLELISM as u64 / 2);
        }
        loop {
            let pages = self.fetch_pages(next_page, batch, map)?;
            next_page += batch;
            let mut done = pages.len() < batch as usize;
            for (n, page) in pages {
                if (n as u64) < PAGE_SIZE {
                    done = true;
                }
                out.extend(page);
            }
            if done {
                self.last_listing_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                return Ok(out);
            }
            batch = REFRESH_PARALLELISM as u64;
        }
    }

    pub fn last_listing_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.last_listing_ms.load(Ordering::Relaxed))
    }

    pub fn refresh_all(&self) -> Result<()> {
        let _serial = lock_plain(&self.sync_lock);
        let wrapping_key = self.wrapping_key();
        let strict = self.is_strict();
        let journal = &self.journal;
        let decode = |page: Vec<FileRecord>| -> Vec<Decoded> { page.into_iter().filter(|r| !journal.is_hidden(&r.id)).map(|r| Self::decode_record(&wrapping_key, r, strict)).collect() };
        let decoded = self.fetch_all(0, &decode)?;
        let mut fresh = VaultIndex::new();
        let mut quarantined: Vec<Quarantined> = Vec::new();
        let mut seen_q = HashSet::new();
        for d in decoded {
            match d {
                Decoded::Entry(e) => {
                    fresh.insert(e);
                }
                Decoded::Quarantined(q) => {
                    if seen_q.insert(q.record.id.clone()) {
                        quarantined.push(q);
                    }
                }
            }
        }
        lock_plain(&self.heal).stale.clear();
        self.apply_heal(&mut fresh);
        *write_lock(&self.index) = fresh;
        *write_lock(&self.quarantined) = quarantined;
        Ok(())
    }

    fn list_for_sync(&self, hint: u64) -> Result<HashMap<String, ([u8; 32], Option<FileRecord>)>> {
        let index = &self.index;
        let map = |page: Vec<FileRecord>| -> Vec<(String, [u8; 32], Option<FileRecord>)> {
            let index = read_lock(index);
            page.into_iter()
                .map(|r| {
                    let fp = record_fingerprint(&r);
                    let known = index.entries.get(&r.id).map(|e| e.fingerprint) == Some(fp);
                    (r.id.clone(), fp, if known { None } else { Some(r) })
                })
                .collect()
        };
        let mut out = HashMap::new();
        for (id, fp, r) in self.fetch_all(hint, &map)? {
            out.entry(id).or_insert((fp, r));
        }
        Ok(out)
    }

    pub fn sync(&self) -> Result<SyncReport> {
        let _serial = lock_plain(&self.sync_lock);
        let mut report = SyncReport::default();
        if self.closed.load(Ordering::SeqCst) {
            return Ok(report);
        }
        let seq0 = self.journal.now();
        let hint = (self.entry_count() + self.quarantined_count()) as u64;
        let mut listed = self.list_for_sync(hint)?;

        let mut gone: Vec<String> = {
            let index = read_lock(&self.index);
            index.entries.keys().filter(|id| !listed.contains_key(*id)).cloned().collect()
        };
        gone.retain(|id| !self.journal.touched_after(id, seq0));
        if !gone.is_empty() {
            let again = self.list_for_sync(hint)?;
            gone.retain(|id| !again.contains_key(id));
            for (id, v) in again {
                if !matches!(listed.get(&id), Some((_, Some(_)))) {
                    listed.insert(id, v);
                }
            }
        }

        let quarantined_ids: HashSet<String> = read_lock(&self.quarantined).iter().map(|q| q.record.id.clone()).collect();
        let stale_ids: HashSet<String> = {
            let mut st = lock_plain(&self.heal);
            st.stale.retain(|id, _| listed.contains_key(id));
            st.keep.retain(|id| listed.contains_key(id));
            st.stale.iter().filter(|(_, it)| it.hidden).map(|(id, _)| id.clone()).collect()
        };
        let (fresh, modified): (Vec<FileRecord>, Vec<FileRecord>) = {
            let index = read_lock(&self.index);
            let mut fresh = Vec::new();
            let mut modified = Vec::new();
            for (id, (fp, r)) in listed.iter_mut() {
                match index.entries.get(id.as_str()) {
                    Some(e) if e.fingerprint != *fp => {
                        if let Some(r) = r.take() {
                            modified.push(r);
                        }
                    }
                    Some(_) => {}
                    None if quarantined_ids.contains(id) || stale_ids.contains(id) || self.journal.is_hidden(id) || self.journal.touched_after(id, seq0) => {}
                    None => {
                        if let Some(r) = r.take() {
                            fresh.push(r);
                        }
                    }
                }
            }
            (fresh, modified)
        };
        let dropped_quarantine = quarantined_ids.iter().any(|id| !listed.contains_key(id));
        if gone.is_empty() && fresh.is_empty() && modified.is_empty() && !dropped_quarantine {
            self.journal.prune(seq0);
            return Ok(report);
        }

        let wrapping_key = self.wrapping_key();
        let strict = self.is_strict();
        let modified_ids: HashSet<String> = modified.iter().map(|r| r.id.clone()).collect();
        let decoded = Self::decode_many(&wrapping_key, fresh.into_iter().chain(modified).collect(), strict);
        drop(wrapping_key);

        let mut new_quarantine = Vec::new();
        let mut removed_entries: Vec<Arc<Entry>> = Vec::new();
        let mut added_entries: Vec<Arc<Entry>> = Vec::new();
        {
            let mut index = write_lock(&self.index);
            if self.closed.load(Ordering::SeqCst) {
                return Ok(SyncReport::default());
            }
            let snapshot = |index: &VaultIndex| -> HashMap<String, (String, Arc<str>)> {
                index.placed.iter().filter_map(|(id, pk)| index.shown_name(id).map(|name| (id.clone(), (pk.clone(), name)))).collect()
            };
            let before = snapshot(&index);
            for id in &gone {
                if self.journal.touched_after(id, seq0) {
                    continue;
                }
                if let Some(e) = index.remove(id) {
                    removed_entries.push(e);
                }
            }
            for d in decoded {
                match d {
                    Decoded::Entry(e) => {
                        let id = e.record.id.clone();
                        if self.journal.touched_after(&id, seq0) || self.journal.is_hidden(&id) {
                            continue;
                        }
                        if modified_ids.contains(&id) {
                            if index.remove(&id).is_none() {
                                continue;
                            }
                            report.modified.push(id.clone());
                        } else if index.entries.contains_key(&id) {
                            continue;
                        }
                        if let Some(e) = index.insert(e) {
                            if !modified_ids.contains(&id) {
                                added_entries.push(e);
                            }
                        }
                    }
                    Decoded::Quarantined(q) => {
                        if !self.journal.touched_after(&q.record.id, seq0) {
                            new_quarantine.push(q);
                        }
                    }
                }
            }
            for id in self.apply_heal(&mut index) {
                report.removed.push(id);
            }
            let after = snapshot(&index);
            let mut touched: HashSet<(String, String)> = HashSet::new();
            for (id, (pk, name)) in &before {
                if after.get(id) != Some(&(pk.clone(), Arc::clone(name))) {
                    touched.insert((pk.clone(), name.to_string()));
                }
            }
            for (id, (pk, name)) in &after {
                if before.get(id) != Some(&(pk.clone(), Arc::clone(name))) {
                    touched.insert((pk.clone(), name.to_string()));
                }
            }
            for id in &report.modified {
                if let Some((pk, name)) = after.get(id) {
                    touched.insert((pk.clone(), name.to_string()));
                }
            }
            report.touched_names = touched.into_iter().filter(|(pk, _)| pk != UNRESOLVED_PARENT).collect();
        }

        {
            let mut q = write_lock(&self.quarantined);
            q.retain(|item| listed.contains_key(&item.record.id));
            for item in new_quarantine {
                if !q.iter().any(|x| x.record.id == item.record.id) {
                    q.push(item);
                }
            }
        }

        let by_ref = |entries: &[Arc<Entry>]| -> HashMap<(String, bool), Vec<usize>> {
            let mut m: HashMap<(String, bool), Vec<usize>> = HashMap::new();
            for (i, e) in entries.iter().enumerate() {
                if let Some(r) = &e.node_ref {
                    m.entry((r.clone(), e.is_folder())).or_default().push(i);
                }
            }
            m
        };
        let old_refs = by_ref(&removed_entries);
        let new_refs = by_ref(&added_entries);
        let mut aliased_old: HashSet<String> = HashSet::new();
        for (key, olds) in &old_refs {
            let Some(news) = new_refs.get(key) else { continue };
            if olds.len() != 1 || news.len() != 1 {
                continue;
            }
            let (old, new) = (&removed_entries[olds[0]], &added_entries[news[0]]);
            let same_content = old.record.content_iv == new.record.content_iv && old.meta.unpadded_size == new.meta.unpadded_size && old.meta.size == new.meta.size;
            report.aliases.push((old.record.id.clone(), new.record.id.clone(), same_content));
            aliased_old.insert(old.record.id.clone());
            if same_content {
                if old.meta.compressed && old.size_is_exact() {
                    new.learn_size(old.size());
                }
                lock_cache(&self.content_cache).rekey(&old.record.id, &new.record.id);
                lock_large(&self.large_cache).rekey(&old.record.id, &new.record.id);
            }
        }
        for e in &removed_entries {
            let id = &e.record.id;
            lock_cache(&self.content_cache).remove(id);
            lock_large(&self.large_cache).remove(id);
            if !aliased_old.contains(id) {
                report.removed.push(id.clone());
            }
        }
        for id in &report.modified {
            lock_cache(&self.content_cache).remove(id);
            lock_large(&self.large_cache).remove(id);
        }
        report.added = added_entries.len() - report.aliases.len();
        self.journal.prune(seq0);
        Ok(report)
    }

    fn apply_heal(&self, index: &mut VaultIndex) -> Vec<String> {
        let (keep, known): (HashSet<String>, HashSet<String>) = {
            let st = lock_plain(&self.heal);
            (st.keep.clone(), st.stale.keys().cloned().collect())
        };
        let legacy_parents: HashSet<&str> = index.entries.values().filter(|e| !e.is_v2()).filter_map(|e| e.meta.parent_id.as_deref()).collect();
        let items: Vec<HealItem> = index
            .entries
            .values()
            .filter(|e| !keep.contains(&e.record.id))
            .map(|e| HealItem {
                id: e.record.id.clone(),
                node_ref: e.node_ref.clone(),
                from: if e.is_v2() { e.meta.from.clone() } else { None },
                rev: e.meta.rev,
                is_folder: e.is_folder(),
                folder_movable: e.is_folder() && e.is_v2() && !legacy_parents.contains(e.record.id.as_str()),
                fingerprint: e.fingerprint,
            })
            .collect();
        let plan = heal::plan(&items);
        if plan.hidden.is_empty() {
            return Vec::new();
        }
        let mut removed = Vec::new();
        let mut st = lock_plain(&self.heal);
        for (id, successor, kind) in plan.hidden {
            if known.contains(&id) {
                continue;
            }
            let hidden = kind == HealKind::Identical;
            let entry = if hidden { index.remove(&id) } else { index.entries.get(&id).cloned() };
            if let Some(entry) = entry {
                st.stale.insert(id.clone(), StaleItem { entry, successor, kind, hidden });
                if hidden {
                    removed.push(id);
                }
            }
        }
        removed
    }

    pub fn stale_count(&self) -> usize {
        lock_plain(&self.heal).stale.len()
    }

    fn keep_after_all(&self, id: &str) {
        let item = lock_plain(&self.heal).stale.remove(id);
        let Some(item) = item else { return };
        lock_plain(&self.heal).keep.insert(id.to_string());
        if item.hidden {
            write_lock(&self.index).insert((*item.entry).clone());
        }
    }

    pub fn heal_pending(&self) -> SyncReport {
        let mut report = SyncReport::default();
        if self.closed.load(Ordering::SeqCst) {
            return report;
        }
        let before = index_snapshot(&read_lock(&self.index));
        let todo: Vec<(String, String, HealKind, bool)> = lock_plain(&self.heal).stale.iter().map(|(id, it)| (id.clone(), it.successor.clone(), it.kind, it.hidden)).collect();
        let mut verified: HashSet<String> = HashSet::new();
        for (id, successor, kind, hidden) in todo {
            if self.closed.load(Ordering::SeqCst) {
                return report;
            }
            if !verified.contains(&successor) {
                if self.entry(&successor).is_none() {
                    log::warn!("[lethean-cli] the copy that was to be kept disappeared; keeping the other copy");
                    self.keep_after_all(&id);
                    continue;
                }
                match self.verify_record(&successor) {
                    Ok(()) => {
                        verified.insert(successor.clone());
                    }
                    Err(e) if is_retryable(&e) => continue,
                    Err(e) => {
                        log::warn!("[lethean-cli] the copy that was to be kept couldn't be read back ({e:#}); keeping both");
                        self.keep_after_all(&id);
                        continue;
                    }
                }
            }
            match self.api.delete_file(&id, None) {
                Ok(()) => {}
                Err(e) if is_not_found(&e) => {}
                Err(_) => continue,
            }
            if !hidden {
                write_lock(&self.index).remove(&id);
            }
            let _ = kind;
            self.journal.touch(&id);
            lock_plain(&self.heal).stale.remove(&id);
            lock_cache(&self.content_cache).remove(&id);
            lock_large(&self.large_cache).remove(&id);
            report.removed.push(id);
        }
        report.removed.extend(self.remove_identical_same_name_copies());
        let after = index_snapshot(&read_lock(&self.index));
        report.touched_names = touched_between(&before, &after);
        report
    }

    fn remove_identical_same_name_copies(&self) -> Vec<String> {
        let groups: Vec<Vec<(String, u64)>> = {
            let index = read_lock(&self.index);
            let mut m: HashMap<(String, Arc<str>, u64), Vec<(String, u64)>> = HashMap::new();
            for (id, pk) in &index.placed {
                let Some(e) = index.entries.get(id) else { continue };
                if e.is_folder() || !e.readable || !e.size_is_exact() {
                    continue;
                }
                m.entry((pk.clone(), Arc::clone(&e.fs_name), e.size())).or_default().push((id.clone(), e.size()));
            }
            m.into_values().filter(|g| g.len() > 1).collect()
        };
        let mut removed = Vec::new();
        for mut group in groups {
            group.sort();
            let mut hashes: Vec<(String, [u8; 32])> = Vec::new();
            for (id, size) in &group {
                let known = lock_plain(&self.heal).hashed.get(id).copied();
                let h = match known {
                    Some(h) => h,
                    None => {
                        {
                            let mut st = lock_plain(&self.heal);
                            if st.hash_bytes_used + size > HEAL_HASH_BUDGET {
                                continue;
                            }
                            st.hash_bytes_used += size;
                        }
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        if self.stream_plaintext(id, &mut hasher).is_err() {
                            continue;
                        }
                        let h: [u8; 32] = hasher.finalize().into();
                        lock_plain(&self.heal).hashed.insert(id.clone(), h);
                        h
                    }
                };
                hashes.push((id.clone(), h));
            }
            let mut first_of: HashMap<[u8; 32], String> = HashMap::new();
            for (id, h) in hashes {
                match first_of.get(&h) {
                    None => {
                        first_of.insert(h, id);
                    }
                    Some(_) => {
                        if self.delete_one(&id).is_ok() {
                            removed.push(id);
                        }
                    }
                }
            }
        }
        removed
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
            let fp = record_fingerprint(&q.record);
            let entry = match aead::decrypt_metadata(&q.file_key, &q.record.encrypted_metadata, &q.record.metadata_iv) {
                Ok(meta) => Entry::new(Self::scrub(q.record), meta, Some(q.file_key)),
                Err(_) => Entry::unreadable(Self::scrub(q.record), Some(q.file_key)),
            }
            .with_fingerprint(fp);
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
            Some(ids) => ids.iter().filter_map(|id| Some(ChildInfo { id: id.clone(), name: index.shown_name(id)?.to_string(), is_folder: index.entries.get(id)?.is_folder() })).collect(),
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
        match self.api.delete_file(id, None) {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(e),
        }
        self.forget_local(id);
        Ok(())
    }

    fn forget_local(&self, id: &str) {
        write_lock(&self.index).remove(id);
        self.journal.touch(id);
        lock_cache(&self.content_cache).remove(id);
        lock_large(&self.large_cache).remove(id);
    }

    fn delete_replaced(&self, id: &str) -> Result<()> {
        if !self.defer_deletes.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return self.delete_one(id);
        }
        lock_plain(&self.journal.hidden).insert(id.to_string());
        self.forget_local(id);
        self.deletes.enqueue(&self.api, &self.journal, id.to_string());
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
        let scratches = (0..count).map(|_| Mutex::new(None)).collect();
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
                scratches,
                pool: Arc::clone(&self.pool),
                prefetched: Mutex::new(vec![false; count as usize]),
                states: Mutex::new(vec![CHUNK_MISSING; count as usize]),
                changed: Condvar::new(),
                resident: AtomicU64::new(0),
                slots: Arc::clone(&self.chunk_slots),
                last_end: AtomicU64::new(0),
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
        let new_entry = self.create_file_streaming_ext(old.name(), &old.meta.mime, size, parent.as_deref(), old.node_ref.as_deref(), factory)?;
        self.delete_replaced(id)?;
        Ok(new_entry)
    }

    pub fn rename_or_move(&self, id: &str, new_name: Option<&str>, new_parent_id: Option<Option<&str>>) -> Result<Entry> {
        let old = self.get(id).context("unknown file")?;
        let old_key = old.file_key.clone().with_context(|| format!("\"{}\" could not be decrypted, so it can't be moved", old.name()))?;
        let new_key = old_key.rebind();
        let mut new_meta = old.meta.clone();
        new_meta.rev = Some(old.meta.rev.unwrap_or(0) + 1);
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
        if let (true, Some(t)) = (old.is_folder(), target.as_deref()) {
            if t == id || self.descendant_ids(id).iter().any(|d| d == t) {
                bail!("can't move a folder into itself");
            }
        }
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
            self.delete_replaced(id)?;
            Ok(self.get(&new_folder.record.id).unwrap_or(new_folder))
        } else {
            let new_file = self.reupload_with_metadata(&old, &new_key, &new_meta)?;
            self.delete_replaced(id)?;
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
        let mut entries = self.all_entries();
        entries.extend(lock_plain(&self.heal).stale.values().filter(|s| s.hidden).map(|s| (*s.entry).clone()));
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
