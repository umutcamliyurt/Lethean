use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use fuser::consts::{FOPEN_DIRECT_IO, FOPEN_KEEP_CACHE};
use std::sync::atomic::AtomicBool;
use fuser::{FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow};
use libc::{c_int, EBADF, EDQUOT, EEXIST, EFBIG, EINVAL, EIO, EISDIR, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY, O_ACCMODE, O_TRUNC};
use log::{error, warn};
use zeroize::Zeroizing;

use crate::scratch::{Scratch, ScratchPool, ScratchReader, ScratchWriter, DEFAULT_POOL_BYTES};
use crate::vault::{LargeFile, Stat, SyncReport, Vault, UNRESOLVED_PARENT};

const TTL: Duration = Duration::from_secs(5);
const ROOT_INO: u64 = 1;

#[cfg(target_os = "macos")]
const RENAME_NOREPLACE_FLAG: u32 = 0x4;
#[cfg(not(target_os = "macos"))]
const RENAME_NOREPLACE_FLAG: u32 = 0x1;

const NET_WORKERS: usize = 64;
const IO_WORKERS: usize = 8;

#[derive(Clone)]
enum Node {
    Root,
    Remote(String),
    Pending(PendingFile),
}

#[derive(Clone)]
struct PendingFile {
    parent_id: Option<String>,
    name: String,
}

#[derive(Clone)]
enum WriteTarget {
    NewFile { parent_id: Option<String>, name: String, mime: String },
    ExistingFile { id: String, save_as: SaveAs },
    Discarded,
}

#[derive(Clone, Debug)]
struct SaveAs {
    parent_id: Option<String>,
    name: String,
    mime: String,
}

fn save_as_for(vault: &Vault, id: &str) -> SaveAs {
    let entry = vault.entry(id);
    let parent_id = match vault.parent_of(id) {
        Some(Some(p)) if p != UNRESOLVED_PARENT => Some(p),
        _ => None,
    };
    SaveAs {
        parent_id,
        name: entry.as_ref().map(|e| e.fs_name().to_string()).unwrap_or_else(|| "Untitled".to_string()),
        mime: entry.as_ref().map(|e| e.meta.mime.clone()).unwrap_or_else(|| "application/octet-stream".to_string()),
    }
}

fn existing_target(vault: &Vault, id: String) -> WriteTarget {
    let save_as = save_as_for(vault, &id);
    WriteTarget::ExistingFile { id, save_as }
}

fn free_name(vault: &Vault, parent: Option<&str>, name: &str) -> String {
    if vault.find_child(parent, name).is_none() {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1.. {
        let candidate = if n == 1 { format!("{stem} (conflicted copy){ext}") } else { format!("{stem} (conflicted copy {n}){ext}") };
        if vault.find_child(parent, &candidate).is_none() {
            return candidate;
        }
    }
    unreachable!()
}

struct WriteFile {
    target: Mutex<WriteTarget>,
    scratch: Arc<Mutex<Scratch>>,
    len: Arc<AtomicU64>,
    commit_lock: Mutex<()>,
}

struct Writer {
    file: Arc<WriteFile>,
    handles: usize,
}

#[derive(Clone)]
enum Pinned {
    Mem(Arc<Zeroizing<Vec<u8>>>),
    Large(Arc<LargeFile>),
}

enum Handle {
    Read { id: String, pinned: Option<Pinned> },
    Write { ino: u64 },
}

struct DirEntry {
    ino: u64,
    kind: FileType,
    name: String,
    id: Option<String>,
}

struct FsState {
    ino_of_id: HashMap<String, u64>,
    node_of_ino: HashMap<u64, Node>,
    lookups: HashMap<u64, u64>,
    next_ino: u64,
    handles: HashMap<u64, Handle>,
    dir_handles: HashMap<u64, Arc<Vec<DirEntry>>>,
    next_fh: u64,
    pending_by_key: HashMap<(Option<String>, String), u64>,
    writers: HashMap<u64, Writer>,
    cached_content: HashMap<u64, String>,
}

fn lock_state(state: &Mutex<FsState>) -> MutexGuard<'_, FsState> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_scratch(s: &Mutex<Scratch>) -> MutexGuard<'_, Scratch> {
    s.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_plain<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy)]
struct AttrCtx {
    uid: u32,
    gid: u32,
    mount_time: SystemTime,
}

fn run_guarded<T>(op: &'static str, work: impl FnOnce() -> Result<T, c_int>) -> Result<T, c_int> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(result) => result,
        Err(payload) => {
            let msg = payload.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| payload.downcast_ref::<String>().cloned()).unwrap_or_else(|| "non-string panic payload".to_string());
            error!("[lethean-cli] internal error in {op}: {msg} (this is a bug in lethean-cli, not a network problem — please report it)");
            Err(EIO)
        }
    }
}

fn errno_of_io(e: &io::Error) -> c_int {
    match e.raw_os_error() {
        Some(code) if code == ENOSPC || code == EDQUOT || code == EFBIG => code,
        _ => EIO,
    }
}

fn errno_of(e: &anyhow::Error) -> c_int {
    for cause in e.chain() {
        if let Some(io_err) = cause.downcast_ref::<io::Error>() {
            let code = errno_of_io(io_err);
            if code != EIO {
                return code;
            }
        }
    }
    EIO
}

const MAX_CONCURRENT_NETWORK_OPS: usize = 16;

struct NetSemaphore {
    available: Mutex<usize>,
    changed: Condvar,
}

impl NetSemaphore {
    fn new(permits: usize) -> Self {
        Self { available: Mutex::new(permits), changed: Condvar::new() }
    }

    fn acquire(self: &Arc<Self>) -> NetPermit {
        let mut count = self.available.lock().unwrap_or_else(|p| p.into_inner());
        while *count == 0 {
            count = self.changed.wait(count).unwrap_or_else(|p| p.into_inner());
        }
        *count -= 1;
        NetPermit { sem: Arc::clone(self) }
    }
}

struct NetPermit {
    sem: Arc<NetSemaphore>,
}

impl Drop for NetPermit {
    fn drop(&mut self) {
        let mut count = self.sem.available.lock().unwrap_or_else(|p| p.into_inner());
        *count += 1;
        drop(count);
        self.sem.changed.notify_one();
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

struct PoolQueue {
    jobs: Mutex<(VecDeque<Job>, bool)>,
    ready: Condvar,
}

struct WorkerPool {
    queue: Arc<PoolQueue>,
}

impl WorkerPool {
    fn new(name: &str, threads: usize) -> Self {
        let queue = Arc::new(PoolQueue { jobs: Mutex::new((VecDeque::new(), false)), ready: Condvar::new() });
        for i in 0..threads {
            let queue = Arc::clone(&queue);
            thread::Builder::new()
                .name(format!("{name}-{i}"))
                .spawn(move || loop {
                    let job = {
                        let mut guard = lock_plain(&queue.jobs);
                        loop {
                            if let Some(job) = guard.0.pop_front() {
                                break Some(job);
                            }
                            if guard.1 {
                                break None;
                            }
                            guard = queue.ready.wait(guard).unwrap_or_else(|p| p.into_inner());
                        }
                    };
                    match job {
                        Some(job) => {
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                        }
                        None => break,
                    }
                })
                .expect("could not start a worker thread");
        }
        Self { queue }
    }

    fn run(&self, job: impl FnOnce() + Send + 'static) {
        lock_plain(&self.queue.jobs).0.push_back(Box::new(job));
        self.queue.ready.notify_one();
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        lock_plain(&self.queue.jobs).1 = true;
        self.queue.ready.notify_all();
    }
}

struct BurstPool {
    name: &'static str,
    cap: usize,
    state: Arc<Mutex<(usize, VecDeque<Job>)>>,
}

impl BurstPool {
    fn new(name: &'static str, cap: usize) -> Self {
        Self { name, cap, state: Arc::new(Mutex::new((0, VecDeque::new()))) }
    }

    fn run(&self, job: impl FnOnce() + Send + 'static) {
        let job: Job = Box::new(job);
        let mut st = lock_plain(&self.state);
        if st.0 >= self.cap {
            st.1.push_back(job);
            return;
        }
        st.0 += 1;
        drop(st);
        let state = Arc::clone(&self.state);
        let spawned = thread::Builder::new().name(self.name.to_string()).spawn(move || {
            let mut next = Some(job);
            while let Some(job) = next {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                let mut st = lock_plain(&state);
                next = st.1.pop_front();
                if next.is_none() {
                    st.0 -= 1;
                }
            }
        });
        if let Err(e) = spawned {
            error!("[lethean-cli] could not start a worker thread: {e}");
            lock_plain(&self.state).0 -= 1;
        }
    }
}

#[derive(Clone, Debug)]
pub struct FsOptions {
    pub scratch_dir: Option<PathBuf>,
    pub scratch_ram_bytes: u64,
    pub refresh_interval: Option<Duration>,
    pub prefetch: bool,
}

pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

impl Default for FsOptions {
    fn default() -> Self {
        Self { scratch_dir: None, scratch_ram_bytes: DEFAULT_POOL_BYTES, refresh_interval: Some(DEFAULT_REFRESH_INTERVAL), prefetch: true }
    }
}

enum NotifyMsg {
    Entry(u64, String),
    Inode(u64),
}

#[derive(Default)]
pub struct NotifyHub {
    tx: Mutex<Option<std::sync::mpsc::Sender<NotifyMsg>>>,
}

pub type NotifierSlot = Arc<NotifyHub>;

impl NotifyHub {
    pub fn attach(&self, notifier: fuser::Notifier) {
        let (tx, rx) = std::sync::mpsc::channel::<NotifyMsg>();
        let spawned = thread::Builder::new().name("lethean-notify".into()).spawn(move || {
            for msg in rx {
                let _ = match msg {
                    NotifyMsg::Entry(parent, name) => notifier.inval_entry(parent, std::ffi::OsStr::new(&name)),
                    NotifyMsg::Inode(ino) => notifier.inval_inode(ino, 0, 0),
                };
            }
        });
        if spawned.is_ok() {
            *lock_plain(&self.tx) = Some(tx);
        }
    }

    pub fn is_attached(&self) -> bool {
        lock_plain(&self.tx).is_some()
    }

    fn send(&self, msg: NotifyMsg) {
        if let Some(tx) = lock_plain(&self.tx).as_ref() {
            let _ = tx.send(msg);
        }
    }

    fn entry(&self, parent: u64, name: &str) {
        self.send(NotifyMsg::Entry(parent, name.to_string()));
    }

    fn inode(&self, ino: u64) {
        self.send(NotifyMsg::Inode(ino));
    }

    fn detach(&self) {
        lock_plain(&self.tx).take();
    }
}

const OPENDIR_SYNC_BUDGET: Duration = Duration::from_millis(300);
const OPENDIR_MAX_AGE: Duration = Duration::from_secs(2);

struct SyncCtl {
    running: bool,
    started: Option<Instant>,
    finished: Option<Instant>,
    last_duration: Duration,
    generation: u64,
    failing: bool,
}

struct Syncer {
    vault: Arc<Vault>,
    state: Arc<Mutex<FsState>>,
    notify: NotifierSlot,
    interval: Duration,
    ctl: Mutex<SyncCtl>,
    changed: Condvar,
    stop: AtomicBool,
}

impl Syncer {
    fn new(vault: Arc<Vault>, state: Arc<Mutex<FsState>>, notify: NotifierSlot, interval: Duration) -> Arc<Self> {
        Arc::new(Self {
            vault: Arc::clone(&vault),
            state,
            notify,
            interval,
            ctl: Mutex::new(SyncCtl { running: false, started: None, finished: Some(Instant::now()), last_duration: vault.last_listing_duration(), generation: 0, failing: false }),
            changed: Condvar::new(),
            stop: AtomicBool::new(false),
        })
    }

    fn min_gap(ctl: &SyncCtl, floor: Duration) -> Duration {
        floor.max(ctl.last_duration * 30)
    }

    fn start_locked(self: &Arc<Self>, ctl: &mut SyncCtl) -> u64 {
        let target = ctl.generation + 1;
        if ctl.running {
            return target;
        }
        ctl.running = true;
        ctl.started = Some(Instant::now());
        let me = Arc::clone(self);
        let spawned = thread::Builder::new().name("lethean-sync".into()).spawn(move || me.run_once());
        if spawned.is_err() {
            ctl.running = false;
        }
        target
    }

    fn kick_if_stale(self: &Arc<Self>, max_age: Duration, budget: Duration) -> Option<(u64, Instant)> {
        if self.stop.load(Ordering::Acquire) {
            return None;
        }
        let mut ctl = lock_plain(&self.ctl);
        if !ctl.running {
            let gap = Self::min_gap(&ctl, max_age);
            if ctl.finished.map(|t| t.elapsed() < gap).unwrap_or(false) {
                return None;
            }
            self.start_locked(&mut ctl);
        }
        let expected = ctl.last_duration.max(self.vault.last_listing_duration());
        if expected > budget {
            return None;
        }
        let started = ctl.started.unwrap_or_else(Instant::now);
        Some((ctl.generation + 1, started + budget))
    }

    fn wait_until(&self, generation: u64, deadline: Instant) {
        let mut ctl = lock_plain(&self.ctl);
        while ctl.generation < generation && !self.stop.load(Ordering::Acquire) {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            ctl = self.changed.wait_timeout(ctl, deadline - now).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
        }
    }

    fn run_once(&self) {
        let t = Instant::now();
        let result = run_guarded("refresh", || self.vault.sync().map_err(|e| {
            let first = !lock_plain(&self.ctl).failing;
            if first {
                warn!("[lethean-cli] could not check the vault for changes made elsewhere (will keep trying): {e:#}");
            }
            EIO
        }));
        let ok = result.is_ok();
        if let Ok(report) = result {
            if !report.is_empty() {
                self.apply(&report);
            }
        }
        if ok {
            self.heal();
        }
        let mut ctl = lock_plain(&self.ctl);
        ctl.running = false;
        ctl.generation += 1;
        ctl.finished = Some(Instant::now());
        ctl.last_duration = t.elapsed();
        if ok && ctl.failing {
            log::info!("[lethean-cli] reconnected; changes made elsewhere are showing again");
        }
        ctl.failing = !ok;
        drop(ctl);
        self.changed.notify_all();
    }

    fn apply(&self, report: &SyncReport) {
        let mut entries: Vec<(u64, String)> = Vec::new();
        let mut inodes: Vec<u64> = Vec::new();
        {
            let mut st = lock_state(&self.state);
            for (old, new, same_content) in &report.aliases {
                let Some(&ino) = st.ino_of_id.get(old) else { continue };
                if st.ino_of_id.contains_key(new) {
                    continue;
                }
                repoint_ino_to(&mut st, ino, Some(old), new);
                if let Some(w) = st.writers.get(&ino) {
                    let mut t = lock_plain(&w.file.target);
                    if let WriteTarget::ExistingFile { id, save_as } = &mut *t {
                        if id == old {
                            *id = new.clone();
                            *save_as = save_as_for(&self.vault, new);
                        }
                    }
                }
                if *same_content {
                    if st.cached_content.get(&ino) == Some(old) {
                        st.cached_content.insert(ino, new.clone());
                    }
                } else {
                    st.cached_content.remove(&ino);
                    inodes.push(ino);
                }
            }
            for id in &report.modified {
                if let Some(&ino) = st.ino_of_id.get(id) {
                    st.cached_content.remove(&ino);
                    inodes.push(ino);
                }
            }
            for id in &report.removed {
                if let Some(&ino) = st.ino_of_id.get(id) {
                    st.cached_content.remove(&ino);
                }
            }
            for (pk, name) in &report.touched_names {
                let parent = if pk.is_empty() { Some(ROOT_INO) } else { st.ino_of_id.get(pk).copied() };
                if let Some(p) = parent {
                    entries.push((p, name.clone()));
                }
            }
        }
        for (p, name) in entries {
            self.notify.entry(p, &name);
        }
        for ino in inodes {
            self.notify.inode(ino);
        }
    }

    fn heal(&self) {
        if let Ok(report) = run_guarded("cleanup", || Ok::<_, c_int>(self.vault.heal_pending())) {
            if !report.is_empty() {
                self.apply(&report);
            }
        }
    }

    fn background(self: Arc<Self>) {
        self.heal();
        loop {
            {
                let mut ctl = lock_plain(&self.ctl);
                loop {
                    if self.stop.load(Ordering::Acquire) {
                        return;
                    }
                    let gap = Self::min_gap(&ctl, self.interval);
                    let due = ctl.finished.map(|t| t + gap).unwrap_or_else(Instant::now);
                    let now = Instant::now();
                    if !ctl.running && now >= due {
                        break;
                    }
                    let wait = if ctl.running { gap } else { due - now };
                    ctl = self.changed.wait_timeout(ctl, wait).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
                }
                self.start_locked(&mut ctl);
            }
        }
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        self.changed.notify_all();
    }
}

#[derive(Default)]
struct ScanTracker {
    dir: Option<String>,
    seen: Vec<String>,
    last: Option<Instant>,
    running: std::collections::HashSet<String>,
}

const SCAN_WINDOW: Duration = Duration::from_secs(3);
const SCAN_TRIGGER: usize = 3;
const PREFETCH_MAX_FILE: u64 = 2 * 1024 * 1024;
const PREFETCH_MAX_BYTES: u64 = 16 * 1024 * 1024;
const PREFETCH_MAX_FILES: usize = 256;
const PREFETCH_PARALLELISM: usize = 8;

fn prefetch_dir(vault: &Vault, stop: &AtomicBool, dir: Option<&str>, after_name: &str) {
    let kids = vault.list_children(dir);
    let start = kids.iter().position(|c| c.name.as_str() == after_name).map(|i| i + 1).unwrap_or(0);
    let mut picked = Vec::new();
    let mut bytes = 0u64;
    for child in &kids[start..] {
        if child.is_folder || child.name == after_name {
            continue;
        }
        let Some(info) = vault.read_info(&child.id) else { continue };
        if info.large || info.size > PREFETCH_MAX_FILE || vault.cached_small(&child.id).is_some() {
            continue;
        }
        if bytes + info.size > PREFETCH_MAX_BYTES || picked.len() >= PREFETCH_MAX_FILES {
            break;
        }
        bytes += info.size;
        picked.push(child.id.clone());
    }
    if picked.is_empty() {
        return;
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    thread::scope(|s| {
        for _ in 0..PREFETCH_PARALLELISM.min(picked.len()) {
            s.spawn(|| loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(id) = picked.get(i) else { return };
                if let Err(e) = vault.download_arc(id) {
                    log::debug!("[lethean-cli] prefetch skipped a file: {e:#}");
                }
            });
        }
    });
}

pub fn default_scratch_dir() -> PathBuf {
    crate::scratch::default_dir()
}

pub struct VaultFs {
    vault: Arc<Vault>,
    state: Arc<Mutex<FsState>>,
    ctx: AttrCtx,
    net_sem: Arc<NetSemaphore>,
    pool: Arc<ScratchPool>,
    net_workers: BurstPool,
    io_workers: WorkerPool,
    notify: NotifierSlot,
    refresh_interval: Option<Duration>,
    syncer: Option<Arc<Syncer>>,
    prefetch: bool,
    scan: Arc<Mutex<ScanTracker>>,
    stop: Arc<AtomicBool>,
}

fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" | "log" | "cfg" | "conf" | "ini" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn name_str(name: &std::ffi::OsStr) -> Result<&str, c_int> {
    name.to_str().ok_or(EINVAL)
}

fn dir_id_of_ino(state: &FsState, vault: &Vault, ino: u64) -> Result<Option<String>, c_int> {
    match state.node_of_ino.get(&ino) {
        Some(Node::Root) => Ok(None),
        Some(Node::Remote(id)) => match vault.stat(id) {
            Some(s) if s.is_folder => Ok(Some(id.clone())),
            Some(_) => Err(ENOTDIR),
            None => Err(ENOENT),
        },
        Some(Node::Pending(_)) => Err(ENOTDIR),
        None => Err(ENOENT),
    }
}

fn hashed_ino(id: &str, salt: u64) -> u64 {
    let mut h = DefaultHasher::new();
    salt.hash(&mut h);
    id.hash(&mut h);
    (h.finish() & ((1u64 << 62) - 1)) | (1u64 << 62)
}

fn ino_for_remote(state: &mut FsState, id: &str) -> u64 {
    if let Some(&ino) = state.ino_of_id.get(id) {
        return ino;
    }
    let mut salt = 0;
    loop {
        let ino = hashed_ino(id, salt);
        match state.node_of_ino.get(&ino) {
            Some(Node::Remote(other)) if other == id => {}
            Some(_) => {
                salt += 1;
                continue;
            }
            None => {
                state.node_of_ino.insert(ino, Node::Remote(id.to_string()));
            }
        }
        state.ino_of_id.insert(id.to_string(), ino);
        return ino;
    }
}

fn peek_ino(state: &FsState, id: &str) -> u64 {
    state.ino_of_id.get(id).copied().unwrap_or_else(|| hashed_ino(id, 0))
}

fn add_lookup(state: &mut FsState, ino: u64) {
    *state.lookups.entry(ino).or_insert(0) += 1;
}

fn repoint_ino_to(state: &mut FsState, ino: u64, old_id: Option<&str>, new_id: &str) {
    if let Some(old) = old_id {
        if state.ino_of_id.get(old) == Some(&ino) {
            state.ino_of_id.remove(old);
        }
    }
    if let Some(Node::Pending(p)) = state.node_of_ino.get(&ino) {
        let key = (p.parent_id.clone(), p.name.clone());
        state.pending_by_key.remove(&key);
    }
    state.ino_of_id.insert(new_id.to_string(), ino);
    state.node_of_ino.insert(ino, Node::Remote(new_id.to_string()));
    if let Some(old) = old_id {
        if old != new_id {
            for h in state.handles.values_mut() {
                if let Handle::Read { id, .. } = h {
                    if id == old {
                        *id = new_id.to_string();
                    }
                }
            }
        }
    }
}

fn alloc_fh(state: &mut FsState) -> u64 {
    let fh = state.next_fh;
    state.next_fh += 1;
    fh
}

fn make_attr(ctx: AttrCtx, ino: u64, kind: FileType, size: u64, perm: u16) -> FileAttr {
    let blocks = size.div_ceil(512).max(if size == 0 { 0 } else { 1 });
    FileAttr {
        ino,
        size,
        blocks,
        atime: ctx.mount_time,
        mtime: ctx.mount_time,
        ctime: ctx.mount_time,
        crtime: ctx.mount_time,
        kind,
        perm,
        nlink: 1,
        uid: ctx.uid,
        gid: ctx.gid,
        rdev: 0,
        blksize: 65536,
        flags: 0,
    }
}

fn dir_attr(ctx: AttrCtx, ino: u64) -> FileAttr {
    make_attr(ctx, ino, FileType::Directory, 0, 0o700)
}

fn file_attr(ctx: AttrCtx, ino: u64, size: u64) -> FileAttr {
    make_attr(ctx, ino, FileType::RegularFile, size, 0o600)
}

fn attr_from_stat(state: &FsState, ctx: AttrCtx, ino: u64, stat: Stat) -> FileAttr {
    if stat.is_folder {
        dir_attr(ctx, ino)
    } else {
        let live_size = state.writers.get(&ino).map(|w| w.file.len.load(Ordering::Acquire));
        file_attr(ctx, ino, live_size.unwrap_or(stat.size))
    }
}

fn attr_for_known_ino(state: &FsState, vault: &Vault, ctx: AttrCtx, ino: u64) -> Option<FileAttr> {
    match state.node_of_ino.get(&ino)? {
        Node::Root => Some(dir_attr(ctx, ino)),
        Node::Remote(id) => Some(attr_from_stat(state, ctx, ino, vault.stat(id)?)),
        Node::Pending(_) => {
            let live_size = state.writers.get(&ino).map(|w| w.file.len.load(Ordering::Acquire));
            Some(file_attr(ctx, ino, live_size.unwrap_or(0)))
        }
    }
}

fn attach_writer(state: &mut FsState, ino: u64, file: Arc<WriteFile>) -> Arc<WriteFile> {
    let entry = state.writers.entry(ino).or_insert_with(|| Writer { file, handles: 0 });
    entry.handles += 1;
    Arc::clone(&entry.file)
}

fn new_write_file(scratch: Scratch, target: WriteTarget) -> Arc<WriteFile> {
    let len = scratch.len_handle();
    Arc::new(WriteFile { target: Mutex::new(target), scratch: Arc::new(Mutex::new(scratch)), len, commit_lock: Mutex::new(()) })
}

fn commit_write_session(vault: &Vault, state: &Mutex<FsState>, notify: &NotifyHub, fh: u64) -> bool {
    let (ino, file) = {
        let st = lock_state(state);
        match st.handles.get(&fh) {
            Some(Handle::Write { ino }) => match st.writers.get(ino) {
                Some(w) => (*ino, Arc::clone(&w.file)),
                None => return true,
            },
            _ => return true,
        }
    };
    commit_write_file(vault, state, notify, ino, &file)
}

fn commit_write_file(vault: &Vault, state: &Mutex<FsState>, notify: &NotifyHub, ino: u64, file: &Arc<WriteFile>) -> bool {
    let _serial = lock_plain(&file.commit_lock);

    let (generation, len) = {
        let s = lock_scratch(&file.scratch);
        if !s.is_dirty() {
            return true;
        }
        (s.generation(), s.len())
    };
    let target = lock_plain(&file.target).clone();

    let factory = || {
        let reader: Box<dyn Read + '_> = Box::new(ScratchReader::new(Arc::clone(&file.scratch), len));
        Ok(reader)
    };

    let mut saved_elsewhere: Option<(Option<String>, String, String)> = None;
    let result = match &target {
        WriteTarget::Discarded => {
            lock_scratch(&file.scratch).mark_committed(generation);
            return true;
        }
        WriteTarget::NewFile { parent_id, name, mime } => {
            let save_name = free_name(vault, parent_id.as_deref(), name);
            if save_name != *name {
                warn!("[lethean-cli] \"{name}\" was created elsewhere while it was being written here; your version is saved as \"{save_name}\"");
                saved_elsewhere = Some((parent_id.clone(), name.clone(), save_name.clone()));
            }
            vault.create_file_streaming(&save_name, mime, len, parent_id.as_deref(), factory)
        }
        WriteTarget::ExistingFile { id, save_as } => {
            if vault.stat(id).is_none() {
                let parent = save_as.parent_id.clone().filter(|p| vault.stat(p).map(|s| s.is_folder).unwrap_or(false));
                let name = free_name(vault, parent.as_deref(), &save_as.name);
                if name != save_as.name {
                    warn!("[lethean-cli] \"{}\" was changed elsewhere while it was open here; your version is saved as \"{name}\"", save_as.name);
                } else {
                    warn!("[lethean-cli] \"{name}\" was removed elsewhere while it was open here; saving your version again");
                }
                saved_elsewhere = Some((parent.clone(), save_as.name.clone(), name.clone()));
                vault.create_file_streaming(&name, &save_as.mime, len, parent.as_deref(), factory)
            } else {
                vault.replace_content_streaming(id, len, factory)
            }
        }
    };

    match result {
        Ok(new_entry) => {
            lock_scratch(&file.scratch).mark_committed(generation);
            let old_id = match &target {
                WriteTarget::ExistingFile { id, .. } => Some(id.clone()),
                _ => None,
            };
            let new_id = new_entry.record.id.clone();
            *lock_plain(&file.target) = existing_target(vault, new_id.clone());
            let mut st = lock_state(state);
            repoint_ino_to(&mut st, ino, old_id.as_deref(), &new_id);
            if let Some((parent, original, saved_as)) = saved_elsewhere {
                let pino = match &parent {
                    None => Some(ROOT_INO),
                    Some(p) => st.ino_of_id.get(p).copied(),
                };
                drop(st);
                if let Some(p) = pino {
                    notify.entry(p, &original);
                    notify.entry(p, &saved_as);
                }
            }
            true
        }
        Err(e) => {
            error!("[lethean-cli] failed to save changes: {e:#}");
            false
        }
    }
}

fn truncate_remote(vault: &Vault, pool: &Arc<ScratchPool>, id: &str, new_size: u64) -> anyhow::Result<crate::vault::Entry> {
    if new_size == 0 {
        return vault.replace_content(id, &[]);
    }
    let mut scratch = pool.new_scratch();
    vault.stream_plaintext(id, &mut ScratchWriter::new(&mut scratch))?;
    scratch.set_len(new_size)?;
    let shared = Arc::new(Mutex::new(scratch));
    vault.replace_content_streaming(id, new_size, || {
        let reader: Box<dyn Read + '_> = Box::new(ScratchReader::new(Arc::clone(&shared), new_size));
        Ok(reader)
    })
}

fn slice_reply(data: &[u8], offset: u64, size: usize) -> &[u8] {
    let start = (offset as usize).min(data.len());
    let end = start.saturating_add(size).min(data.len());
    &data[start..end]
}

fn build_listing(state: &FsState, vault: &Vault, ino: u64, dir_id: Option<&str>) -> Vec<DirEntry> {
    let children = vault.list_children(dir_id);
    let mut entries = Vec::with_capacity(children.len() + 2);
    entries.push(DirEntry { ino, kind: FileType::Directory, name: ".".to_string(), id: None });
    entries.push(DirEntry { ino: ROOT_INO, kind: FileType::Directory, name: "..".to_string(), id: None });
    let mut seen: std::collections::HashSet<String> = [".".to_string(), "..".to_string()].into_iter().collect();
    for ((parent, name), pino) in &state.pending_by_key {
        if parent.as_deref() == dir_id && seen.insert(name.clone()) {
            entries.push(DirEntry { ino: *pino, kind: FileType::RegularFile, name: name.clone(), id: None });
        }
    }
    for child in children {
        if !seen.insert(child.name.clone()) {
            continue;
        }
        entries.push(DirEntry { ino: peek_ino(state, &child.id), kind: if child.is_folder { FileType::Directory } else { FileType::RegularFile }, name: child.name, id: Some(child.id) });
    }
    entries
}

fn listing_for(state: &mut FsState, vault: &Vault, ino: u64, fh: u64, offset: i64) -> Result<Arc<Vec<DirEntry>>, c_int> {
    if offset > 0 {
        if let Some(l) = state.dir_handles.get(&fh) {
            return Ok(Arc::clone(l));
        }
    }
    let dir_id = dir_id_of_ino(state, vault, ino)?;
    let listing = Arc::new(build_listing(state, vault, ino, dir_id.as_deref()));
    state.dir_handles.insert(fh, Arc::clone(&listing));
    Ok(listing)
}

impl VaultFs {
    pub fn new(vault: Vault) -> Self {
        Self::with_options(vault, FsOptions::default())
    }

    pub fn with_options(mut vault: Vault, options: FsOptions) -> Self {
        let mut node_of_ino = HashMap::new();
        node_of_ino.insert(ROOT_INO, Node::Root);
        let scratch_dir = options.scratch_dir.unwrap_or_else(default_scratch_dir);
        let pool = ScratchPool::new(options.scratch_ram_bytes, scratch_dir);
        vault.set_scratch_pool(Arc::clone(&pool));
        vault.set_deferred_deletes(true);
        Self {
            vault: Arc::new(vault),
            state: Arc::new(Mutex::new(FsState {
                ino_of_id: HashMap::new(),
                node_of_ino,
                lookups: HashMap::new(),
                next_ino: 2,
                handles: HashMap::new(),
                dir_handles: HashMap::new(),
                next_fh: 1,
                pending_by_key: HashMap::new(),
                writers: HashMap::new(),
                cached_content: HashMap::new(),
            })),
            ctx: AttrCtx { uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() }, mount_time: SystemTime::now() },
            net_sem: Arc::new(NetSemaphore::new(MAX_CONCURRENT_NETWORK_OPS)),
            pool,
            net_workers: BurstPool::new("lethean-net", NET_WORKERS),
            io_workers: WorkerPool::new("lethean-io", IO_WORKERS),
            notify: Arc::new(NotifyHub::default()),
            refresh_interval: options.refresh_interval.filter(|d| !d.is_zero()),
            syncer: None,
            prefetch: options.prefetch,
            scan: Arc::new(Mutex::new(ScanTracker::default())),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        self.vault.refresh_all()
    }

    pub fn notifier_slot(&self) -> NotifierSlot {
        Arc::clone(&self.notify)
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(s) = self.syncer.take() {
            s.shutdown();
        }
        self.notify.detach();
    }

    fn kick_sync(&self) -> Option<(Arc<Syncer>, u64, Instant)> {
        let syncer = self.syncer.as_ref()?;
        let (generation, deadline) = syncer.kick_if_stale(OPENDIR_MAX_AGE, OPENDIR_SYNC_BUDGET)?;
        Some((Arc::clone(syncer), generation, deadline))
    }

    fn note_read_open(&self, id: &str) {
        if !self.prefetch {
            return;
        }
        let Some(info) = self.vault.read_info(id) else { return };
        if info.large || info.size > PREFETCH_MAX_FILE {
            return;
        }
        let Some(parent) = self.vault.parent_of(id) else { return };
        if parent.as_deref() == Some(UNRESOLVED_PARENT) {
            return;
        }
        let key = parent.clone().unwrap_or_default();
        let trigger = {
            let mut scan = lock_plain(&self.scan);
            let now = Instant::now();
            let same_dir = scan.dir.as_deref() == Some(key.as_str()) && scan.last.map(|t| now - t < SCAN_WINDOW).unwrap_or(false);
            if !same_dir {
                scan.dir = Some(key.clone());
                scan.seen.clear();
            }
            scan.last = Some(now);
            if scan.seen.len() < SCAN_TRIGGER && !scan.seen.iter().any(|s| s == id) {
                scan.seen.push(id.to_string());
            }
            if scan.seen.len() >= SCAN_TRIGGER && !scan.running.contains(&key) && self.vault.cached_small(id).is_none() {
                scan.running.insert(key.clone());
                true
            } else {
                false
            }
        };
        if !trigger {
            return;
        }
        let name = self.vault.entry(id).map(|e| e.fs_name().to_string()).unwrap_or_default();
        let vault = Arc::clone(&self.vault);
        let stop = Arc::clone(&self.stop);
        let scan = Arc::clone(&self.scan);
        let spawned = thread::Builder::new().name("lethean-prefetch".into()).spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prefetch_dir(&vault, &stop, parent.as_deref(), &name)));
            lock_plain(&scan).running.remove(&key);
        });
        if spawned.is_err() {
            lock_plain(&self.scan).running.clear();
        }
    }
}

impl Drop for VaultFs {
    fn drop(&mut self) {
        self.shutdown();
        self.vault.close();
    }
}

impl Filesystem for VaultFs {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        if let Err(max) = config.set_max_readahead(1024 * 1024) {
            let _ = config.set_max_readahead(max);
        }
        let _ = config.add_capabilities(fuser::consts::FUSE_DO_READDIRPLUS);
        if let Err(max) = config.set_max_background(64) {
            let _ = config.set_max_background(max);
        }
        if let Some(interval) = self.refresh_interval {
            let syncer = Syncer::new(Arc::clone(&self.vault), Arc::clone(&self.state), Arc::clone(&self.notify), interval);
            let bg = Arc::clone(&syncer);
            if thread::Builder::new().name("lethean-refresh".into()).spawn(move || bg.background()).is_ok() {
                self.syncer = Some(syncer);
            }
        }
        Ok(())
    }

    fn destroy(&mut self) {
        self.shutdown();
        self.vault.flush_pending_deletes();
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name = match name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let mut state = lock_state(&self.state);
        let parent_id = match dir_id_of_ino(&state, &self.vault, parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };

        if let Some(&ino) = state.pending_by_key.get(&(parent_id.clone(), name.to_string())) {
            if let Some(attr) = attr_for_known_ino(&state, &self.vault, self.ctx, ino) {
                add_lookup(&mut state, ino);
                return reply.entry(&TTL, &attr, 0);
            }
        }

        let Some(child) = self.vault.find_child(parent_id.as_deref(), name) else {
            drop(state);
            let _ = self.kick_sync();
            return reply.error(ENOENT);
        };
        let ino = ino_for_remote(&mut state, &child.record.id);
        let stat = Stat { is_folder: child.is_folder(), size: child.size(), size_is_exact: child.size_is_exact() };
        let attr = attr_from_stat(&state, self.ctx, ino, stat);
        add_lookup(&mut state, ino);
        reply.entry(&TTL, &attr, 0)
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        if ino == ROOT_INO {
            return;
        }
        let mut state = lock_state(&self.state);
        let remaining = match state.lookups.get_mut(&ino) {
            Some(n) => {
                *n = n.saturating_sub(nlookup);
                *n
            }
            None => 0,
        };
        if remaining > 0 {
            return;
        }
        state.lookups.remove(&ino);
        if state.writers.contains_key(&ino) {
            return;
        }
        if let Some(Node::Remote(id)) = state.node_of_ino.get(&ino) {
            let id = id.clone();
            state.node_of_ino.remove(&ino);
            if state.ino_of_id.get(&id) == Some(&ino) {
                state.ino_of_id.remove(&id);
            }
            state.cached_content.remove(&ino);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let state = lock_state(&self.state);
        match attr_for_known_ino(&state, &self.vault, self.ctx, ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(new_size) = size else {
            let state = lock_state(&self.state);
            return match attr_for_known_ino(&state, &self.vault, self.ctx, ino) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(ENOENT),
            };
        };

        let writer = { lock_state(&self.state).writers.get(&ino).map(|w| Arc::clone(&w.file)) };
        if let Some(file) = writer {
            let result = lock_scratch(&file.scratch).set_len(new_size);
            if let Err(e) = result {
                error!("[lethean-cli] truncate failed: {e}");
                return reply.error(errno_of_io(&e));
            }
            let state = lock_state(&self.state);
            return match attr_for_known_ino(&state, &self.vault, self.ctx, ino) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(ENOENT),
            };
        }

        let node = { lock_state(&self.state).node_of_ino.get(&ino).cloned() };
        let Some(Node::Remote(id)) = node else {
            let state = lock_state(&self.state);
            return match attr_for_known_ino(&state, &self.vault, self.ctx, ino) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(ENOENT),
            };
        };

        match self.vault.stat(&id) {
            Some(s) if s.is_folder => return reply.error(EISDIR),
            Some(_) => {}
            None => return reply.error(ENOENT),
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let ctx = self.ctx;
        let net_sem = Arc::clone(&self.net_sem);
        let pool = Arc::clone(&self.pool);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("truncate", move || {
                let new_entry = truncate_remote(&vault, &pool, &id, new_size).map_err(|e| {
                    error!("[lethean-cli] truncate failed: {e:#}");
                    errno_of(&e)
                })?;
                let mut state = lock_state(&state_arc);
                repoint_ino_to(&mut state, ino, Some(&id), &new_entry.record.id);
                attr_for_known_ino(&state, &vault, ctx, ino).ok_or(ENOENT)
            });
            match outcome {
                Ok(attr) => reply.attr(&TTL, &attr),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        let name = match name_str(name) {
            Ok(n) => n.to_string(),
            Err(e) => return reply.error(e),
        };
        let parent_id = {
            let state = lock_state(&self.state);
            match dir_id_of_ino(&state, &self.vault, parent) {
                Ok(p) => p,
                Err(e) => return reply.error(e),
            }
        };
        if self.vault.find_child(parent_id.as_deref(), &name).is_some() {
            return reply.error(EEXIST);
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let ctx = self.ctx;
        let net_sem = Arc::clone(&self.net_sem);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("mkdir", move || {
                let entry = vault.create_folder(&name, parent_id.as_deref()).map_err(|e| {
                    error!("[lethean-cli] mkdir failed: {e:#}");
                    EIO
                })?;
                let mut state = lock_state(&state_arc);
                let ino = ino_for_remote(&mut state, &entry.record.id);
                let attr = attr_for_known_ino(&state, &vault, ctx, ino).ok_or(EIO)?;
                add_lookup(&mut state, ino);
                Ok(attr)
            });
            match outcome {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let name = match name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = {
            let state = lock_state(&self.state);
            match dir_id_of_ino(&state, &self.vault, parent) {
                Ok(p) => p,
                Err(e) => return reply.error(e),
            }
        };

        {
            let mut state = lock_state(&self.state);
            if let Some(ino) = state.pending_by_key.remove(&(parent_id.clone(), name.to_string())) {
                state.node_of_ino.remove(&ino);
                if let Some(w) = state.writers.get(&ino) {
                    *lock_plain(&w.file.target) = WriteTarget::Discarded;
                }
                return reply.ok();
            }
        }

        let entry = match self.vault.find_child(parent_id.as_deref(), name) {
            Some(e) => e,
            None => return reply.error(ENOENT),
        };
        if entry.is_folder() {
            return reply.error(EISDIR);
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let id = entry.record.id.clone();
        let net_sem = Arc::clone(&self.net_sem);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("unlink", move || {
                vault.delete_one(&id).map_err(|e| {
                    error!("[lethean-cli] unlink failed: {e:#}");
                    EIO
                })?;
                let mut state = lock_state(&state_arc);
                if let Some(ino) = state.ino_of_id.remove(&id) {
                    state.cached_content.remove(&ino);
                    if let Some(w) = state.writers.get(&ino) {
                        *lock_plain(&w.file.target) = WriteTarget::Discarded;
                    }
                }
                Ok(())
            });
            match outcome {
                Ok(()) => reply.ok(),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let name = match name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = {
            let state = lock_state(&self.state);
            match dir_id_of_ino(&state, &self.vault, parent) {
                Ok(p) => p,
                Err(e) => return reply.error(e),
            }
        };
        let entry = match self.vault.find_child(parent_id.as_deref(), name) {
            Some(e) => e,
            None => return reply.error(ENOENT),
        };
        if !entry.is_folder() {
            return reply.error(ENOTDIR);
        }
        let has_pending_children = {
            let state = lock_state(&self.state);
            state.pending_by_key.keys().any(|(p, _)| p.as_deref() == Some(entry.record.id.as_str()))
        };
        if self.vault.has_children(&entry.record.id) || has_pending_children {
            return reply.error(ENOTEMPTY);
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let id = entry.record.id.clone();
        let net_sem = Arc::clone(&self.net_sem);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("rmdir", move || {
                vault.delete_one(&id).map_err(|e| {
                    error!("[lethean-cli] rmdir failed: {e:#}");
                    EIO
                })?;
                lock_state(&state_arc).ino_of_id.remove(&id);
                Ok(())
            });
            match outcome {
                Ok(()) => reply.ok(),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, newparent: u64, newname: &std::ffi::OsStr, flags: u32, reply: ReplyEmpty) {
        if flags & !RENAME_NOREPLACE_FLAG != 0 {
            return reply.error(EINVAL);
        }
        let name = match name_str(name) {
            Ok(n) => n.to_string(),
            Err(e) => return reply.error(e),
        };
        let newname = match name_str(newname) {
            Ok(n) => n.to_string(),
            Err(e) => return reply.error(e),
        };
        let (parent_id, new_parent_id) = {
            let state = lock_state(&self.state);
            let p = match dir_id_of_ino(&state, &self.vault, parent) {
                Ok(p) => p,
                Err(e) => return reply.error(e),
            };
            let np = match dir_id_of_ino(&state, &self.vault, newparent) {
                Ok(p) => p,
                Err(e) => return reply.error(e),
            };
            (p, np)
        };
        let entry = match self.vault.find_child(parent_id.as_deref(), &name) {
            Some(e) => e,
            None => return reply.error(ENOENT),
        };
        let existing = self.vault.find_child(new_parent_id.as_deref(), &newname).filter(|e| e.record.id != entry.record.id);
        let pending_target = lock_state(&self.state).pending_by_key.contains_key(&(new_parent_id.clone(), newname.clone()));
        if (existing.is_some() || pending_target) && flags & RENAME_NOREPLACE_FLAG != 0 {
            return reply.error(EEXIST);
        }
        if pending_target {
            return reply.error(libc::EBUSY);
        }
        if let Some(target) = &existing {
            match (entry.is_folder(), target.is_folder()) {
                (true, false) => return reply.error(ENOTDIR),
                (false, true) => return reply.error(EISDIR),
                (true, true) => {
                    let has_pending = lock_state(&self.state).pending_by_key.keys().any(|(p, _)| p.as_deref() == Some(target.record.id.as_str()));
                    if self.vault.has_children(&target.record.id) || has_pending {
                        return reply.error(ENOTEMPTY);
                    }
                }
                (false, false) => {}
            }
        }
        if entry.is_folder() {
            if let Some(np) = new_parent_id.as_deref() {
                if np == entry.record.id || self.vault.descendant_ids(&entry.record.id).iter().any(|d| d == np) {
                    return reply.error(EINVAL);
                }
            }
        }
        let existing_id_to_replace = existing.map(|e| e.record.id.clone());

        let name_changed = if name == newname { None } else { Some(newname) };
        let parent_changed = if parent_id == new_parent_id { None } else { Some(new_parent_id) };

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let entry_id = entry.record.id.clone();
        let net_sem = Arc::clone(&self.net_sem);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("rename", move || {
                let parent_changed_ref = parent_changed.as_ref().map(|p| p.as_deref());
                let new_entry = vault.rename_or_move(&entry_id, name_changed.as_deref(), parent_changed_ref).map_err(|e| {
                    error!("[lethean-cli] rename failed: {e:#}");
                    EIO
                })?;
                if let Some(existing_id) = &existing_id_to_replace {
                    match vault.delete_one(existing_id) {
                        Ok(()) => {
                            let mut state = lock_state(&state_arc);
                            if let Some(ino) = state.ino_of_id.remove(existing_id) {
                                state.cached_content.remove(&ino);
                                if let Some(w) = state.writers.get(&ino) {
                                    *lock_plain(&w.file.target) = WriteTarget::Discarded;
                                }
                            }
                        }
                        Err(e) => warn!("[lethean-cli] rename: the replaced item could not be removed and is still there: {e:#}"),
                    }
                }
                let mut state = lock_state(&state_arc);
                if let Some(&ino) = state.ino_of_id.get(&entry_id) {
                    repoint_ino_to(&mut state, ino, Some(&entry_id), &new_entry.record.id);
                    if let Some(w) = state.writers.get(&ino) {
                        let mut t = lock_plain(&w.file.target);
                        if let WriteTarget::ExistingFile { id, save_as } = &mut *t {
                            if *id == entry_id {
                                *id = new_entry.record.id.clone();
                                *save_as = save_as_for(&vault, &new_entry.record.id);
                            }
                        }
                    }
                }
                Ok(())
            });
            match outcome {
                Ok(()) => reply.ok(),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let accmode = flags & O_ACCMODE;
        let node = {
            let state = lock_state(&self.state);
            state.node_of_ino.get(&ino).cloned()
        };
        let node = match node {
            Some(n) => n,
            None => return reply.error(ENOENT),
        };

        match node {
            Node::Root => reply.error(EISDIR),
            Node::Pending(_) => {
                let mut state = lock_state(&self.state);
                if !state.writers.contains_key(&ino) {
                    return reply.error(EIO);
                }
                let existing = Arc::clone(&state.writers[&ino].file);
                attach_writer(&mut state, ino, existing);
                let fh = alloc_fh(&mut state);
                state.handles.insert(fh, Handle::Write { ino });
                drop(state);
                reply.opened(fh, 0);
            }
            Node::Remote(id) => {
                let stat = match self.vault.stat(&id) {
                    Some(s) => s,
                    None => return reply.error(ENOENT),
                };
                if stat.is_folder {
                    return reply.error(EISDIR);
                }

                if accmode == libc::O_RDONLY {
                    let mut state = lock_state(&self.state);
                    let open_flags = if !stat.size_is_exact {
                        FOPEN_DIRECT_IO
                    } else if state.writers.contains_key(&ino) {
                        0
                    } else if state.cached_content.get(&ino) == Some(&id) {
                        FOPEN_KEEP_CACHE
                    } else {
                        state.cached_content.insert(ino, id.clone());
                        0
                    };
                    let fh = alloc_fh(&mut state);
                    state.handles.insert(fh, Handle::Read { id: id.clone(), pinned: None });
                    drop(state);
                    reply.opened(fh, open_flags);
                    self.note_read_open(&id);
                    return;
                }

                {
                    let mut state = lock_state(&self.state);
                    if let Some(existing) = state.writers.get(&ino).map(|w| Arc::clone(&w.file)) {
                        let file = attach_writer(&mut state, ino, existing);
                        let fh = alloc_fh(&mut state);
                        state.handles.insert(fh, Handle::Write { ino });
                        drop(state);
                        if flags & O_TRUNC != 0 {
                            let mut s = lock_scratch(&file.scratch);
                            let _ = s.set_len(0);
                        }
                        return reply.opened(fh, 0);
                    }
                }

                if flags & O_TRUNC != 0 {
                    let mut scratch = self.pool.new_scratch();
                    scratch.mark_dirty();
                    let file = new_write_file(scratch, existing_target(&self.vault, id));
                    let mut state = lock_state(&self.state);
                    attach_writer(&mut state, ino, file);
                    let fh = alloc_fh(&mut state);
                    state.handles.insert(fh, Handle::Write { ino });
                    drop(state);
                    return reply.opened(fh, 0);
                }

                let vault = Arc::clone(&self.vault);
                let state_arc = Arc::clone(&self.state);
                let net_sem = Arc::clone(&self.net_sem);
                let pool = Arc::clone(&self.pool);
                self.net_workers.run(move || {
                    let _permit = net_sem.acquire();
                    let outcome = run_guarded("open", move || {
                        let mut scratch = pool.new_scratch();
                        vault.stream_plaintext(&id, &mut ScratchWriter::new(&mut scratch)).map_err(|e| {
                            let name = vault.entry(&id).map(|e| e.name().to_string()).unwrap_or_default();
                            error!("[lethean-cli] could not load \"{name}\" for writing: {e:#}");
                            errno_of(&e)
                        })?;
                        scratch.mark_committed(scratch.generation());
                        let file = new_write_file(scratch, existing_target(&vault, id));
                        let mut state = lock_state(&state_arc);
                        let existing = state.writers.get(&ino).map(|w| Arc::clone(&w.file));
                        attach_writer(&mut state, ino, existing.unwrap_or(file));
                        let fh = alloc_fh(&mut state);
                        state.handles.insert(fh, Handle::Write { ino });
                        Ok(fh)
                    });
                    match outcome {
                        Ok(fh) => reply.opened(fh, 0),
                        Err(errno) => reply.error(errno),
                    }
                });
            }
        }
    }

    fn read(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
        let offset = offset.max(0) as u64;
        let size = size as usize;

        enum Plan {
            FromWriter(Arc<WriteFile>),
            Remote { id: String, pinned: Option<Pinned> },
        }

        let plan = {
            let mut guard = lock_state(&self.state);
            let st = &mut *guard;
            if let Some(w) = st.writers.get(&ino) {
                Plan::FromWriter(Arc::clone(&w.file))
            } else {
                match st.handles.get(&fh) {
                    Some(Handle::Read { id, pinned }) => Plan::Remote { id: id.clone(), pinned: pinned.clone() },
                    Some(Handle::Write { ino: wino }) => match st.writers.get(wino) {
                        Some(w) => Plan::FromWriter(Arc::clone(&w.file)),
                        None => return reply.error(EIO),
                    },
                    None => return reply.error(EBADF),
                }
            }
        };

        match plan {
            Plan::FromWriter(file) => {
                let mut buf = vec![0u8; size];
                let result = lock_scratch(&file.scratch).read_at(offset, &mut buf);
                match result {
                    Ok(n) => reply.data(&buf[..n]),
                    Err(e) => {
                        error!("[lethean-cli] read from write buffer failed: {e}");
                        reply.error(errno_of_io(&e));
                    }
                }
            }
            Plan::Remote { pinned: Some(Pinned::Mem(data)), .. } => reply.data(slice_reply(&data, offset, size)),
            Plan::Remote { pinned: Some(Pinned::Large(file)), .. } => {
                let vault = Arc::clone(&self.vault);
                self.io_workers.run(move || match vault.read_large(&file, offset, size) {
                    Ok(bytes) => reply.data(&bytes),
                    Err(e) => {
                        error!("[lethean-cli] read failed: {e}");
                        reply.error(errno_of_io(&e));
                    }
                });
            }
            Plan::Remote { id, pinned: None } => {
                if let Some(data) = self.vault.cached_small(&id) {
                    reply.data(slice_reply(&data, offset, size));
                    if let Some(Handle::Read { pinned: slot @ None, .. }) = lock_state(&self.state).handles.get_mut(&fh) {
                        *slot = Some(Pinned::Mem(data));
                    }
                    return;
                }
                let vault = Arc::clone(&self.vault);
                let state_arc = Arc::clone(&self.state);
                let net_sem = Arc::clone(&self.net_sem);
                self.net_workers.run(move || {
                    if let Some(bytes) = vault.try_read_cached(&id, offset, size) {
                        return reply.data(&bytes);
                    }
                    let _permit = net_sem.acquire();
                    let outcome = run_guarded("read", move || {
                        let info = vault.read_info(&id).ok_or(ENOENT)?;
                        let pinned = if info.large {
                            Pinned::Large(vault.load_large(&id).map_err(|e| {
                                error!("[lethean-cli] read failed: {e:#}");
                                errno_of(&e)
                            })?)
                        } else {
                            Pinned::Mem(vault.download_arc(&id).map_err(|e| {
                                error!("[lethean-cli] read failed: {e:#}");
                                errno_of(&e)
                            })?)
                        };
                        let bytes = match &pinned {
                            Pinned::Mem(data) => slice_reply(data, offset, size).to_vec(),
                            Pinned::Large(f) => vault.read_large(f, offset, size).map_err(|e| {
                                error!("[lethean-cli] read failed: {e}");
                                errno_of_io(&e)
                            })?,
                        };
                        if let Some(Handle::Read { pinned: slot, .. }) = lock_state(&state_arc).handles.get_mut(&fh) {
                            *slot = Some(pinned);
                        }
                        Ok(bytes)
                    });
                    match outcome {
                        Ok(bytes) => reply.data(&bytes),
                        Err(errno) => reply.error(errno),
                    }
                });
            }
        }
    }

    fn write(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
        let offset = offset.max(0) as u64;
        let file = {
            let st = lock_state(&self.state);
            match st.handles.get(&fh) {
                Some(Handle::Write { ino }) => st.writers.get(ino).map(|w| Arc::clone(&w.file)),
                Some(Handle::Read { .. }) => return reply.error(EBADF),
                None => return reply.error(EINVAL),
            }
        };
        let Some(file) = file else { return reply.error(EIO) };
        let result = lock_scratch(&file.scratch).write_at(offset, data);
        match result {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => {
                error!("[lethean-cli] write failed: {e}");
                reply.error(errno_of_io(&e));
            }
        }
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        let needs_commit = {
            let st = lock_state(&self.state);
            match st.handles.get(&fh) {
                Some(Handle::Write { ino }) => st.writers.get(ino).map(|w| lock_scratch(&w.file.scratch).is_dirty()).unwrap_or(false),
                _ => false,
            }
        };
        if !needs_commit {
            return reply.ok();
        }
        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let net_sem = Arc::clone(&self.net_sem);
        let notify = Arc::clone(&self.notify);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            match run_guarded("flush", move || Ok::<bool, c_int>(commit_write_session(&vault, &state_arc, &notify, fh))) {
                Ok(true) => reply.ok(),
                Ok(false) => reply.error(EIO),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        fn close_write_handle(st: &mut FsState, fh: u64) {
            if let Some(Handle::Write { ino }) = st.handles.remove(&fh) {
                let mut drop_writer = false;
                if let Some(w) = st.writers.get_mut(&ino) {
                    w.handles = w.handles.saturating_sub(1);
                    drop_writer = w.handles == 0;
                }
                if drop_writer {
                    st.writers.remove(&ino);
                }
            }
        }

        {
            let mut st = lock_state(&self.state);
            let writer_dirty = match st.handles.get(&fh) {
                Some(Handle::Write { ino }) => Some(st.writers.get(ino).map(|w| lock_scratch(&w.file.scratch).is_dirty()).unwrap_or(false)),
                _ => None,
            };
            match writer_dirty {
                None => {
                    st.handles.remove(&fh);
                    return reply.ok();
                }
                Some(false) => {
                    close_write_handle(&mut st, fh);
                    return reply.ok();
                }
                Some(true) => {}
            }
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let net_sem = Arc::clone(&self.net_sem);
        let notify = Arc::clone(&self.notify);
        self.net_workers.run(move || {
            let _permit = net_sem.acquire();
            let state_for_cleanup = Arc::clone(&state_arc);
            match run_guarded("release", move || Ok::<bool, c_int>(commit_write_session(&vault, &state_arc, &notify, fh))) {
                Ok(true) => {
                    let mut st = lock_state(&state_for_cleanup);
                    close_write_handle(&mut st, fh);
                }
                Ok(false) => {
                    warn!("[lethean-cli] release: changes are still unsaved after retries; keeping the write buffer for a later attempt");
                }
                Err(_) => {
                    warn!("[lethean-cli] release: internal error while saving; keeping the write buffer for a later attempt");
                }
            }
            reply.ok();
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn create(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, _mode: u32, _umask: u32, flags: i32, reply: ReplyCreate) {
        let name = match name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let state = lock_state(&self.state);
        let parent_id = match dir_id_of_ino(&state, &self.vault, parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let already_pending = state.pending_by_key.contains_key(&(parent_id.clone(), name.to_string()));
        drop(state);
        if already_pending || self.vault.find_child(parent_id.as_deref(), name).is_some() {
            return reply.error(EEXIST);
        }

        let mime = guess_mime(name);
        let mut scratch = self.pool.new_scratch();
        scratch.mark_dirty();
        let file = new_write_file(scratch, WriteTarget::NewFile { parent_id: parent_id.clone(), name: name.to_string(), mime: mime.clone() });

        let mut state = lock_state(&self.state);
        let ino = state.next_ino;
        state.next_ino += 1;
        state.node_of_ino.insert(ino, Node::Pending(PendingFile { parent_id: parent_id.clone(), name: name.to_string() }));
        state.pending_by_key.insert((parent_id, name.to_string()), ino);
        attach_writer(&mut state, ino, file);
        let fh = alloc_fh(&mut state);
        state.handles.insert(fh, Handle::Write { ino });

        let attr = attr_for_known_ino(&state, &self.vault, self.ctx, ino);
        if attr.is_some() {
            add_lookup(&mut state, ino);
        }
        drop(state);
        let _ = flags;
        match attr {
            Some(attr) => reply.created(&TTL, &attr, 0, fh, 0),
            None => reply.error(EIO),
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let fh = {
            let mut state = lock_state(&self.state);
            match dir_id_of_ino(&state, &self.vault, ino) {
                Ok(_) => alloc_fh(&mut state),
                Err(e) => return reply.error(e),
            }
        };
        match self.kick_sync() {
            Some((syncer, generation, deadline)) => self.net_workers.run(move || {
                syncer.wait_until(generation, deadline);
                reply.opened(fh, 0);
            }),
            None => reply.opened(fh, 0),
        }
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let mut state = lock_state(&self.state);
        let listing = match listing_for(&mut state, &self.vault, ino, fh, offset) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        drop(state);

        for (i, entry) in listing.iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(entry.ino, (i + 1) as i64, entry.kind, &entry.name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectoryPlus) {
        let mut state = lock_state(&self.state);
        let listing = match listing_for(&mut state, &self.vault, ino, fh, offset) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        for (i, entry) in listing.iter().enumerate().skip(offset.max(0) as usize) {
            let (entry_ino, attr) = match &entry.id {
                Some(id) => {
                    let Some(stat) = self.vault.stat(id) else { continue };
                    let entry_ino = ino_for_remote(&mut state, id);
                    (entry_ino, attr_from_stat(&state, self.ctx, entry_ino, stat))
                }
                None => match attr_for_known_ino(&state, &self.vault, self.ctx, entry.ino) {
                    Some(attr) => (entry.ino, attr),
                    None => continue,
                },
            };
            if reply.add(entry_ino, (i + 1) as i64, &entry.name, &TTL, &attr, 0) {
                break;
            }
            if entry.name != "." && entry.name != ".." {
                add_lookup(&mut state, entry_ino);
            }
        }
        drop(state);
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, reply: ReplyEmpty) {
        lock_state(&self.state).dir_handles.remove(&fh);
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let total_blocks: u64 = 1 << 30;
        reply.statfs(total_blocks, total_blocks / 2, total_blocks / 2, 1 << 20, 1 << 20, 65536, 255, 65536);
    }

    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_guarded_turns_a_panic_into_eio_instead_of_propagating() {
        let result: Result<(), c_int> = run_guarded("test-op", || panic!("simulated bug: malformed record"));
        assert_eq!(result, Err(EIO));
    }

    #[test]
    fn run_guarded_still_returns_the_real_error_when_there_is_no_panic() {
        let ok: Result<i32, c_int> = run_guarded("test-op", || Ok(42));
        assert_eq!(ok, Ok(42));

        let err: Result<i32, c_int> = run_guarded("test-op", || Err(ENOENT));
        assert_eq!(err, Err(ENOENT));
    }

    #[test]
    fn a_panicking_worker_thread_still_delivers_a_clean_reply() {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), c_int>>();
        let handle = thread::spawn(move || {
            let outcome = run_guarded("test-op", || -> Result<(), c_int> {
                let iv_len = 3;
                assert_eq!(iv_len, 12, "invalid AES-GCM nonce length");
                Ok(())
            });
            tx.send(outcome).unwrap();
        });

        handle.join().expect("the worker thread itself must not panic");
        let outcome = rx.recv_timeout(Duration::from_secs(5)).expect("must receive a reply promptly, not hang");
        assert_eq!(outcome, Err(EIO));
    }

    #[test]
    fn net_semaphore_bounds_concurrency_and_survives_a_panic() {
        let sem = Arc::new(NetSemaphore::new(2));

        let p1 = sem.acquire();
        let p2 = sem.acquire();
        assert_eq!(*sem.available.lock().unwrap(), 0);

        let sem_bg = Arc::clone(&sem);
        let waiter = thread::spawn(move || {
            let _p3 = sem_bg.acquire();
        });
        thread::sleep(Duration::from_millis(100));
        assert!(!waiter.is_finished(), "acquire() should still be blocked while both permits are held");

        drop(p1);
        waiter.join().expect("waiter should unblock and finish once a permit is released");
        drop(p2);

        assert_eq!(*sem.available.lock().unwrap(), 2);
        let sem_panic = Arc::clone(&sem);
        thread::spawn(move || {
            let _permit = sem_panic.acquire();
            let _: Result<(), c_int> = run_guarded("test-op", || panic!("simulated panic while holding a permit"));
        })
        .join()
        .expect("the outer worker thread must not panic");

        assert_eq!(*sem.available.lock().unwrap(), 2, "permit must be returned even after a panic inside the guarded work");
    }

    #[test]
    fn burst_pool_runs_every_job_with_bounded_threads_and_survives_panics() {
        use std::sync::atomic::AtomicUsize;
        let pool = BurstPool::new("test-burst", 4);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));
        for i in 0..200 {
            let (running, peak, done) = (Arc::clone(&running), Arc::clone(&peak), Arc::clone(&done));
            pool.run(move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(1));
                running.fetch_sub(1, Ordering::SeqCst);
                done.fetch_add(1, Ordering::SeqCst);
                if i % 50 == 0 {
                    panic!("simulated bug in a job");
                }
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while done.load(Ordering::SeqCst) < 200 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(done.load(Ordering::SeqCst), 200, "every queued job must run, even after panics");
        assert!(peak.load(Ordering::SeqCst) <= 4, "at most `cap` jobs at once, saw {}", peak.load(Ordering::SeqCst));
        thread::sleep(Duration::from_millis(50));
        assert_eq!(lock_plain(&pool.state).0, 0, "threads exit once the queue is empty");
    }

    #[test]
    fn worker_pool_runs_jobs_and_survives_panics() {
        use std::sync::atomic::AtomicUsize;
        let pool = WorkerPool::new("test-pool", 2);
        let done = Arc::new(AtomicUsize::new(0));
        for i in 0..100 {
            let done = Arc::clone(&done);
            pool.run(move || {
                done.fetch_add(1, Ordering::SeqCst);
                if i % 10 == 0 {
                    panic!("simulated bug in a job");
                }
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while done.load(Ordering::SeqCst) < 100 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(done.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn inode_numbers_are_stable_per_id_and_never_collide_with_counters_or_each_other() {
        let mut node_of_ino = HashMap::new();
        node_of_ino.insert(ROOT_INO, Node::Root);
        let mut st = FsState { ino_of_id: HashMap::new(), node_of_ino, lookups: HashMap::new(), next_ino: 2, handles: HashMap::new(), dir_handles: HashMap::new(), next_fh: 1, pending_by_key: HashMap::new(), writers: HashMap::new(), cached_content: HashMap::new() };
        let a = ino_for_remote(&mut st, "file-a");
        assert_eq!(peek_ino(&st, "file-b"), hashed_ino("file-b", 0), "listings report the same number lookup will assign");
        let b = ino_for_remote(&mut st, "file-b");
        assert_ne!(a, b);
        assert!(a >= 1 << 62 && b >= 1 << 62, "hashed inodes live above the counter range");
        assert_eq!(ino_for_remote(&mut st, "file-a"), a);
        st.ino_of_id.remove("file-b");
        st.node_of_ino.insert(b, Node::Remote("someone-else".into()));
        let b2 = ino_for_remote(&mut st, "file-b");
        assert_ne!(b2, b, "a taken number is never handed out twice");
    }

    #[test]
    fn only_disk_space_style_errors_keep_their_errno() {
        assert_eq!(errno_of_io(&io::Error::from_raw_os_error(ENOSPC)), ENOSPC);
        assert_eq!(errno_of_io(&io::Error::from_raw_os_error(libc::ECONNRESET)), EIO);
        assert_eq!(errno_of_io(&io::Error::new(io::ErrorKind::Other, "x")), EIO);
        let wrapped = anyhow::Error::new(io::Error::from_raw_os_error(ENOSPC)).context("upload failed");
        assert_eq!(errno_of(&wrapped), ENOSPC);
    }
}
