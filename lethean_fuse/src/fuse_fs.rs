use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow};
use libc::{c_int, EBADF, EDQUOT, EEXIST, EFBIG, EINVAL, EIO, EISDIR, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY, O_ACCMODE, O_TRUNC};
use log::{error, warn};
use zeroize::Zeroizing;

use crate::scratch::{Scratch, ScratchPool, ScratchReader, ScratchWriter, DEFAULT_POOL_BYTES};
use crate::vault::{LargeFile, Vault};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;


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
    ExistingFile { id: String },
    Discarded,
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

impl Pinned {
    fn read(&self, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
        match self {
            Pinned::Mem(data) => {
                let start = (offset as usize).min(data.len());
                let end = start.saturating_add(size).min(data.len());
                Ok(data[start..end].to_vec())
            }
            Pinned::Large(f) => f.read_at(offset, size),
        }
    }
}

enum Handle {
    Read { id: String, pinned: Option<Pinned> },
    Write { ino: u64 },
}

struct FsState {
    ino_of_id: HashMap<String, u64>,
    node_of_ino: HashMap<u64, Node>,
    next_ino: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    pending_by_key: HashMap<(Option<String>, String), u64>,
    writers: HashMap<u64, Writer>,
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

const MAX_CONCURRENT_NETWORK_OPS: usize = 8;

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

#[derive(Clone, Debug)]
pub struct FsOptions {
    pub scratch_dir: Option<PathBuf>,
    pub scratch_ram_bytes: u64,
}

impl Default for FsOptions {
    fn default() -> Self {
        Self { scratch_dir: None, scratch_ram_bytes: DEFAULT_POOL_BYTES }
    }
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
        Some(Node::Remote(id)) => match vault.get(id) {
            Some(e) if e.is_folder() => Ok(Some(id.clone())),
            Some(_) => Err(ENOTDIR),
            None => Err(ENOENT),
        },
        Some(Node::Pending(_)) => Err(ENOTDIR),
        None => Err(ENOENT),
    }
}

fn ino_for_remote(state: &mut FsState, id: &str) -> u64 {
    if let Some(&ino) = state.ino_of_id.get(id) {
        return ino;
    }
    let ino = state.next_ino;
    state.next_ino += 1;
    state.ino_of_id.insert(id.to_string(), ino);
    state.node_of_ino.insert(ino, Node::Remote(id.to_string()));
    ino
}

fn repoint_ino_to(state: &mut FsState, ino: u64, old_id: Option<&str>, new_id: &str) {
    if let Some(old) = old_id {
        state.ino_of_id.remove(old);
    }
    if let Some(Node::Pending(p)) = state.node_of_ino.get(&ino) {
        let key = (p.parent_id.clone(), p.name.clone());
        state.pending_by_key.remove(&key);
    }
    state.ino_of_id.insert(new_id.to_string(), ino);
    state.node_of_ino.insert(ino, Node::Remote(new_id.to_string()));
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
    make_attr(ctx, ino, FileType::Directory, 0, 0o755)
}

fn file_attr(ctx: AttrCtx, ino: u64, size: u64) -> FileAttr {
    make_attr(ctx, ino, FileType::RegularFile, size, 0o644)
}

fn attr_for_known_ino(state: &FsState, vault: &Vault, ctx: AttrCtx, ino: u64) -> Option<FileAttr> {
    let live_size = state.writers.get(&ino).map(|w| w.file.len.load(Ordering::Acquire));
    match state.node_of_ino.get(&ino)? {
        Node::Root => Some(dir_attr(ctx, ino)),
        Node::Remote(id) => {
            let entry = vault.get(id)?;
            if entry.is_folder() {
                Some(dir_attr(ctx, ino))
            } else {
                Some(file_attr(ctx, ino, live_size.unwrap_or_else(|| entry.size())))
            }
        }
        Node::Pending(_) => Some(file_attr(ctx, ino, live_size.unwrap_or(0))),
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

fn commit_write_session(vault: &Vault, state: &Mutex<FsState>, fh: u64) -> bool {
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
    commit_write_file(vault, state, ino, &file)
}

fn commit_write_file(vault: &Vault, state: &Mutex<FsState>, ino: u64, file: &Arc<WriteFile>) -> bool {
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

    let result = match &target {
        WriteTarget::Discarded => {
            lock_scratch(&file.scratch).mark_committed(generation);
            return true;
        }
        WriteTarget::NewFile { parent_id, name, mime } => vault.create_file_streaming(name, mime, len, parent_id.as_deref(), factory),
        WriteTarget::ExistingFile { id } => {
            if vault.get(id).is_none() {
                warn!("[lethean-cli] dropping unsaved changes to a file that no longer exists");
                lock_scratch(&file.scratch).mark_committed(generation);
                return true;
            }
            vault.replace_content_streaming(id, len, factory)
        }
    };

    match result {
        Ok(new_entry) => {
            lock_scratch(&file.scratch).mark_committed(generation);
            let old_id = match &target {
                WriteTarget::ExistingFile { id } => Some(id.clone()),
                _ => None,
            };
            let new_id = new_entry.record.id.clone();
            *lock_plain(&file.target) = WriteTarget::ExistingFile { id: new_id.clone() };
            let mut st = lock_state(state);
            repoint_ino_to(&mut st, ino, old_id.as_deref(), &new_id);
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
        Self {
            vault: Arc::new(vault),
            state: Arc::new(Mutex::new(FsState {
                ino_of_id: HashMap::new(),
                node_of_ino,
                next_ino: 2,
                handles: HashMap::new(),
                next_fh: 1,
                pending_by_key: HashMap::new(),
                writers: HashMap::new(),
            })),
            ctx: AttrCtx { uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() }, mount_time: SystemTime::now() },
            net_sem: Arc::new(NetSemaphore::new(MAX_CONCURRENT_NETWORK_OPS)),
            pool,
        }
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        self.vault.refresh_all()
    }
}

impl Drop for VaultFs {
    fn drop(&mut self) {
        self.vault.close();
    }
}

impl Filesystem for VaultFs {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        if let Err(max) = config.set_max_readahead(1024 * 1024) {
            let _ = config.set_max_readahead(max);
        }
        Ok(())
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
                return reply.entry(&TTL, &attr, 0);
            }
        }

        let child_id = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
            Some(e) => e.record.id,
            None => return reply.error(ENOENT),
        };
        let ino = ino_for_remote(&mut state, &child_id);
        match attr_for_known_ino(&state, &self.vault, self.ctx, ino) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(ENOENT),
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

        match self.vault.get(&id) {
            Some(e) if e.is_folder() => return reply.error(EISDIR),
            Some(_) => {}
            None => return reply.error(ENOENT),
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let ctx = self.ctx;
        let net_sem = Arc::clone(&self.net_sem);
        let pool = Arc::clone(&self.pool);
        thread::spawn(move || {
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
        if self.vault.find_child_by_name(parent_id.as_deref(), &name).is_some() {
            return reply.error(EEXIST);
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let ctx = self.ctx;
        let net_sem = Arc::clone(&self.net_sem);
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("mkdir", move || {
                let entry = vault.create_folder(&name, parent_id.as_deref()).map_err(|e| {
                    error!("[lethean-cli] mkdir failed: {e:#}");
                    EIO
                })?;
                let mut state = lock_state(&state_arc);
                let ino = ino_for_remote(&mut state, &entry.record.id);
                attr_for_known_ino(&state, &vault, ctx, ino).ok_or(EIO)
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

        let entry = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
            Some(e) => e,
            None => return reply.error(ENOENT),
        };
        if entry.is_folder() {
            return reply.error(EISDIR);
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let id = entry.record.id;
        let net_sem = Arc::clone(&self.net_sem);
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("unlink", move || {
                vault.delete_one(&id).map_err(|e| {
                    error!("[lethean-cli] unlink failed: {e:#}");
                    EIO
                })?;
                let mut state = lock_state(&state_arc);
                if let Some(ino) = state.ino_of_id.remove(&id) {
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
        let entry = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
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
        let id = entry.record.id;
        let net_sem = Arc::clone(&self.net_sem);
        thread::spawn(move || {
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

    fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, newparent: u64, newname: &std::ffi::OsStr, _flags: u32, reply: ReplyEmpty) {
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
        let entry = match self.vault.find_child_by_name(parent_id.as_deref(), &name) {
            Some(e) => e,
            None => return reply.error(ENOENT),
        };
        let existing_id_to_replace = self.vault.find_child_by_name(new_parent_id.as_deref(), &newname).map(|e| e.record.id).filter(|id| *id != entry.record.id);

        let name_changed = if name == newname { None } else { Some(newname) };
        let parent_changed = if parent_id == new_parent_id { None } else { Some(new_parent_id) };

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let entry_id = entry.record.id;
        let net_sem = Arc::clone(&self.net_sem);
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            let outcome = run_guarded("rename", move || {
                if let Some(existing_id) = &existing_id_to_replace {
                    let _ = vault.delete_one(existing_id);
                    lock_state(&state_arc).ino_of_id.remove(existing_id);
                }
                let parent_changed_ref = parent_changed.as_ref().map(|p| p.as_deref());
                let new_entry = vault.rename_or_move(&entry_id, name_changed.as_deref(), parent_changed_ref).map_err(|e| {
                    error!("[lethean-cli] rename failed: {e:#}");
                    EIO
                })?;
                let mut state = lock_state(&state_arc);
                if let Some(&ino) = state.ino_of_id.get(&entry_id) {
                    repoint_ino_to(&mut state, ino, Some(&entry_id), &new_entry.record.id);
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
                let entry = match self.vault.get(&id) {
                    Some(e) => e,
                    None => return reply.error(ENOENT),
                };
                if entry.is_folder() {
                    return reply.error(EISDIR);
                }

                if accmode == libc::O_RDONLY {
                    let mut state = lock_state(&self.state);
                    let fh = alloc_fh(&mut state);
                    state.handles.insert(fh, Handle::Read { id, pinned: None });
                    drop(state);
                    return reply.opened(fh, 0);
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
                    let file = new_write_file(scratch, WriteTarget::ExistingFile { id });
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
                thread::spawn(move || {
                    let _permit = net_sem.acquire();
                    let outcome = run_guarded("open", move || {
                        let mut scratch = pool.new_scratch();
                        vault.stream_plaintext(&id, &mut ScratchWriter::new(&mut scratch)).map_err(|e| {
                            error!("[lethean-cli] could not load \"{}\" for writing: {e:#}", entry.name());
                            errno_of(&e)
                        })?;
                        scratch.mark_committed(scratch.generation());
                        let file = new_write_file(scratch, WriteTarget::ExistingFile { id });
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
            Plan::Remote { pinned: Some(Pinned::Mem(data)), .. } => {
                let start = (offset as usize).min(data.len());
                let end = start.saturating_add(size).min(data.len());
                reply.data(&data[start..end]);
            }
            Plan::Remote { pinned: Some(Pinned::Large(file)), .. } => {
                thread::spawn(move || match file.read_at(offset, size) {
                    Ok(bytes) => reply.data(&bytes),
                    Err(e) => {
                        error!("[lethean-cli] read failed: {e}");
                        reply.error(errno_of_io(&e));
                    }
                });
            }
            Plan::Remote { id, pinned: None } => {
                let vault = Arc::clone(&self.vault);
                let state_arc = Arc::clone(&self.state);
                let net_sem = Arc::clone(&self.net_sem);
                thread::spawn(move || {
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
                        let bytes = pinned.read(offset, size).map_err(|e| errno_of_io(&e))?;
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
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            match run_guarded("flush", move || Ok::<bool, c_int>(commit_write_session(&vault, &state_arc, fh))) {
                Ok(true) => reply.ok(),
                Ok(false) => reply.error(EIO),
                Err(errno) => reply.error(errno),
            }
        });
    }

    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        let is_writer = matches!(lock_state(&self.state).handles.get(&fh), Some(Handle::Write { .. }));
        if !is_writer {
            lock_state(&self.state).handles.remove(&fh);
            return reply.ok();
        }

        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let net_sem = Arc::clone(&self.net_sem);
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            let state_for_cleanup = Arc::clone(&state_arc);
            match run_guarded("release", move || Ok::<bool, c_int>(commit_write_session(&vault, &state_arc, fh))) {
                Ok(true) => {
                    let mut st = lock_state(&state_for_cleanup);
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
        if already_pending || self.vault.find_child_by_name(parent_id.as_deref(), name).is_some() {
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
        drop(state);
        let _ = flags;
        match attr {
            Some(attr) => reply.created(&TTL, &attr, 0, fh, 0),
            None => reply.error(EIO),
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let state = lock_state(&self.state);
        match dir_id_of_ino(&state, &self.vault, ino) {
            Ok(_) => reply.opened(0, 0),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let mut state = lock_state(&self.state);
        let dir_id = match dir_id_of_ino(&state, &self.vault, ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![(ino, FileType::Directory, ".".to_string())];
        entries.push((ROOT_INO, FileType::Directory, "..".to_string()));

        for child in self.vault.list_children(dir_id.as_deref()) {
            let child_ino = ino_for_remote(&mut state, &child.id);
            entries.push((child_ino, if child.is_folder { FileType::Directory } else { FileType::RegularFile }, child.name));
        }
        for ((parent, name), pino) in &state.pending_by_key {
            if *parent == dir_id {
                entries.push((*pino, FileType::RegularFile, name.clone()));
            }
        }
        drop(state);

        for (i, (entry_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry_ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
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
    fn only_disk_space_style_errors_keep_their_errno() {
        assert_eq!(errno_of_io(&io::Error::from_raw_os_error(ENOSPC)), ENOSPC);
        assert_eq!(errno_of_io(&io::Error::from_raw_os_error(libc::ECONNRESET)), EIO);
        assert_eq!(errno_of_io(&io::Error::new(io::ErrorKind::Other, "x")), EIO);
        let wrapped = anyhow::Error::new(io::Error::from_raw_os_error(ENOSPC)).context("upload failed");
        assert_eq!(errno_of(&wrapped), ENOSPC);
    }
}
