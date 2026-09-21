use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow};
use libc::{c_int, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, O_ACCMODE, O_TRUNC};
use log::{error, warn};
use zeroize::Zeroize;

use crate::vault::Vault;

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
    mime: String,
}

#[derive(Clone)]
enum WriteTarget {
    NewFile { ino: u64, parent_id: Option<String>, name: String, mime: String },
    ExistingFile { ino: u64, id: String },
}

struct WriteSession {
    target: WriteTarget,
    buffer: Vec<u8>,
    dirty: bool,
}

enum Handle {
    Read { id: String, data: Option<Vec<u8>> },
    Write(WriteSession),
}

struct FsState {
    ino_of_id: HashMap<String, u64>,
    node_of_ino: HashMap<u64, Node>,
    next_ino: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
}

fn lock_state(state: &Mutex<FsState>) -> MutexGuard<'_, FsState> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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

pub struct VaultFs {
    vault: Arc<Vault>,
    state: Arc<Mutex<FsState>>,
    ctx: AttrCtx,
    net_sem: Arc<NetSemaphore>,
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
    match state.node_of_ino.get(&ino)? {
        Node::Root => Some(dir_attr(ctx, ino)),
        Node::Remote(id) => {
            let entry = vault.get(id)?;
            if entry.is_folder() {
                Some(dir_attr(ctx, ino))
            } else {
                let live_size = state.handles.values().find_map(|h| match h {
                    Handle::Write(WriteSession { target: WriteTarget::ExistingFile { ino: wino, .. }, buffer, .. }) if *wino == ino => Some(buffer.len() as u64),
                    _ => None,
                });
                Some(file_attr(ctx, ino, live_size.unwrap_or(entry.size())))
            }
        }
        Node::Pending(_) => {
            let live_size = state.handles.values().find_map(|h| match h {
                Handle::Write(WriteSession { target: WriteTarget::NewFile { ino: wino, .. }, buffer, .. }) if *wino == ino => Some(buffer.len() as u64),
                _ => None,
            });
            Some(file_attr(ctx, ino, live_size.unwrap_or(0)))
        }
    }
}

fn commit_write_session(vault: &Vault, state: &Mutex<FsState>, fh: u64) -> bool {
    let taken = {
        let mut st = lock_state(state);
        match st.handles.get_mut(&fh) {
            Some(Handle::Write(s)) if s.dirty => Some((s.target.clone(), std::mem::take(&mut s.buffer))),
            _ => None,
        }
    };
    let Some((target, buffer)) = taken else { return true };

    let result = match &target {
        WriteTarget::NewFile { parent_id, name, mime, .. } => vault.create_file(name, mime, &buffer, parent_id.as_deref()),
        WriteTarget::ExistingFile { id, .. } => vault.replace_content(id, &buffer),
    };

    let mut st = lock_state(state);
    if let Some(Handle::Write(s)) = st.handles.get_mut(&fh) {
        s.buffer = buffer;
    }
    match result {
        Ok(new_entry) => {
            let (ino, old_id) = match &target {
                WriteTarget::NewFile { ino, .. } => (*ino, None),
                WriteTarget::ExistingFile { ino, id } => (*ino, Some(id.clone())),
            };
            if let Some(Handle::Write(s)) = st.handles.get_mut(&fh) {
                s.dirty = false;
            }
            repoint_ino_to(&mut st, ino, old_id.as_deref(), &new_entry.record.id);
            true
        }
        Err(e) => {
            error!("[lethean-cli] failed to save changes: {e:#}");
            false
        }
    }
}

impl VaultFs {
    pub fn new(vault: Vault) -> Self {
        let mut node_of_ino = HashMap::new();
        node_of_ino.insert(ROOT_INO, Node::Root);
        Self {
            vault: Arc::new(vault),
            state: Arc::new(Mutex::new(FsState { ino_of_id: HashMap::new(), node_of_ino, next_ino: 2, handles: HashMap::new(), next_fh: 1 })),
            ctx: AttrCtx { uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() }, mount_time: SystemTime::now() },
            net_sem: Arc::new(NetSemaphore::new(MAX_CONCURRENT_NETWORK_OPS)),
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

        if let Some((&ino, _)) = state.node_of_ino.iter().find(|(_, n)| matches!(n, Node::Pending(p) if p.parent_id == parent_id && p.name == name)) {
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
        fh: Option<u64>,
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

        if let Some(fh) = fh {
            let mut state = lock_state(&self.state);
            if let Some(Handle::Write(session)) = state.handles.get_mut(&fh) {
                session.buffer.resize(new_size as usize, 0);
                session.dirty = true;
            }
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
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            let id_for_log = id.clone();
            let outcome = run_guarded("truncate", move || {
                let mut bytes = vault.download_decrypted(&id).unwrap_or_default();
                bytes.resize(new_size as usize, 0);
                let new_entry = vault.replace_content(&id, &bytes).map_err(|e| {
                    error!("[lethean-cli] truncate failed: {e:#}");
                    EIO
                })?;
                let mut state = lock_state(&state_arc);
                repoint_ino_to(&mut state, ino, Some(&id), &new_entry.record.id);
                attr_for_known_ino(&state, &vault, ctx, ino).ok_or(ENOENT)
            });
            let _ = &id_for_log;
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
                lock_state(&state_arc).ino_of_id.remove(&id);
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
        if !self.vault.children_of(Some(&entry.record.id)).is_empty() {
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
            Node::Pending(p) => {
                let mut state = lock_state(&self.state);
                let fh = alloc_fh(&mut state);
                state.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::NewFile { ino, parent_id: p.parent_id, name: p.name, mime: p.mime }, buffer: Vec::new(), dirty: false }));
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
                    state.handles.insert(fh, Handle::Read { id, data: None });
                    drop(state);
                    reply.opened(fh, 0);
                } else if flags & O_TRUNC != 0 {
                    let mut state = lock_state(&self.state);
                    let fh = alloc_fh(&mut state);
                    state.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::ExistingFile { ino, id }, buffer: Vec::new(), dirty: false }));
                    drop(state);
                    reply.opened(fh, 0);
                } else {
                    let vault = Arc::clone(&self.vault);
                    let state_arc = Arc::clone(&self.state);
                    let net_sem = Arc::clone(&self.net_sem);
                    thread::spawn(move || {
                        let _permit = net_sem.acquire();
                        let outcome = run_guarded("open", move || {
                            let buffer = match vault.download_decrypted(&id) {
                                Ok(b) => b,
                                Err(e) => {
                                    warn!("[lethean-cli] could not preload \"{}\" for writing: {e:#}", entry.name());
                                    Vec::new()
                                }
                            };
                            let mut state = lock_state(&state_arc);
                            let fh = alloc_fh(&mut state);
                            state.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::ExistingFile { ino, id }, buffer, dirty: false }));
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
    }

    fn read(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
        let offset = offset.max(0) as usize;

        let needs_download = {
            let state = lock_state(&self.state);
            matches!(state.handles.get(&fh), Some(Handle::Read { data: None, .. }))
        };

        if needs_download {
            let id = {
                let state = lock_state(&self.state);
                match state.handles.get(&fh) {
                    Some(Handle::Read { id, .. }) => id.clone(),
                    _ => return reply.error(EINVAL),
                }
            };
            let vault = Arc::clone(&self.vault);
            let state_arc = Arc::clone(&self.state);
            let net_sem = Arc::clone(&self.net_sem);
            thread::spawn(move || {
                let _permit = net_sem.acquire();
                let outcome = run_guarded("read", move || {
                    let bytes = vault.download_decrypted(&id).map_err(|e| {
                        error!("[lethean-cli] read failed: {e:#}");
                        EIO
                    })?;
                    let slice_end = (offset + size as usize).min(bytes.len());
                    let slice: Vec<u8> = if offset >= bytes.len() { Vec::new() } else { bytes[offset..slice_end].to_vec() };
                    let mut state = lock_state(&state_arc);
                    if let Some(Handle::Read { data, .. }) = state.handles.get_mut(&fh) {
                        *data = Some(bytes);
                    }
                    Ok(slice)
                });
                match outcome {
                    Ok(slice) => reply.data(&slice),
                    Err(errno) => reply.error(errno),
                }
            });
            return;
        }

        let state = lock_state(&self.state);
        let result: Option<Vec<u8>> = match state.handles.get(&fh) {
            Some(Handle::Read { data: Some(d), .. }) => {
                let end = (offset + size as usize).min(d.len());
                Some(if offset >= d.len() { Vec::new() } else { d[offset..end].to_vec() })
            }
            Some(Handle::Write(session)) => {
                let b = &session.buffer;
                let end = (offset + size as usize).min(b.len());
                Some(if offset >= b.len() { Vec::new() } else { b[offset..end].to_vec() })
            }
            _ => None,
        };
        drop(state);
        match result {
            Some(bytes) => reply.data(&bytes),
            None => reply.error(EINVAL),
        }
    }

    fn write(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
        let offset = offset.max(0) as usize;
        let mut state = lock_state(&self.state);
        match state.handles.get_mut(&fh) {
            Some(Handle::Write(session)) => {
                let end = offset + data.len();
                if session.buffer.len() < end {
                    session.buffer.resize(end, 0);
                }
                session.buffer[offset..end].copy_from_slice(data);
                session.dirty = true;
                reply.written(data.len() as u32);
            }
            Some(Handle::Read { .. }) => reply.error(libc::EBADF),
            None => reply.error(EINVAL),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
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
        let vault = Arc::clone(&self.vault);
        let state_arc = Arc::clone(&self.state);
        let net_sem = Arc::clone(&self.net_sem);
        thread::spawn(move || {
            let _permit = net_sem.acquire();
            let state_arc2 = Arc::clone(&state_arc);
            match run_guarded("release", move || Ok::<bool, c_int>(commit_write_session(&vault, &state_arc, fh))) {
                Ok(true) => {
                    if let Some(handle) = lock_state(&state_arc2).handles.remove(&fh) {
                        match handle {
                            Handle::Write(mut session) => session.buffer.zeroize(),
                            Handle::Read { mut data, .. } => {
                                if let Some(bytes) = data.as_mut() {
                                    bytes.zeroize();
                                }
                            }
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
        drop(state);
        if self.vault.find_child_by_name(parent_id.as_deref(), name).is_some() {
            return reply.error(EEXIST);
        }

        let mime = guess_mime(name);
        let mut state = lock_state(&self.state);
        let ino = state.next_ino;
        state.next_ino += 1;
        state.node_of_ino.insert(ino, Node::Pending(PendingFile { parent_id: parent_id.clone(), name: name.to_string(), mime: mime.clone() }));

        let fh = alloc_fh(&mut state);
        state.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::NewFile { ino, parent_id, name: name.to_string(), mime }, buffer: Vec::new(), dirty: false }));

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

        let children: Vec<(String, FileType, String)> =
            self.vault.children_of(dir_id.as_deref()).into_iter().map(|e| (e.record.id.clone(), if e.is_folder() { FileType::Directory } else { FileType::RegularFile }, e.name().to_string())).collect();
        for (id, kind, name) in children {
            let child_ino = ino_for_remote(&mut state, &id);
            entries.push((child_ino, kind, name));
        }
        for (ino, node) in &state.node_of_ino {
            if let Node::Pending(p) = node {
                if p.parent_id == dir_id {
                    entries.push((*ino, FileType::RegularFile, p.name.clone()));
                }
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
}