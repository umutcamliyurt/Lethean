
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow};
use libc::{c_int, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, O_ACCMODE, O_TRUNC};
use log::{error, warn};

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

pub struct VaultFs {
    vault: Vault,
    ino_of_id: HashMap<String, u64>,
    node_of_ino: HashMap<u64, Node>,
    next_ino: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    uid: u32,
    gid: u32,
    mount_time: SystemTime,
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

impl VaultFs {
    pub fn new(vault: Vault) -> Self {
        let mut node_of_ino = HashMap::new();
        node_of_ino.insert(ROOT_INO, Node::Root);
        Self {
            vault,
            ino_of_id: HashMap::new(),
            node_of_ino,
            next_ino: 2,
            handles: HashMap::new(),
            next_fh: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            mount_time: SystemTime::now(),
        }
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        self.vault.refresh_all()
    }

    fn dir_id_of_ino(&self, ino: u64) -> Result<Option<String>, c_int> {
        match self.node_of_ino.get(&ino) {
            Some(Node::Root) => Ok(None),
            Some(Node::Remote(id)) => match self.vault.get(id) {
                Some(e) if e.is_folder() => Ok(Some(id.clone())),
                Some(_) => Err(ENOTDIR),
                None => Err(ENOENT),
            },
            Some(Node::Pending(_)) => Err(ENOTDIR),
            None => Err(ENOENT),
        }
    }

    fn ino_for_remote(&mut self, id: &str) -> u64 {
        if let Some(&ino) = self.ino_of_id.get(id) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_of_id.insert(id.to_string(), ino);
        self.node_of_ino.insert(ino, Node::Remote(id.to_string()));
        ino
    }

    fn repoint_ino_to(&mut self, ino: u64, old_id: Option<&str>, new_id: &str) {
        if let Some(old) = old_id {
            self.ino_of_id.remove(old);
        }
        self.ino_of_id.insert(new_id.to_string(), ino);
        self.node_of_ino.insert(ino, Node::Remote(new_id.to_string()));
    }

    fn alloc_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        fh
    }

    fn dir_attr(&self, ino: u64) -> FileAttr {
        self.make_attr(ino, FileType::Directory, 0, 0o755)
    }

    fn file_attr(&self, ino: u64, size: u64) -> FileAttr {
        self.make_attr(ino, FileType::RegularFile, size, 0o644)
    }

    fn make_attr(&self, ino: u64, kind: FileType, size: u64, perm: u16) -> FileAttr {
        let blocks = size.div_ceil(512).max(if size == 0 { 0 } else { 1 });
        FileAttr {
            ino,
            size,
            blocks,
            atime: self.mount_time,
            mtime: self.mount_time,
            ctime: self.mount_time,
            crtime: self.mount_time,
            kind,
            perm,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 65536,
            flags: 0,
        }
    }

    fn attr_for_known_ino(&self, ino: u64) -> Option<FileAttr> {
        match self.node_of_ino.get(&ino)? {
            Node::Root => Some(self.dir_attr(ino)),
            Node::Remote(id) => {
                let entry = self.vault.get(id)?;
                if entry.is_folder() {
                    Some(self.dir_attr(ino))
                } else {
                    let live_size = self.handles.values().find_map(|h| match h {
                        Handle::Write(WriteSession { target: WriteTarget::ExistingFile { ino: wino, .. }, buffer, .. }) if *wino == ino => Some(buffer.len() as u64),
                        _ => None,
                    });
                    Some(self.file_attr(ino, live_size.unwrap_or(entry.size())))
                }
            }
            Node::Pending(_) => {
                let live_size = self.handles.values().find_map(|h| match h {
                    Handle::Write(WriteSession { target: WriteTarget::NewFile { ino: wino, .. }, buffer, .. }) if *wino == ino => Some(buffer.len() as u64),
                    _ => None,
                });
                Some(self.file_attr(ino, live_size.unwrap_or(0)))
            }
        }
    }

    fn name_str(name: &std::ffi::OsStr) -> Result<&str, c_int> {
        name.to_str().ok_or(EINVAL)
    }

    fn commit_write_session(&mut self, fh: u64) {
        let session = match self.handles.get_mut(&fh) {
            Some(Handle::Write(s)) if s.dirty => s,
            _ => return,
        };
        let result = match &session.target {
            WriteTarget::NewFile { parent_id, name, mime, .. } => self.vault.create_file(name, mime, &session.buffer, parent_id.as_deref()),
            WriteTarget::ExistingFile { id, .. } => self.vault.replace_content(id, &session.buffer),
        };
        match result {
            Ok(new_entry) => {
                let (ino, old_id) = match &session.target {
                    WriteTarget::NewFile { ino, .. } => (*ino, None),
                    WriteTarget::ExistingFile { ino, id } => (*ino, Some(id.clone())),
                };
                session.dirty = false;
                self.repoint_ino_to(ino, old_id.as_deref(), &new_entry.record.id);
            }
            Err(e) => {
                error!("[lethean-cli] failed to save changes: {e:#}");
            }
        }
    }
}

impl Filesystem for VaultFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name = match Self::name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = match self.dir_id_of_ino(parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };

        if let Some((&ino, _)) = self.node_of_ino.iter().find(|(_, n)| matches!(n, Node::Pending(p) if p.parent_id == parent_id && p.name == name)) {
            if let Some(attr) = self.attr_for_known_ino(ino) {
                return reply.entry(&TTL, &attr, 0);
            }
        }

        let child_id = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
            Some(e) => e.record.id.clone(),
            None => return reply.error(ENOENT),
        };
        let ino = self.ino_for_remote(&child_id);
        match self.attr_for_known_ino(ino) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self.attr_for_known_ino(ino) {
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
        if let Some(new_size) = size {
            if let Some(fh) = fh {
                if let Some(Handle::Write(session)) = self.handles.get_mut(&fh) {
                    session.buffer.resize(new_size as usize, 0);
                    session.dirty = true;
                }
            } else if let Some(Node::Remote(id)) = self.node_of_ino.get(&ino).cloned() {
                match self.vault.get(&id) {
                    Some(e) if e.is_folder() => return reply.error(EISDIR),
                    Some(_) => {
                        let mut bytes = self.vault.download_decrypted(&id).unwrap_or_default();
                        bytes.resize(new_size as usize, 0);
                        match self.vault.replace_content(&id, &bytes) {
                            Ok(new_entry) => self.repoint_ino_to(ino, Some(&id), &new_entry.record.id),
                            Err(e) => {
                                error!("[lethean-cli] truncate failed: {e:#}");
                                return reply.error(EIO);
                            }
                        }
                    }
                    None => return reply.error(ENOENT),
                }
            }
        }
        match self.attr_for_known_ino(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(ENOENT),
        }
    }

    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        let name = match Self::name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = match self.dir_id_of_ino(parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        if self.vault.find_child_by_name(parent_id.as_deref(), name).is_some() {
            return reply.error(EEXIST);
        }
        match self.vault.create_folder(name, parent_id.as_deref()) {
            Ok(entry) => {
                let ino = self.ino_for_remote(&entry.record.id);
                match self.attr_for_known_ino(ino) {
                    Some(attr) => reply.entry(&TTL, &attr, 0),
                    None => reply.error(EIO),
                }
            }
            Err(e) => {
                error!("[lethean-cli] mkdir failed: {e:#}");
                reply.error(EIO)
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let name = match Self::name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = match self.dir_id_of_ino(parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let entry = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
            Some(e) => e.clone(),
            None => return reply.error(ENOENT),
        };
        if entry.is_folder() {
            return reply.error(EISDIR);
        }
        match self.vault.delete_one(&entry.record.id) {
            Ok(()) => {
                self.ino_of_id.remove(&entry.record.id);
                reply.ok();
            }
            Err(e) => {
                error!("[lethean-cli] unlink failed: {e:#}");
                reply.error(EIO)
            }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let name = match Self::name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = match self.dir_id_of_ino(parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let entry = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
            Some(e) => e.clone(),
            None => return reply.error(ENOENT),
        };
        if !entry.is_folder() {
            return reply.error(ENOTDIR);
        }
        if !self.vault.children_of(Some(&entry.record.id)).is_empty() {
            return reply.error(ENOTEMPTY);
        }
        match self.vault.delete_one(&entry.record.id) {
            Ok(()) => {
                self.ino_of_id.remove(&entry.record.id);
                reply.ok();
            }
            Err(e) => {
                error!("[lethean-cli] rmdir failed: {e:#}");
                reply.error(EIO)
            }
        }
    }

    fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, newparent: u64, newname: &std::ffi::OsStr, _flags: u32, reply: ReplyEmpty) {
        let name = match Self::name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let newname = match Self::name_str(newname) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = match self.dir_id_of_ino(parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let new_parent_id = match self.dir_id_of_ino(newparent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let entry = match self.vault.find_child_by_name(parent_id.as_deref(), name) {
            Some(e) => e.clone(),
            None => return reply.error(ENOENT),
        };

        if let Some(existing) = self.vault.find_child_by_name(new_parent_id.as_deref(), newname) {
            let existing_id = existing.record.id.clone();
            if existing_id != entry.record.id {
                let _ = self.vault.delete_one(&existing_id);
                self.ino_of_id.remove(&existing_id);
            }
        }

        let name_changed = if name == newname { None } else { Some(newname) };
        let parent_changed = if parent_id == new_parent_id { None } else { Some(new_parent_id.as_deref()) };

        match self.vault.rename_or_move(&entry.record.id, name_changed, parent_changed) {
            Ok(new_entry) => {
                if let Some(&ino) = self.ino_of_id.get(&entry.record.id) {
                    self.repoint_ino_to(ino, Some(&entry.record.id), &new_entry.record.id);
                }
                reply.ok();
            }
            Err(e) => {
                error!("[lethean-cli] rename failed: {e:#}");
                reply.error(EIO)
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let accmode = flags & O_ACCMODE;
        let node = match self.node_of_ino.get(&ino).cloned() {
            Some(n) => n,
            None => return reply.error(ENOENT),
        };

        match node {
            Node::Root => reply.error(EISDIR),
            Node::Pending(p) => {
                let fh = self.alloc_fh();
                self.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::NewFile { ino, parent_id: p.parent_id, name: p.name, mime: p.mime }, buffer: Vec::new(), dirty: false }));
                reply.opened(fh, 0);
            }
            Node::Remote(id) => {
                let entry = match self.vault.get(&id) {
                    Some(e) => e.clone(),
                    None => return reply.error(ENOENT),
                };
                if entry.is_folder() {
                    return reply.error(EISDIR);
                }
                let fh = self.alloc_fh();
                if accmode == libc::O_RDONLY {
                    self.handles.insert(fh, Handle::Read { id, data: None });
                } else {
                    let buffer = if flags & O_TRUNC != 0 {
                        Vec::new()
                    } else {
                        match self.vault.download_decrypted(&id) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("[lethean-cli] could not preload \"{}\" for writing: {e:#}", entry.name());
                                Vec::new()
                            }
                        }
                    };
                    self.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::ExistingFile { ino, id }, buffer, dirty: false }));
                }
                reply.opened(fh, 0);
            }
        }
    }

    fn read(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
        let offset = offset.max(0) as usize;
        let bytes: Vec<u8> = match self.handles.get_mut(&fh) {
            Some(Handle::Read { id, data }) => {
                if data.is_none() {
                    match self.vault.download_decrypted(id) {
                        Ok(b) => *data = Some(b),
                        Err(e) => {
                            error!("[lethean-cli] read failed: {e:#}");
                            return reply.error(EIO);
                        }
                    }
                }
                data.as_ref().cloned().unwrap_or_default()
            }
            Some(Handle::Write(session)) => session.buffer.clone(),
            None => return reply.error(EINVAL),
        };
        if offset >= bytes.len() {
            return reply.data(&[]);
        }
        let end = (offset + size as usize).min(bytes.len());
        reply.data(&bytes[offset..end]);
    }

    fn write(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
        let offset = offset.max(0) as usize;
        match self.handles.get_mut(&fh) {
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
        self.commit_write_session(fh);
        reply.ok();
    }

    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        self.commit_write_session(fh);
        self.handles.remove(&fh);
        reply.ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn create(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, _mode: u32, _umask: u32, flags: i32, reply: ReplyCreate) {
        let name = match Self::name_str(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let parent_id = match self.dir_id_of_ino(parent) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        if self.vault.find_child_by_name(parent_id.as_deref(), name).is_some() {
            return reply.error(EEXIST);
        }

        let mime = guess_mime(name);
        let ino = self.next_ino;
        self.next_ino += 1;
        self.node_of_ino.insert(ino, Node::Pending(PendingFile { parent_id: parent_id.clone(), name: name.to_string(), mime: mime.clone() }));

        let fh = self.alloc_fh();
        self.handles.insert(fh, Handle::Write(WriteSession { target: WriteTarget::NewFile { ino, parent_id, name: name.to_string(), mime }, buffer: Vec::new(), dirty: false }));

        let attr = self.attr_for_known_ino(ino).expect("just inserted");
        let _ = flags;
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        match self.dir_id_of_ino(ino) {
            Ok(_) => reply.opened(0, 0),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let dir_id = match self.dir_id_of_ino(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![(ino, FileType::Directory, ".".to_string())];
        entries.push((ROOT_INO, FileType::Directory, "..".to_string()));

        let ids: Vec<String> = self.vault.children_of(dir_id.as_deref()).into_iter().map(|e| e.record.id.clone()).collect();
        for id in ids {
            let (kind, name) = match self.vault.get(&id) {
                Some(entry) => (if entry.is_folder() { FileType::Directory } else { FileType::RegularFile }, entry.name().to_string()),
                None => continue,
            };
            let child_ino = self.ino_for_remote(&id);
            entries.push((child_ino, kind, name));
        }
        for (ino, node) in &self.node_of_ino {
            if let Node::Pending(p) = node {
                if p.parent_id == dir_id {
                    entries.push((*ino, FileType::RegularFile, p.name.clone()));
                }
            }
        }

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
