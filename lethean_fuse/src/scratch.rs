
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

pub const BLOCK: usize = 64 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SLOT: u64 = (NONCE_LEN + BLOCK + TAG_LEN) as u64;

pub const DEFAULT_POOL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHED_BLOCKS: usize = 64;

#[cfg(unix)]
fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}
#[cfg(unix)]
fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, buf, off)
}
#[cfg(not(unix))]
fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut f = f;
    f.seek(SeekFrom::Start(off))?;
    f.read_exact(buf)
}
#[cfg(not(unix))]
fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut f = f;
    f.seek(SeekFrom::Start(off))?;
    f.write_all(buf)
}

pub fn default_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("LETHEAN_SCRATCH_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    match dirs::cache_dir() {
        Some(d) => d.join("lethean-cli").join("scratch"),
        None => std::env::temp_dir().join("lethean-cli-scratch"),
    }
}

pub struct ScratchPool {
    max_bytes: u64,
    used: AtomicU64,
    dir: PathBuf,
}

impl ScratchPool {
    pub fn new(max_bytes: u64, dir: PathBuf) -> Arc<Self> {
        Arc::new(Self { max_bytes, used: AtomicU64::new(0), dir })
    }

    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    fn try_reserve(&self, n: u64) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            if cur + n > self.max_bytes {
                return false;
            }
            match self.used.compare_exchange_weak(cur, cur + n, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    fn release(&self, n: u64) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }

    pub fn new_scratch(self: &Arc<Self>) -> Scratch {
        Scratch::new(Arc::clone(self))
    }
}

fn open_spill_file(dir: &Path) -> io::Result<(File, Option<PathBuf>)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;

    for _ in 0..16 {
        let mut rnd = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut rnd);
        let path = dir.join(format!("scratch-{}-{}", std::process::id(), hex::encode(rnd)));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => {
                #[cfg(unix)]
                {
                    let _ = std::fs::remove_file(&path);
                    return Ok((f, None));
                }
                #[cfg(not(unix))]
                return Ok((f, Some(path)));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not create a unique scratch file"))
}

struct CachedBlock {
    data: Zeroizing<Vec<u8>>,
    dirty: bool,
}

pub struct Scratch {
    pool: Arc<ScratchPool>,
    cipher: Aes256Gcm,
    nonce_prefix: [u8; 4],
    nonce_ctr: u64,
    file: Option<File>,
    #[allow(dead_code)]
    file_path: Option<PathBuf>,
    on_disk: Vec<bool>,
    cache: HashMap<u64, CachedBlock>,
    order: VecDeque<u64>,
    reserved: usize,
    io_buf: Zeroizing<Vec<u8>>,
    len: u64,
    len_pub: Arc<AtomicU64>,
    generation: u64,
    committed_generation: u64,
}

impl Scratch {
    fn new(pool: Arc<ScratchPool>) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut key[..]);
        let mut prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut prefix);
        Self {
            pool,
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..])),
            nonce_prefix: prefix,
            nonce_ctr: 0,
            file: None,
            file_path: None,
            on_disk: Vec::new(),
            cache: HashMap::new(),
            order: VecDeque::new(),
            reserved: 0,
            io_buf: Zeroizing::new(Vec::new()),
            len: 0,
            len_pub: Arc::new(AtomicU64::new(0)),
            generation: 0,
            committed_generation: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.len_pub)
    }

    pub fn is_dirty(&self) -> bool {
        self.generation != self.committed_generation
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn mark_committed(&mut self, generation: u64) {
        self.committed_generation = generation;
    }

    pub fn mark_dirty(&mut self) {
        self.generation += 1;
    }

    pub fn cached_bytes(&self) -> usize {
        self.cache.len() * BLOCK
    }

    fn set_len_internal(&mut self, len: u64) {
        self.len = len;
        self.len_pub.store(len, Ordering::Release);
        self.generation += 1;
    }

    fn is_on_disk(&self, idx: u64) -> bool {
        self.on_disk.get(idx as usize).copied().unwrap_or(false)
    }

    fn set_on_disk(&mut self, idx: u64, v: bool) {
        let i = idx as usize;
        if i >= self.on_disk.len() {
            if !v {
                return;
            }
            self.on_disk.resize(i + 1, false);
        }
        self.on_disk[i] = v;
    }

    fn touch(&mut self, idx: u64) {
        if self.order.back() == Some(&idx) {
            return;
        }
        if let Some(pos) = self.order.iter().position(|x| *x == idx) {
            self.order.remove(pos);
            self.order.push_back(idx);
        }
    }

    fn write_slot(&mut self, idx: u64, data: &[u8]) -> io::Result<()> {
        debug_assert_eq!(data.len(), BLOCK);
        if self.file.is_none() {
            let (f, p) = open_spill_file(&self.pool.dir)?;
            self.file = Some(f);
            self.file_path = p;
        }
        self.nonce_ctr += 1;
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&self.nonce_ctr.to_be_bytes());

        self.io_buf.clear();
        self.io_buf.extend_from_slice(&nonce);
        self.io_buf.extend_from_slice(data);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &idx.to_be_bytes(), &mut self.io_buf[NONCE_LEN..])
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "scratch encryption failed"))?;
        self.io_buf.extend_from_slice(&tag);
        write_all_at(self.file.as_ref().expect("opened above"), &self.io_buf, idx * SLOT)?;
        self.set_on_disk(idx, true);
        Ok(())
    }

    fn read_slot_to_iobuf(&mut self, idx: u64) -> io::Result<()> {
        let file = self.file.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "scratch file missing"))?;
        self.io_buf.clear();
        self.io_buf.resize(SLOT as usize, 0);
        read_exact_at(file, &mut self.io_buf, idx * SLOT)?;
        let (nonce, rest) = self.io_buf.split_at_mut(NONCE_LEN);
        let (ct, tag) = rest.split_at_mut(BLOCK);
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce), &idx.to_be_bytes(), ct, Tag::from_slice(tag))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "scratch block failed authentication"))?;
        Ok(())
    }

    fn load_block(&mut self, idx: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.is_on_disk(idx) {
            self.read_slot_to_iobuf(idx)?;
            Ok(Zeroizing::new(self.io_buf[NONCE_LEN..NONCE_LEN + BLOCK].to_vec()))
        } else {
            Ok(Zeroizing::new(vec![0u8; BLOCK]))
        }
    }

    fn evict_lru(&mut self) -> io::Result<()> {
        let Some(idx) = self.order.pop_front() else { return Ok(()) };
        let Some(block) = self.cache.remove(&idx) else { return Ok(()) };
        if block.dirty {
            if let Err(e) = self.write_slot(idx, &block.data) {
                self.cache.insert(idx, block);
                self.order.push_front(idx);
                return Err(e);
            }
        }
        if self.reserved > self.cache.len() {
            self.pool.release(BLOCK as u64);
            self.reserved -= 1;
        }
        Ok(())
    }

    fn make_room(&mut self) -> io::Result<()> {
        loop {
            if self.cache.len() < MAX_CACHED_BLOCKS && self.pool.try_reserve(BLOCK as u64) {
                self.reserved += 1;
                return Ok(());
            }
            if self.cache.is_empty() {
                return Ok(());
            }
            self.evict_lru()?;
        }
    }

    fn cached_block_mut(&mut self, idx: u64, load: bool) -> io::Result<&mut CachedBlock> {
        if self.cache.contains_key(&idx) {
            self.touch(idx);
        } else {
            self.make_room()?;
            let data = if load { self.load_block(idx)? } else { Zeroizing::new(vec![0u8; BLOCK]) };
            self.cache.insert(idx, CachedBlock { data, dirty: false });
            self.order.push_back(idx);
        }
        Ok(self.cache.get_mut(&idx).expect("just inserted"))
    }

    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset.checked_add(data.len() as u64).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "write offset overflow"))?;
        let mut pos = offset;
        let mut src = data;
        while !src.is_empty() {
            let idx = pos / BLOCK as u64;
            let within = (pos % BLOCK as u64) as usize;
            let n = (BLOCK - within).min(src.len());
            let full = within == 0 && n == BLOCK;
            let blk = self.cached_block_mut(idx, !full)?;
            blk.data[within..within + n].copy_from_slice(&src[..n]);
            blk.dirty = true;
            pos += n as u64;
            src = &src[n..];
        }
        let new_len = self.len.max(end);
        self.set_len_internal(new_len);
        Ok(())
    }

    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || out.is_empty() {
            return Ok(0);
        }
        let total = (out.len() as u64).min(self.len - offset) as usize;
        let mut done = 0usize;
        while done < total {
            let pos = offset + done as u64;
            let idx = pos / BLOCK as u64;
            let within = (pos % BLOCK as u64) as usize;
            let n = (BLOCK - within).min(total - done);
            if let Some(b) = self.cache.get(&idx) {
                out[done..done + n].copy_from_slice(&b.data[within..within + n]);
            } else if self.is_on_disk(idx) {
                self.read_slot_to_iobuf(idx)?;
                out[done..done + n].copy_from_slice(&self.io_buf[NONCE_LEN + within..NONCE_LEN + within + n]);
            } else {
                out[done..done + n].fill(0);
            }
            done += n;
        }
        Ok(total)
    }

    pub fn set_len(&mut self, new_len: u64) -> io::Result<()> {
        if new_len < self.len {
            let keep_blocks = new_len.div_ceil(BLOCK as u64);

            let doomed: Vec<u64> = self.cache.keys().copied().filter(|i| *i >= keep_blocks).collect();
            for i in doomed {
                self.cache.remove(&i);
                if let Some(pos) = self.order.iter().position(|x| *x == i) {
                    self.order.remove(pos);
                }
            }
            while self.reserved > self.cache.len() {
                self.pool.release(BLOCK as u64);
                self.reserved -= 1;
            }
            if self.on_disk.len() as u64 > keep_blocks {
                self.on_disk.truncate(keep_blocks as usize);
            }

            let tail = (new_len % BLOCK as u64) as usize;
            if tail != 0 {
                let idx = keep_blocks - 1;
                if self.cache.contains_key(&idx) || self.is_on_disk(idx) {
                    let blk = self.cached_block_mut(idx, true)?;
                    blk.data[tail..].fill(0);
                    blk.dirty = true;
                }
            }
        }
        self.set_len_internal(new_len);
        Ok(())
    }

    #[cfg(test)]
    fn raw_spill_bytes(&self) -> Vec<u8> {
        let Some(f) = &self.file else { return Vec::new() };
        let len = f.metadata().unwrap().len();
        let mut buf = vec![0u8; len as usize];
        read_exact_at(f, &mut buf, 0).unwrap();
        buf
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.reserved > 0 {
            self.pool.release((self.reserved * BLOCK) as u64);
            self.reserved = 0;
        }
        self.cache.clear();
        self.io_buf.zeroize();
        if let Some(p) = &self.file_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn lock(s: &Mutex<Scratch>) -> std::sync::MutexGuard<'_, Scratch> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

pub struct ScratchReader {
    scratch: Arc<Mutex<Scratch>>,
    pos: u64,
    end: u64,
}

impl ScratchReader {
    pub fn new(scratch: Arc<Mutex<Scratch>>, len: u64) -> Self {
        Self { scratch, pos: 0, end: len }
    }
}

impl Read for ScratchReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.end || out.is_empty() {
            return Ok(0);
        }
        let want = (out.len() as u64).min(self.end - self.pos) as usize;
        let n = lock(&self.scratch).read_at(self.pos, &mut out[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "scratch shrank while it was being uploaded"));
        }
        self.pos += n as u64;
        Ok(n)
    }
}

pub struct ScratchWriter<'a> {
    scratch: &'a mut Scratch,
    pos: u64,
}

impl<'a> ScratchWriter<'a> {
    pub fn new(scratch: &'a mut Scratch) -> Self {
        Self { scratch, pos: 0 }
    }
}

impl Write for ScratchWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.scratch.write_at(self.pos, buf)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("lethean-scratch-test-{tag}-{}", std::process::id()));
        d
    }

    fn read_all(s: &mut Scratch) -> Vec<u8> {
        let mut out = vec![0u8; s.len() as usize];
        let n = s.read_at(0, &mut out).unwrap();
        assert_eq!(n, out.len());
        out
    }

    #[test]
    fn matches_a_vec_model_under_random_writes_truncates_and_tiny_budget() {
        let pool = ScratchPool::new(2 * BLOCK as u64, tmp_dir("model"));
        let mut s = pool.new_scratch();
        let mut model: Vec<u8> = Vec::new();
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);

        for step in 0..400 {
            match rng.gen_range(0..10) {
                0..=6 => {
                    let off = rng.gen_range(0..(5 * BLOCK as u64));
                    let n = rng.gen_range(1..(BLOCK * 2 + 123));
                    let data: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
                    s.write_at(off, &data).unwrap();
                    let end = off as usize + n;
                    if model.len() < end {
                        model.resize(end, 0);
                    }
                    model[off as usize..end].copy_from_slice(&data);
                }
                7 | 8 => {
                    let new_len = rng.gen_range(0..(6 * BLOCK as u64));
                    s.set_len(new_len).unwrap();
                    model.resize(new_len as usize, 0);
                }
                _ => {
                    if !model.is_empty() {
                        let off = rng.gen_range(0..model.len());
                        let n = rng.gen_range(1..(BLOCK + 10));
                        let mut got = vec![0u8; n];
                        let r = s.read_at(off as u64, &mut got).unwrap();
                        let want_end = (off + n).min(model.len());
                        assert_eq!(&got[..r], &model[off..want_end], "step {step}");
                    }
                }
            }
            assert_eq!(s.len(), model.len() as u64, "step {step}");
            assert!(pool.used_bytes() <= 2 * BLOCK as u64, "pool budget exceeded at step {step}");
        }
        assert_eq!(read_all(&mut s), model);
        drop(s);
        assert_eq!(pool.used_bytes(), 0, "dropping a scratch must give its reservation back");
    }

    #[test]
    fn spilled_data_is_encrypted_on_disk() {
        let pool = ScratchPool::new(BLOCK as u64, tmp_dir("enc"));
        let mut s = pool.new_scratch();
        let secret = b"TOP-SECRET-PLAINTEXT-MARKER".repeat(10_000);
        s.write_at(0, &secret).unwrap();
        assert!(s.cached_bytes() <= BLOCK, "more than the budget is cached in RAM");
        let raw = s.raw_spill_bytes();
        assert!(!raw.is_empty(), "this much data should have spilled");
        assert!(!raw.windows(20).any(|w| w == &b"TOP-SECRET-PLAINTEXT"[..]), "plaintext leaked into the spill file");
        assert_eq!(read_all(&mut s), secret);
    }

    #[test]
    fn corrupted_spill_is_detected_not_returned() {
        let pool = ScratchPool::new(BLOCK as u64, tmp_dir("tamper"));
        let mut s = pool.new_scratch();
        s.write_at(0, &vec![7u8; 3 * BLOCK]).unwrap();
        let f = s.file.as_ref().unwrap();
        write_all_at(f, &[0xFF; 8], 40).unwrap();
        let mut out = vec![0u8; 3 * BLOCK];
        assert!(s.read_at(0, &mut out).is_err());
    }

    #[test]
    fn extending_after_truncate_reads_zeros_not_stale_bytes() {
        let pool = ScratchPool::new(DEFAULT_POOL_BYTES, tmp_dir("trunc"));
        let mut s = pool.new_scratch();
        s.write_at(0, &vec![9u8; 100]).unwrap();
        s.set_len(10).unwrap();
        s.set_len(100).unwrap();
        let got = read_all(&mut s);
        assert_eq!(&got[..10], &[9u8; 10]);
        assert!(got[10..].iter().all(|b| *b == 0));
    }

    #[test]
    fn dirty_tracking_follows_generations() {
        let pool = ScratchPool::new(DEFAULT_POOL_BYTES, tmp_dir("dirty"));
        let mut s = pool.new_scratch();
        assert!(!s.is_dirty());
        s.write_at(0, b"a").unwrap();
        assert!(s.is_dirty());
        let g = s.generation();
        s.write_at(1, b"b").unwrap();
        s.mark_committed(g);
        assert!(s.is_dirty(), "a write after the snapshot must stay dirty");
        s.mark_committed(s.generation());
        assert!(!s.is_dirty());
    }

    #[test]
    fn reader_and_writer_stream_a_large_file() {
        let pool = ScratchPool::new(4 * BLOCK as u64, tmp_dir("stream"));
        let mut s = pool.new_scratch();
        let data: Vec<u8> = (0..(BLOCK * 10 + 5)).map(|i| (i % 251) as u8).collect();
        ScratchWriter::new(&mut s).write_all(&data).unwrap();
        let len = s.len();
        let shared = Arc::new(Mutex::new(s));
        let mut back = Vec::new();
        ScratchReader::new(Arc::clone(&shared), len).read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
    }
}
