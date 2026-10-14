
mod common;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::crypto::gcm_stream::padme;

const CHUNK_SIZE: u32 = 1024 * 1024;
use lethean_fuse_lib::fuse_fs::{FsOptions, VaultFs};

fn fuse_usable() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok() && ["fusermount3", "fusermount"].iter().any(|c| std::process::Command::new(c).arg("-V").output().is_ok())
}

fn write_pattern(path: &Path, len: u64) {
    let mut f = File::create(path).expect("create");
    let mut buf = vec![0u8; 256 * 1024];
    let mut pos = 0u64;
    while pos < len {
        let n = buf.len().min((len - pos) as usize);
        for (k, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern_byte(pos + k as u64);
        }
        f.write_all(&buf[..n]).expect("write");
        pos += n as u64;
    }
    f.sync_all().ok();
}

fn read_all(path: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    File::open(path).and_then(|mut f| f.read_to_end(&mut v)).expect("read");
    v
}

#[test]
fn mounted_filesystem_round_trips_small_and_chunked_files() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);

    let mount_dir = std::env::temp_dir().join(format!("lethean-mnt-{}", std::process::id()));
    let scratch_dir = std::env::temp_dir().join(format!("lethean-scratch-{}", std::process::id()));
    fs::create_dir_all(&mount_dir).unwrap();
    fs::create_dir_all(&scratch_dir).unwrap();

    let mut vfs = VaultFs::with_options(vault, FsOptions { scratch_dir: Some(scratch_dir.clone()), scratch_ram_bytes: 4 * 1024 * 1024 });
    vfs.refresh().unwrap();
    let session = fuser::spawn_mount2(vfs, &mount_dir, &[fuser::MountOption::FSName("lethean-test".into())]).expect("mount");

    let small = mount_dir.join("small.txt");
    fs::write(&small, b"hello chunked world").unwrap();
    assert_eq!(read_all(&small), b"hello chunked world");

    let size: u64 = 9 * 1024 * 1024 + 321;
    let big = mount_dir.join("big.bin");
    write_pattern(&big, size);
    assert_eq!(fs::metadata(&big).unwrap().len(), size);

    {
        let files = server.files.lock().unwrap();
        assert_eq!(files.len(), 2, "one small blob and one streamed blob");
        assert!(files.iter().any(|(_, s)| s.blob.len() as u64 == padme(size) + 16));
    }

    let got = read_all(&big);
    assert_eq!(got.len() as u64, size);
    assert_eq!(&got[..1000], &expected(0, 1000)[..]);
    assert_eq!(&got[got.len() - 1000..], &expected(size - 1000, 1000)[..]);
    assert!(got.iter().enumerate().step_by(4093).all(|(i, b)| *b == pattern_byte(i as u64)));

    let mut f = File::open(&big).unwrap();
    for &off in &[size - 5, 3 * CHUNK_SIZE as u64 + 7, 12345, 0] {
        f.seek(SeekFrom::Start(off)).unwrap();
        let mut buf = vec![0u8; 5000];
        let n = f.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &expected(off, n)[..], "offset {off}");
    }
    drop(f);

    let mut names: Vec<String> = fs::read_dir(&mount_dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["big.bin", "small.txt"]);

    let empty = mount_dir.join("empty");
    File::create(&empty).unwrap();
    assert_eq!(fs::metadata(&empty).unwrap().len(), 0);

    fs::write(&small, b"replaced").unwrap();
    assert_eq!(read_all(&small), b"replaced");
    {
        let mut f = OpenOptions::new().append(true).open(&small).unwrap();
        f.write_all(b" and appended").unwrap();
    }
    assert_eq!(read_all(&small), b"replaced and appended");

    {
        let mut f = OpenOptions::new().read(true).write(true).open(&big).unwrap();
        f.seek(SeekFrom::Start(5 * CHUNK_SIZE as u64 + 10)).unwrap();
        f.write_all(b"PATCHED").unwrap();
    }
    let mut want = expected(5 * CHUNK_SIZE as u64, 64);
    want[10..17].copy_from_slice(b"PATCHED");
    let mut f = File::open(&big).unwrap();
    f.seek(SeekFrom::Start(5 * CHUNK_SIZE as u64)).unwrap();
    let mut buf = vec![0u8; 64];
    f.read_exact(&mut buf).unwrap();
    assert_eq!(buf, want);
    assert_eq!(fs::metadata(&big).unwrap().len(), size);
    drop(f);

    fs::remove_file(&small).unwrap();
    fs::remove_file(&empty).unwrap();
    assert!(!small.exists());
    let mut names: Vec<String> = fs::read_dir(&mount_dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["big.bin"]);

    drop(session);
    let leftovers: Vec<_> = fs::read_dir(&scratch_dir).map(|d| d.count()).into_iter().collect();
    assert!(leftovers.iter().all(|&n| n == 0), "scratch dir should hold no named files (spill files are unlinked)");
    let _ = fs::remove_dir_all(&mount_dir);
    let _ = fs::remove_dir_all(&scratch_dir);
}

fn mount(server: &Server, key: &[u8], tag: &str) -> (fuser::BackgroundSession, std::path::PathBuf, std::path::PathBuf) {
    let vault = new_vault(server.addr, key);
    let mount_dir = std::env::temp_dir().join(format!("lethean-mnt-{tag}-{}", std::process::id()));
    let scratch_dir = std::env::temp_dir().join(format!("lethean-scratch-{tag}-{}", std::process::id()));
    fs::create_dir_all(&mount_dir).unwrap();
    fs::create_dir_all(&scratch_dir).unwrap();
    let mut vfs = VaultFs::with_options(vault, FsOptions { scratch_dir: Some(scratch_dir.clone()), scratch_ram_bytes: 4 * 1024 * 1024 });
    vfs.refresh().unwrap();
    let session = fuser::spawn_mount2(vfs, &mount_dir, &[fuser::MountOption::FSName("lethean-test".into())]).expect("mount");
    (session, mount_dir, scratch_dir)
}

#[test]
fn gzip_compressed_files_are_served_in_full_through_the_mount() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();

    let small: Vec<u8> = b"All work and no play makes Jack a dull boy.\n".iter().cycle().take(200_000).copied().collect();
    let large: Vec<u8> = b"0123456789abcdef lorem ipsum dolor sit amet ".iter().cycle().take(20 * 1024 * 1024).copied().collect();
    let page = expected(0, 4096);
    for (name, body) in [("notes.txt", &small), ("log.txt", &large), ("page.bin", &page)] {
        let p = aead::encrypt_file(&key, name, "text/plain", body, None).unwrap();
        let meta = aead::decrypt_metadata(&aead::unwrap_file_key(&key, &p.wrapped_file_key, &p.wrap_iv).unwrap(), &p.encrypted_metadata, &p.metadata_iv).unwrap();
        assert!(meta.compressed && meta.unpadded_size.unwrap() < body.len() as u64, "test data must actually be compressed");
        inject(&server, [("content_iv", p.content_iv), ("encrypted_metadata", p.encrypted_metadata), ("metadata_iv", p.metadata_iv), ("wrapped_file_key", p.wrapped_file_key), ("wrap_iv", p.wrap_iv)], p.ciphertext);
    }

    let (session, mount_dir, scratch_dir) = mount(&server, &key, "gz");
    assert!(read_all(&mount_dir.join("notes.txt")) == small, "small compressed file must not be cut at its compressed length");
    assert!(read_all(&mount_dir.join("log.txt")) == large, "large compressed file must not be cut at its compressed length");
    assert_eq!(fs::read(mount_dir.join("page.bin")).unwrap().len(), page.len(), "nearly-incompressible file must not lose its tail");
    std::thread::sleep(std::time::Duration::from_secs(6));
    assert_eq!(fs::metadata(mount_dir.join("notes.txt")).unwrap().len(), small.len() as u64, "stat reports the real size once known");
    assert!(read_all(&mount_dir.join("notes.txt")) == small);

    let mine = mount_dir.join("mine.txt");
    fs::write(&mine, &small).unwrap();
    drop(session);

    let (session, mount_dir2, scratch_dir2) = mount(&server, &key, "gz2");
    assert!(read_all(&mount_dir2.join("mine.txt")) == small, "a fresh mount reads back what was written");
    drop(session);
    for d in [mount_dir, scratch_dir, mount_dir2, scratch_dir2] {
        let _ = fs::remove_dir_all(d);
    }
}

#[test]
fn reopening_serves_new_content_after_a_rewrite_and_large_dirs_list_fully() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let (session, mount_dir, scratch_dir) = mount(&server, &key, "rw");

    let path = mount_dir.join("doc.bin");
    let v1 = expected(0, 300_000);
    fs::write(&path, &v1).unwrap();
    for _ in 0..3 {
        assert!(read_all(&path) == v1, "repeated reads of an unchanged file");
    }
    let v2 = expected(777, 250_000);
    fs::write(&path, &v2).unwrap();
    assert!(read_all(&path) == v2, "the kept page cache must not serve the old version");
    {
        let mut f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(1000)).unwrap();
        f.write_all(b"EDIT").unwrap();
    }
    let mut v3 = v2.clone();
    v3[1000..1004].copy_from_slice(b"EDIT");
    assert!(read_all(&path) == v3);

    let dir = mount_dir.join("many");
    fs::create_dir(&dir).unwrap();
    for i in 0..600 {
        fs::write(dir.join(format!("n{i:04}")), format!("{i}")).unwrap();
    }
    for _ in 0..2 {
        let mut names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names.len(), 600);
        assert_eq!(names.first().map(String::as_str), Some("n0000"));
        assert_eq!(names.last().map(String::as_str), Some("n0599"));
    }
    assert_eq!(fs::read_to_string(dir.join("n0123")).unwrap(), "123");
    fs::remove_file(dir.join("n0123")).unwrap();
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 599);

    drop(session);
    let _ = fs::remove_dir_all(&mount_dir);
    let _ = fs::remove_dir_all(&scratch_dir);
}
