mod common;

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::crypto::format::ParentRef;
use lethean_fuse_lib::fuse_fs::{FsOptions, VaultFs};
use lethean_fuse_lib::vault::{kernel_safe_name, Vault};

fn fuse_usable() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok() && ["fusermount3", "fusermount"].iter().any(|c| std::process::Command::new(c).arg("-V").output().is_ok())
}

struct Mounted {
    dir: PathBuf,
    _session: fuser::BackgroundSession,
}

fn mount(vault: Vault, tag: &str) -> Mounted {
    let dir = std::env::temp_dir().join(format!("lethean-hard-{tag}-{}", std::process::id()));
    let scratch = std::env::temp_dir().join(format!("lethean-hard-scratch-{tag}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let mut vfs = VaultFs::with_options(vault, FsOptions { scratch_dir: Some(scratch), scratch_ram_bytes: 8 * 1024 * 1024, ..Default::default() });
    vfs.refresh().unwrap();
    let session = fuser::spawn_mount2(vfs, &dir, &[fuser::MountOption::FSName("lethean-hard".into()), fuser::MountOption::DefaultPermissions]).expect("mount");
    Mounted { dir, _session: session }
}

fn inject_payload(server: &Server, p: lethean_fuse_lib::types::EncryptedFilePayload) -> String {
    inject(server, [("content_iv", p.content_iv), ("encrypted_metadata", p.encrypted_metadata), ("metadata_iv", p.metadata_iv), ("wrapped_file_key", p.wrapped_file_key), ("wrap_iv", p.wrap_iv)], p.ciphertext)
}

fn renameat2(from: &Path, to: &Path, flags: u32) -> std::io::Result<()> {
    let a = CString::new(from.as_os_str().as_bytes()).unwrap();
    let b = CString::new(to.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
fn kernel_safe_names_are_single_valid_components() {
    assert_eq!(kernel_safe_name("report.pdf"), "report.pdf");
    for hostile in ["a/b", "..", ".", "", "nul\0byte", &"x".repeat(300), &"é".repeat(200)] {
        let safe = kernel_safe_name(hostile);
        assert!(!safe.is_empty() && safe != "." && safe != "..", "{hostile:?} -> {safe:?}");
        assert!(!safe.contains('/') && !safe.contains('\0'), "{hostile:?} -> {safe:?}");
        assert!(safe.len() <= 255, "{hostile:?} -> {} bytes", safe.len());
    }
}

#[test]
fn a_hostile_item_name_no_longer_breaks_the_whole_directory_listing() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let long = "L".repeat(2000);
    for name in ["normal.txt", "a/b.txt", "..", long.as_str()] {
        inject_payload(&server, aead::encrypt_file(&key, name, "text/plain", name.as_bytes(), None).unwrap());
    }
    let m = mount(new_vault(server.addr, &key), "names");

    let mut names: Vec<String> = fs::read_dir(&m.dir).expect("listing the folder must not fail").map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names.len(), 4, "{names:?}");
    assert!(names.contains(&"normal.txt".to_string()));
    for n in &names {
        assert!(n.len() <= 255 && n != ".." && !n.contains('/'));
        let content = fs::read(m.dir.join(n)).unwrap_or_else(|e| panic!("open {n:?}: {e}"));
        assert!(!content.is_empty());
    }
    assert_eq!(fs::read(m.dir.join("a\u{2215}b.txt")).unwrap(), b"a/b.txt");
}

#[test]
fn mounted_items_are_private_to_the_owner() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let folder = aead::encrypt_folder(&key, "dir", None).unwrap();
    inject_payload(&server, folder);
    inject_payload(&server, aead::encrypt_file(&key, "secret.txt", "text/plain", b"s", None).unwrap());
    let m = mount(new_vault(server.addr, &key), "perms");
    for p in [m.dir.clone(), m.dir.join("dir"), m.dir.join("secret.txt")] {
        let mode = fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{} is accessible to group/others: {mode:o}", p.display());
    }
}

#[test]
fn rename_honours_flags_and_never_loses_the_target() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let m = mount(new_vault(server.addr, &key), "rename");
    let d = &m.dir;
    fs::write(d.join("a.txt"), b"AAA").unwrap();
    fs::write(d.join("b.txt"), b"BBB").unwrap();

    let err = renameat2(&d.join("a.txt"), &d.join("b.txt"), libc::RENAME_EXCHANGE).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL), "{err}");
    assert_eq!(fs::read(d.join("a.txt")).unwrap(), b"AAA");
    assert_eq!(fs::read(d.join("b.txt")).unwrap(), b"BBB");

    let err = renameat2(&d.join("a.txt"), &d.join("b.txt"), libc::RENAME_NOREPLACE).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST), "{err}");
    assert_eq!(fs::read(d.join("b.txt")).unwrap(), b"BBB");

    fs::create_dir(d.join("full")).unwrap();
    fs::write(d.join("full").join("keep.txt"), b"KEEP").unwrap();
    fs::create_dir(d.join("other")).unwrap();
    assert_eq!(fs::rename(d.join("a.txt"), d.join("full")).unwrap_err().raw_os_error(), Some(libc::EISDIR));
    assert_eq!(fs::rename(d.join("other"), d.join("full")).unwrap_err().raw_os_error(), Some(libc::ENOTEMPTY));
    assert_eq!(fs::read(d.join("full").join("keep.txt")).unwrap(), b"KEEP", "the non-empty folder must survive");

    fs::create_dir(d.join("full").join("sub")).unwrap();
    let err = fs::rename(d.join("full"), d.join("full").join("sub").join("loop")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL), "{err}");
    assert_eq!(fs::read(d.join("full").join("keep.txt")).unwrap(), b"KEEP");

    fs::rename(d.join("a.txt"), d.join("b.txt")).unwrap();
    assert!(!d.join("a.txt").exists());
    assert_eq!(fs::read(d.join("b.txt")).unwrap(), b"AAA");
}

#[test]
fn readdirplus_listing_reports_sizes_and_types_and_survives_unmount() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let payload = aead::encrypt_folder(&key, "docs", None).unwrap();
    let node_ref = aead::unwrap_file_key(&key, &payload.wrapped_file_key, &payload.wrap_iv).unwrap().node_ref();
    let docs = ParentRef { id: inject_payload(&server, payload), node_ref };
    for i in 0..300 {
        inject_payload(&server, aead::encrypt_file(&key, &format!("f{i:03}.txt"), "text/plain", &vec![b'x'; i + 1], Some(&docs)).unwrap());
    }
    let m = mount(new_vault(server.addr, &key), "rdplus");
    let mut seen = 0;
    for e in fs::read_dir(m.dir.join("docs")).unwrap() {
        let e = e.unwrap();
        let i: usize = e.file_name().to_string_lossy()[1..4].parse().unwrap();
        let md = e.metadata().unwrap();
        assert!(md.is_file());
        assert_eq!(md.len(), (i + 1) as u64);
        seen += 1;
    }
    assert_eq!(seen, 300);
    assert!(m.dir.join("docs").is_dir());
}

#[test]
fn read_ahead_does_not_re_download_a_bad_chunk_on_every_read() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let chunk = 32 * 1024 * 1024u64;
    let size = 3 * chunk + 99;
    let started = Arc::new(AtomicUsize::new(0));
    let e = new_vault(server.addr, &key).create_file_streaming("big.bin", "application/octet-stream", size, None, || Ok(Box::new(PatternReader::new(size, Arc::clone(&started))) as Box<dyn Read>)).unwrap();
    {
        let mut files = server.files.lock().unwrap();
        let blob = &mut files.iter_mut().find(|(id, _)| *id == e.record.id).unwrap().1.blob;
        blob[(chunk + 16 + 1000) as usize] ^= 0x55;
    }
    let v = new_vault(server.addr, &key);
    v.refresh_all().unwrap();
    let f = v.load_large(&e.record.id).unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    let mut off = 0u64;
    while std::time::Instant::now() < until {
        let part = v.read_large(&f, off, 128 * 1024).unwrap();
        assert_eq!(part, expected(off, part.len()));
        off = (off + part.len() as u64) % chunk;
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let gets = server.range_gets.load(Ordering::SeqCst);
    assert!(gets <= 5, "{gets} range requests: the tampered chunk was re-downloaded on every read");
    assert!(v.read_large(&f, chunk + 10, 100).is_err());
    assert_eq!(v.read_large(&f, 2 * chunk, 64).unwrap(), expected(2 * chunk, 64));
}

#[test]
fn large_uploads_send_parts_concurrently_and_round_trip() {
    let server = start_multipart_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let size = 3 * 32 * 1024 * 1024 + 4321u64;
    let started = Arc::new(AtomicUsize::new(0));
    let v = new_vault(server.addr, &key);
    let t = std::time::Instant::now();
    let e = v.create_file_streaming("parts.bin", "application/octet-stream", size, None, || Ok(Box::new(PatternReader::new(size, Arc::clone(&started))) as Box<dyn Read>)).unwrap();
    eprintln!("multipart upload of {} MiB took {:?}", size >> 20, t.elapsed());
    assert_eq!(server.parts_seen.load(Ordering::SeqCst), 4);
    assert!(server.peak_parts_in_flight.load(Ordering::SeqCst) >= 2, "parts were uploaded one at a time");

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    let mut got = Vec::new();
    reader.stream_plaintext(&e.record.id, &mut got).unwrap();
    assert_eq!(got.len() as u64, size);
    assert!(got == expected(0, size as usize), "content mismatch after a parallel multipart upload");
}
