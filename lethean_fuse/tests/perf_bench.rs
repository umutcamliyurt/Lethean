mod common;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::fuse_fs::{FsOptions, VaultFs};

const MIB: u64 = 1024 * 1024;
const BIG: u64 = 256 * MIB + 12_345;
const SMALL_FILES: usize = 1000;
const MANY_FILES: usize = 20_000;

fn fuse_usable() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok()
}

fn rss_kib() -> u64 {
    let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn inject_payload(server: &Server, p: lethean_fuse_lib::types::EncryptedFilePayload) -> String {
    inject(server, [("content_iv", p.content_iv), ("encrypted_metadata", p.encrypted_metadata), ("metadata_iv", p.metadata_iv), ("wrapped_file_key", p.wrapped_file_key), ("wrap_iv", p.wrap_iv)], p.ciphertext)
}

#[test]
#[ignore]
fn perf_bench() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();

    let uploader = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));
    for name in ["big1.bin", "big2.bin"] {
        uploader
            .create_file_streaming(name, "application/octet-stream", BIG, None, || Ok(Box::new(PatternReader::new(BIG, Arc::clone(&started))) as Box<dyn Read>))
            .expect("upload big");
    }
    let folder = |name: &str| {
        let payload = aead::encrypt_folder(&key, name, None).unwrap();
        let node_ref = aead::unwrap_file_key(&key, &payload.wrapped_file_key, &payload.wrap_iv).unwrap().node_ref();
        lethean_fuse_lib::crypto::format::ParentRef { id: inject_payload(&server, payload), node_ref }
    };
    let small_dir = folder("small");
    for i in 0..SMALL_FILES {
        let body: Vec<u8> = (0..4096 + (i % 13) * 100).map(|_| rand::random::<u8>()).collect();
        inject_payload(&server, aead::encrypt_file(&key, &format!("f{i:05}.txt"), "application/octet-stream", &body, Some(&small_dir)).unwrap());
    }
    let many_dir = folder("many");
    for i in 0..MANY_FILES {
        inject_payload(&server, aead::encrypt_file(&key, &format!("entry-{i:06}.dat"), "application/octet-stream", b"x", Some(&many_dir)).unwrap());
    }
    drop(uploader);

    let rss0 = rss_kib();
    let probe = new_vault(server.addr, &key);
    probe.refresh_all().unwrap();
    let index_mib = (rss_kib().saturating_sub(rss0)) as f64 / 1024.0;
    drop(probe);

    let tag = std::process::id();
    let mount_dir = std::env::temp_dir().join(format!("lethean-bench-mnt-{tag}"));
    let scratch_dir = std::env::temp_dir().join(format!("lethean-bench-scratch-{tag}"));
    fs::create_dir_all(&mount_dir).unwrap();
    fs::create_dir_all(&scratch_dir).unwrap();
    let vault = new_vault(server.addr, &key);
    let t = Instant::now();
    let mut vfs = VaultFs::with_options(vault, FsOptions { scratch_dir: Some(scratch_dir.clone()), scratch_ram_bytes: 64 * MIB });
    vfs.refresh().unwrap();
    let refresh_s = t.elapsed().as_secs_f64();
    let session = fuser::spawn_mount2(vfs, &mount_dir, &[fuser::MountOption::FSName("lethean-bench".into())]).expect("mount");

    let mut report: Vec<(String, String)> = Vec::new();
    report.push(("index RSS for 22k entries".into(), format!("{index_mib:.1} MiB")));
    report.push(("refresh (22k records)".into(), format!("{:.0} ms", refresh_s * 1e3)));

    let served0 = server.bytes_served.load(Ordering::SeqCst);
    let t = Instant::now();
    let mut f = File::open(mount_dir.join("big1.bin")).unwrap();
    let mut buf = vec![0u8; 4096];
    f.read_exact(&mut buf).unwrap();
    assert_eq!(buf, expected(0, 4096));
    report.push(("big file: first 4 KiB (cold)".into(), format!("{:.0} ms, {} MiB fetched", t.elapsed().as_secs_f64() * 1e3, (server.bytes_served.load(Ordering::SeqCst) - served0) as u64 / MIB)));

    let t = Instant::now();
    let mut big = vec![0u8; MIB as usize];
    let mut total = 4096u64;
    loop {
        let n = f.read(&mut big).unwrap();
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    assert_eq!(total, BIG);
    let s = t.elapsed().as_secs_f64();
    report.push(("big file: sequential read (cold)".into(), format!("{:.0} MiB/s", BIG as f64 / MIB as f64 / s)));
    drop(f);

    let t = Instant::now();
    let mut f = File::open(mount_dir.join("big1.bin")).unwrap();
    let mut total = 0u64;
    loop {
        let n = f.read(&mut big).unwrap();
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    assert_eq!(total, BIG);
    report.push(("big file: sequential re-read (warm)".into(), format!("{:.0} MiB/s", BIG as f64 / MIB as f64 / t.elapsed().as_secs_f64())));
    drop(f);

    let served0 = server.bytes_served.load(Ordering::SeqCst);
    let t = Instant::now();
    let mut f = File::open(mount_dir.join("big2.bin")).unwrap();
    f.seek(SeekFrom::Start(BIG - 4096)).unwrap();
    f.read_exact(&mut buf).unwrap();
    assert_eq!(buf, expected(BIG - 4096, 4096));
    report.push(("big file: last 4 KiB (cold)".into(), format!("{:.0} ms, {} MiB fetched", t.elapsed().as_secs_f64() * 1e3, (server.bytes_served.load(Ordering::SeqCst) - served0) as u64 / MIB)));
    let t = Instant::now();
    let mut x = 0x1234_5678u64;
    for _ in 0..64 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let off = (x >> 11) % (BIG - 4096);
        f.seek(SeekFrom::Start(off)).unwrap();
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, expected(off, 4096));
    }
    report.push(("big file: 64 random 4 KiB reads".into(), format!("{:.0} ms", t.elapsed().as_secs_f64() * 1e3)));
    drop(f);

    let t = Instant::now();
    let names: Vec<_> = fs::read_dir(mount_dir.join("many")).unwrap().map(|e| e.unwrap().file_name()).collect();
    report.push(("  readdir only, 20k names (cold)".into(), format!("{:.0} ms", t.elapsed().as_secs_f64() * 1e3)));
    let t2 = Instant::now();
    for n in &names {
        let _ = fs::symlink_metadata(mount_dir.join("many").join(n)).unwrap().len();
    }
    report.push(("  stat 20k names (cold)".into(), format!("{:.0} ms", t2.elapsed().as_secs_f64() * 1e3)));
    std::thread::sleep(std::time::Duration::from_secs(6));
    let t = Instant::now();
    let mut n = 0;
    for e in fs::read_dir(mount_dir.join("many")).unwrap() {
        let e = e.unwrap();
        let _ = e.metadata().unwrap().len();
        n += 1;
    }
    assert_eq!(n, MANY_FILES);
    report.push(("ls -l of 20k-entry dir (cold)".into(), format!("{:.0} ms", t.elapsed().as_secs_f64() * 1e3)));

    let gets0 = server.full_gets.load(Ordering::SeqCst);
    let t = Instant::now();
    for i in 0..SMALL_FILES {
        let got = fs::read(mount_dir.join("small").join(format!("f{i:05}.txt"))).unwrap();
        assert_eq!(got.len(), 4096 + (i % 13) * 100, "file {i}");
    }
    report.push(("read 1000 small files".into(), format!("{:.0} ms, {} blob GETs", t.elapsed().as_secs_f64() * 1e3, server.full_gets.load(Ordering::SeqCst) - gets0)));

    let t = Instant::now();
    for i in 0..SMALL_FILES {
        let _ = fs::read(mount_dir.join("small").join(format!("f{i:05}.txt"))).unwrap();
    }
    report.push(("re-read 1000 small files (warm)".into(), format!("{:.0} ms", t.elapsed().as_secs_f64() * 1e3)));

    report.push(("RSS at end (incl. mock server blobs)".into(), format!("{} MiB", rss_kib() / 1024)));

    drop(session);
    let _ = fs::remove_dir_all(&mount_dir);
    let _ = fs::remove_dir_all(&scratch_dir);
    println!("\n==== perf_bench ====");
    for (k, v) in &report {
        println!("{k:<40} {v}");
    }
}
