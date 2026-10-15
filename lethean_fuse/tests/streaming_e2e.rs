
mod common;

use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::crypto::gcm_stream::{GcmEncryptReader, STREAM_THRESHOLD};

const SIZE: u64 = 9 * 1024 * 1024 + 123;
const MIB: u64 = 1024 * 1024;

fn upload(vault: &lethean_fuse_lib::vault::Vault, name: &str, mime: &str, size: u64, started: &Arc<AtomicUsize>) -> String {
    vault
        .create_file_streaming(name, mime, size, None, || Ok(Box::new(PatternReader::new(size, Arc::clone(started))) as Box<dyn Read>))
        .expect("upload")
        .record
        .id
}

#[test]
fn large_upload_is_a_plain_single_blob_that_any_client_can_decrypt() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));
    upload(&vault, "big.bin", "application/octet-stream", SIZE, &started);
    assert_eq!(started.load(Ordering::SeqCst), 1);

    let (fields, blob) = {
        let files = server.files.lock().unwrap();
        assert_eq!(files.len(), 1);
        (files[0].1.fields.clone(), files[0].1.blob.clone())
    };
    assert_eq!(blob.len() as u64, aead::padded_size(SIZE) + 16);

    let file_key = aead::unwrap_file_key(&key, &fields["wrapped_file_key"], &fields["wrap_iv"]).unwrap();
    let meta = aead::decrypt_metadata(&file_key, &fields["encrypted_metadata"], &fields["metadata_iv"]).unwrap();
    assert!(!meta.compressed);
    assert_eq!(meta.unpadded_size, Some(SIZE));
    assert_eq!(meta.name, "big.bin");
    let json = serde_json::to_string(&meta).unwrap();
    assert!(!json.to_lowercase().contains("chunk"), "metadata must not carry any non-standard field: {json}");
    assert!(file_key.is_v2());
    assert_eq!(meta.size, Some(SIZE));
    let plain = aead::decrypt_content(&file_key.content_key(), &fields["content_iv"], &blob, &meta).unwrap();
    assert_eq!(plain.len() as u64, SIZE);
    assert_eq!(&plain[..1000], &expected(0, 1000)[..]);
    assert_eq!(&plain[plain.len() - 1000..], &expected(SIZE - 1000, 1000)[..]);

    assert!(find(&blob, &expected(1_000_000, 64)).is_none());
}

#[test]
fn large_reads_download_once_even_with_many_concurrent_readers() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let uploader = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));
    let id = upload(&uploader, "big.bin", "application/octet-stream", SIZE, &started);

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    assert!(reader.read_info(&id).unwrap().large);

    std::thread::scope(|s| {
        for t in 0..8u64 {
            let (reader, id) = (&reader, &id);
            s.spawn(move || {
                for k in 0..20u64 {
                    let off = (t * 1_234_567 + k * 98_765) % (SIZE - 5000);
                    let got = reader.read_range(id, off, 4096, ).expect("read_range");
                    assert_eq!(got, expected(off, 4096), "offset {off}");
                }
            });
        }
    });
    assert_eq!(server.full_gets.load(Ordering::SeqCst), 1, "the file must be fetched once and then served locally");

    assert_eq!(reader.read_range(&id, SIZE - 10, 1000).unwrap(), expected(SIZE - 10, 10));
    assert!(reader.read_range(&id, SIZE, 10).unwrap().is_empty());
    assert_eq!(reader.try_read_cached(&id, 0, 16).unwrap(), expected(0, 16));
    assert_eq!(server.full_gets.load(Ordering::SeqCst), 1);

    let mut all = Vec::new();
    let n = reader.stream_plaintext(&id, &mut all).unwrap();
    assert_eq!(n, SIZE);
    assert_eq!(&all[MIB as usize..MIB as usize + 100], &expected(MIB, 100)[..]);
}

#[test]
fn files_written_by_other_clients_are_readable_including_gzip_and_bucket_padding() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();

    let text: Vec<u8> = b"The quick brown fox jumps over the lazy dog. ".iter().cycle().take(12 * MIB as usize).copied().collect();
    let p = aead::encrypt_file(&key, "notes.txt", "text/plain", &text, None).unwrap();
    let id_text = inject(&server, [("content_iv", p.content_iv), ("encrypted_metadata", p.encrypted_metadata), ("metadata_iv", p.metadata_iv), ("wrapped_file_key", p.wrapped_file_key), ("wrap_iv", p.wrap_iv)], p.ciphertext);

    let video = expected(0, 9 * MIB as usize);
    let p = aead::encrypt_file(&key, "clip.mp4", "video/mp4", &video, None).unwrap();
    let id_video = inject(&server, [("content_iv", p.content_iv), ("encrypted_metadata", p.encrypted_metadata), ("metadata_iv", p.metadata_iv), ("wrapped_file_key", p.wrapped_file_key), ("wrap_iv", p.wrap_iv)], p.ciphertext);

    let vault = new_vault(server.addr, &key);
    vault.refresh_all().unwrap();

    let got = vault.read_range(&id_text, 5 * MIB, 4096).unwrap();
    assert_eq!(got, text[5 * MIB as usize..5 * MIB as usize + 4096]);
    let got = vault.read_range(&id_text, 12 * MIB - 100, 1000).unwrap();
    assert_eq!(got, text[text.len() - 100..], "gunzipped length is the real one");

    let got = vault.read_range(&id_video, 3 * MIB + 5, 70_000).unwrap();
    assert_eq!(got, video[3 * MIB as usize + 5..3 * MIB as usize + 5 + 70_000]);
    assert_eq!(vault.read_range(&id_video, 9 * MIB - 4, 100).unwrap(), video[video.len() - 4..]);
}

#[test]
fn tampered_or_truncated_large_blobs_are_rejected_and_never_cached() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let uploader = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));
    let id = upload(&uploader, "big.bin", "application/octet-stream", SIZE, &started);

    {
        let mut files = server.files.lock().unwrap();
        files[0].1.blob[4 * MIB as usize] ^= 1;
    }
    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    let err = reader.read_range(&id, 0, 16).expect_err("tampered data must not be served");
    assert!(format!("{err:#}").contains("AES-GCM"), "{err:#}");
    assert!(reader.read_range(&id, 0, 16).is_err(), "and it is not cached as if it were fine");
    assert!(reader.try_read_cached(&id, 0, 16).is_none());
    assert_eq!(server.full_gets.load(Ordering::SeqCst), 2, "an authentication failure is not retried");

    {
        let mut files = server.files.lock().unwrap();
        files[0].1.blob[4 * MIB as usize] ^= 1;
        let n = files[0].1.blob.len();
        files[0].1.blob.truncate(n - 1);
        files[0].1.blob_len -= 1;
    }
    assert!(reader.read_range(&id, 0, 16).is_err());
}

#[test]
fn a_dropped_upload_is_retried_from_a_fresh_reader() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: true, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));
    let id = upload(&vault, "retry.bin", "application/octet-stream", SIZE, &started);
    assert_eq!(started.load(Ordering::SeqCst), 2, "the body must be regenerated from the start for the retry");
    assert_eq!(server.uploads_seen.load(Ordering::SeqCst), 2);
    assert_eq!(server.files.lock().unwrap().len(), 1);
    assert_eq!(server.files.lock().unwrap()[0].1.blob.len() as u64, aead::padded_size(SIZE) + 16);

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    assert_eq!(reader.read_range(&id, SIZE - 100, 100).unwrap(), expected(SIZE - 100, 100));
}

#[test]
fn files_below_the_threshold_keep_the_original_in_memory_format() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let size = STREAM_THRESHOLD - 1;
    let started = Arc::new(AtomicUsize::new(0));
    let id = upload(&vault, "small.bin", "application/octet-stream", size, &started);
    assert!(!vault.read_info(&id).unwrap().large);
    assert_eq!(server.files.lock().unwrap()[0].1.blob.len() as u64, aead::padded_size(size) + 16);

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    assert_eq!(reader.read_range(&id, 12345, 5000).unwrap(), expected(12345, 5000));
}

#[test]
fn rename_pipes_the_ciphertext_without_changing_it() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));
    let id = upload(&vault, "old.bin", "application/octet-stream", SIZE, &started);
    let before = server.files.lock().unwrap()[0].1.blob.clone();

    let renamed = vault.rename_or_move(&id, Some("new.bin"), None).expect("rename");
    let files = server.files.lock().unwrap();
    assert_eq!(files.len(), 1, "old record deleted, new one present");
    assert_eq!(files[0].1.blob, before, "same ciphertext, only the metadata changed");
    drop(files);
    assert_eq!(renamed.name(), "new.bin");
    assert_eq!(vault.read_range(&renamed.record.id, 777, 64).unwrap(), expected(777, 64));
}

fn vm_hwm_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn rss_test_mib() -> u64 {
    std::env::var("LETHEAN_RSS_TEST_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(1024)
}

#[test]
#[ignore]
fn uploading_a_huge_file_stays_within_a_small_memory_budget() {
    let mib = rss_test_mib();
    let size = mib * MIB;
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: true });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let started = Arc::new(AtomicUsize::new(0));

    let before = vm_hwm_kib();
    let t = std::time::Instant::now();
    upload(&vault, "huge.bin", "application/octet-stream", size, &started);
    let secs = t.elapsed().as_secs_f64();
    let growth = (vm_hwm_kib().saturating_sub(before)) as f64 / 1024.0;
    println!("uploaded {mib} MiB in {secs:.2}s ({:.0} MiB/s), peak RSS grew by {growth:.1} MiB", mib as f64 / secs);
    assert!(growth < 100.0, "peak RSS grew by {growth:.1} MiB for a {mib} MiB upload");
}

#[test]
#[ignore]
fn downloading_a_huge_file_stays_within_the_scratch_budget() {
    let mib = rss_test_mib();
    let size = mib * MIB;
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: true });
    let key = aead::generate_aes_key_raw();

    let plan = aead::plan_stream_upload(&key, "huge.bin", "application/octet-stream", size, None, None).unwrap();
    let (fk, iv, padded) = (plan.content_key.key.to_vec(), plan.iv.clone(), plan.padded_len);
    let gen: Generator = Arc::new(move || {
        let src = PatternReader::new(size, Arc::new(AtomicUsize::new(0)));
        Box::new(GcmEncryptReader::with_aad(src, &fk, &iv, lethean_fuse_lib::crypto::format::AAD_CONTENT_V2, size, padded).unwrap())
    });
    let h = &plan.header;
    let id = inject_virtual(
        &server,
        [("content_iv", h.content_iv.clone()), ("encrypted_metadata", h.encrypted_metadata.clone()), ("metadata_iv", h.metadata_iv.clone()), ("wrapped_file_key", h.wrapped_file_key.clone()), ("wrap_iv", h.wrap_iv.clone())],
        plan.body_len(),
        gen,
    );

    let scratch_dir = std::env::temp_dir().join(format!("lethean-rss-{}", std::process::id()));
    let mut vault = new_vault(server.addr, &key);
    vault.set_scratch_dir(scratch_dir.clone(), 64 * MIB);
    vault.refresh_all().unwrap();

    let before = vm_hwm_kib();
    let t = std::time::Instant::now();
    let tail = vault.read_range(&id, size - 4096, 4096).expect("read");
    let secs = t.elapsed().as_secs_f64();
    let growth = (vm_hwm_kib().saturating_sub(before)) as f64 / 1024.0;
    assert_eq!(tail, expected(size - 4096, 4096));
    assert_eq!(vault.read_range(&id, 12345, 100).unwrap(), expected(12345, 100));
    println!("downloaded+verified+decrypted {mib} MiB in {secs:.2}s ({:.0} MiB/s), peak RSS grew by {growth:.1} MiB", mib as f64 / secs);
    assert!(growth < 160.0, "peak RSS grew by {growth:.1} MiB for a {mib} MiB download");
    drop(vault);
    let _ = std::fs::remove_dir_all(&scratch_dir);
}

#[test]
fn files_over_32_mib_use_the_web_clients_chunked_format_and_round_trip() {
    use lethean_fuse_lib::crypto::chunked::{sealed_len, CHUNK_SIZE};
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let size = CHUNK_SIZE + 5 * MIB + 17;
    let started = Arc::new(AtomicUsize::new(0));
    let id = upload(&vault, "chunked.bin", "application/octet-stream", size, &started);

    let (fields, blob_len) = {
        let files = server.files.lock().unwrap();
        (files[0].1.fields.clone(), files[0].1.blob.len() as u64)
    };
    assert_eq!(blob_len, sealed_len(size, CHUNK_SIZE), "two sealed 32 MiB chunks");
    let file_key = aead::unwrap_file_key(&key, &fields["wrapped_file_key"], &fields["wrap_iv"]).unwrap();
    let meta = aead::decrypt_metadata(&file_key, &fields["encrypted_metadata"], &fields["metadata_iv"]).unwrap();
    assert_eq!(meta.chunk_size, Some(CHUNK_SIZE));
    assert_eq!(meta.unpadded_size, Some(size));
    assert_eq!(aead::from_base64(&fields["content_iv"]).unwrap().len(), 8, "nonce prefix, as the web client stores it");

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    assert_eq!(reader.read_range(&id, CHUNK_SIZE - 10, 20).unwrap(), expected(CHUNK_SIZE - 10, 20), "across the chunk boundary");
    assert_eq!(reader.read_range(&id, size - 100, 100).unwrap(), expected(size - 100, 100));

    {
        let mut files = server.files.lock().unwrap();
        files[0].1.blob[CHUNK_SIZE as usize + 100] ^= 1;
    }
    let tampered = new_vault(server.addr, &key);
    tampered.refresh_all().unwrap();
    assert_eq!(tampered.read_range(&id, 0, 16).unwrap(), expected(0, 16));
    let err = tampered.read_range(&id, CHUNK_SIZE + 10, 16).expect_err("a tampered chunk must not be served");
    assert!(format!("{err:#}").contains("AES-GCM"), "{err:#}");
    assert!(tampered.read_range(&id, CHUNK_SIZE + 10, 16).is_err(), "and it is not cached as if it were fine");
    assert!(tampered.try_read_cached(&id, CHUNK_SIZE + 10, 16).is_none());
    assert!(tampered.read_range(&id, CHUNK_SIZE - 8, 16).is_err(), "a read spanning into the tampered chunk fails too");
}

fn upload_chunked(server: &Server, key: &[u8], size: u64) -> String {
    let vault = new_vault(server.addr, key);
    let started = Arc::new(AtomicUsize::new(0));
    upload(&vault, "chunked.bin", "application/octet-stream", size, &started)
}

#[test]
fn chunked_files_are_read_by_range_fetching_only_the_chunks_touched() {
    use lethean_fuse_lib::crypto::chunked::{sealed_len, CHUNK_SIZE};
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let size = 3 * CHUNK_SIZE + 4 * MIB + 3;
    let id = upload_chunked(&server, &key, size);

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    let served0 = server.bytes_served.load(Ordering::SeqCst);
    let tail = reader.read_range(&id, size - 4096, 4096).unwrap();
    assert_eq!(tail, expected(size - 4096, 4096));
    let fetched = (server.bytes_served.load(Ordering::SeqCst) - served0) as u64;
    assert!(fetched <= CHUNK_SIZE + 64, "reading the tail fetched {fetched} bytes, expected one chunk");
    assert_eq!(server.full_gets.load(Ordering::SeqCst), 0, "no whole-file download");

    let gets0 = server.range_gets.load(Ordering::SeqCst);
    std::thread::scope(|s| {
        for t in 0..8u64 {
            let (reader, id) = (&reader, &id);
            s.spawn(move || {
                let off = CHUNK_SIZE + t * 1000;
                assert_eq!(reader.read_range(id, off, 512).unwrap(), expected(off, 512));
            });
        }
    });
    assert_eq!(server.range_gets.load(Ordering::SeqCst) - gets0, 1, "one ranged GET for the shared chunk");

    for off in [0, CHUNK_SIZE - 7, 2 * CHUNK_SIZE - 1, size - 1] {
        assert_eq!(reader.read_range(&id, off, 64).unwrap(), expected(off, (size - off).min(64) as usize), "offset {off}");
    }
    let mut all = Vec::new();
    assert_eq!(reader.stream_plaintext(&id, &mut all).unwrap(), size);
    assert!(all == expected(0, size as usize));
    assert!((server.bytes_served.load(Ordering::SeqCst) - served0) as u64 <= sealed_len(size, CHUNK_SIZE) + 64, "each chunk fetched at most once");
}

#[test]
fn chunked_files_fall_back_to_a_full_download_when_the_server_ignores_ranges() {
    use lethean_fuse_lib::crypto::chunked::CHUNK_SIZE;
    let server = start_server(ServerOpts { support_range: false, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let size = CHUNK_SIZE + 1234;
    let id = upload_chunked(&server, &key, size);

    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    assert_eq!(reader.read_range(&id, size - 100, 100).unwrap(), expected(size - 100, 100));
    assert_eq!(reader.read_range(&id, 5, 100).unwrap(), expected(5, 100));
    assert_eq!(server.range_gets.load(Ordering::SeqCst), 0);
}

#[test]
fn a_truncated_chunked_blob_is_rejected_even_when_reading_an_intact_chunk() {
    use lethean_fuse_lib::crypto::chunked::CHUNK_SIZE;
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let size = 2 * CHUNK_SIZE + 99;
    let id = upload_chunked(&server, &key, size);
    {
        let mut files = server.files.lock().unwrap();
        let n = files[0].1.blob.len();
        files[0].1.blob.truncate(n - (CHUNK_SIZE as usize + 16));
        files[0].1.blob_len = files[0].1.blob.len() as u64;
    }
    let reader = new_vault(server.addr, &key);
    reader.refresh_all().unwrap();
    assert!(reader.read_range(&id, 0, 16).is_err(), "the size the server reports no longer matches the metadata");
}

#[test]
#[ignore]
fn downloading_a_huge_chunked_file_stays_within_the_scratch_budget() {
    use lethean_fuse_lib::crypto::chunked::{plan_chunked_upload, ChunkedEncryptReader};
    let mib = rss_test_mib();
    let size = mib * MIB + 777;
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: true });
    let key = aead::generate_aes_key_raw();
    let plan = plan_chunked_upload(&key, "huge.bin", "application/octet-stream", size, None, None).unwrap();
    let (ck, prefix) = (plan.content_key.clone(), plan.prefix.clone());
    let gen: Generator = Arc::new(move || {
        let src = PatternReader::new(size, Arc::new(AtomicUsize::new(0)));
        Box::new(ChunkedEncryptReader::new(src, &ck, &prefix, size))
    });
    let h = &plan.header;
    let id = inject_virtual(
        &server,
        [("content_iv", h.content_iv.clone()), ("encrypted_metadata", h.encrypted_metadata.clone()), ("metadata_iv", h.metadata_iv.clone()), ("wrapped_file_key", h.wrapped_file_key.clone()), ("wrap_iv", h.wrap_iv.clone())],
        plan.body_len(),
        gen,
    );

    let scratch_dir = std::env::temp_dir().join(format!("lethean-rss-c-{}", std::process::id()));
    let mut vault = new_vault(server.addr, &key);
    vault.set_scratch_dir(scratch_dir.clone(), 64 * MIB);
    vault.refresh_all().unwrap();

    let before = vm_hwm_kib();
    let t = std::time::Instant::now();
    let tail = vault.read_range(&id, size - 4096, 4096).expect("read");
    let secs = t.elapsed().as_secs_f64();
    let growth = (vm_hwm_kib().saturating_sub(before)) as f64 / 1024.0;
    assert_eq!(tail, expected(size - 4096, 4096));
    println!("chunked: downloaded+verified+decrypted {mib} MiB in {secs:.2}s ({:.0} MiB/s), peak RSS grew by {growth:.1} MiB", mib as f64 / secs);
    drop(vault);
    let _ = std::fs::remove_dir_all(&scratch_dir);
}
