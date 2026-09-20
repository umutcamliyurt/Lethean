
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use lethean_fuse_lib::api::ApiClient;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::types::FileRecord;
use lethean_fuse_lib::vault::Vault;

const SLOW_DELAY: Duration = Duration::from_millis(1500);
const FAST_BUDGET: Duration = Duration::from_millis(500);

fn record_from_payload(id: &str, payload: &lethean_fuse_lib::types::EncryptedFilePayload) -> FileRecord {
    FileRecord {
        id: id.to_string(),
        content_iv: payload.content_iv.clone(),
        encrypted_metadata: payload.encrypted_metadata.clone(),
        metadata_iv: payload.metadata_iv.clone(),
        wrapped_file_key: payload.wrapped_file_key.clone(),
        wrap_iv: payload.wrap_iv.clone(),
        size: None,
    }
}

fn record_to_json(r: &FileRecord) -> String {
    format!(
        r#"{{"id":"{}","content_iv":"{}","encrypted_metadata":"{}","metadata_iv":"{}","wrapped_file_key":"{}","wrap_iv":"{}"}}"#,
        r.id, r.content_iv, r.encrypted_metadata, r.metadata_iv, r.wrapped_file_key, r.wrap_iv
    )
}

fn handle_connection(mut stream: TcpStream, slow_id: String, fast_id: String, records_json: String, slow_ciphertext: Vec<u8>, fast_ciphertext: Vec<u8>) {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("").to_string();

    let body: Vec<u8> = if path.starts_with("/files/") && path.ends_with("/blob") {
        if path.contains(&slow_id) {
            thread::sleep(SLOW_DELAY);
            slow_ciphertext
        } else {
            debug_assert!(path.contains(&fast_id));
            fast_ciphertext
        }
    } else {
        records_json.into_bytes()
    };

    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

#[test]
fn slow_download_does_not_block_a_concurrent_fast_one() {
    let wrapping_key = aead::generate_aes_key_raw();
    let slow_payload = aead::encrypt_file(&wrapping_key, "slow.bin", "application/octet-stream", b"hello", None).unwrap();
    let fast_payload = aead::encrypt_file(&wrapping_key, "fast.bin", "application/octet-stream", b"hello", None).unwrap();

    let slow_id = "slowfile00000000000000000000000".to_string();
    let fast_id = "fastfile00000000000000000000000".to_string();

    let slow_record = record_from_payload(&slow_id, &slow_payload);
    let fast_record = record_from_payload(&fast_id, &fast_payload);
    let records_json = format!("[{},{}]", record_to_json(&slow_record), record_to_json(&fast_record));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let slow_id_srv = slow_id.clone();

    let fast_id_srv = fast_id.clone();
    let slow_ciphertext = slow_payload.ciphertext.clone();
    let fast_ciphertext = fast_payload.ciphertext.clone();
    let server = thread::spawn(move || {
        for stream in listener.incoming().take(3) {
            let Ok(stream) = stream else { continue };
            let slow_id = slow_id_srv.clone();
            let fast_id = fast_id_srv.clone();
            let records_json = records_json.clone();
            let slow_ciphertext = slow_ciphertext.clone();
            let fast_ciphertext = fast_ciphertext.clone();
            thread::spawn(move || handle_connection(stream, slow_id, fast_id, records_json, slow_ciphertext, fast_ciphertext));
        }
    });

    let api = ApiClient::new(format!("http://{addr}")).expect("client");
    api.set_vault_id(Some("test-vault".to_string()));
    let vault = Arc::new(Vault::new(api, wrapping_key));
    vault.refresh_all().expect("refresh_all should populate both entries from the mock /files listing");
    assert_eq!(vault.all_entries().len(), 2);

    let barrier = Arc::new(Barrier::new(2));

    let vault_slow = Arc::clone(&vault);
    let slow_id_2 = slow_id.clone();
    let barrier_slow = Arc::clone(&barrier);
    let slow_thread = thread::spawn(move || {
        barrier_slow.wait();
        let start = Instant::now();
        let result = vault_slow.download_decrypted(&slow_id_2);
        (result, start.elapsed())
    });

    let vault_fast = Arc::clone(&vault);
    let fast_id_2 = fast_id.clone();
    let barrier_fast = Arc::clone(&barrier);
    let fast_thread = thread::spawn(move || {
        barrier_fast.wait();
        thread::sleep(Duration::from_millis(150));
        let start = Instant::now();
        let result = vault_fast.download_decrypted(&fast_id_2);
        (result, start.elapsed())
    });

    let (slow_result, slow_elapsed) = slow_thread.join().unwrap();
    let (fast_result, fast_elapsed) = fast_thread.join().unwrap();
    server.join().unwrap();

    assert_eq!(slow_result.unwrap(), b"hello");
    assert_eq!(fast_result.unwrap(), b"hello");
    assert!(slow_elapsed >= SLOW_DELAY, "slow request should have actually taken the full server-side delay, took {slow_elapsed:?}");
    assert!(
        fast_elapsed < FAST_BUDGET,
        "fast request took {fast_elapsed:?} while a slow one was in flight — that means it got stuck behind it, i.e. the freeze bug is back"
    );
}
