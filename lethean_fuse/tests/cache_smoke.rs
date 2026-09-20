
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use lethean_fuse_lib::api::ApiClient;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::types::FileRecord;
use lethean_fuse_lib::vault::Vault;

fn record_to_json(r: &FileRecord) -> String {
    format!(
        r#"{{"id":"{}","content_iv":"{}","encrypted_metadata":"{}","metadata_iv":"{}","wrapped_file_key":"{}","wrap_iv":"{}"}}"#,
        r.id, r.content_iv, r.encrypted_metadata, r.metadata_iv, r.wrapped_file_key, r.wrap_iv
    )
}

fn handle_connection(mut stream: TcpStream, blob_hits: Arc<AtomicUsize>, records_json: String, ciphertext: Vec<u8>) {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("").to_string();

    let body: Vec<u8> = if path.ends_with("/blob") {
        blob_hits.fetch_add(1, Ordering::SeqCst);
        ciphertext
    } else {
        records_json.into_bytes()
    };

    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

#[test]
fn second_read_of_the_same_file_is_served_from_cache_not_the_network() {
    let wrapping_key = aead::generate_aes_key_raw();
    let payload = aead::encrypt_file(&wrapping_key, "cached.bin", "application/octet-stream", b"cache me please", None).unwrap();
    let id = "cachedfile0000000000000000000000".to_string();
    let record = FileRecord {
        id: id.clone(),
        content_iv: payload.content_iv.clone(),
        encrypted_metadata: payload.encrypted_metadata.clone(),
        metadata_iv: payload.metadata_iv.clone(),
        wrapped_file_key: payload.wrapped_file_key.clone(),
        wrap_iv: payload.wrap_iv.clone(),
        size: None,
    };
    let records_json = format!("[{}]", record_to_json(&record));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let blob_hits = Arc::new(AtomicUsize::new(0));
    let blob_hits_srv = Arc::clone(&blob_hits);
    let ciphertext = payload.ciphertext.clone();

    let server = thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let Ok(stream) = stream else { continue };
            handle_connection(stream, Arc::clone(&blob_hits_srv), records_json.clone(), ciphertext.clone());
        }
    });

    let api = ApiClient::new(format!("http://{addr}")).expect("client");
    api.set_vault_id(Some("test-vault".to_string()));
    let vault = Vault::new(api, wrapping_key);
    vault.refresh_all().expect("refresh_all should populate the one entry from the mock /files listing");

    let first = vault.download_decrypted(&id).expect("first read should succeed over the network");
    let second = vault.download_decrypted(&id).expect("second read should succeed from the cache");
    server.join().unwrap();

    assert_eq!(first, b"cache me please");
    assert_eq!(second, b"cache me please");
    assert_eq!(blob_hits.load(Ordering::SeqCst), 1, "a second read of the same, unchanged file must not hit the network again");
}

#[test]
fn deleting_a_file_evicts_it_from_the_cache_so_a_stale_copy_can_never_be_served() {
    let wrapping_key = aead::generate_aes_key_raw();
    let payload = aead::encrypt_file(&wrapping_key, "todelete.bin", "application/octet-stream", b"will be deleted", None).unwrap();
    let id = "deletedfile000000000000000000000".to_string();
    let record = FileRecord {
        id: id.clone(),
        content_iv: payload.content_iv.clone(),
        encrypted_metadata: payload.encrypted_metadata.clone(),
        metadata_iv: payload.metadata_iv.clone(),
        wrapped_file_key: payload.wrapped_file_key.clone(),
        wrap_iv: payload.wrap_iv.clone(),
        size: None,
    };
    let records_json = format!("[{}]", record_to_json(&record));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let blob_hits = Arc::new(AtomicUsize::new(0));
    let blob_hits_srv = Arc::clone(&blob_hits);
    let ciphertext = payload.ciphertext.clone();
    let id_srv = id.clone();

    let server = thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let mut lines = req.lines();
            let request_line = lines.next().unwrap_or("").to_string();
            let path = request_line.split_whitespace().nth(1).unwrap_or("").to_string();
            let method = request_line.split_whitespace().next().unwrap_or("").to_string();

            if method == "DELETE" {
                let body = b"{}";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
                break;
            }

            let body: Vec<u8> = if path.ends_with("/blob") {
                blob_hits_srv.fetch_add(1, Ordering::SeqCst);
                ciphertext.clone()
            } else if path.contains(&id_srv) {
                b"{}".to_vec()
            } else {
                records_json.clone().into_bytes()
            };
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });

    let api = ApiClient::new(format!("http://{addr}")).expect("client");
    api.set_vault_id(Some("test-vault".to_string()));
    let vault = Vault::new(api, wrapping_key);
    vault.refresh_all().expect("refresh_all should populate the one entry");

    let _ = vault.download_decrypted(&id).expect("first read populates the cache");
    vault.delete_one(&id).expect("delete should succeed");
    server.join().unwrap();

    assert!(vault.download_decrypted(&id).is_err(), "a deleted file must not still be servable from a stale cache entry");
}