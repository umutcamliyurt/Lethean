
mod common;

use std::io::Read;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::crypto::chunked::CHUNK_SIZE;
use lethean_fuse_lib::vault::{Vault, UNRESOLVED_PARENT};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn path_of(vault: &Vault, id: &str) -> String {
    let mut names = Vec::new();
    let mut cur = Some(id.to_string());
    let mut guard = 0;
    while let Some(c) = cur {
        if c == UNRESOLVED_PARENT || guard > 64 {
            names.push("<unresolved>".to_string());
            break;
        }
        guard += 1;
        names.push(vault.get(&c).map(|e| e.name().to_string()).unwrap_or_else(|| "<missing>".into()));
        cur = vault.parent_of(&c).flatten();
    }
    names.reverse();
    names.join("/")
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[test]
fn reads_a_vault_written_by_the_web_client() {
    let Ok(dir) = std::env::var("LETHEAN_INTEROP_IN") else {
        eprintln!("skipping: LETHEAN_INTEROP_IN not set");
        return;
    };
    let manifest: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/manifest.json")).unwrap()).unwrap();
    let key = aead::from_base64(manifest["wrappingKey"].as_str().unwrap()).unwrap();
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let items = manifest["items"].as_array().unwrap();
    for item in items {
        let f = &item["fields"];
        let get = |k: &str| f[k].as_str().unwrap().to_string();
        let blob = std::fs::read(format!("{dir}/{}.bin", item["id"].as_str().unwrap())).unwrap();
        let id = inject(&server, [("content_iv", get("content_iv")), ("encrypted_metadata", get("encrypted_metadata")), ("metadata_iv", get("metadata_iv")), ("wrapped_file_key", get("wrapped_file_key")), ("wrap_iv", get("wrap_iv"))], blob);
        assert_eq!(id, item["id"].as_str().unwrap(), "fixture IDs must match the mock server's");
    }

    let vault = new_vault(server.addr, &key);
    vault.refresh_all().unwrap();
    assert_eq!(vault.entry_count(), items.len());
    for item in items {
        let id = item["id"].as_str().unwrap();
        let entry = vault.get(id).unwrap_or_else(|| panic!("{id} missing"));
        let want_path = item["path"].as_str().unwrap();
        assert!(entry.readable, "{want_path}: metadata unreadable");
        assert_eq!(path_of(&vault, id), want_path, "placement");
        assert_eq!(entry.is_v2(), item["format"] == 2, "{want_path}: format");
        assert_eq!(entry.node_ref.as_deref(), item["nodeRef"].as_str(), "{want_path}: node reference must match the web client's");
        if let Some(want) = item["sha256"].as_str() {
            let mut out = Vec::new();
            vault.stream_plaintext(id, &mut out).unwrap_or_else(|e| panic!("{want_path}: {e:#}"));
            assert_eq!(sha_hex(&out), want, "{want_path}: content");
            assert_eq!(entry.size(), item["size"].as_u64().unwrap(), "{want_path}: size");
            if entry.meta.chunk_size.is_some() {
                let tail = vault.read_range(id, out.len() as u64 - 100, 100).unwrap();
                assert_eq!(tail, out[out.len() - 100..]);
            }
        }
        println!("ok  {want_path}");
    }
}

#[test]
fn writes_a_vault_the_web_client_can_read() {
    let Ok(dir) = std::env::var("LETHEAN_INTEROP_OUT") else {
        eprintln!("skipping: LETHEAN_INTEROP_OUT not set");
        return;
    };
    std::fs::create_dir_all(&dir).unwrap();
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    vault.refresh_all().unwrap();

    let pattern = |n: u64| -> Box<dyn Fn() -> std::io::Result<Box<dyn Read>>> { Box::new(move || Ok(Box::new(PatternReader::new(n, Arc::new(AtomicUsize::new(0)))) as Box<dyn Read>)) };
    let docs = vault.create_folder("Docs", None).unwrap();
    let notes = vault.create_file("notes.txt", "text/plain", &b"compress me please ".repeat(4000), Some(&docs.record.id)).unwrap();
    vault.create_file("photo.bin", "image/jpeg", &aead::random_bytes(20000), None).unwrap();
    let stream_size = 9 * 1024 * 1024 + 77;
    vault.create_file_streaming("stream.bin", "application/octet-stream", stream_size, Some(&docs.record.id), pattern(stream_size)).unwrap();
    vault.create_file("empty.txt", "text/plain", b"", None).unwrap();
    let sub = vault.create_folder("Sub", Some(&docs.record.id)).unwrap();
    vault.rename_or_move(&notes.record.id, None, Some(Some(sub.record.id.as_str()))).unwrap();
    vault.rename_or_move(&docs.record.id, Some("Docs2"), None).unwrap();
    let chunk_size = CHUNK_SIZE + 999;
    vault.create_file_streaming("chunk.bin", "application/octet-stream", chunk_size, None, pattern(chunk_size)).unwrap();

    drop(vault);
    let vault = new_vault(server.addr, &key);
    vault.refresh_all().unwrap();
    let mut out = Vec::new();
    for entry in vault.all_entries() {
        let id = entry.record.id.clone();
        let (fields, blob) = {
            let files = server.files.lock().unwrap();
            let (_, s) = files.iter().find(|(fid, _)| *fid == id).unwrap();
            let blob = match &s.generator {
                Some(g) => {
                    let mut b = Vec::new();
                    g().read_to_end(&mut b).unwrap();
                    b
                }
                None => s.blob.clone(),
            };
            (s.fields.clone(), blob)
        };
        std::fs::write(format!("{dir}/{id}.bin"), &blob).unwrap();
        let mut plain = Vec::new();
        let sha = if entry.is_folder() {
            Value::Null
        } else {
            vault.stream_plaintext(&id, &mut plain).unwrap();
            json!(sha_hex(&plain))
        };
        out.push(json!({ "id": id, "path": path_of(&vault, &id), "sha256": sha, "nodeRef": entry.node_ref, "fields": fields }));
    }
    let names: Vec<String> = out.iter().map(|v| v["path"].as_str().unwrap().to_string()).collect();
    for p in ["Docs2", "Docs2/Sub", "Docs2/Sub/notes.txt", "Docs2/stream.bin", "photo.bin", "chunk.bin", "empty.txt"] {
        assert!(names.iter().any(|n| n == p), "missing {p} in {names:?}");
    }
    assert_eq!(names.len(), 7, "{names:?}");
    std::fs::write(format!("{dir}/manifest.json"), serde_json::to_string_pretty(&json!({ "wrappingKey": aead::to_base64(&key), "items": out })).unwrap()).unwrap();
    println!("wrote {} FUSE records to {dir}", out.len());
}
