
mod common;

use std::collections::BTreeMap;
use std::io::Read;

use common::*;
use lethean_fuse_lib::crypto::aead::{self, aes_gcm_encrypt, aes_gcm_encrypt_aad, encrypt_metadata, from_base64, pad_metadata_bytes, pad_to_bucket, random_bytes, to_base64, wrap_file_key};
use lethean_fuse_lib::crypto::format::{FileKey, ParentRef, AAD_CONTENT_V2};
use lethean_fuse_lib::types::{EncryptedFilePayload, FileMeta};
use lethean_fuse_lib::upgrade::upgrade_legacy_items;
use lethean_fuse_lib::vault::{Vault, UNRESOLVED_PARENT};
use sha2::{Digest, Sha256};

fn put(server: &Server, p: EncryptedFilePayload) -> String {
    inject(server, [("content_iv", p.content_iv), ("encrypted_metadata", p.encrypted_metadata), ("metadata_iv", p.metadata_iv), ("wrapped_file_key", p.wrapped_file_key), ("wrap_iv", p.wrap_iv)], p.ciphertext)
}

fn inj(k: usize) -> String {
    format!("inj{:029}", k + 1000)
}

fn legacy(wk: &[u8], meta: FileMeta, data: &[u8]) -> (EncryptedFilePayload, FileKey) {
    let key = FileKey::legacy(random_bytes(32)).unwrap();
    let (encrypted_metadata, metadata_iv) = encrypt_metadata(&key, &meta).unwrap();
    let ct = aes_gcm_encrypt(key.raw(), &if meta.is_folder { Vec::new() } else { pad_to_bucket(data) }).unwrap();
    let (wrapped_file_key, wrap_iv) = wrap_file_key(wk, &key).unwrap();
    (EncryptedFilePayload { ciphertext: ct.ciphertext, content_iv: to_base64(&ct.iv), encrypted_metadata, metadata_iv, wrapped_file_key, wrap_iv }, key)
}

fn legacy_file(wk: &[u8], name: &str, data: &[u8], parent_id: Option<&str>) -> (EncryptedFilePayload, FileKey) {
    let mut meta = FileMeta::new_file(name.into(), "text/plain".into(), false, data.len() as u64, None);
    meta.parent_id = parent_id.map(String::from);
    legacy(wk, meta, data)
}

fn legacy_folder(wk: &[u8], name: &str, parent_id: Option<&str>) -> (EncryptedFilePayload, FileKey) {
    let mut meta = FileMeta::new_folder(name.into(), None);
    meta.parent_id = parent_id.map(String::from);
    legacy(wk, meta, &[])
}

fn key_of(wk: &[u8], p: &EncryptedFilePayload) -> FileKey {
    aead::unwrap_file_key(wk, &p.wrapped_file_key, &p.wrap_iv).unwrap()
}

fn forge_meta(key: &FileKey, padded: &[u8]) -> (String, String) {
    let (mk, aad) = key.metadata_key();
    let enc = aes_gcm_encrypt_aad(&mk, padded, &aad).unwrap();
    (to_base64(&enc.ciphertext), to_base64(&enc.iv))
}

fn forge_meta_json(key: &FileKey, json: serde_json::Value) -> (String, String) {
    forge_meta(key, &pad_metadata_bytes(json.to_string().as_bytes()))
}

fn path_of(vault: &Vault, id: &str) -> String {
    let mut names = Vec::new();
    let mut cur = Some(id.to_string());
    while let Some(c) = cur {
        if c == UNRESOLVED_PARENT || names.len() > 64 {
            names.push("<unresolved>".to_string());
            break;
        }
        names.push(vault.get(&c).map(|e| e.name().to_string()).unwrap_or_else(|| "<missing>".into()));
        cur = vault.parent_of(&c).flatten();
    }
    names.reverse();
    names.join("/")
}

fn snapshot(vault: &Vault) -> BTreeMap<String, String> {
    vault
        .all_entries()
        .into_iter()
        .map(|e| {
            let content = if e.is_folder() {
                "folder".to_string()
            } else {
                let mut out = Vec::new();
                vault.stream_plaintext(&e.record.id, &mut out).unwrap();
                hex::encode(Sha256::digest(&out))
            };
            (path_of(vault, &e.record.id), content)
        })
        .collect()
}

#[test]
fn folders_are_placed_by_node_reference_not_server_ids() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let wk = aead::generate_aes_key_raw();
    let pa = aead::encrypt_folder(&wk, "A", None).unwrap();
    let pb = aead::encrypt_folder(&wk, "B", None).unwrap();
    let ref_a = key_of(&wk, &pa).node_ref();
    put(&server, aead::encrypt_file(&wk, "c.txt", "text/plain", b"c", Some(&ParentRef { id: inj(2), node_ref: ref_a.clone() })).unwrap());
    let a = put(&server, pa);
    let b = put(&server, pb);
    put(&server, legacy_file(&wk, "l.txt", b"l", Some(&b)).0);
    let orphan = put(&server, aead::encrypt_file(&wk, "o.txt", "text/plain", b"o", Some(&ParentRef { id: a.clone(), node_ref: "AAAAAAAAAAAAAAAAAAAAAA".into() })).unwrap());

    let vault = new_vault(server.addr, &wk);
    vault.refresh_all().unwrap();
    let names = |p: Option<&str>| vault.children_of(p).into_iter().map(|e| e.name().to_string()).collect::<Vec<_>>();
    assert_eq!(names(Some(&a)), ["c.txt"], "v2 item follows its authenticated folder, whatever the server ID says");
    assert_eq!(names(Some(&b)), ["l.txt"], "legacy items still follow the server ID");
    assert_eq!(names(None), ["A", "B"], "an item whose folder can't be verified isn't shown anywhere");
    assert_eq!(vault.parent_of(&orphan), Some(Some(UNRESOLVED_PARENT.to_string())));

    let uploads = server.files.lock().unwrap().len();
    let moved = vault.rename_or_move(&a, Some("A2"), Some(Some(b.as_str()))).unwrap();
    assert_eq!(server.files.lock().unwrap().len(), uploads, "only the folder itself was re-uploaded (old one deleted)");
    assert_eq!(names(Some(&moved.record.id)), ["c.txt"]);
    let fresh = new_vault(server.addr, &wk);
    fresh.refresh_all().unwrap();
    let c = fresh.all_entries().into_iter().find(|e| e.name() == "c.txt").unwrap();
    assert_eq!(path_of(&fresh, &c.record.id), "B/A2/c.txt");
}

#[test]
fn format_downgrade_and_metadata_content_confusion_are_rejected() {
    let wk = aead::generate_aes_key_raw();
    let p = aead::encrypt_file(&wk, "x.txt", "text/plain", &b"hello ".repeat(1000), None).unwrap();
    let key = key_of(&wk, &p);
    assert!(key.is_v2());
    let meta = aead::decrypt_metadata(&key, &p.encrypted_metadata, &p.metadata_iv).unwrap();

    let (w, iv) = wrap_file_key(&wk, &FileKey::legacy(key.raw().to_vec()).unwrap()).unwrap();
    let as_legacy = aead::unwrap_file_key(&wk, &w, &iv).unwrap();
    assert!(!as_legacy.is_v2());
    assert!(aead::decrypt_metadata(&as_legacy, &p.encrypted_metadata, &p.metadata_iv).is_err());
    assert!(aead::decrypt_content(&as_legacy.content_key(), &p.content_iv, &p.ciphertext, &meta).is_err());

    assert!(aead::decrypt_content(&key.content_key(), &p.metadata_iv, &from_base64(&p.encrypted_metadata).unwrap(), &meta).is_err());
    assert!(aead::decrypt_metadata(&key, &to_base64(&p.ciphertext), &p.content_iv).is_err());

    let (lp, lk) = legacy_file(&wk, "old.txt", b"old", None);
    let as_v2 = FileKey::v2(lk.raw().to_vec(), [7u8; 16]).unwrap();
    assert!(aead::decrypt_metadata(&as_v2, &lp.encrypted_metadata, &lp.metadata_iv).is_err());

    let moved = key.rebind();
    assert!(aead::decrypt_metadata(&moved, &p.encrypted_metadata, &p.metadata_iv).is_err());
}

#[test]
fn non_canonical_format2_data_is_rejected() {
    let key = FileKey::new_v2();
    let good = serde_json::json!({"name": "x.bin", "mime": "application/octet-stream", "unpaddedSize": 10, "size": 10});
    let (m, iv) = forge_meta_json(&key, good.clone());
    let meta = aead::decrypt_metadata(&key, &m, &iv).unwrap();
    for (label, bad) in [
        ("huge chunk size", serde_json::json!({"name": "x", "mime": "a", "unpaddedSize": 10, "size": 10, "chunkSize": 1u64 << 30})),
        ("size mismatch", serde_json::json!({"name": "x", "mime": "a", "unpaddedSize": 10, "size": 11})),
        ("missing size", serde_json::json!({"name": "x", "mime": "a", "unpaddedSize": 10})),
        ("parent without pref", serde_json::json!({"name": "x", "mime": "a", "unpaddedSize": 1, "size": 1, "parentId": "abc"})),
        ("pref without parent", serde_json::json!({"name": "x", "mime": "a", "unpaddedSize": 1, "size": 1, "pref": "AAAAAAAAAAAAAAAAAAAAAA"})),
        ("folder with size", serde_json::json!({"name": "x", "mime": "application/x-lethean-folder", "isFolder": true, "size": 1})),
        ("empty name", serde_json::json!({"name": "", "mime": "a", "unpaddedSize": 1, "size": 1})),
    ] {
        let (m, iv) = forge_meta_json(&key, bad);
        assert!(aead::decrypt_metadata(&key, &m, &iv).is_err(), "{label} accepted");
    }
    let mut dirty = pad_metadata_bytes(good.to_string().as_bytes());
    *dirty.last_mut().unwrap() = 1;
    let (m, iv) = forge_meta(&key, &dirty);
    assert!(aead::decrypt_metadata(&key, &m, &iv).is_err(), "non-zero metadata filler accepted");

    let ck = key.content_key();
    let seal = |plain: &[u8]| {
        let enc = aes_gcm_encrypt_aad(&ck.key, plain, AAD_CONTENT_V2).unwrap();
        (enc.ciphertext, to_base64(&enc.iv))
    };
    let mut padded = pad_to_bucket(b"0123456789");
    let (ct, civ) = seal(&padded);
    assert_eq!(aead::decrypt_content(&ck, &civ, &ct, &meta).unwrap(), b"0123456789");
    padded[5000] = 1;
    let (ct, civ) = seal(&padded);
    assert!(aead::decrypt_content(&ck, &civ, &ct, &meta).is_err(), "hidden bytes in padding accepted");
    let (ct, civ) = seal(&vec![0u8; 4 * 16 * 1024]);
    assert!(aead::decrypt_content(&ck, &civ, &ct, &meta).is_err(), "wrong bucket accepted");

    let bomb = aead::compress_bytes(&vec![0u8; 64 * 1024 * 1024]).unwrap();
    let (ct, civ) = seal(&pad_to_bucket(&bomb));
    let mut m = FileMeta::new_file("b".into(), "a".into(), true, bomb.len() as u64, None);
    m.size = Some(1000);
    let t = std::time::Instant::now();
    assert!(aead::decrypt_content(&ck, &civ, &ct, &m).is_err(), "gzip bomb accepted");
    assert!(t.elapsed().as_secs() < 5);
    m.size = Some(64 * 1024 * 1024);
    assert_eq!(aead::decrypt_content(&ck, &civ, &ct, &m).unwrap().len(), 64 * 1024 * 1024);
}

#[test]
fn streamed_reads_enforce_canonical_padding_too() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let wk = aead::generate_aes_key_raw();
    let size = 9 * 1024 * 1024u64;
    let make = |dirty: bool| {
        let key = FileKey::new_v2();
        let mut meta = FileMeta::new_file(format!("s{dirty}.bin"), "application/octet-stream".into(), false, size, None);
        meta.size = Some(size);
        let (em, miv) = encrypt_metadata(&key, &meta).unwrap();
        let mut plain = pad_to_bucket(&vec![0x41u8; size as usize]);
        if dirty {
            *plain.last_mut().unwrap() = 1;
        }
        let ck = key.content_key();
        let enc = aes_gcm_encrypt_aad(&ck.key, &plain, AAD_CONTENT_V2).unwrap();
        let (w, wiv) = wrap_file_key(&wk, &key).unwrap();
        EncryptedFilePayload { ciphertext: enc.ciphertext, content_iv: to_base64(&enc.iv), encrypted_metadata: em, metadata_iv: miv, wrapped_file_key: w, wrap_iv: wiv }
    };
    let clean = put(&server, make(false));
    let dirty = put(&server, make(true));
    let vault = new_vault(server.addr, &wk);
    vault.refresh_all().unwrap();
    assert_eq!(vault.read_range(&clean, size - 3, 3).unwrap(), b"AAA");
    assert!(vault.read_range(&dirty, 0, 3).is_err(), "streamed file with hidden bytes in padding accepted");
}

#[test]
fn strict_mode_hides_legacy_records_but_rotation_still_rewraps_them() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let wk = aead::generate_aes_key_raw();
    let v2 = put(&server, aead::encrypt_file(&wk, "new.txt", "text/plain", b"new", None).unwrap());
    let old = put(&server, legacy_file(&wk, "old.txt", b"old", None).0);

    let vault = new_vault(server.addr, &wk);
    vault.set_strict(true);
    vault.refresh_all().unwrap();
    assert_eq!(vault.entry_count(), 1);
    assert_eq!(vault.quarantined_count(), 1);
    assert!(vault.get(&old).is_none());

    let new_wk = aead::generate_aes_key_raw();
    assert_eq!(vault.rotate_password("b".repeat(64).as_str(), &new_wk).unwrap(), 2);
    let body: serde_json::Value = serde_json::from_str(server.rotation.lock().unwrap().as_ref().unwrap()).unwrap();
    let rewraps = body["rewraps"].as_array().unwrap();
    assert_eq!(rewraps.len(), 2, "every record, including the hidden one");
    for r in rewraps {
        let k = aead::unwrap_file_key(&new_wk, r["wrapped_file_key"].as_str().unwrap(), r["wrap_iv"].as_str().unwrap()).unwrap();
        assert_eq!(k.is_v2(), r["file_id"] == v2.as_str(), "each key keeps its own format");
    }
    vault.admit_quarantined();
    assert_eq!(vault.entry_count(), 2);
}

fn mixed_vault(server: &Server, wk: &[u8]) {
    let (old_dir, old_key) = legacy_folder(wk, "Old", None);
    let old_dir = put(server, old_dir);
    put(server, legacy_file(wk, "old.txt", b"inside the old folder", Some(&old_dir)).0);
    put(server, legacy_file(wk, "notes.txt", &b"legacy notes ".repeat(5000), None).0);
    put(server, aead::encrypt_file(wk, "inside-old.txt", "text/plain", b"v2 in legacy folder", Some(&ParentRef { id: old_dir.clone(), node_ref: old_key.node_ref() })).unwrap());
    put(server, legacy_file(wk, "orphan.txt", b"parent long gone", Some("missingfolder")).0);
    let new_dir = put(server, aead::encrypt_folder(wk, "New", None).unwrap());
    put(server, legacy_file(wk, "moved-legacy.txt", b"legacy file in a v2 folder", Some(&new_dir)).0);
}

#[test]
fn upgrade_reencrypts_every_legacy_item_and_keeps_the_tree() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let wk = aead::generate_aes_key_raw();
    mixed_vault(&server, &wk);
    let vault = new_vault(server.addr, &wk);
    vault.refresh_all().unwrap();
    assert_eq!(vault.legacy_entries().len(), 5);
    let mut before = snapshot(&vault);
    let orphan = before.remove("<missing>/orphan.txt").expect("orphan hidden before upgrade");

    let report = upgrade_legacy_items(&vault, |_, _, _| {}).unwrap();
    assert!(report.failed.is_empty() && report.folders_kept == 0, "{report:?}");
    assert!(vault.legacy_entries().is_empty());
    let fresh = new_vault(server.addr, &wk);
    fresh.refresh_all().unwrap();
    assert!(fresh.all_entries().iter().all(|e| e.is_v2() && e.readable));
    let mut after = snapshot(&fresh);
    assert_eq!(after.remove("orphan.txt").as_ref(), Some(&orphan), "orphan recovered at the top level");
    assert_eq!(after, before, "every path and every byte preserved");
    assert_eq!(fresh.all_entries().iter().filter(|e| e.meta.from.is_some()).count(), 5);

    let files = server.files.lock().unwrap().len();
    let again = upgrade_legacy_items(&fresh, |_, _, _| {}).unwrap();
    assert_eq!(again.upgraded, 0);
    assert_eq!(server.files.lock().unwrap().len(), files, "a second run changes nothing");
}

#[test]
fn upgrade_resumes_and_replaces_a_corrupted_copy() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let wk = aead::generate_aes_key_raw();
    mixed_vault(&server, &wk);
    let vault = new_vault(server.addr, &wk);
    vault.refresh_all().unwrap();
    let mut before = snapshot(&vault);
    before.remove("<missing>/orphan.txt");

    let notes = vault.legacy_entries().into_iter().find(|e| e.name() == "notes.txt").unwrap();
    let (scratch, len) = vault.plaintext_to_scratch(&notes.record.id).unwrap();
    let dup = vault
        .create_file_streaming_ext("notes.txt", "text/plain", len, None, notes.node_ref.as_deref(), || Ok(Box::new(lethean_fuse_lib::scratch::ScratchReader::new(scratch.clone(), len)) as Box<dyn Read>))
        .unwrap();
    {
        let mut files = server.files.lock().unwrap();
        let (_, s) = files.iter_mut().find(|(id, _)| *id == dup.record.id).unwrap();
        let n = s.blob.len();
        s.blob[n - 1] ^= 1;
    }
    let vault = new_vault(server.addr, &wk);
    vault.refresh_all().unwrap();
    let report = upgrade_legacy_items(&vault, |_, _, _| {}).unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    let fresh = new_vault(server.addr, &wk);
    fresh.refresh_all().unwrap();
    assert_eq!(fresh.all_entries().iter().filter(|e| e.name() == "notes.txt").count(), 1, "bad copy discarded, no duplicates");
    let mut after = snapshot(&fresh);
    after.remove("orphan.txt");
    assert_eq!(after, before);
}
