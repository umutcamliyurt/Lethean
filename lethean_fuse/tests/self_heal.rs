
mod common;

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::time::Duration;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::fuse_fs::{FsOptions, VaultFs};
use lethean_fuse_lib::vault::Vault;

fn server() -> Server {
    start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false })
}

fn fresh(server: &Server, key: &[u8]) -> Vault {
    let v = new_vault(server.addr, key);
    v.refresh_all().unwrap();
    v
}

fn root_names(v: &Vault) -> Vec<String> {
    v.list_children(None).into_iter().map(|c| c.name).collect()
}

fn read(v: &Vault, name: &str) -> Vec<u8> {
    let e = v.find_child(None, name).unwrap_or_else(|| panic!("{name} not listed"));
    v.download_decrypted(&e.record.id).unwrap()
}

fn crashed_save(v: &Vault, name: &str, old: &[u8], new: &[u8]) -> (String, String) {
    let o = v.create_file(name, "text/plain", old, None).unwrap();
    let new_bytes = new.to_vec();
    let n = v
        .create_file_streaming_ext(name, "text/plain", new.len() as u64, None, o.node_ref.as_deref(), || Ok(Box::new(std::io::Cursor::new(new_bytes.clone())) as Box<dyn Read>))
        .unwrap();
    (o.record.id, n.record.id)
}

fn stored(server: &Server, id: &str) -> Stored {
    server.files.lock().unwrap().iter().find(|(i, _)| i == id).map(|(_, s)| s.clone()).unwrap()
}

fn reinject(server: &Server, s: &Stored) -> String {
    let f = |k: &str| s.fields[k].clone();
    inject(server, [("content_iv", f("content_iv")), ("encrypted_metadata", f("encrypted_metadata")), ("metadata_iv", f("metadata_iv")), ("wrapped_file_key", f("wrapped_file_key")), ("wrap_iv", f("wrap_iv"))], s.blob.clone())
}

#[test]
fn a_save_that_crashed_before_removing_the_old_version_heals_on_next_load() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let (old, new) = crashed_save(&new_vault(server.addr, &key), "notes.txt", b"version 1", b"version 2");
    assert_eq!(server.files.lock().unwrap().len(), 2);

    let v = fresh(&server, &key);
    let report = v.heal_pending();
    assert_eq!(report.removed, [old.clone()]);
    assert_eq!(root_names(&v), ["notes.txt"]);
    assert_eq!(read(&v, "notes.txt"), b"version 2");
    let left: Vec<String> = server.files.lock().unwrap().iter().map(|(i, _)| i.clone()).collect();
    assert_eq!(left, [new]);
}

#[test]
fn a_rename_whose_original_was_never_removed_heals_on_next_load() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let v = new_vault(server.addr, &key);
    let o = v.create_file("draft.txt", "text/plain", b"text", None).unwrap();
    let original = stored(&server, &o.record.id);
    let renamed = v.rename_or_move(&o.record.id, Some("final.txt"), None).unwrap();
    let leftover = reinject(&server, &original);

    let v = fresh(&server, &key);
    v.heal_pending();
    assert_eq!(root_names(&v), ["final.txt"]);
    let left: Vec<String> = server.files.lock().unwrap().iter().map(|(i, _)| i.clone()).collect();
    assert_eq!(left, [renamed.record.id.clone()], "the original ({leftover}) is gone, the renamed copy stays");
    assert_eq!(read(&v, "final.txt"), b"text");
}

#[test]
fn an_upload_stored_twice_is_listed_once_at_once_and_cleaned_up() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let v = new_vault(server.addr, &key);
    let a = v.create_file("photo.jpg", "image/jpeg", b"pixels", None).unwrap();
    let copy = reinject(&server, &stored(&server, &a.record.id));

    let v = fresh(&server, &key);
    assert_eq!(root_names(&v), ["photo.jpg"], "an identical copy is never even shown");
    assert_eq!(v.heal_pending().removed, [copy]);
    assert_eq!(server.files.lock().unwrap().len(), 1);
}

#[test]
fn the_same_file_uploaded_twice_separately_is_reduced_to_one_but_different_files_stay() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let v = new_vault(server.addr, &key);
    v.create_file("scan.pdf", "application/pdf", b"same bytes", None).unwrap();
    v.create_file("scan.pdf", "application/pdf", b"same bytes", None).unwrap();
    v.create_file("todo.txt", "text/plain", b"from laptop", None).unwrap();
    v.create_file("todo.txt", "text/plain", b"from phone!", None).unwrap();

    let v = fresh(&server, &key);
    assert_eq!(v.heal_pending().removed.len(), 1);
    assert_eq!(root_names(&v), ["scan.pdf", "todo (2).txt", "todo.txt"]);
    assert_eq!(server.files.lock().unwrap().len(), 3);
}

#[test]
fn a_broken_newer_copy_never_costs_the_good_original() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let (old, new) = crashed_save(&new_vault(server.addr, &key), "ledger.csv", b"good, old", b"newer, then damaged");
    {
        let mut files = server.files.lock().unwrap();
        let (_, s) = files.iter_mut().find(|(i, _)| *i == new).unwrap();
        let n = s.blob.len();
        s.blob[n - 1] ^= 1;
    }
    let v = fresh(&server, &key);
    assert!(v.heal_pending().removed.is_empty());
    assert_eq!(server.files.lock().unwrap().len(), 2, "nothing deleted");
    let names = root_names(&v);
    assert_eq!(names, ["ledger (2).csv", "ledger.csv"], "both stay visible");
    let ids: Vec<String> = v.list_children(None).into_iter().map(|c| c.id).collect();
    assert!(ids.contains(&old));
    assert_eq!(v.download_decrypted(&old).unwrap(), b"good, old");
    assert!(v.heal_pending().removed.is_empty(), "and it isn't retried into a deletion later");
}

#[test]
fn two_edits_of_the_same_version_both_survive() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let v = new_vault(server.addr, &key);
    let base = v.create_file("plan.md", "text/markdown", b"base", None).unwrap();
    for body in [&b"edit from laptop"[..], &b"edit from phone"[..]] {
        let bytes = body.to_vec();
        v.create_file_streaming_ext("plan.md", "text/markdown", bytes.len() as u64, None, base.node_ref.as_deref(), || Ok(Box::new(std::io::Cursor::new(bytes.clone())) as Box<dyn Read>)).unwrap();
    }
    let v = fresh(&server, &key);
    assert_eq!(v.heal_pending().removed, [base.record.id.clone()], "only the shared original goes");
    let mut bodies: Vec<Vec<u8>> = v.list_children(None).into_iter().map(|c| v.download_decrypted(&c.id).unwrap()).collect();
    bodies.sort();
    assert_eq!(bodies, [b"edit from laptop".to_vec(), b"edit from phone".to_vec()]);
}

#[test]
fn a_live_mount_cleans_up_leftovers_by_itself() {
    if !(OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok()) {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = server();
    let key = aead::generate_aes_key_raw();
    crashed_save(&new_vault(server.addr, &key), "notes.txt", b"version 1", b"version 2");
    let mnt = std::env::temp_dir().join(format!("lethean-heal-{}", std::process::id()));
    let scratch = std::env::temp_dir().join(format!("lethean-heal-scratch-{}", std::process::id()));
    fs::create_dir_all(&mnt).unwrap();
    fs::create_dir_all(&scratch).unwrap();
    let mut vfs = VaultFs::with_options(new_vault(server.addr, &key), FsOptions { scratch_dir: Some(scratch.clone()), scratch_ram_bytes: 4 << 20, refresh_interval: Some(Duration::from_secs(1)), ..Default::default() });
    vfs.refresh().unwrap();
    let notify = vfs.notifier_slot();
    let session = fuser::Session::new(vfs, &mnt, &[fuser::MountOption::FSName("lethean-test".into())]).unwrap();
    notify.attach(session.notifier());
    let session = session.spawn().unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut names: Vec<String> = fs::read_dir(&mnt).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        if names == ["notes.txt"] && server.files.lock().unwrap().len() == 1 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "still {names:?} with {} records", server.files.lock().unwrap().len());
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(fs::read(mnt.join("notes.txt")).unwrap(), b"version 2");

    fs::write(mnt.join("notes.txt"), b"version 3").unwrap();
    drop(session);
    let v = fresh(&server, &key);
    let e = v.find_child(None, "notes.txt").unwrap();
    assert!(e.meta.from.is_some(), "a save names the version it replaces");
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn a_password_change_rewraps_copies_that_are_hidden_but_not_yet_removed() {
    let server = server();
    let key = aead::generate_aes_key_raw();
    let v = new_vault(server.addr, &key);
    let a = v.create_file("photo.jpg", "image/jpeg", b"pixels", None).unwrap();
    let copy = reinject(&server, &stored(&server, &a.record.id));
    let v = fresh(&server, &key);
    assert_eq!(v.stale_count(), 1, "the copy is hidden, not yet removed");
    let new_key = aead::generate_aes_key_raw();
    v.rotate_password("new-vault-id-0000", &new_key).unwrap();
    let body = server.rotation.lock().unwrap().clone().unwrap();
    assert!(body.contains(&a.record.id) && body.contains(&copy), "both records are re-wrapped");
}
