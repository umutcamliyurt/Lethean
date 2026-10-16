
mod common;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::fuse_fs::{FsOptions, VaultFs};

fn fuse_usable() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok() && ["fusermount3", "fusermount"].iter().any(|c| std::process::Command::new(c).arg("-V").output().is_ok())
}

fn eventually(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for: {what}");
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir).map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    v.sort();
    v
}

#[test]
fn sync_picks_up_creates_edits_renames_and_deletes_made_elsewhere() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    let a = web.create_file("a.txt", "text/plain", b"version 1", None).unwrap();
    let gone = web.create_file("gone.txt", "text/plain", b"bye", None).unwrap();
    let docs = web.create_folder("docs", None).unwrap();
    web.create_file("inside.txt", "text/plain", b"in docs", Some(&docs.record.id)).unwrap();

    let local = new_vault(server.addr, &key);
    local.refresh_all().unwrap();
    assert_eq!(local.entry_count(), 4);
    assert!(local.sync().unwrap().is_empty(), "nothing changed yet");

    web.replace_content(&a.record.id, b"version 2 from the web").unwrap();
    web.create_file("new.txt", "text/plain", b"fresh", None).unwrap();
    web.delete_one(&gone.record.id).unwrap();
    let renamed = web.rename_or_move(&docs.record.id, Some("papers"), None).unwrap();

    let report = local.sync().unwrap();
    assert!(!report.is_empty());
    let a_now = local.find_child(None, "a.txt").expect("edited file still listed");
    assert_ne!(a_now.record.id, a.record.id, "the edit is a new record");
    assert_eq!(local.download_decrypted(&a_now.record.id).unwrap(), b"version 2 from the web");
    assert!(local.find_child(None, "new.txt").is_some(), "new file appears");
    assert!(local.find_child(None, "gone.txt").is_none(), "deleted file disappears");
    assert!(local.find_child(None, "docs").is_none());
    let papers = local.find_child(None, "papers").expect("renamed folder appears");
    assert_eq!(papers.record.id, renamed.record.id);
    assert!(local.find_child(Some(&papers.record.id), "inside.txt").is_some(), "children follow their renamed folder");
    assert!(report.aliases.iter().any(|(old, new, _)| old == &docs.record.id && new == &renamed.record.id), "a rename is recognised as the same folder: {report:?}");
    assert!(report.touched_names.iter().any(|(pk, n)| pk.is_empty() && n == "new.txt"));
    assert!(report.touched_names.iter().any(|(pk, n)| pk.is_empty() && n == "gone.txt"));
    assert_eq!(local.entry_count(), 4, "a.txt (new id), new.txt, papers, inside.txt");

    assert!(local.sync().unwrap().is_empty(), "a second sync with no changes reports nothing");
}

#[test]
fn a_local_save_is_never_undone_by_a_sync_and_the_old_copy_never_reappears() {
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let local = new_vault(server.addr, &key);
    local.set_deferred_deletes(true);
    let f = local.create_file("notes.txt", "text/plain", b"one", None).unwrap();
    for round in 0..5 {
        let cur = local.find_child(None, "notes.txt").unwrap();
        let body = format!("round {round}");
        local.replace_content(&cur.record.id, body.as_bytes()).unwrap();
        local.sync().unwrap();
        let now = local.find_child(None, "notes.txt").expect("still there");
        assert_eq!(local.download_decrypted(&now.record.id).unwrap(), body.as_bytes());
        assert_eq!(local.children_of(None).len(), 1, "never two copies of a saved file");
    }
    local.flush_pending_deletes();
    assert_eq!(server.files.lock().unwrap().len(), 1, "old copies are removed from the server in the background");
    assert!(local.get(&f.record.id).is_none());
}

fn mount_live(server: &Server, key: &[u8], tag: &str, refresh: Duration) -> (fuser::BackgroundSession, std::path::PathBuf, std::path::PathBuf) {
    let vault = new_vault(server.addr, key);
    let mount_dir = std::env::temp_dir().join(format!("lethean-live-{tag}-{}", std::process::id()));
    let scratch_dir = std::env::temp_dir().join(format!("lethean-live-scratch-{tag}-{}", std::process::id()));
    fs::create_dir_all(&mount_dir).unwrap();
    fs::create_dir_all(&scratch_dir).unwrap();
    let mut vfs = VaultFs::with_options(vault, FsOptions { scratch_dir: Some(scratch_dir.clone()), scratch_ram_bytes: 4 * 1024 * 1024, refresh_interval: Some(refresh), ..Default::default() });
    vfs.refresh().unwrap();
    let notify = vfs.notifier_slot();
    let session = fuser::Session::new(vfs, &mount_dir, &[fuser::MountOption::FSName("lethean-test".into())]).expect("mount");
    notify.attach(session.notifier());
    (session.spawn().expect("spawn"), mount_dir, scratch_dir)
}

#[test]
fn a_live_mount_shows_web_app_changes_without_remounting() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    let report = web.create_file("report.txt", "text/plain", b"draft", None).unwrap();
    let old = web.create_file("old.txt", "text/plain", b"old", None).unwrap();
    let folder = web.create_folder("Projects", None).unwrap();
    web.create_file("plan.md", "text/markdown", b"# plan", Some(&folder.record.id)).unwrap();

    let (session, mnt, scratch) = mount_live(&server, &key, "web", Duration::from_secs(1));
    assert_eq!(fs::read(mnt.join("report.txt")).unwrap(), b"draft");
    assert_eq!(fs::read(mnt.join("Projects/plan.md")).unwrap(), b"# plan");

    let mut held = fs::File::open(mnt.join("Projects/plan.md")).unwrap();

    web.replace_content(&report.record.id, b"final version, edited in the browser").unwrap();
    web.delete_one(&old.record.id).unwrap();
    web.create_file("added.txt", "text/plain", b"from the web", None).unwrap();
    web.rename_or_move(&folder.record.id, Some("Archive"), None).unwrap();

    eventually("edited content", Duration::from_secs(8), || fs::read(mnt.join("report.txt")).map(|b| b == b"final version, edited in the browser").unwrap_or(false));
    eventually("new/removed/renamed names", Duration::from_secs(8), || names(&mnt) == ["Archive", "added.txt", "report.txt"]);
    assert_eq!(fs::read(mnt.join("added.txt")).unwrap(), b"from the web");
    assert!(!mnt.join("old.txt").exists());
    assert!(!mnt.join("Projects").exists());
    assert_eq!(fs::read(mnt.join("Archive/plan.md")).unwrap(), b"# plan");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut held, &mut s).unwrap();
    assert_eq!(s, "# plan", "a file held open across its folder's rename keeps working");
    drop(held);

    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn ls_refreshes_on_demand_even_between_background_checks() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    web.create_file("one.txt", "text/plain", b"1", None).unwrap();
    let (session, mnt, scratch) = mount_live(&server, &key, "ls", Duration::from_secs(3600));
    assert_eq!(names(&mnt), ["one.txt"]);
    web.create_file("two.txt", "text/plain", b"2", None).unwrap();
    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(names(&mnt), ["one.txt", "two.txt"], "the very next ls shows the new file");
    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn editing_a_file_here_while_the_web_app_changes_it_keeps_both_versions() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    let doc = web.create_file("doc.txt", "text/plain", b"base", None).unwrap();
    let (session, mnt, scratch) = mount_live(&server, &key, "conflict", Duration::from_secs(1));

    let mut f = OpenOptions::new().write(true).truncate(true).open(mnt.join("doc.txt")).unwrap();
    f.write_all(b"edited in the mount").unwrap();
    web.replace_content(&doc.record.id, b"edited in the browser").unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    drop(f);

    eventually("both versions listed", Duration::from_secs(8), || names(&mnt) == ["doc (conflicted copy).txt", "doc.txt"]);
    assert_eq!(fs::read(mnt.join("doc.txt")).unwrap(), b"edited in the browser");
    assert_eq!(fs::read(mnt.join("doc (conflicted copy).txt")).unwrap(), b"edited in the mount");
    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn reading_through_a_folder_prefetches_the_rest_once() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    let dir = web.create_folder("src", None).unwrap();
    for i in 0..40 {
        web.create_file(&format!("m{i:02}.rs"), "text/plain", format!("fn f{i}() {{}}").as_bytes(), Some(&dir.record.id)).unwrap();
    }
    let (session, mnt, scratch) = mount_live(&server, &key, "prefetch", Duration::from_secs(3600));
    let gets0 = server.full_gets.load(Ordering::SeqCst);
    for i in 0..3 {
        assert_eq!(fs::read_to_string(mnt.join(format!("src/m{i:02}.rs"))).unwrap(), format!("fn f{i}() {{}}"));
    }
    eventually("prefetch to finish", Duration::from_secs(5), || server.full_gets.load(Ordering::SeqCst) - gets0 >= 40);
    for i in 0..40 {
        assert_eq!(fs::read_to_string(mnt.join(format!("src/m{i:02}.rs"))).unwrap(), format!("fn f{i}() {{}}"));
    }
    assert_eq!(server.full_gets.load(Ordering::SeqCst) - gets0, 40, "every file is downloaded exactly once");
    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}
