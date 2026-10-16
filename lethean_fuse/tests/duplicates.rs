
mod common;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Duration;

use common::*;
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::fuse_fs::{FsOptions, VaultFs};

fn fuse_usable() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok() && ["fusermount3", "fusermount"].iter().any(|c| std::process::Command::new(c).arg("-V").output().is_ok())
}

fn raw_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn mount(server: &Server, key: &[u8], tag: &str) -> (fuser::BackgroundSession, std::path::PathBuf, std::path::PathBuf) {
    let vault = new_vault(server.addr, key);
    let mount_dir = std::env::temp_dir().join(format!("lethean-dup-{tag}-{}", std::process::id()));
    let scratch_dir = std::env::temp_dir().join(format!("lethean-dup-scratch-{tag}-{}", std::process::id()));
    fs::create_dir_all(&mount_dir).unwrap();
    fs::create_dir_all(&scratch_dir).unwrap();
    let mut vfs = VaultFs::with_options(vault, FsOptions { scratch_dir: Some(scratch_dir.clone()), scratch_ram_bytes: 4 * 1024 * 1024, refresh_interval: Some(Duration::from_secs(1)), ..Default::default() });
    vfs.refresh().unwrap();
    let notify = vfs.notifier_slot();
    let session = fuser::Session::new(vfs, &mount_dir, &[fuser::MountOption::FSName("lethean-test".into())]).expect("mount");
    notify.attach(session.notifier());
    (session.spawn().expect("spawn"), mount_dir, scratch_dir)
}

#[test]
fn same_named_items_on_the_server_are_listed_once_each_and_all_reachable() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    web.create_file("photo.jpg", "image/jpeg", b"first upload", None).unwrap();
    web.create_file("photo.jpg", "image/jpeg", b"second upload", None).unwrap();
    web.create_file("notes", "text/plain", b"no extension A", None).unwrap();
    web.create_file("notes", "text/plain", b"no extension B", None).unwrap();

    let (session, mnt, scratch) = mount(&server, &key, "list");
    let names = raw_names(&mnt);
    assert_eq!(names, ["notes", "notes (2)", "photo (2).jpg", "photo.jpg"], "no name is listed twice");
    let mut bodies: Vec<Vec<u8>> = ["photo.jpg", "photo (2).jpg"].iter().map(|n| fs::read(mnt.join(n)).unwrap()).collect();
    bodies.sort();
    assert_eq!(bodies, [b"first upload".to_vec(), b"second upload".to_vec()], "both copies can be opened");

    fs::remove_file(mnt.join("photo.jpg")).unwrap();
    std::thread::sleep(Duration::from_millis(5500));
    assert_eq!(raw_names(&mnt), ["notes", "notes (2)", "photo.jpg"], "the remaining copy takes the plain name back");

    web.create_file("notes", "text/plain", b"a third, from the web", None).unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(raw_names(&mnt), ["notes", "notes (2)", "notes (3)", "photo.jpg"], "a duplicate arriving later gets its own name too");
    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn copying_many_new_files_never_lists_a_name_twice_mid_save() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let (session, mnt, scratch) = mount(&server, &key, "midsave");
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lister = {
        let (mnt, done) = (mnt.clone(), std::sync::Arc::clone(&done));
        std::thread::spawn(move || {
            let mut worst = 0usize;
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                let names = raw_names(&mnt);
                let mut uniq = names.clone();
                uniq.dedup();
                worst = worst.max(names.len() - uniq.len());
            }
            worst
        })
    };
    for i in 0..200 {
        fs::write(mnt.join(format!("f{i:03}.txt")), format!("{i}")).unwrap();
    }
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(lister.join().unwrap(), 0, "a listing taken while files are being saved shows each name once");
    assert_eq!(server.files.lock().unwrap().len(), 200);
    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn saving_a_new_file_whose_name_was_just_taken_elsewhere_does_not_duplicate_it() {
    if !fuse_usable() {
        eprintln!("skipping: FUSE not available");
        return;
    }
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let web = new_vault(server.addr, &key);
    let (session, mnt, scratch) = mount(&server, &key, "race");
    let mut f = fs::File::create(mnt.join("todo.txt")).unwrap();
    std::io::Write::write_all(&mut f, b"written in the mount").unwrap();
    web.create_file("todo.txt", "text/plain", b"uploaded in the browser", None).unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    drop(f);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(raw_names(&mnt), ["todo (conflicted copy).txt", "todo.txt"]);
    assert_eq!(fs::read(mnt.join("todo.txt")).unwrap(), b"uploaded in the browser");
    assert_eq!(fs::read(mnt.join("todo (conflicted copy).txt")).unwrap(), b"written in the mount");
    drop(session);
    let _ = fs::remove_dir_all(&mnt);
    let _ = fs::remove_dir_all(&scratch);
}
