
mod common;

use common::*;
use lethean_fuse_lib::crypto::aead::{aes_gcm_encrypt, encrypt_metadata, pad_to_bucket, random_bytes, to_base64, wrap_file_key};
use lethean_fuse_lib::crypto::format::FileKey;
use lethean_fuse_lib::types::FileMeta;

#[test]
fn renaming_a_legacy_file_whose_upload_answer_was_lost_keeps_exactly_the_renamed_copy() {
    std::env::set_var("MOCK_LOSE_FIRST_UPLOAD_RESPONSE", "1");
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let wk = lethean_fuse_lib::crypto::aead::generate_aes_key_raw();

    let key = FileKey::legacy(random_bytes(32)).unwrap();
    let meta = FileMeta::new_file("old name.txt".into(), "text/plain".into(), false, 5, None);
    let (encrypted_metadata, metadata_iv) = encrypt_metadata(&key, &meta).unwrap();
    let ct = aes_gcm_encrypt(key.raw(), &pad_to_bucket(b"hello")).unwrap();
    let (wrapped_file_key, wrap_iv) = wrap_file_key(&wk, &key).unwrap();
    let original = inject(&server, [("content_iv", to_base64(&ct.iv)), ("encrypted_metadata", encrypted_metadata), ("metadata_iv", metadata_iv), ("wrapped_file_key", wrapped_file_key), ("wrap_iv", wrap_iv)], ct.ciphertext);

    let vault = new_vault(server.addr, &wk);
    vault.refresh_all().unwrap();
    let renamed = vault.rename_or_move(&original, Some("new name.txt"), None).expect("rename succeeds despite the lost answer");
    assert_ne!(renamed.record.id, original, "the retry must not mistake the original for the renamed copy");

    let files = server.files.lock().unwrap().iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
    assert_eq!(files, [renamed.record.id.clone()], "exactly one copy remains: the renamed one");
    let fresh = new_vault(server.addr, &wk);
    fresh.refresh_all().unwrap();
    let e = fresh.find_child(None, "new name.txt").expect("renamed file is listed");
    assert_eq!(fresh.download_decrypted(&e.record.id).unwrap(), b"hello");
}
