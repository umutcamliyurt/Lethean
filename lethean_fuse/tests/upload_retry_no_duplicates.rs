mod common;

use common::*;
use lethean_fuse_lib::crypto::aead;

#[test]
fn an_upload_whose_answer_was_lost_is_not_stored_twice() {
    std::env::set_var("MOCK_LOSE_FIRST_UPLOAD_RESPONSE", "1");
    let server = start_server(ServerOpts { support_range: true, fail_first_upload: false, discard_blobs: false });
    let key = aead::generate_aes_key_raw();
    let vault = new_vault(server.addr, &key);
    let entry = vault.create_file("report.pdf", "application/pdf", b"quarterly numbers", None).expect("the retry recognises the stored upload");
    assert_eq!(server.files.lock().unwrap().len(), 1, "exactly one copy on the server");
    assert_eq!(vault.download_decrypted(&entry.record.id).unwrap(), b"quarterly numbers");
}
