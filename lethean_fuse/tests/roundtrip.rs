
use lethean_fuse_lib::crypto::aead;
use lethean_fuse_lib::crypto::kdf;

#[test]
fn padding_buckets_match_ts_table() {
    assert_eq!(aead::padded_size(0), 16 * 1024);
    assert_eq!(aead::padded_size(16 * 1024), 16 * 1024);
    assert_eq!(aead::padded_size(16 * 1024 + 1), 64 * 1024);
    assert_eq!(aead::padded_size(1024 * 1024 * 1024), 1024 * 1024 * 1024);
    assert_eq!(aead::padded_size(1024 * 1024 * 1024 + 1), 5 * 256 * 1024 * 1024);
}

#[test]
fn metadata_padding_buckets_match_ts_table() {
    assert_eq!(aead::padded_metadata_size(1), 64);
    assert_eq!(aead::padded_metadata_size(64), 64);
    assert_eq!(aead::padded_metadata_size(65), 128);
    assert_eq!(aead::padded_metadata_size(4096), 4096);
    assert_eq!(aead::padded_metadata_size(4097), 8192);
}

#[test]
fn metadata_pad_unpad_round_trip() {
    let original = b"{\"name\":\"hello.txt\",\"mime\":\"text/plain\"}";
    let padded = aead::pad_metadata_bytes(original);
    assert!(aead::METADATA_PADDING_BUCKETS.contains(&(padded.len() as u64)));
    let unpadded = aead::unpad_metadata_bytes(&padded);
    assert_eq!(unpadded, original);
}

#[test]
fn content_pad_strip_round_trip() {
    let original = vec![7u8; 12345];
    let padded = aead::pad_to_bucket(&original);
    assert!(aead::PADDING_BUCKETS.contains(&(padded.len() as u64)));
    let stripped = aead::strip_padding(&padded, Some(original.len() as u64));
    assert_eq!(stripped, original);
}

#[test]
fn kdf_params_match_ts_table() {
    let v1 = kdf::kdf_params(1).unwrap();
    assert_eq!((v1.parallelism, v1.iterations, v1.memory_kib, v1.hash_len), (1, 4, 98304, 32));
    let v2 = kdf::kdf_params(2).unwrap();
    assert_eq!((v2.parallelism, v2.iterations, v2.memory_kib, v2.hash_len), (1, 6, 262144, 32));
    assert!(kdf::kdf_params(3).is_err());
}

#[test]
fn unlock_vault_is_deterministic_for_same_inputs() {
    let a = kdf::unlock_vault("correct horse battery staple 42!", Some("tok"), 2).unwrap();
    let b = kdf::unlock_vault("correct horse battery staple 42!", Some("tok"), 2).unwrap();
    assert_eq!(a.vault_id, b.vault_id);
    assert_eq!(a.wrapping_key_raw, b.wrapping_key_raw);

    let c = kdf::unlock_vault("correct horse battery staple 42!", Some("other-tok"), 2).unwrap();
    assert_ne!(a.vault_id, c.vault_id);

    let d = kdf::unlock_vault("correct horse battery staple 42!", Some("tok"), 1).unwrap();
    assert_ne!(a.vault_id, d.vault_id);
}

#[test]
fn file_envelope_round_trip() {
    let wrapping_key = aead::generate_aes_key_raw();
    let contents = b"the quick brown fox jumps over the lazy dog".repeat(500);
    let payload = aead::encrypt_file(&wrapping_key, "fox.txt", "text/plain", &contents, Some("parent-123")).unwrap();

    let file_key = aead::unwrap_file_key(&wrapping_key, &payload.wrapped_file_key, &payload.wrap_iv).unwrap();
    let meta = aead::decrypt_metadata(&file_key, &payload.encrypted_metadata, &payload.metadata_iv).unwrap();
    assert_eq!(meta.name, "fox.txt");
    assert_eq!(meta.mime, "text/plain");
    assert_eq!(meta.parent_id.as_deref(), Some("parent-123"));
    assert!(!meta.is_folder);

    let decrypted = aead::decrypt_content(&file_key, &payload.content_iv, &payload.ciphertext, meta.compressed, meta.unpadded_size).unwrap();
    assert_eq!(decrypted, contents);
}

#[test]
fn folder_envelope_round_trip() {
    let wrapping_key = aead::generate_aes_key_raw();
    let payload = aead::encrypt_folder(&wrapping_key, "Photos", None).unwrap();

    let file_key = aead::unwrap_file_key(&wrapping_key, &payload.wrapped_file_key, &payload.wrap_iv).unwrap();
    let meta = aead::decrypt_metadata(&file_key, &payload.encrypted_metadata, &payload.metadata_iv).unwrap();
    assert_eq!(meta.name, "Photos");
    assert!(meta.is_folder);
    assert_eq!(meta.mime, lethean_fuse_lib::types::FOLDER_MIME);
}

#[test]
fn tampered_ciphertext_fails_to_decrypt() {
    let wrapping_key = aead::generate_aes_key_raw();
    let payload = aead::encrypt_file(&wrapping_key, "a.txt", "text/plain", b"hello", None).unwrap();
    let file_key = aead::unwrap_file_key(&wrapping_key, &payload.wrapped_file_key, &payload.wrap_iv).unwrap();

    let mut tampered = payload.ciphertext.clone();
    tampered[0] ^= 0xFF;
    assert!(aead::decrypt_content(&file_key, &payload.content_iv, &tampered, false, Some(5)).is_err());
}

#[test]
fn base64_accepts_url_safe_and_unpadded() {
    let bytes = aead::random_bytes(37);
    let standard = aead::to_base64(&bytes);
    let url_safe_unpadded = standard.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string();
    assert_eq!(aead::from_base64(&url_safe_unpadded).unwrap(), bytes);
}
