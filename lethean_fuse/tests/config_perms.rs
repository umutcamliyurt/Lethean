use std::os::unix::fs::PermissionsExt;

use lethean_fuse_lib::config::Config;

#[test]
fn config_is_saved_owner_only_and_atomically() {
    let home = std::env::temp_dir().join(format!("lethean-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &home);
    unsafe { libc::umask(0o022) };

    let mut c = Config::default();
    c.access_token = Some("operator-token".to_string());
    c.save().unwrap();

    let dir = home.join("lethean-cli");
    let file = dir.join("config.json");
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(Config::load().unwrap().access_token.as_deref(), Some("operator-token"));

    c.access_token = Some("rotated".to_string());
    c.save().unwrap();
    assert_eq!(Config::load().unwrap().access_token.as_deref(), Some("rotated"));
    let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).filter(|n| n != "config.json").collect();
    assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&home);
}
