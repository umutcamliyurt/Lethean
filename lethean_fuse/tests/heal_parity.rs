
use lethean_fuse_lib::heal::{plan, HealItem, HealKind};
use sha2::{Digest, Sha256};

#[test]
fn rust_and_web_clients_make_identical_healing_decisions() {
    let Ok(path) = std::env::var("HEAL_PARITY_FILE") else {
        eprintln!("skipping: set HEAL_PARITY_FILE");
        return;
    };
    let cases: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut decisions = 0;
    for (n, case) in cases.iter().enumerate() {
        let items: Vec<HealItem> = case["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| HealItem {
                id: i["id"].as_str().unwrap().into(),
                node_ref: i["nodeRef"].as_str().map(String::from),
                from: i["from"].as_str().map(String::from),
                rev: i["rev"].as_u64(),
                is_folder: i["isFolder"].as_bool().unwrap(),
                folder_movable: i["folderMovable"].as_bool().unwrap(),
                fingerprint: Sha256::digest(i["fingerprint"].as_str().unwrap().as_bytes()).into(),
            })
            .collect();
        let ours: Vec<(String, String, &str)> = plan(&items).hidden.into_iter().map(|(a, b, k)| (a, b, if k == HealKind::Identical { "identical" } else { "superseded" })).collect();
        let theirs: Vec<(String, String, String)> = case["plan"].as_array().unwrap().iter().map(|d| (d["id"].as_str().unwrap().into(), d["successor"].as_str().unwrap().into(), d["kind"].as_str().unwrap().into())).collect();
        let ours_cmp: Vec<(String, String, String)> = ours.into_iter().map(|(a, b, k)| (a, b, k.to_string())).collect();
        assert_eq!(ours_cmp, theirs, "case {n} differs: {}", case["items"]);
        decisions += theirs.len();
    }
    eprintln!("{} listings, {decisions} decisions, all identical", cases.len());
}
