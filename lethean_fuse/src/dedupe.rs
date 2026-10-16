
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::vault::Vault;

#[derive(Debug, Default)]
pub struct DedupeReport {
    pub identical_extras: Vec<(String, String)>,
    pub differing: Vec<(String, usize)>,
    pub unreadable: Vec<(String, String)>,
}

pub fn find_duplicates(vault: &Vault) -> DedupeReport {
    let mut groups: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for e in vault.all_entries() {
        if e.is_folder() || !e.readable {
            continue;
        }
        let Some(parent) = vault.parent_of(&e.record.id) else { continue };
        groups.entry((parent.unwrap_or_default(), e.name().to_string())).or_default().push(e.record.id.clone());
    }
    let mut report = DedupeReport::default();
    for ((_, name), mut ids) in groups {
        if ids.len() < 2 {
            continue;
        }
        ids.sort();
        let mut by_hash: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
        for id in &ids {
            let mut h = Sha256::new();
            match vault.stream_plaintext(id, &mut h) {
                Ok(_) => by_hash.entry(h.finalize().into()).or_default().push(id.clone()),
                Err(err) => report.unreadable.push((name.clone(), format!("{err:#}"))),
            }
        }
        if by_hash.len() > 1 {
            report.differing.push((name.clone(), ids.len()));
        }
        for same in by_hash.values() {
            for extra in &same[1..] {
                report.identical_extras.push((name.clone(), extra.clone()));
            }
        }
    }
    report
}

pub fn remove_identical_extras(vault: &Vault, report: &DedupeReport, mut on_error: impl FnMut(&str, &anyhow::Error)) -> usize {
    let mut removed = 0;
    for (name, id) in &report.identical_extras {
        match vault.delete_one(id) {
            Ok(()) => removed += 1,
            Err(e) => on_error(name, &e),
        }
    }
    removed
}
