
use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::Result;

use crate::scratch::ScratchReader;
use crate::vault::{Entry, Vault, UNRESOLVED_PARENT};

#[derive(Debug, Default)]
pub struct UpgradeReport {
    pub upgraded: usize,
    pub failed: Vec<(String, String)>,
    pub folders_kept: usize,
}

fn depth(vault: &Vault, id: &str) -> usize {
    let mut d = 0;
    let mut seen = HashSet::from([id.to_string()]);
    let mut cur = vault.parent_of(id).flatten();
    while let Some(p) = cur {
        if p == UNRESOLVED_PARENT || !seen.insert(p.clone()) {
            break;
        }
        d += 1;
        cur = vault.parent_of(&p).flatten();
    }
    d
}

pub fn upgrade_legacy_items(vault: &Vault, mut progress: impl FnMut(usize, usize, &str)) -> Result<UpgradeReport> {
    let mut report = UpgradeReport::default();
    let legacy: Vec<Entry> = vault.legacy_entries().into_iter().filter(|e| e.readable).collect();
    if legacy.is_empty() {
        return Ok(report);
    }

    let mut by_from: HashMap<String, String> = HashMap::new();
    for e in vault.all_entries() {
        if e.is_v2() {
            if let Some(from) = &e.meta.from {
                by_from.insert(from.clone(), e.record.id.clone());
            }
        }
    }

    let mut id_map: HashMap<String, String> = HashMap::new();
    let target_parent = |id_map: &HashMap<String, String>, old_id: &str| -> Option<String> {
        let p = vault.parent_of(old_id).flatten()?;
        if let Some(mapped) = id_map.get(&p) {
            return Some(mapped.clone());
        }
        vault.get(&p).filter(|e| e.is_folder()).map(|_| p)
    };
    let reuse = |by_from: &mut HashMap<String, String>, old: &Entry| -> Option<String> {
        let r = old.node_ref.clone()?;
        let existing = by_from.get(&r)?.clone();
        vault.get(&existing)?;
        match vault.verify_record(&existing) {
            Ok(()) => Some(existing),
            Err(_) => {
                let _ = vault.delete_one(&existing);
                by_from.remove(&r);
                None
            }
        }
    };

    let total = legacy.len();
    let mut done = 0;

    let mut folders: Vec<Entry> = legacy.iter().filter(|e| e.is_folder()).cloned().collect();
    folders.sort_by_key(|f| depth(vault, &f.record.id));
    for folder in &folders {
        progress(done, total, folder.name());
        let result = (|| -> Result<String> {
            if let Some(id) = reuse(&mut by_from, folder) {
                return Ok(id);
            }
            let created = vault.create_folder_ext(folder.name(), target_parent(&id_map, &folder.record.id).as_deref(), folder.node_ref.as_deref())?;
            vault.verify_record(&created.record.id)?;
            Ok(created.record.id)
        })();
        match result {
            Ok(new_id) => {
                id_map.insert(folder.record.id.clone(), new_id);
            }
            Err(e) => report.failed.push((folder.name().to_string(), format!("{e:#}"))),
        }
    }

    for file in legacy.iter().filter(|e| !e.is_folder()) {
        progress(done, total, file.name());
        let result = (|| -> Result<()> {
            if reuse(&mut by_from, file).is_none() {
                let (scratch, len) = vault.plaintext_to_scratch(&file.record.id)?;
                let created = vault.create_file_streaming_ext(file.name(), &file.meta.mime, len, target_parent(&id_map, &file.record.id).as_deref(), file.node_ref.as_deref(), || {
                    let r: Box<dyn Read> = Box::new(ScratchReader::new(scratch.clone(), len));
                    Ok(r)
                })?;
                vault.verify_record(&created.record.id)?;
            }
            vault.delete_one(&file.record.id)
        })();
        match result {
            Ok(()) => report.upgraded += 1,
            Err(e) => report.failed.push((file.name().to_string(), format!("{e:#}"))),
        }
        done += 1;
    }

    for e in vault.all_entries() {
        if !e.is_v2() {
            continue;
        }
        let Some(Some(parent)) = vault.parent_of(&e.record.id) else { continue };
        let Some(target) = id_map.get(&parent) else { continue };
        if *target == e.record.id {
            continue;
        }
        progress(done, total, e.name());
        if let Err(err) = vault.rename_or_move(&e.record.id, None, Some(Some(target.as_str()))) {
            report.failed.push((e.name().to_string(), format!("{err:#}")));
        }
    }

    for folder in folders.iter().rev() {
        let id = &folder.record.id;
        if !id_map.contains_key(id) || vault.has_children(id) {
            report.folders_kept += 1;
            done += 1;
            continue;
        }
        progress(done, total, folder.name());
        match vault.delete_one(id) {
            Ok(()) => report.upgraded += 1,
            Err(e) => {
                report.failed.push((folder.name().to_string(), format!("{e:#}")));
                report.folders_kept += 1;
            }
        }
        done += 1;
    }
    progress(total, total, "");
    Ok(report)
}
