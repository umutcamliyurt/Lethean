
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct HealItem {
    pub id: String,
    pub node_ref: Option<String>,
    pub from: Option<String>,
    pub rev: Option<u64>,
    pub is_folder: bool,
    pub folder_movable: bool,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealKind {
    Identical,
    Superseded,
}

#[derive(Debug, Default, Clone)]
pub struct HealPlan {
    pub hidden: Vec<(String, String, HealKind)>,
}

pub fn plan(items: &[HealItem]) -> HealPlan {
    let mut hidden: BTreeMap<String, (String, HealKind)> = BTreeMap::new();

    let mut by_fp: HashMap<[u8; 32], Vec<&HealItem>> = HashMap::new();
    for it in items {
        by_fp.entry(it.fingerprint).or_default().push(it);
    }
    for group in by_fp.values().filter(|g| g.len() > 1) {
        let keeper = group.iter().map(|i| i.id.as_str()).min().expect("non-empty");
        for it in group {
            if it.id != keeper {
                hidden.insert(it.id.clone(), (keeper.to_string(), HealKind::Identical));
            }
        }
    }

    let visible = |hidden: &BTreeMap<String, (String, HealKind)>, it: &&HealItem| !hidden.contains_key(&it.id);

    let mut by_ref: HashMap<(&str, bool), Vec<&HealItem>> = HashMap::new();
    for it in items.iter().filter(|it| visible(&hidden, it)) {
        if it.is_folder && !it.folder_movable {
            continue;
        }
        if let Some(r) = it.node_ref.as_deref() {
            by_ref.entry((r, it.is_folder)).or_default().push(it);
        }
    }
    let mut rule2: Vec<(String, String)> = Vec::new();
    for group in by_ref.values().filter(|g| g.len() > 1) {
        let top = group.iter().map(|i| i.rev.unwrap_or(0)).max().expect("non-empty");
        let winners: Vec<&&HealItem> = group.iter().filter(|i| i.rev.unwrap_or(0) == top).collect();
        if winners.len() != 1 {
            continue;
        }
        let winner = &winners[0].id;
        for it in group {
            if &it.id != winner {
                rule2.push((it.id.clone(), winner.clone()));
            }
        }
    }
    for (id, succ) in rule2 {
        hidden.insert(id, (succ, HealKind::Superseded));
    }

    let files_by_ref: HashMap<&str, Vec<&HealItem>> = {
        let mut m: HashMap<&str, Vec<&HealItem>> = HashMap::new();
        for it in items.iter().filter(|it| !it.is_folder && visible(&hidden, it)) {
            if let Some(r) = it.node_ref.as_deref() {
                m.entry(r).or_default().push(it);
            }
        }
        m
    };
    let mut successor_of: BTreeMap<String, String> = BTreeMap::new();
    for n in items.iter().filter(|it| !it.is_folder && visible(&hidden, it)) {
        let Some(from) = n.from.as_deref() else { continue };
        if Some(from) == n.node_ref.as_deref() {
            continue;
        }
        for old in files_by_ref.get(from).into_iter().flatten() {
            if old.id == n.id {
                continue;
            }
            let e = successor_of.entry(old.id.clone()).or_insert_with(|| n.id.clone());
            if n.id < *e {
                *e = n.id.clone();
            }
        }
    }
    let mut cyclic: HashSet<String> = HashSet::new();
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    for (old, first) in &successor_of {
        let mut cur = first.clone();
        let mut seen = HashSet::from([old.clone()]);
        let mut ok = true;
        while let Some(next) = successor_of.get(&cur) {
            if !seen.insert(cur.clone()) {
                ok = false;
                break;
            }
            cur = next.clone();
        }
        if !ok || seen.contains(&cur) {
            cyclic.insert(old.clone());
            continue;
        }
        resolved.insert(old.clone(), cur);
    }
    for (old, succ) in resolved {
        if !cyclic.contains(&old) && !cyclic.contains(&succ) {
            hidden.insert(old, (succ, HealKind::Superseded));
        }
    }

    HealPlan { hidden: hidden.into_iter().map(|(id, (succ, kind))| (id, succ, kind)).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, node_ref: &str) -> HealItem {
        let mut fp = [0u8; 32];
        fp[..id.len().min(32)].copy_from_slice(&id.as_bytes()[..id.len().min(32)]);
        HealItem { id: id.into(), node_ref: Some(node_ref.into()), from: None, rev: None, is_folder: false, folder_movable: false, fingerprint: fp }
    }

    fn hidden(plan: &HealPlan) -> Vec<(&str, &str, HealKind)> {
        plan.hidden.iter().map(|(a, b, k)| (a.as_str(), b.as_str(), *k)).collect()
    }

    #[test]
    fn unrelated_items_are_left_alone() {
        assert!(plan(&[item("a", "r1"), item("b", "r2")]).hidden.is_empty());
    }

    #[test]
    fn identical_records_keep_the_smallest_id() {
        let mut b = item("b", "r1");
        let mut c = item("c", "r1");
        let a = item("a", "r1");
        b.fingerprint = a.fingerprint;
        c.fingerprint = a.fingerprint;
        assert_eq!(hidden(&plan(&[c, a, b])), [("b", "a", HealKind::Identical), ("c", "a", HealKind::Identical)]);
    }

    #[test]
    fn copies_of_one_object_keep_the_highest_rev_and_ties_decide_nothing() {
        let mut old = item("x9", "r1");
        old.rev = Some(1);
        let mut new = item("x1", "r1");
        new.rev = Some(2);
        assert_eq!(hidden(&plan(&[old.clone(), new.clone()])), [("x9", "x1", HealKind::Superseded)]);
        let unversioned = [item("p", "r1"), item("q", "r1")];
        assert!(plan(&unversioned).hidden.is_empty(), "no rev on either: can't tell which is newer");
        let mut f1 = item("f1", "rf");
        f1.is_folder = true;
        f1.rev = Some(3);
        let mut f2 = item("f2", "rf");
        f2.is_folder = true;
        assert!(plan(&[f1.clone(), f2.clone()]).hidden.is_empty(), "legacy or legacy-parent folders are never hidden");
        f1.folder_movable = true;
        f2.folder_movable = true;
        assert_eq!(hidden(&plan(&[f1, f2])), [("f2", "f1", HealKind::Superseded)]);
    }

    #[test]
    fn a_replaced_file_is_hidden_and_chains_point_at_the_last_version() {
        let v1 = item("v1", "r1");
        let mut v2 = item("v2", "r2");
        v2.from = Some("r1".into());
        let mut v3 = item("v3", "r3");
        v3.from = Some("r2".into());
        assert_eq!(hidden(&plan(&[v1, v2, v3])), [("v1", "v3", HealKind::Superseded), ("v2", "v3", HealKind::Superseded)]);
    }

    #[test]
    fn folders_are_never_replaced_by_from_and_cycles_decide_nothing() {
        let mut folder = item("fold", "rf");
        folder.is_folder = true;
        folder.folder_movable = true;
        let mut upgraded = item("newf", "rg");
        upgraded.is_folder = true;
        upgraded.from = Some("rf".into());
        assert!(plan(&[folder, upgraded]).hidden.is_empty());
        let mut a = item("a", "ra");
        a.from = Some("rb".into());
        let mut b = item("b", "rb");
        b.from = Some("ra".into());
        assert!(plan(&[a, b]).hidden.is_empty());
    }

    #[test]
    fn two_saves_of_the_same_version_both_stay() {
        let base = item("base", "r0");
        let mut here = item("here", "r1");
        here.from = Some("r0".into());
        let mut there = item("there", "r2");
        there.from = Some("r0".into());
        assert_eq!(hidden(&plan(&[base, here, there])), [("base", "here", HealKind::Superseded)], "only the shared original goes; the two edits are both kept");
    }
}
