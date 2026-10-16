
export interface UploadFields {
  contentIv: string;
  encryptedMetadata: string;
  metadataIv: string;
  wrappedFileKey: string;
  wrapIv: string;
}

export interface RecordFields {
  id: string;
  content_iv: string;
  encrypted_metadata: string;
  metadata_iv: string;
  wrapped_file_key: string;
  wrap_iv: string;
}

export function isSameUpload(record: RecordFields, fields: UploadFields): boolean {
  return record.metadata_iv === fields.metadataIv
    && record.encrypted_metadata === fields.encryptedMetadata
    && record.content_iv === fields.contentIv
    && record.wrapped_file_key === fields.wrappedFileKey
    && record.wrap_iv === fields.wrapIv;
}

function splitExt(name: string): [string, string] {
  const i = name.lastIndexOf('.');
  return i > 0 && i < name.length - 1 ? [name.slice(0, i), name.slice(i)] : [name, ''];
}

export function numberedName(name: string, n: number): string {
  const [stem, ext] = splitExt(name);
  return `${stem} (${n})${ext}`;
}

export function freeName(name: string, taken: ReadonlySet<string>): string {
  if (!taken.has(name)) return name;
  for (let n = 2; ; n++) {
    const candidate = numberedName(name, n);
    if (!taken.has(candidate)) return candidate;
  }
}

export function uniqueById<T extends { id: string }>(items: readonly T[]): T[] {
  const seen = new Set<string>();
  return items.filter((r) => (seen.has(r.id) ? false : (seen.add(r.id), true)));
}


export interface HealItem {
  id: string;
  nodeRef: string | null;
  from: string | null;
  rev: number | null;
  isFolder: boolean;
  folderMovable: boolean;
  fingerprint: string;
}

export type HealKind = 'identical' | 'superseded';

export interface HealDecision {
  id: string;
  successor: string;
  kind: HealKind;
}

export function recordFingerprint(r: RecordFields): string {
  return [r.content_iv, r.encrypted_metadata, r.metadata_iv, r.wrapped_file_key, r.wrap_iv].map((f) => `${f.length}:${f}`).join('|');
}

function minId(ids: string[]): string {
  return ids.reduce((a, b) => (b < a ? b : a));
}

export function healPlan(items: readonly HealItem[]): HealDecision[] {
  const hidden = new Map<string, { successor: string; kind: HealKind }>();

  const byFp = new Map<string, HealItem[]>();
  for (const it of items) byFp.set(it.fingerprint, [...(byFp.get(it.fingerprint) ?? []), it]);
  for (const group of byFp.values()) {
    if (group.length < 2) continue;
    const keeper = minId(group.map((i) => i.id));
    for (const it of group) if (it.id !== keeper) hidden.set(it.id, { successor: keeper, kind: 'identical' });
  }

  const byRef = new Map<string, HealItem[]>();
  for (const it of items) {
    if (hidden.has(it.id) || it.nodeRef === null || (it.isFolder && !it.folderMovable)) continue;
    const key = `${it.isFolder ? 'd' : 'f'}:${it.nodeRef}`;
    byRef.set(key, [...(byRef.get(key) ?? []), it]);
  }
  const rule2: Array<[string, string]> = [];
  for (const group of byRef.values()) {
    if (group.length < 2) continue;
    const top = Math.max(...group.map((i) => i.rev ?? 0));
    const winners = group.filter((i) => (i.rev ?? 0) === top);
    if (winners.length !== 1) continue;
    for (const it of group) if (it.id !== winners[0]!.id) rule2.push([it.id, winners[0]!.id]);
  }
  for (const [id, succ] of rule2) hidden.set(id, { successor: succ, kind: 'superseded' });

  const filesByRef = new Map<string, HealItem[]>();
  for (const it of items) {
    if (it.isFolder || hidden.has(it.id) || it.nodeRef === null) continue;
    filesByRef.set(it.nodeRef, [...(filesByRef.get(it.nodeRef) ?? []), it]);
  }
  const successorOf = new Map<string, string>();
  for (const n of items) {
    if (n.isFolder || hidden.has(n.id) || n.from === null || n.from === n.nodeRef) continue;
    for (const old of filesByRef.get(n.from) ?? []) {
      if (old.id === n.id) continue;
      const cur = successorOf.get(old.id);
      if (cur === undefined || n.id < cur) successorOf.set(old.id, n.id);
    }
  }
  const cyclic = new Set<string>();
  const resolved = new Map<string, string>();
  for (const [old, first] of [...successorOf.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    let cur = first;
    const seen = new Set([old]);
    let ok = true;
    for (let next = successorOf.get(cur); next !== undefined; next = successorOf.get(cur)) {
      if (seen.has(cur)) { ok = false; break; }
      seen.add(cur);
      cur = next;
    }
    if (!ok || seen.has(cur)) { cyclic.add(old); continue; }
    resolved.set(old, cur);
  }
  for (const [old, succ] of resolved) {
    if (!cyclic.has(old) && !cyclic.has(succ)) hidden.set(old, { successor: succ, kind: 'superseded' });
  }

  return [...hidden.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([id, v]) => ({ id, ...v }));
}

export function shownNames(items: ReadonlyArray<{ id: string; name: string }>): Map<string, string> {
  const out = new Map<string, string>();
  const taken = new Set<string>();
  const firstOf = new Map<string, string>();
  for (const it of items) if (!firstOf.has(it.name)) firstOf.set(it.name, it.id);
  for (const it of items) if (firstOf.get(it.name) === it.id) taken.add(it.name);
  for (const it of items) {
    if (firstOf.get(it.name) === it.id) { out.set(it.id, it.name); continue; }
    const name = freeName(it.name, taken);
    taken.add(name);
    out.set(it.id, name);
  }
  return out;
}
