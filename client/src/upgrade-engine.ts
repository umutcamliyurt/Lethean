import { nodeRef, FILE_FORMAT_LEGACY, FILE_FORMAT_V2 } from './crypto-encrypt-core.js';
import type { ChunkedFilePayload, EncryptedFilePayload, FileMeta, FileRecord } from './types.js';
import type { FileKey, NewRecordOptions, ParentRef } from './crypto-encrypt-core.js';

export interface UpgradeDeps {
  records(): FileRecord[];
  keyOf(id: string): FileKey | undefined;
  metaOf(id: string): FileMeta | undefined;
  parentOf(id: string): string | null;
  parentRef(folderId: string | null): ParentRef | null;
  readPlaintext(record: FileRecord): Promise<Blob>;
  encryptFile(file: File, parent: ParentRef | null, opts: NewRecordOptions): Promise<EncryptedFilePayload | ChunkedFilePayload>;
  encryptFolder(name: string, parent: ParentRef | null, opts: NewRecordOptions): Promise<EncryptedFilePayload>;
  upload(payload: EncryptedFilePayload | ChunkedFilePayload): Promise<FileRecord>;
  adopt(record: FileRecord): Promise<void>;
  verify(record: FileRecord): Promise<void>;
  relocate(id: string, newParentId: string | null): Promise<string>;
  remove(id: string): Promise<void>;
  stillUnlocked(): boolean;
  onProgress?(done: number, total: number, name: string): void;
}

export interface UpgradeReport {
  upgraded: number;
  failed: Array<{ name: string; error: string }>;
  foldersKept: number;
  stopped: boolean;
}

const MAX_NAME = 4096;

function safeName(name: string | undefined): string {
  const trimmed = (name ?? '').slice(0, MAX_NAME);
  return trimmed || 'Untitled';
}

class StoppedError extends Error {}

export async function upgradeLegacyItems(deps: UpgradeDeps): Promise<UpgradeReport> {
  const report: UpgradeReport = { upgraded: 0, failed: [], foldersKept: 0, stopped: false };
  const isLegacy = (id: string) => deps.keyOf(id)?.format === FILE_FORMAT_LEGACY;
  const byId = () => new Map(deps.records().map((r) => [r.id, r] as const));
  const checkUnlocked = () => { if (!deps.stillUnlocked()) throw new StoppedError('Vault locked'); };

  const legacy = deps.records().filter((r) => isLegacy(r.id) && deps.metaOf(r.id));
  if (!legacy.length) return report;

  const byFrom = new Map<string, string>();
  for (const r of deps.records()) {
    const meta = deps.metaOf(r.id);
    if (deps.keyOf(r.id)?.format === FILE_FORMAT_V2 && typeof meta?.from === 'string') byFrom.set(meta.from, r.id);
  }
  const legacyRef = new Map<string, string>();
  for (const r of legacy) legacyRef.set(r.id, await nodeRef(deps.keyOf(r.id)!));

  const idMap = new Map<string, string>();
  const isFolder = (id: string) => deps.metaOf(id)?.isFolder === true;

  const depth = (id: string): number => {
    let d = 0;
    const seen = new Set<string>([id]);
    for (let cur = deps.parentOf(id); cur && !seen.has(cur); cur = deps.parentOf(cur)) { seen.add(cur); d++; }
    return d;
  };

  const targetParent = (oldId: string): string | null => {
    const p = deps.parentOf(oldId);
    if (p === null) return null;
    const mapped = idMap.get(p);
    if (mapped) return mapped;
    return byId().has(p) && isFolder(p) ? p : null;
  };

  const total = legacy.length;
  let done = 0;
  const step = (name: string) => deps.onProgress?.(done, total, name);

  const reuseReplacement = async (oldId: string): Promise<string | null> => {
    const existingId = byFrom.get(legacyRef.get(oldId)!);
    const existing = existingId ? byId().get(existingId) : undefined;
    if (!existing) return null;
    try {
      await deps.verify(existing);
      return existing.id;
    } catch {
      await deps.remove(existing.id).catch(() => {});
      byFrom.delete(legacyRef.get(oldId)!);
      return null;
    }
  };

  const fail = (id: string, err: unknown) => {
    if (err instanceof StoppedError) throw err;
    report.failed.push({ name: deps.metaOf(id)?.name ?? id, error: (err as Error)?.message || String(err) });
  };

  try {
    const folders = legacy.filter((r) => isFolder(r.id)).sort((a, b) => depth(a.id) - depth(b.id));
    for (const folder of folders) {
      checkUnlocked();
      const meta = deps.metaOf(folder.id)!;
      step(meta.name);
      try {
        let newId = await reuseReplacement(folder.id);
        if (!newId) {
          const payload = await deps.encryptFolder(safeName(meta.name), deps.parentRef(targetParent(folder.id)), { from: legacyRef.get(folder.id)! });
          const created = await deps.upload(payload);
          await deps.adopt(created);
          await deps.verify(created);
          newId = created.id;
        }
        idMap.set(folder.id, newId);
      } catch (err) {
        fail(folder.id, err);
      }
    }

    for (const file of legacy.filter((r) => !isFolder(r.id))) {
      checkUnlocked();
      const meta = deps.metaOf(file.id)!;
      step(meta.name);
      try {
        if (!(await reuseReplacement(file.id))) {
          const plaintext = await deps.readPlaintext(file);
          const source = new File([plaintext], safeName(meta.name), { type: meta.mime || 'application/octet-stream' });
          const payload = await deps.encryptFile(source, deps.parentRef(targetParent(file.id)), { from: legacyRef.get(file.id)! });
          const created = await deps.upload(payload);
          await deps.adopt(created);
          await deps.verify(created);
        }
        await deps.remove(file.id);
        report.upgraded++;
      } catch (err) {
        fail(file.id, err);
      }
      done++;
    }

    for (const r of deps.records()) {
      checkUnlocked();
      if (deps.keyOf(r.id)?.format !== FILE_FORMAT_V2) continue;
      const parent = deps.parentOf(r.id);
      const target = parent !== null ? idMap.get(parent) : undefined;
      if (!target || target === r.id) continue;
      step(deps.metaOf(r.id)?.name ?? '');
      try {
        await deps.relocate(r.id, target);
      } catch (err) {
        fail(r.id, err);
      }
    }

    for (const folder of folders.slice().reverse()) {
      checkUnlocked();
      if (!idMap.has(folder.id)) { report.foldersKept++; done++; continue; }
      const stillUsed = deps.records().some((r) => r.id !== folder.id && deps.parentOf(r.id) === folder.id);
      if (stillUsed) { report.foldersKept++; done++; continue; }
      step(deps.metaOf(folder.id)?.name ?? '');
      try {
        await deps.remove(folder.id);
        report.upgraded++;
      } catch (err) {
        fail(folder.id, err);
        report.foldersKept++;
      }
      done++;
    }
  } catch (err) {
    if (!(err instanceof StoppedError)) throw err;
    report.stopped = true;
  }
  deps.onProgress?.(total, total, '');
  return report;
}
