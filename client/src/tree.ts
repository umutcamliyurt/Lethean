import { fileKeyCache, metaCache } from './state.js';
import { nodeRef, FILE_FORMAT_V2 } from './crypto-encrypt-core.js';
import type { FileKey, ParentRef } from './crypto-encrypt-core.js';

const refById = new Map<string, string>();
const idsByRef = new Map<string, Set<string>>();

export const UNRESOLVED_PARENT = '\u0000unresolved-parent';

function forgetRef(id: string): void {
  const ref = refById.get(id);
  if (ref === undefined) return;
  refById.delete(id);
  const ids = idsByRef.get(ref);
  ids?.delete(id);
  if (ids && ids.size === 0) idsByRef.delete(ref);
}

export async function rememberFileKey(id: string, key: FileKey): Promise<void> {
  fileKeyCache.set(id, key);
  const ref = await nodeRef(key);
  if (fileKeyCache.get(id) !== key) return;
  forgetRef(id);
  refById.set(id, ref);
  let ids = idsByRef.get(ref);
  if (!ids) idsByRef.set(ref, (ids = new Set()));
  ids.add(id);
}

export function nodeRefOf(id: string): string | null {
  return refById.get(id) ?? null;
}

export function forgetFileKey(id: string): void {
  fileKeyCache.delete(id);
  forgetRef(id);
}

export function clearFileKeys(): void {
  fileKeyCache.clear();
  refById.clear();
  idsByRef.clear();
}

function declaredParentId(id: string): string | null {
  const parentId = metaCache.get(id)?.parentId;
  return typeof parentId === 'string' ? parentId : null;
}

export function effectiveParentId(id: string): string | null {
  const meta = metaCache.get(id);
  const declared = declaredParentId(id);
  if (!meta || fileKeyCache.get(id)?.format !== FILE_FORMAT_V2) return declared;
  if (declared === null || typeof meta.pref !== 'string') return declared === null ? null : UNRESOLVED_PARENT;
  let candidates = [...(idsByRef.get(meta.pref) ?? [])]
    .filter((c) => c !== id && metaCache.get(c)?.isFolder === true);
  if (candidates.length === 0) {
    candidates = [...metaCache.entries()]
      .filter(([c, m]) => c !== id && m.isFolder === true && m.from === meta.pref && fileKeyCache.get(c)?.format === FILE_FORMAT_V2)
      .map(([c]) => c);
  }
  if (candidates.length === 0) return UNRESOLVED_PARENT;
  if (candidates.includes(declared)) return declared;
  return candidates.sort()[0]!;
}

export function parentRefFor(folderId: string | null): ParentRef | null {
  if (folderId === null) return null;
  const ref = refById.get(folderId);
  if (!ref || metaCache.get(folderId)?.isFolder !== true) {
    throw new Error("That folder isn't fully loaded yet — wait for the gallery to finish loading and try again.");
  }
  return { id: folderId, ref };
}
