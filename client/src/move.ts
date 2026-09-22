import { showLightbox, closeLightbox } from './lightbox.js';
import { metaCache } from './state.js';
import { icon, showToast } from './utils.js';
import type { FileRecord } from './types.js';

function parentIdOf(id: string): string | null {
  return (metaCache.get(id)?.parentId as string | null | undefined) ?? null;
}

function isDescendantOrSelf(candidateId: string, ancestorId: string): boolean {
  let cur: string | null = candidateId;
  const seen = new Set<string>();
  while (cur && !seen.has(cur)) {
    if (cur === ancestorId) return true;
    seen.add(cur);
    cur = parentIdOf(cur);
  }
  return false;
}

interface FolderNode {
  id: string | null;
  name: string;
  depth: number;
}

function buildFolderList(records: FileRecord[], excludeIds: Set<string>): FolderNode[] {
  const folders = records.filter((r) => metaCache.get(r.id)?.isFolder);

  const blocked = new Set<string>();
  for (const folder of folders) {
    for (const excludedId of excludeIds) {
      if (isDescendantOrSelf(folder.id, excludedId)) { blocked.add(folder.id); break; }
    }
  }

  const byParent = new Map<string | null, FileRecord[]>();
  for (const f of folders) {
    const parentId = parentIdOf(f.id);
    if (!byParent.has(parentId)) byParent.set(parentId, []);
    byParent.get(parentId)!.push(f);
  }

  const result: FolderNode[] = [{ id: null, name: 'Home', depth: 0 }];
  const walk = (parentId: string | null, depth: number): void => {
    const children = (byParent.get(parentId) || []).slice().sort((a, b) =>
      (metaCache.get(a.id)?.name || '').localeCompare(metaCache.get(b.id)?.name || ''));
    for (const child of children) {
      if (blocked.has(child.id)) continue;
      result.push({ id: child.id, name: metaCache.get(child.id)?.name || '…', depth });
      walk(child.id, depth + 1);
    }
  };
  walk(null, 1);
  return result;
}

export async function openMovePicker(
  selectedIds: string[],
  records: FileRecord[],
  onChoose: (destinationFolderId: string | null) => Promise<void>
): Promise<void> {
  const excludeIds = new Set(selectedIds);
  const nodes = buildFolderList(records, excludeIds);

  showLightbox(`
    <div class="settings-panel">
      <h2>Move ${selectedIds.length} item${selectedIds.length === 1 ? '' : 's'}</h2>
      <p class="subtitle">Choose a destination folder.</p>
      <div class="move-picker-list" id="move-picker-list"></div>
    </div>
  `);

  const listEl = document.getElementById('move-picker-list')!;
  for (const node of nodes) {
    const item = document.createElement('div');
    item.className = 'move-picker-item';
    item.style.paddingLeft = `${12 + node.depth * 16}px`;
    item.innerHTML = `${icon('folder')}<span></span>`;
    item.querySelector('span')!.textContent = node.name;
    item.addEventListener('click', () => {
      closeLightbox();
      void onChoose(node.id).catch((err: unknown) => {
        showToast("Couldn't move. " + (err instanceof Error ? err.message : String(err)), 'error');
      });
    });
    listEl.appendChild(item);
  }
}
