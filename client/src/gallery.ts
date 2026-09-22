import * as C from './crypto.js';
import * as api from './api.js';
import {
  boxGrid, fileListEl, fileListBody, viewGridBtn, viewListBtn,
  emptyState, gridLabel, searchInput, searchClearBtn, gridSentinel, usagePill, breadcrumbEl,
  selectToggleBtn, selectionBarEl, selectionCountEl, selectionSelectAllBtn,
  selectionDownloadBtn, selectionMoveBtn, selectionDeleteBtn, selectionCancelBtn,
} from './dom.js';
import { fileKeyCache, metaCache, objectUrlCache, getWrappingKeyRaw } from './state.js';
import { getStoredViewMode, setStoredViewMode } from './storage.js';
import { fileKind, fileTypeLabel, formatBytes, decryptedSize, icon, showToast, isCoarsePointerDevice } from './utils.js';
import { openTile, downloadAndSave } from './lightbox.js';
import { shareFile } from './share.js';
import { openMovePicker } from './move.js';
import type { FileMeta, FileRecord, UsageResponse, ViewMode } from './types.js';

let viewMode: ViewMode = getStoredViewMode();

export function setViewMode(mode: ViewMode): void {
  if (mode !== 'grid' && mode !== 'list') return;
  if (viewMode === mode) return;
  viewMode = mode;
  setStoredViewMode(mode);
  updateViewToggleUI();
  renderCurrentView();
}

function updateViewToggleUI(): void {
  boxGrid.classList.toggle('hidden', viewMode !== 'grid');
  fileListEl.classList.toggle('hidden', viewMode !== 'list');
  viewGridBtn?.classList.toggle('active', viewMode === 'grid');
  viewListBtn?.classList.toggle('active', viewMode === 'list');
  viewGridBtn?.setAttribute('aria-pressed', String(viewMode === 'grid'));
  viewListBtn?.setAttribute('aria-pressed', String(viewMode === 'list'));
}

viewGridBtn?.addEventListener('click', () => setViewMode('grid'));
viewListBtn?.addEventListener('click', () => setViewMode('list'));
updateViewToggleUI();


let selectionMode = false;
const selectedIds = new Set<string>();

selectToggleBtn?.addEventListener('click', () => setSelectionMode(!selectionMode));
selectionSelectAllBtn?.addEventListener('click', () => selectAllVisible());
selectionDownloadBtn?.addEventListener('click', () => void handleDownloadSelected());
selectionMoveBtn?.addEventListener('click', () => void handleMoveSelected());
selectionDeleteBtn?.addEventListener('click', () => void handleDeleteSelected());
selectionCancelBtn?.addEventListener('click', () => setSelectionMode(false));

function setSelectionMode(on: boolean): void {
  selectionMode = on;
  if (!on) selectedIds.clear();
  selectToggleBtn?.classList.toggle('active', on);
  selectToggleBtn?.setAttribute('aria-pressed', String(on));
  updateSelectionBar();
  renderCurrentView();
}

function updateSelectionBar(): void {
  selectionBarEl?.classList.toggle('hidden', !selectionMode);
  if (selectionCountEl) selectionCountEl.textContent = `${selectedIds.size} selected`;
  if (selectionDownloadBtn) selectionDownloadBtn.disabled = selectedIds.size === 0;
  if (selectionMoveBtn) selectionMoveBtn.disabled = selectedIds.size === 0;
  if (selectionDeleteBtn) selectionDeleteBtn.disabled = selectedIds.size === 0;
}

function toggleSelect(id: string): void {
  if (!selectionMode) setSelectionMode(true);
  if (selectedIds.has(id)) selectedIds.delete(id);
  else selectedIds.add(id);
  updateSelectionBar();
  renderCurrentView();
}

function selectAllVisible(): void {
  const shown = visibleRecords();
  const allSelected = shown.length > 0 && shown.every((r) => selectedIds.has(r.id));
  if (allSelected) {
    for (const r of shown) selectedIds.delete(r.id);
  } else {
    for (const r of shown) selectedIds.add(r.id);
  }
  updateSelectionBar();
  renderCurrentView();
}

async function handleDownloadSelected(): Promise<void> {
  const ids = [...selectedIds];
  if (!ids.length) return;

  const fileIds = new Set<string>();
  for (const id of ids) {
    const meta = metaCache.get(id);
    if (!meta) continue;
    if (meta.isFolder) {
      for (const d of collectDescendantIds(id)) {
        if (!metaCache.get(d)?.isFolder) fileIds.add(d);
      }
    } else {
      fileIds.add(id);
    }
  }

  if (!fileIds.size) {
    showToast('No files to download in the selection.', 'error');
    return;
  }

  for (const id of fileIds) {
    const record = records.find((r) => r.id === id);
    const meta = metaCache.get(id);
    if (!record || !meta) continue;
    await downloadAndSave(record, meta);
  }
}

async function handleDeleteSelected(): Promise<void> {
  const ids = [...selectedIds];
  if (!ids.length) return;

  const allIds = new Set<string>();
  for (const id of ids) {
    allIds.add(id);
    if (metaCache.get(id)?.isFolder) {
      for (const d of collectDescendantIds(id)) allIds.add(d);
    }
  }
  const label = `${ids.length} item${ids.length === 1 ? '' : 's'}`;
  const extra = allIds.size > ids.length ? ` and everything inside them (${allIds.size} total)` : '';
  if (!confirm(`Delete ${label}${extra}? This can't be undone.`)) return;

  let failed = 0;
  for (const id of allIds) {
    try {
      await api.deleteFile(id);
      if (objectUrlCache.has(id)) { URL.revokeObjectURL(objectUrlCache.get(id)!); objectUrlCache.delete(id); }
      fileKeyCache.delete(id);
      metaCache.delete(id);
    } catch {
      failed++;
    }
  }
  records = records.filter((r) => !allIds.has(r.id));
  setSelectionMode(false);
  renderCurrentView();
  scheduleUsageRefresh();
  if (failed) showToast(`Deleted ${allIds.size - failed} item(s); ${failed} failed.`, 'error');
  else showToast(allIds.size === 1 ? 'Deleted.' : `Deleted ${allIds.size} items.`);
}

async function handleMoveSelected(): Promise<void> {
  const ids = [...selectedIds];
  if (!ids.length) return;
  await openMovePicker(ids, records, async (destinationFolderId) => {
    await moveRecords(ids, destinationFolderId);
  });
}

function isDescendantOf(id: string, ancestorId: string): boolean {
  let cur: string | null = parentIdOf(id);
  const seen = new Set<string>();
  while (cur && !seen.has(cur)) {
    if (cur === ancestorId) return true;
    seen.add(cur);
    cur = parentIdOf(cur);
  }
  return false;
}

async function moveOneRecord(oldId: string, newParentId: string | null): Promise<string> {
  const fileKeyRaw = fileKeyCache.get(oldId);
  const meta = metaCache.get(oldId);
  const record = records.find((r) => r.id === oldId);
  if (!fileKeyRaw || !meta || !record) {
    throw new Error(`"${meta?.name ?? oldId}" isn't fully loaded yet — wait for the gallery to finish loading and try again.`);
  }

  const rawCiphertext = await api.downloadContent(oldId);
  const updatedMeta: FileMeta = { ...meta, parentId: newParentId };
  const { encryptedMetadata, metadataIv } = await C.encryptMetadata(fileKeyRaw, updatedMeta);

  const newRecord = await api.uploadFile({
    ciphertext: rawCiphertext,
    contentIv: record.content_iv,
    encryptedMetadata,
    metadataIv,
    wrappedFileKey: record.wrapped_file_key,
    wrapIv: record.wrap_iv,
  });

  await api.deleteFile(oldId);

  if (objectUrlCache.has(oldId)) { URL.revokeObjectURL(objectUrlCache.get(oldId)!); objectUrlCache.delete(oldId); }
  fileKeyCache.delete(oldId);
  metaCache.delete(oldId);
  fileKeyCache.set(newRecord.id, fileKeyRaw);
  metaCache.set(newRecord.id, updatedMeta);
  records = records.filter((r) => r.id !== oldId);
  records.push(newRecord);

  return newRecord.id;
}

async function moveSubtree(rootId: string, newParentId: string | null): Promise<void> {
  const isFolder = !!metaCache.get(rootId)?.isFolder;
  const descendantIds = isFolder ? collectDescendantIds(rootId) : [];

  const idMap = new Map<string, string>();
  const newRootId = await moveOneRecord(rootId, newParentId);
  idMap.set(rootId, newRootId);

  for (const id of descendantIds) {
    const oldParentId = parentIdOf(id);
    const mappedParent = oldParentId != null ? (idMap.get(oldParentId) ?? oldParentId) : null;
    const newId = await moveOneRecord(id, mappedParent);
    idMap.set(id, newId);
  }
}

async function moveRecords(ids: string[], destinationFolderId: string | null): Promise<void> {
  const idSet = new Set(ids);
  const targets = ids.filter((id) => ![...idSet].some((other) => other !== id && isDescendantOf(id, other)));

  let moved = 0;
  let failed = 0;
  for (const id of targets) {
    if (id === destinationFolderId) { continue; }
    if (parentIdOf(id) === destinationFolderId) { continue; }
    if (destinationFolderId != null && (destinationFolderId === id || isDescendantOf(destinationFolderId, id))) {
      failed++;
      continue;
    }
    try {
      await moveSubtree(id, destinationFolderId);
      moved++;
    } catch (err) {
      failed++;
      showToast((err as Error).message, 'error');
    }
  }

  setSelectionMode(false);
  renderCurrentView();
  scheduleUsageRefresh();
  if (failed) showToast(`Moved ${moved} item(s); ${failed} failed.`, 'error');
  else if (moved) showToast(`Moved ${moved} item${moved === 1 ? '' : 's'}.`);
}

const PAGE_SIZE = 24;
let pageOffset = 0;
let hasMorePages = true;
let isLoadingPage = false;
let searchQuery = '';
let records: FileRecord[] = [];

let currentFolderId: string | null = null;

export function getCurrentFolderId(): string | null {
  return currentFolderId;
}

function parentIdOf(recordId: string): string | null {
  const meta = metaCache.get(recordId);
  return (meta?.parentId as string | null | undefined) ?? null;
}

export function navigateToFolder(folderId: string | null): void {
  if (folderId === currentFolderId) return;
  currentFolderId = folderId;
  if (searchInput) searchInput.value = '';
  searchQuery = '';
  searchClearBtn?.classList.add('hidden');
  renderCurrentView();
}

export function getRecords(): FileRecord[] {
  return records;
}

export function resetRecords(): void {
  records = [];
  currentFolderId = null;
}

export function clearRenderedGrid(): void {
  for (const url of objectUrlCache.values()) URL.revokeObjectURL(url);
  objectUrlCache.clear();
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  emptyState.classList.add('hidden');
  gridLabel.textContent = '';
  if (breadcrumbEl) { breadcrumbEl.innerHTML = ''; breadcrumbEl.classList.add('hidden'); }
  usagePill.textContent = '\u2014 items \u00b7,';
  if (searchInput) searchInput.value = '';
  searchQuery = '';
  searchClearBtn?.classList.add('hidden');
  currentFolderId = null;
}

export async function refreshGallery(): Promise<void> {
  records = [];
  pageOffset = 0;
  hasMorePages = true;
  try {
    const usage = await api.getUsage();
    updateUsagePill(usage);
  } catch (err) {
    showToast((err as Error).message, 'error');
  }
  renderCurrentView();
  await loadAllPages();
}

export async function addUploadedRecord(record: FileRecord): Promise<void> {
  if (!fileKeyCache.has(record.id)) {
    try {
      const fileKeyRaw = await C.unwrapFileKey(getWrappingKeyRaw()!, record.wrapped_file_key, record.wrap_iv);
      fileKeyCache.set(record.id, fileKeyRaw);
      const meta = await C.decryptMetadata(fileKeyRaw, record.encrypted_metadata, record.metadata_iv);
      metaCache.set(record.id, meta);
    } catch {
      metaCache.set(record.id, { name: 'Unreadable item', mime: 'application/octet-stream' });
    }
  }

  records.push(record);
  scheduleUsageRefresh();
  appendRecordIfVisible(record);
}

let usageRefreshTimer: ReturnType<typeof setTimeout> | null = null;
const USAGE_REFRESH_DEBOUNCE_MS = 400;

function scheduleUsageRefresh(): void {
  if (usageRefreshTimer) return;
  usageRefreshTimer = setTimeout(async () => {
    usageRefreshTimer = null;
    try {
      const usage = await api.getUsage();
      updateUsagePill(usage);
    } catch (err) {
      showToast((err as Error).message, 'error');
    }
  }, USAGE_REFRESH_DEBOUNCE_MS);
}

function appendRecordIfVisible(record: FileRecord): void {
  if (parentIdOf(record.id) !== currentFolderId) return;
  if (searchQuery) {
    const name = (metaCache.get(record.id)?.name || '').toLowerCase();
    if (!name.includes(searchQuery.toLowerCase())) return;
  }

  const shown = visibleRecords();
  updateEmptyState(shown, !!searchQuery);
  updateGridLabel(shown, !!searchQuery);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  target.appendChild(render(record));
}

function updateUsagePill(usage: UsageResponse): void {
  usagePill.textContent = usage.quota_bytes != null
    ? `${formatBytes(usage.total_bytes)} / ${formatBytes(usage.quota_bytes)} \u00b7 ${usage.file_count} item${usage.file_count === 1 ? '' : 's'}`
    : `${usage.file_count} item${usage.file_count === 1 ? '' : 's'} \u00b7 ${formatBytes(usage.total_bytes)}`;
}

async function loadAllPages(): Promise<void> {
  while (hasMorePages) {
    await loadNextPage();
  }
}

async function loadNextPage(): Promise<void> {
  if (isLoadingPage || !hasMorePages) return;
  isLoadingPage = true;
  gridSentinel.classList.remove('hidden');
  gridSentinel.textContent = 'Loading\u2026';
  try {
    const page = await api.listFiles({ offset: pageOffset, limit: PAGE_SIZE });
    const known = new Set(records.map((r) => r.id));
    const fresh = page.filter((r) => !known.has(r.id));

    if (page.length < PAGE_SIZE || fresh.length === 0) hasMorePages = false;
    pageOffset += page.length || PAGE_SIZE;

    await Promise.all(fresh.map(async (record) => {
      if (fileKeyCache.has(record.id)) return;
      try {
        const fileKeyRaw = await C.unwrapFileKey(getWrappingKeyRaw()!, record.wrapped_file_key, record.wrap_iv);
        fileKeyCache.set(record.id, fileKeyRaw);
        const meta = await C.decryptMetadata(fileKeyRaw, record.encrypted_metadata, record.metadata_iv);
        metaCache.set(record.id, meta);
      } catch {
        metaCache.set(record.id, { name: 'Unreadable item', mime: 'application/octet-stream' });
      }
    }));

    records = records.concat(fresh);
    renderCurrentView();
  } catch (err) {
    showToast((err as Error).message, 'error');
    hasMorePages = false;
  } finally {
    isLoadingPage = false;
    gridSentinel.classList.toggle('hidden', !hasMorePages);
  }
}

export function visibleRecords(): FileRecord[] {
  const inFolder = records.filter((r) => parentIdOf(r.id) === currentFolderId);
  const q = searchQuery.toLowerCase();
  const filtered = q
    ? inFolder.filter((r) => (metaCache.get(r.id)?.name || '').toLowerCase().includes(q))
    : inFolder;
  return filtered.slice().sort((a, b) => {
    const aFolder = !!metaCache.get(a.id)?.isFolder;
    const bFolder = !!metaCache.get(b.id)?.isFolder;
    if (aFolder !== bFolder) return aFolder ? -1 : 1;
    return 0;
  });
}

function folderPathTo(folderId: string | null): FileRecord[] {
  const path: FileRecord[] = [];
  let cur = folderId;
  const seen = new Set<string>();
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const rec = records.find((r) => r.id === cur);
    if (!rec) break;
    path.unshift(rec);
    cur = parentIdOf(rec.id);
  }
  return path;
}

function renderBreadcrumb(): void {
  if (!breadcrumbEl) return;
  const path = folderPathTo(currentFolderId);
  breadcrumbEl.innerHTML = '';
  breadcrumbEl.classList.toggle('hidden', path.length === 0);
  if (path.length === 0) return;

  const homeBtn = document.createElement('button');
  homeBtn.type = 'button';
  homeBtn.className = 'breadcrumb-item';
  homeBtn.textContent = 'Home';
  homeBtn.addEventListener('click', () => navigateToFolder(null));
  breadcrumbEl.appendChild(homeBtn);

  path.forEach((folder, i) => {
    const sep = document.createElement('span');
    sep.className = 'breadcrumb-sep';
    sep.textContent = '/';
    breadcrumbEl.appendChild(sep);

    const meta = metaCache.get(folder.id);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'breadcrumb-item' + (i === path.length - 1 ? ' current' : '');
    btn.textContent = meta?.name || '\u2026';
    btn.addEventListener('click', () => navigateToFolder(folder.id));
    breadcrumbEl.appendChild(btn);
  });
}

function renderCurrentView(): void {
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  const shown = visibleRecords();
  const searching = !!searchQuery;

  renderBreadcrumb();
  updateEmptyState(shown, searching);
  updateGridLabel(shown, searching);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  const fragment = document.createDocumentFragment();
  for (const record of shown) {
    fragment.appendChild(render(record));
  }
  target.appendChild(fragment);
}

function updateEmptyState(shown: FileRecord[], searching: boolean): void {
  emptyState.classList.toggle('hidden', shown.length > 0);
  emptyState.querySelector('h3')!.textContent = searching ? 'No matches' : 'Nothing here';
  emptyState.querySelector('p')!.textContent = searching
    ? `Nothing matches "${searchQuery}".`
    : (currentFolderId ? 'This folder is empty.' : 'Upload something above to see it here.');
}

function updateGridLabel(shown: FileRecord[], searching: boolean): void {
  const allInFolder = records.filter((r) => parentIdOf(r.id) === currentFolderId);
  gridLabel.textContent = shown.length
    ? `Files \u00b7 ${shown.length}${searching ? ` of ${allInFolder.length}` : ''}`
    : '';
}

let searchDebounce: ReturnType<typeof setTimeout> | null = null;
searchInput?.addEventListener('input', () => {
  if (searchDebounce) clearTimeout(searchDebounce);
  searchClearBtn?.classList.toggle('hidden', !searchInput.value);
  searchDebounce = setTimeout(() => {
    searchQuery = searchInput.value.trim();
    renderCurrentView();
  }, 180);
});

searchClearBtn?.addEventListener('click', () => {
  searchInput.value = '';
  searchQuery = '';
  searchClearBtn.classList.add('hidden');
  renderCurrentView();
  searchInput.focus();
});

function renderTile(record: FileRecord): HTMLDivElement {
  const meta: FileMeta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const isFolder = !!meta.isFolder;
  const kind = isFolder ? 'folder' : fileKind(meta.mime);

  const tile = document.createElement('div');
  tile.className = 'box-tile'
    + (isFolder ? ' is-folder' : '')
    + (selectionMode ? ' selection-mode' : '')
    + (selectedIds.has(record.id) ? ' selected' : '');
  tile.dataset.id = record.id;
  tile.tabIndex = 0;
  tile.setAttribute('role', 'button');
  tile.setAttribute('aria-label', isFolder ? `Open folder ${meta.name}` : `Open ${meta.name}`);

  tile.innerHTML = `
    <label class="box-select-label">
      <input type="checkbox" class="box-select-checkbox">
    </label>
    ${isCoarsePointerDevice ? '' : `
      <div class="box-menu">
        ${isFolder ? '' : `<button type="button" class="btn-icon share-btn" title="Share">${icon('share')}</button>`}
        <button type="button" class="btn-icon delete-btn" title="Delete">${icon('trash')}</button>
      </div>
    `}
    <div class="box-body">
      ${isFolder ? `<div class="box-icon">${icon('folder')}</div><div class="box-name"></div>`
        : kind === 'image' ? `<div class="box-icon">${icon('image')}</div><div class="box-name"></div>`
        : kind === 'video' ? `<div class="box-play">${icon('play')}</div><div class="box-icon">${icon('video')}</div><div class="box-name"></div>`
        : `<div class="box-icon">${icon('file')}</div><div class="box-name"></div>`}
    </div>
  `;
  tile.querySelector('.box-name')!.textContent = meta.name;
  tile.querySelector('.delete-btn')?.setAttribute('aria-label', `Delete ${meta.name}`);
  tile.querySelector('.share-btn')?.setAttribute('aria-label', `Share ${meta.name}`);

  const selectCheckbox = tile.querySelector('.box-select-checkbox') as HTMLInputElement;
  selectCheckbox.checked = selectedIds.has(record.id);
  selectCheckbox.setAttribute('aria-label', `Select ${meta.name}`);
  selectCheckbox.addEventListener('click', (e) => e.stopPropagation());
  selectCheckbox.addEventListener('change', () => toggleSelect(record.id));

  const openThisTile = () => (isFolder ? navigateToFolder(record.id) : openTile(record.id));

  tile.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    if (target.closest('.delete-btn') || target.closest('.share-btn') || target.closest('.box-select-label')) return;
    if (selectionMode) { toggleSelect(record.id); return; }
    openThisTile();
  });
  tile.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (selectionMode) toggleSelect(record.id);
      else openThisTile();
    }
  });
  tile.querySelector('.delete-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
  });
  tile.querySelector('.share-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    shareFile(record);
  });

  if (!isFolder && kind === 'image') {
    const observer = new IntersectionObserver(async (entries) => {
      if (entries[0]?.isIntersecting) {
        observer.disconnect();
        try {
          const url = await getDecryptedUrl(record);
          const img = document.createElement('img');
          img.src = url;
          img.alt = meta.name;
          tile.querySelector('.box-body')!.prepend(img);
        } catch {
        }
      }
    }, { rootMargin: '200px' });
    observer.observe(tile);
  }

  return tile;
}

function renderListRow(record: FileRecord): HTMLDivElement {
  const meta: FileMeta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const isFolder = !!meta.isFolder;
  const kind = isFolder ? 'folder' : fileKind(meta.mime);

  const row = document.createElement('div');
  row.className = 'file-list-row'
    + (isFolder ? ' is-folder' : '')
    + (selectionMode ? ' selection-mode' : '')
    + (selectedIds.has(record.id) ? ' selected' : '');
  row.dataset.id = record.id;
  row.tabIndex = 0;
  row.setAttribute('role', 'row');
  row.setAttribute('aria-label', isFolder ? `Open folder ${meta.name}` : `Open ${meta.name}`);

  row.innerHTML = `
    <span class="file-row-name" role="cell">
      <span class="file-row-select"><input type="checkbox" class="file-row-checkbox"></span>
      <span class="file-row-icon">${icon(isFolder ? 'folder' : kind === 'image' ? 'image' : kind === 'video' ? 'video' : 'file')}</span>
      <span class="file-row-text"></span>
    </span>
    <span class="file-row-type" role="cell"></span>
    <span class="file-row-size" role="cell">${isFolder ? '\u2014' : formatBytes(decryptedSize(record, meta))}</span>
    <span class="file-row-actions" role="cell">
      ${isFolder ? '' : `<button type="button" class="btn-icon file-share-btn" title="Share">${icon('share')}</button>`}
      ${isFolder ? '' : `<button type="button" class="btn-icon file-download-btn" title="Download">${icon('download')}</button>`}
      <button type="button" class="btn-icon file-delete-btn" title="Delete">${icon('trash')}</button>
    </span>
  `;
  row.querySelector('.file-row-text')!.textContent = meta.name;
  row.querySelector('.file-row-type')!.textContent = fileTypeLabel(meta);
  row.querySelector('.file-share-btn')?.setAttribute('aria-label', `Share ${meta.name}`);
  row.querySelector('.file-download-btn')?.setAttribute('aria-label', `Download ${meta.name}`);
  row.querySelector('.file-delete-btn')!.setAttribute('aria-label', `Delete ${meta.name}`);

  const rowCheckbox = row.querySelector('.file-row-checkbox') as HTMLInputElement;
  rowCheckbox.checked = selectedIds.has(record.id);
  rowCheckbox.setAttribute('aria-label', `Select ${meta.name}`);
  rowCheckbox.addEventListener('click', (e) => e.stopPropagation());
  rowCheckbox.addEventListener('change', () => toggleSelect(record.id));

  const openThisRow = () => (isFolder ? navigateToFolder(record.id) : openTile(record.id));

  row.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    if (target.closest('.file-download-btn')
      || target.closest('.file-share-btn')
      || target.closest('.file-delete-btn')
      || target.closest('.file-row-select')) return;
    if (selectionMode) { toggleSelect(record.id); return; }
    openThisRow();
  });
  row.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (selectionMode) toggleSelect(record.id);
      else openThisRow();
    }
  });
  row.querySelector('.file-share-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    shareFile(record);
  });
  row.querySelector('.file-download-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    downloadAndSave(record, meta);
  });
  row.querySelector('.file-delete-btn')!.addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
  });

  return row;
}

export async function getDecryptedBytes(record: FileRecord): Promise<Uint8Array> {
  const fileKeyRaw = fileKeyCache.get(record.id)!;
  const ciphertext = await api.downloadContent(record.id);
  const meta = metaCache.get(record.id)!;
  return C.decryptContent(fileKeyRaw, record.content_iv, ciphertext, meta.compressed, meta.unpaddedSize);
}

export async function getDecryptedUrl(record: FileRecord): Promise<string> {
  if (objectUrlCache.has(record.id)) return objectUrlCache.get(record.id)!;
  const meta = metaCache.get(record.id)!;
  let bytes: Uint8Array | null = await getDecryptedBytes(record);
  const blob = new Blob([bytes as BlobPart], { type: meta.mime });
  bytes = null;
  const url = URL.createObjectURL(blob);
  objectUrlCache.set(record.id, url);
  return url;
}

function collectDescendantIds(folderId: string): string[] {
  const result: string[] = [];
  const visited = new Set<string>([folderId]);
  const stack = [folderId];
  while (stack.length) {
    const id = stack.pop()!;
    for (const r of records) {
      if (parentIdOf(r.id) === id && !visited.has(r.id)) {
        visited.add(r.id);
        result.push(r.id);
        if (metaCache.get(r.id)?.isFolder) stack.push(r.id);
      }
    }
  }
  return result;
}

export async function createFolder(name: string): Promise<void> {
  const trimmed = name.trim();
  if (!trimmed) return;
  const wrappingKeyRaw = getWrappingKeyRaw();
  if (!wrappingKeyRaw) return;
  try {
    const payload = await C.encryptFolder(wrappingKeyRaw, trimmed, currentFolderId);
    await api.uploadFile(payload);
    await refreshGallery();
    showToast('Folder created.');
  } catch (err) {
    showToast("Couldn't create folder. " + (err as Error).message, 'error');
  }
}

export function removeRecordLocally(fileId: string): void {
  if (objectUrlCache.has(fileId)) { URL.revokeObjectURL(objectUrlCache.get(fileId)!); objectUrlCache.delete(fileId); }
  fileKeyCache.delete(fileId);
  metaCache.delete(fileId);
  records = records.filter((r) => r.id !== fileId);
  renderCurrentView();
}

export async function handleDelete(fileId: string): Promise<boolean> {
  const meta = metaCache.get(fileId);
  const isFolder = !!meta?.isFolder;
  const descendantIds = isFolder ? collectDescendantIds(fileId) : [];

  const confirmMsg = isFolder
    ? descendantIds.length
      ? `Delete "${meta?.name ?? 'this folder'}" and everything inside it (${descendantIds.length} item${descendantIds.length === 1 ? '' : 's'})? This can't be undone.`
      : `Delete "${meta?.name ?? 'this folder'}"? This can't be undone.`
    : `Delete "${meta?.name ?? 'this file'}"? This can't be undone.`;
  if (!confirm(confirmMsg)) return false;

  const idsToDelete = [...descendantIds, fileId];
  try {
    for (const id of idsToDelete) {
      await api.deleteFile(id);
      if (objectUrlCache.has(id)) { URL.revokeObjectURL(objectUrlCache.get(id)!); objectUrlCache.delete(id); }
      fileKeyCache.delete(id);
      metaCache.delete(id);
    }
    const removed = new Set(idsToDelete);
    records = records.filter((r) => !removed.has(r.id));
    renderCurrentView();
    showToast(isFolder ? 'Folder deleted.' : 'Deleted.');
    return true;
  } catch (err) {
    showToast("Couldn't delete that item. " + (err as Error).message, 'error');
    await refreshGallery();
    return false;
  }
}