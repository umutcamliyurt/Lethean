import * as C from './crypto.js';
import * as api from './api.js';
import {
  boxGrid, fileListEl, fileListBody, viewGridBtn, viewListBtn,
  emptyState, gridLabel, searchInput, searchClearBtn, gridSentinel, usagePill, breadcrumbEl,
} from './dom.js';
import { fileKeyCache, metaCache, objectUrlCache, getWrappingKeyRaw } from './state.js';
import { getStoredViewMode, setStoredViewMode } from './storage.js';
import { fileKind, fileTypeLabel, formatBytes, decryptedSize, icon, showToast } from './utils.js';
import { openTile, downloadAndSave } from './lightbox.js';
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

    for (const record of fresh) {
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
    }

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
  tile.className = 'box-tile' + (isFolder ? ' is-folder' : '');
  tile.dataset.id = record.id;
  tile.tabIndex = 0;
  tile.setAttribute('role', 'button');
  tile.setAttribute('aria-label', isFolder ? `Open folder ${meta.name}` : `Open ${meta.name}`);

  tile.innerHTML = `
    <div class="box-menu">
      <button type="button" class="btn-icon delete-btn" title="Delete">${icon('trash')}</button>
    </div>
    <div class="box-body">
      ${isFolder ? `<div class="box-icon">${icon('folder')}</div><div class="box-name"></div>`
        : kind === 'image' ? `<div class="box-icon">${icon('image')}</div><div class="box-name"></div>`
        : kind === 'video' ? `<div class="box-play">${icon('play')}</div><div class="box-icon">${icon('video')}</div><div class="box-name"></div>`
        : `<div class="box-icon">${icon('file')}</div><div class="box-name"></div>`}
    </div>
  `;
  tile.querySelector('.box-name')!.textContent = meta.name;
  tile.querySelector('.delete-btn')!.setAttribute('aria-label', `Delete ${meta.name}`);

  const openThisTile = () => (isFolder ? navigateToFolder(record.id) : openTile(record.id));

  tile.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).closest('.delete-btn')) return;
    openThisTile();
  });
  tile.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openThisTile(); }
  });
  tile.querySelector('.delete-btn')!.addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
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
  row.className = 'file-list-row' + (isFolder ? ' is-folder' : '');
  row.dataset.id = record.id;
  row.tabIndex = 0;
  row.setAttribute('role', 'row');
  row.setAttribute('aria-label', isFolder ? `Open folder ${meta.name}` : `Open ${meta.name}`);

  row.innerHTML = `
    <span class="file-row-name" role="cell">
      <span class="file-row-icon">${icon(isFolder ? 'folder' : kind === 'image' ? 'image' : kind === 'video' ? 'video' : 'file')}</span>
      <span class="file-row-text"></span>
    </span>
    <span class="file-row-type" role="cell"></span>
    <span class="file-row-size" role="cell">${isFolder ? '\u2014' : formatBytes(decryptedSize(record, meta))}</span>
    <span class="file-row-actions" role="cell">
      ${isFolder ? '' : `<button type="button" class="btn-icon file-download-btn" title="Download">${icon('download')}</button>`}
      <button type="button" class="btn-icon file-delete-btn" title="Delete">${icon('trash')}</button>
    </span>
  `;
  row.querySelector('.file-row-text')!.textContent = meta.name;
  row.querySelector('.file-row-type')!.textContent = fileTypeLabel(meta);
  row.querySelector('.file-download-btn')?.setAttribute('aria-label', `Download ${meta.name}`);
  row.querySelector('.file-delete-btn')!.setAttribute('aria-label', `Delete ${meta.name}`);

  const openThisRow = () => (isFolder ? navigateToFolder(record.id) : openTile(record.id));

  row.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).closest('.file-download-btn') || (e.target as HTMLElement).closest('.file-delete-btn')) return;
    openThisRow();
  });
  row.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openThisRow(); }
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

async function handleDelete(fileId: string): Promise<void> {
  const meta = metaCache.get(fileId);
  const isFolder = !!meta?.isFolder;
  const descendantIds = isFolder ? collectDescendantIds(fileId) : [];

  const confirmMsg = isFolder
    ? descendantIds.length
      ? `Delete "${meta?.name ?? 'this folder'}" and everything inside it (${descendantIds.length} item${descendantIds.length === 1 ? '' : 's'})? This can't be undone.`
      : `Delete "${meta?.name ?? 'this folder'}"? This can't be undone.`
    : `Delete "${meta?.name ?? 'this file'}"? This can't be undone.`;
  if (!confirm(confirmMsg)) return;

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
  } catch (err) {
    showToast("Couldn't delete that item. " + (err as Error).message, 'error');
    await refreshGallery();
  }
}