import * as C from './crypto.js';
import * as api from './api.js';
import {
  boxGrid, fileListEl, fileListBody, viewGridBtn, viewListBtn,
  emptyState, gridLabel, searchInput, searchClearBtn, gridSentinel, usagePill,
} from './dom.js';
import { fileKeyCache, metaCache, objectUrlCache, getWrappingKeyRaw } from './state.js';
import { getStoredViewMode, setStoredViewMode } from './storage.js';
import { fileKind, formatBytes, decryptedSize, icon, showToast } from './utils.js';
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
let gridObserver: IntersectionObserver | null = null;
let records: FileRecord[] = [];

export function getRecords(): FileRecord[] {
  return records;
}

export function resetRecords(): void {
  records = [];
}

export function clearRenderedGrid(): void {
  for (const url of objectUrlCache.values()) URL.revokeObjectURL(url);
  objectUrlCache.clear();
  if (gridObserver) { gridObserver.disconnect(); gridObserver = null; }
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  emptyState.classList.add('hidden');
  gridLabel.textContent = '';
  usagePill.textContent = '\u2014 items \u00b7,';
  if (searchInput) searchInput.value = '';
  searchQuery = '';
  searchClearBtn?.classList.add('hidden');
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
  await loadNextPage();
  setupGridSentinel();
}

function updateUsagePill(usage: UsageResponse): void {
  usagePill.textContent = usage.quota_bytes != null
    ? `${formatBytes(usage.total_bytes)} / ${formatBytes(usage.quota_bytes)} \u00b7 ${usage.file_count} item${usage.file_count === 1 ? '' : 's'}`
    : `${usage.file_count} item${usage.file_count === 1 ? '' : 's'} \u00b7 ${formatBytes(usage.total_bytes)}`;
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
    appendToCurrentView(fresh);
  } catch (err) {
    showToast((err as Error).message, 'error');
    hasMorePages = false;
  } finally {
    isLoadingPage = false;
    gridSentinel.classList.toggle('hidden', !hasMorePages);
  }
}

async function loadAllPagesForSearch(): Promise<void> {
  while (hasMorePages) {
    await loadNextPage();
  }
}

function setupGridSentinel(): void {
  if (gridObserver) gridObserver.disconnect();
  gridObserver = new IntersectionObserver((entries) => {
    if (entries[0]?.isIntersecting) loadNextPage();
  }, { rootMargin: '400px' });
  gridObserver.observe(gridSentinel);
}

export function visibleRecords(): FileRecord[] {
  if (!searchQuery) return records;
  const q = searchQuery.toLowerCase();
  return records.filter((r) => (metaCache.get(r.id)?.name || '').toLowerCase().includes(q));
}

function renderCurrentView(): void {
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  const shown = visibleRecords();
  const searching = !!searchQuery;

  updateEmptyState(shown, searching);
  updateGridLabel(shown, searching);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  for (const record of shown) {
    target.appendChild(render(record));
  }
}

function appendToCurrentView(newRecords: FileRecord[]): void {
  const searching = !!searchQuery;
  const q = searchQuery.toLowerCase();
  const toShow = searching
    ? newRecords.filter((r) => (metaCache.get(r.id)?.name || '').toLowerCase().includes(q))
    : newRecords;

  const shown = visibleRecords();
  updateEmptyState(shown, searching);
  updateGridLabel(shown, searching);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  const fragment = document.createDocumentFragment();
  for (const record of toShow) {
    fragment.appendChild(render(record));
  }
  target.appendChild(fragment);
}

function updateEmptyState(shown: FileRecord[], searching: boolean): void {
  emptyState.classList.toggle('hidden', shown.length > 0);
  emptyState.querySelector('h3')!.textContent = searching ? 'No matches' : 'No files yet';
  emptyState.querySelector('p')!.textContent = searching
    ? `Nothing matches "${searchQuery}".`
    : 'Upload something above to see it here.';
}

function updateGridLabel(shown: FileRecord[], searching: boolean): void {
  gridLabel.textContent = shown.length
    ? `Files \u00b7 ${shown.length}${searching ? ` of ${records.length}` : ''}`
    : '';
}

let searchDebounce: ReturnType<typeof setTimeout> | null = null;
searchInput?.addEventListener('input', () => {
  if (searchDebounce) clearTimeout(searchDebounce);
  searchClearBtn?.classList.toggle('hidden', !searchInput.value);
  searchDebounce = setTimeout(async () => {
    searchQuery = searchInput.value.trim();
    if (searchQuery && hasMorePages) {
      gridSentinel.textContent = 'Loading all files to search\u2026';
      await loadAllPagesForSearch();
    }
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
  const kind = fileKind(meta.mime);

  const tile = document.createElement('div');
  tile.className = 'box-tile';
  tile.dataset.id = record.id;
  tile.tabIndex = 0;
  tile.setAttribute('role', 'button');
  tile.setAttribute('aria-label', `Open ${meta.name}`);

  tile.innerHTML = `
    <div class="box-menu">
      <button type="button" class="btn-icon delete-btn" title="Delete">${icon('trash')}</button>
    </div>
    <div class="box-body">
      ${kind === 'image' ? `<div class="box-icon">${icon('image')}</div><div class="box-name"></div>`
        : kind === 'video' ? `<div class="box-play">${icon('play')}</div><div class="box-icon">${icon('video')}</div><div class="box-name"></div>`
        : `<div class="box-icon">${icon('file')}</div><div class="box-name"></div>`}
    </div>
  `;
  tile.querySelector('.box-name')!.textContent = meta.name;
  tile.querySelector('.delete-btn')!.setAttribute('aria-label', `Delete ${meta.name}`);

  tile.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).closest('.delete-btn')) return;
    openTile(record.id);
  });
  tile.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openTile(record.id); }
  });
  tile.querySelector('.delete-btn')!.addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
  });

  if (kind === 'image') {
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

function fileTypeLabel(meta: FileMeta | undefined | null): string {
  const kind = fileKind(meta?.mime);
  if (kind === 'image') return 'Image';
  if (kind === 'video') return 'Video';
  const sub = (meta?.mime || '').split('/')[1];
  return sub ? sub.replace('x-', '').toUpperCase() : 'File';
}

function renderListRow(record: FileRecord): HTMLDivElement {
  const meta: FileMeta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const kind = fileKind(meta.mime);

  const row = document.createElement('div');
  row.className = 'file-list-row';
  row.dataset.id = record.id;
  row.tabIndex = 0;
  row.setAttribute('role', 'row');
  row.setAttribute('aria-label', `Open ${meta.name}`);

  row.innerHTML = `
    <span class="file-row-name" role="cell">
      <span class="file-row-icon">${icon(kind === 'image' ? 'image' : kind === 'video' ? 'video' : 'file')}</span>
      <span class="file-row-text"></span>
    </span>
    <span class="file-row-type" role="cell"></span>
    <span class="file-row-size" role="cell">${formatBytes(decryptedSize(record, meta))}</span>
    <span class="file-row-actions" role="cell">
      <button type="button" class="btn-icon file-download-btn" title="Download">${icon('download')}</button>
      <button type="button" class="btn-icon file-delete-btn" title="Delete">${icon('trash')}</button>
    </span>
  `;
  row.querySelector('.file-row-text')!.textContent = meta.name;
  row.querySelector('.file-row-type')!.textContent = fileTypeLabel(meta);
  row.querySelector('.file-download-btn')!.setAttribute('aria-label', `Download ${meta.name}`);
  row.querySelector('.file-delete-btn')!.setAttribute('aria-label', `Delete ${meta.name}`);

  row.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).closest('.file-download-btn') || (e.target as HTMLElement).closest('.file-delete-btn')) return;
    openTile(record.id);
  });
  row.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openTile(record.id); }
  });
  row.querySelector('.file-download-btn')!.addEventListener('click', (e) => {
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

async function handleDelete(fileId: string): Promise<void> {
  const meta = metaCache.get(fileId);
  if (!confirm(`Delete "${meta?.name ?? 'this file'}"? This can't be undone.`)) return;
  try {
    await api.deleteFile(fileId);
    if (objectUrlCache.has(fileId)) { URL.revokeObjectURL(objectUrlCache.get(fileId)!); objectUrlCache.delete(fileId); }
    fileKeyCache.delete(fileId);
    metaCache.delete(fileId);
    records = records.filter((r) => r.id !== fileId);
    renderCurrentView();
    showToast('Deleted.');
  } catch (err) {
    showToast("Couldn't delete that file. " + (err as Error).message, 'error');
  }
}
