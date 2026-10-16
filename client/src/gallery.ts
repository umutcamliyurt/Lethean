import * as C from './crypto.js';
import * as api from './api.js';
import {
  boxGrid, fileListEl, fileListBody, viewGridBtn, viewListBtn,
  emptyState, gridLabel, searchInput, searchClearBtn, gridSentinel, usagePill, breadcrumbEl,
  selectToggleBtn, selectionBarEl, selectionCountEl, selectionSelectAllBtn,
  selectionDownloadBtn, selectionMoveBtn, selectionDeleteBtn, selectionCancelBtn,
} from './dom.js';
import { fileKeyCache, metaCache, objectUrlCache, getWrappingKeyRaw, getCurrentVaultId } from './state.js';
import { acquireThumbnail, releaseThumbnail, dropThumbnail, clearThumbnails } from './thumbnails.js';
import { getStoredViewMode, setStoredViewMode, isVaultLegacyFree, markVaultLegacyFree } from './storage.js';
import { fileKind, fileTypeLabel, formatBytes, decryptedSize, icon, showToast, isCoarsePointerDevice } from './utils.js';
import { openTile, downloadAndSave } from './lightbox.js';
import { shareFile } from './share.js';
import { openMovePicker } from './move.js';
import type { FileMeta, FileRecord, UsageResponse, ViewMode } from './types.js';
import { rememberFileKey, forgetFileKey, effectiveParentId, parentRefFor, nodeRefOf } from './tree.js';
import { uniqueById, healPlan, recordFingerprint, shownNames } from './dedupe-core.js';
import type { UploadFields, HealKind, HealItem } from './dedupe-core.js';
import type { FileKey } from './crypto-encrypt-core.js';

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

function selectEverythingVisible(): void {
  const shown = visibleRecords();
  if (!shown.length) return;
  if (!selectionMode) {
    selectionMode = true;
    selectToggleBtn?.classList.add('active');
    selectToggleBtn?.setAttribute('aria-pressed', 'true');
  }
  for (const r of shown) selectedIds.add(r.id);
  updateSelectionBar();
  renderCurrentView();
}

function isTypingTarget(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  if (!el) return false;
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable;
}

document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || e.key.toLowerCase() !== 'a') return;
  if (document.getElementById('app-screen')?.classList.contains('hidden')) return;
  if (!document.getElementById('lightbox')?.classList.contains('hidden')) return;
  if (isTypingTarget(e.target)) return;
  e.preventDefault();
  selectEverythingVisible();
});

function finishBulk(ids: Iterable<string>): void {
  for (const id of ids) selectedIds.delete(id);
  if (selectionMode && selectedIds.size === 0) setSelectionMode(false);
  else { updateSelectionBar(); renderCurrentView(); }
}

async function handleDownloadSelected(): Promise<void> {
  await downloadIds([...selectedIds]);
}

async function downloadIds(ids: string[]): Promise<void> {
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
  await deleteIds([...selectedIds]);
}

async function deleteIds(ids: string[]): Promise<void> {
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
      dropThumbnail(id);
      forgetFileKey(id);
      metaCache.delete(id);
    } catch {
      failed++;
    }
  }
  records = records.filter((r) => !allIds.has(r.id));
  finishBulk(allIds);
  scheduleUsageRefresh();
  if (failed) showToast(`Deleted ${allIds.size - failed} item(s); ${failed} failed.`, 'error');
  else showToast(allIds.size === 1 ? 'Deleted.' : `Deleted ${allIds.size} items.`);
}

async function handleMoveSelected(): Promise<void> {
  await moveIds([...selectedIds]);
}

async function moveIds(ids: string[]): Promise<void> {
  if (!ids.length) return;
  await openMovePicker(ids, records, async (destinationFolderId) => {
    await moveRecords(ids, destinationFolderId);
  });
}

export function namesInFolder(folderId: string | null, exceptIds: Iterable<string> = []): Set<string> {
  const except = new Set(exceptIds);
  const names = new Set<string>();
  for (const r of records) {
    if (except.has(r.id) || parentIdOf(r.id) !== folderId) continue;
    const name = metaCache.get(r.id)?.name;
    if (name) names.add(name);
  }
  return names;
}

export function nameTakenIn(folderId: string | null, name: string, exceptIds: Iterable<string> = []): boolean {
  return namesInFolder(folderId, exceptIds).has(name);
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
  const oldFileKey = fileKeyCache.get(oldId);
  const meta = metaCache.get(oldId);
  const record = records.find((r) => r.id === oldId);
  const wrappingKeyRaw = getWrappingKeyRaw();
  if (!oldFileKey || !meta || !record || !wrappingKeyRaw) {
    throw new Error(`"${meta?.name ?? oldId}" isn't fully loaded yet — wait for the gallery to finish loading and try again.`);
  }

  const { stream } = await api.openDownloadStream(oldId);
  const ciphertextBlob = await C.streamToBlob(stream);
  const { parentId: _oldParentId, pref: _oldPref, ...rest } = meta;
  const rev = (meta.rev ?? 0) + 1;
  const updatedMeta: FileMeta = oldFileKey.format === C.FILE_FORMAT_V2
    ? { ...rest, rev, ...C.parentFields(parentRefFor(newParentId)) }
    : { ...rest, rev, parentId: newParentId };

  const fileKey = C.rebindFileKey(oldFileKey);
  const { encryptedMetadata, metadataIv } = await C.encryptMetadata(fileKey, updatedMeta);
  const wrap = fileKey === oldFileKey
    ? { wrappedFileKey: record.wrapped_file_key, wrapIv: record.wrap_iv }
    : await C.wrapFileKey(wrappingKeyRaw, fileKey);

  const fields = {
    contentIv: record.content_iv,
    encryptedMetadata,
    metadataIv,
    ...wrap,
  };
  const newRecord = await api.uploadFile(
    ciphertextBlob.size <= api.SINGLE_UPLOAD_MAX_BYTES
      ? { ...fields, ciphertext: ciphertextBlob }
      : api.ciphertextBlobAsParts(fields, ciphertextBlob)
  );

  metaCache.set(newRecord.id, updatedMeta);
  await rememberFileKey(newRecord.id, fileKey);
  if (!records.some((r) => r.id === newRecord.id)) records.push(newRecord);
  await settleUploads([{ fields, keepId: newRecord.id }]);

  try {
    await api.deleteFileWithRetry(oldId);
  } catch (err) {
    throw new Error(`"${meta.name}" was copied to its new place, but the original couldn't be removed (${(err as Error).message}). Delete the original yourself.`);
  }

  if (objectUrlCache.has(oldId)) { URL.revokeObjectURL(objectUrlCache.get(oldId)!); objectUrlCache.delete(oldId); }
  dropThumbnail(oldId);
  forgetFileKey(oldId);
  metaCache.delete(oldId);
  records = records.filter((r) => r.id !== oldId);

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
    const name = metaCache.get(id)?.name;
    if (name && nameTakenIn(destinationFolderId, name, [id])) {
      failed++;
      showToast(`"${name}" wasn't moved: something with that name is already there.`, 'error');
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

  finishBulk(ids);
  scheduleUsageRefresh();
  if (failed) showToast(`Moved ${moved} item(s); ${failed} failed.`, 'error');
  else if (moved) showToast(`Moved ${moved} item${moved === 1 ? '' : 's'}.`);
}

const PAGE_SIZE = 24;
let pageOffset = 0;
let lastPageKey = '';
let hasMorePages = true;
let isLoadingPage = false;
let searchQuery = '';
let records: FileRecord[] = [];

let currentFolderId: string | null = null;

export function getCurrentFolderId(): string | null {
  return currentFolderId;
}

function parentIdOf(recordId: string): string | null {
  return effectiveParentId(recordId);
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
  loadGeneration++;
  staleRecords.clear();
  healKeep.clear();
  contentHashes.clear();
  hashBytesUsed = 0;
  fingerprintOwner.clear();
  records = [];
  quarantined = [];
  strictMode = false;
  legacyFreeMarker = null;
  legacyNoticeShown = false;
  currentFolderId = null;
}

export function clearRenderedGrid(): void {
  unmountAllThumbs();
  clearThumbnails();
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

let loadGeneration = 0;
let refreshRunning: Promise<void> | null = null;
let refreshQueued: Promise<void> | null = null;

export function refreshGallery(): Promise<void> {
  if (!refreshRunning) {
    refreshRunning = refreshGalleryNow().finally(() => { refreshRunning = null; });
    return refreshRunning;
  }
  if (!refreshQueued) {
    refreshQueued = refreshRunning.catch(() => {}).then(() => {
      refreshQueued = null;
      return refreshGallery();
    });
  }
  return refreshQueued;
}

async function refreshGalleryNow(): Promise<void> {
  loadGeneration++;
  staleRecords.clear();
  fingerprintOwner.clear();
  records = [];
  quarantined = [];
  pageOffset = 0;
  lastPageKey = '';
  hasMorePages = true;
  loadFailed = false;
  while (isLoadingPage) await new Promise((r) => setTimeout(r, 20));
  const vaultId = getCurrentVaultId();
  legacyFreeMarker = vaultId ? await C.deriveVaultMarkers(vaultId) : null;
  strictMode = legacyFreeMarker !== null && isVaultLegacyFree(legacyFreeMarker);
  try {
    const usage = await api.getUsage();
    updateUsagePill(usage);
  } catch (err) {
    showToast((err as Error).message, 'error');
  }
  renderCurrentView();
  await loadAllPages();
  settleLegacyState();
  if (isFullyLoaded()) void healVault();
}

let quarantined: FileRecord[] = [];
let loadFailed = false;
let strictMode = false;
let legacyFreeMarker: { confirmed: string; legacyFree: string } | null = null;
let legacyNoticeShown = false;

function settleLegacyState(): void {
  if (loadFailed || !legacyFreeMarker) return;
  const legacyCount = legacyRecords().length;
  if (!strictMode && legacyCount === 0 && quarantined.length === 0 && staleRecords.size === 0) {
    markVaultLegacyFree(legacyFreeMarker);
    strictMode = true;
  }
  if (legacyNoticeShown) return;
  if (quarantined.length) {
    legacyNoticeShown = true;
    showToast(`${quarantined.length} outdated item${quarantined.length === 1 ? ' was' : 's were'} hidden because this vault has already been upgraded. Review in Settings \u2192 Upgrade Vault.`, 'error');
  } else if (legacyCount) {
    legacyNoticeShown = true;
    showToast(`${legacyCount} item${legacyCount === 1 ? ' uses' : 's use'} an older, weaker format. Upgrade in Settings \u2192 Upgrade Vault.`);
  }
}

export function recheckLegacyState(): void {
  settleLegacyState();
}

export function isStrictMode(): boolean {
  return strictMode;
}

export function isFullyLoaded(): boolean {
  return !hasMorePages && !loadFailed && !isLoadingPage;
}

export function legacyRecords(): FileRecord[] {
  return records.filter((r) => fileKeyCache.get(r.id)?.format === C.FILE_FORMAT_LEGACY);
}

export function getQuarantined(): FileRecord[] {
  return quarantined.slice();
}

export function getRecordsForRotation(): FileRecord[] {
  const hidden = [...staleRecords.values()].filter((s) => s.hidden);
  for (const s of hidden) {
    if (s.key && !fileKeyCache.has(s.record.id)) fileKeyCache.set(s.record.id, s.key);
  }
  return uniqueById(records.concat(quarantined, hidden.map((s) => s.record)));
}

export async function admitQuarantined(): Promise<void> {
  const admitted: FileRecord[] = [];
  for (const record of quarantined) {
    const fileKey = fileKeyCache.get(record.id);
    if (!fileKey) continue;
    try {
      metaCache.set(record.id, await C.decryptMetadata(fileKey, record.encrypted_metadata, record.metadata_iv));
    } catch {
      metaCache.set(record.id, { name: 'Unreadable item', mime: 'application/octet-stream' });
    }
    admitted.push(record);
  }
  quarantined = quarantined.filter((r) => !admitted.includes(r));
  records = records.concat(admitted);
  renderCurrentView();
}

export async function ensureFullyLoaded(): Promise<boolean> {
  while (isLoadingPage) await new Promise((r) => setTimeout(r, 50));
  if (loadFailed) await refreshGallery();
  else if (hasMorePages) await loadAllPages();
  return !hasMorePages && !loadFailed;
}

export async function relocateRecord(id: string, newParentId: string | null): Promise<string> {
  const newId = await moveOneRecord(id, newParentId);
  const legacyChildren = records.filter((r) => fileKeyCache.get(r.id)?.format === C.FILE_FORMAT_LEGACY && parentIdOf(r.id) === id);
  for (const child of legacyChildren) await relocateRecord(child.id, newId);
  return newId;
}

export async function deleteRecord(id: string): Promise<void> {
  await api.deleteFile(id);
  removeRecordLocally(id);
}

export function rerender(): void {
  renderCurrentView();
}

export async function addUploadedRecord(record: FileRecord): Promise<void> {
  if (!fileKeyCache.has(record.id)) {
    try {
      const fileKey = await C.unwrapFileKey(getWrappingKeyRaw()!, record.wrapped_file_key, record.wrap_iv);
      await rememberFileKey(record.id, fileKey);
      const meta = await C.decryptMetadata(fileKey, record.encrypted_metadata, record.metadata_iv);
      metaCache.set(record.id, meta);
    } catch {
      metaCache.set(record.id, { name: 'Unreadable item', mime: 'application/octet-stream' });
    }
  }

  scheduleUsageRefresh();
  if (records.some((r) => r.id === record.id)) return;
  records.push(record);
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

function isVisibleInCurrentView(record: FileRecord): boolean {
  if (parentIdOf(record.id) !== currentFolderId) return false;
  if (searchQuery) {
    const name = (metaCache.get(record.id)?.name || '').toLowerCase();
    if (!name.includes(searchQuery.toLowerCase())) return false;
  }
  return true;
}

function appendVisibleRecords(toAppend: FileRecord[]): void {
  refreshDisplayNames();
  const shown = visibleRecords();
  updateEmptyState(shown, !!searchQuery);
  updateGridLabel(shown, !!searchQuery);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  const fragment = document.createDocumentFragment();
  for (const record of toAppend) fragment.appendChild(render(record));
  target.appendChild(fragment);
}

function appendRecordIfVisible(record: FileRecord): void {
  if (!isVisibleInCurrentView(record)) return;
  appendVisibleRecords([record]);
}

function updateUsagePill(usage: UsageResponse): void {
  usagePill.textContent = usage.quota_bytes != null
    ? `${formatBytes(usage.total_bytes)} / ${formatBytes(usage.quota_bytes)} \u00b7 ${usage.file_count} item${usage.file_count === 1 ? '' : 's'}`
    : `${usage.file_count} item${usage.file_count === 1 ? '' : 's'} \u00b7 ${formatBytes(usage.total_bytes)}`;
}

async function loadAllPages(): Promise<void> {
  while (hasMorePages) {
    if (isLoadingPage) { await new Promise((r) => setTimeout(r, 20)); continue; }
    await loadNextPage();
  }
}

async function loadNextPage(): Promise<void> {
  if (isLoadingPage || !hasMorePages) return;
  isLoadingPage = true;
  const generation = loadGeneration;
  gridSentinel.classList.remove('hidden');
  gridSentinel.textContent = 'Loading\u2026';
  try {
    const page = await api.listFiles({ offset: pageOffset, limit: PAGE_SIZE });
    if (generation !== loadGeneration) return;
    const known = new Set(records.map((r) => r.id).concat(quarantined.map((r) => r.id)));
    const listed = uniqueById(page.filter((r) => !known.has(r.id)));

    const pageKey = page.map((r) => r.id).join(',');
    if (page.length < PAGE_SIZE || (listed.length === 0 && pageKey === lastPageKey)) hasMorePages = false;
    lastPageKey = pageKey;
    pageOffset += page.length || PAGE_SIZE;

    const refused = new Set<string>();
    await Promise.all(listed.map(async (record) => {
      let fileKey = fileKeyCache.get(record.id);
      try {
        if (!fileKey) {
          fileKey = await C.unwrapFileKey(getWrappingKeyRaw()!, record.wrapped_file_key, record.wrap_iv);
          await rememberFileKey(record.id, fileKey);
        }
        if (strictMode && fileKey.format === C.FILE_FORMAT_LEGACY) {
          metaCache.delete(record.id);
          refused.add(record.id);
          return;
        }
        if (!metaCache.has(record.id)) {
          metaCache.set(record.id, await C.decryptMetadata(fileKey, record.encrypted_metadata, record.metadata_iv));
        }
      } catch {
        metaCache.set(record.id, { name: 'Unreadable item', mime: 'application/octet-stream' });
      }
    }));
    if (generation !== loadGeneration) return;
    const knownNow = new Set(records.map((r) => r.id).concat(quarantined.map((r) => r.id)));
    quarantined = quarantined.concat(listed.filter((r) => refused.has(r.id) && !knownNow.has(r.id)));
    const fresh = listed.filter((r) => !refused.has(r.id) && !knownNow.has(r.id));

    const isFirstPage = records.length === 0;
    records = records.concat(fresh);
    const hidIdentical = hideIdenticalAmong(fresh);
    const freshVisible = fresh.filter((r) => isVisibleInCurrentView(r));
    if (isFirstPage || hidIdentical || freshVisible.some((r) => metaCache.get(r.id)?.isFolder)) {
      renderCurrentView();
    } else if (freshVisible.length) {
      appendVisibleRecords(freshVisible);
    }
  } catch (err) {
    if (generation !== loadGeneration) return;
    showToast((err as Error).message, 'error');
    hasMorePages = false;
    loadFailed = true;
  } finally {
    isLoadingPage = false;
    gridSentinel.classList.toggle('hidden', !hasMorePages);
  }
}

export function visibleRecords(): FileRecord[] {
  const inFolder = uniqueById(records).filter((r) => parentIdOf(r.id) === currentFolderId);
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

let displayNames = new Map<string, string>();

function refreshDisplayNames(): void {
  const inFolder = uniqueById(records).filter((r) => parentIdOf(r.id) === currentFolderId);
  displayNames = shownNames(inFolder.map((r) => ({ id: r.id, name: metaCache.get(r.id)?.name || '\u2026' })));
}

function displayName(record: FileRecord, meta: FileMeta): string {
  return displayNames.get(record.id) ?? meta.name;
}

function renderCurrentView(): void {
  unmountAllThumbs();
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  refreshDisplayNames();
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

const thumbTiles = new WeakMap<Element, FileRecord>();
const thumbObserver = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    const tile = entry.target as HTMLElement;
    const record = thumbTiles.get(tile);
    if (!record) continue;
    if (entry.isIntersecting) mountThumb(tile, record);
    else unmountThumb(tile, record.id);
  }
}, { rootMargin: '600px 0px' });

function mountThumb(tile: HTMLElement, record: FileRecord): void {
  if (tile.dataset.thumb) return;
  const meta = metaCache.get(record.id);
  if (!meta) return;
  tile.dataset.thumb = 'pending';
  const wanted = () => tile.isConnected && tile.dataset.thumb === 'pending';
  acquireThumbnail(record, meta, wanted).then((url) => {
    if (!url) { if (wanted()) delete tile.dataset.thumb; return; }
    if (!wanted()) { releaseThumbnail(record.id); return; }
    const img = document.createElement('img');
    img.decoding = 'async';
    img.alt = meta.name;
    img.src = url;
    tile.querySelector('.box-body')!.prepend(img);
    tile.dataset.thumb = 'on';
  });
}

function unmountThumb(tile: HTMLElement, id: string): void {
  const state = tile.dataset.thumb;
  delete tile.dataset.thumb;
  if (state !== 'on') return;
  const img = tile.querySelector('.box-body > img') as HTMLImageElement | null;
  if (img) { img.removeAttribute('src'); img.remove(); }
  releaseThumbnail(id);
}

function unmountAllThumbs(): void {
  boxGrid.querySelectorAll<HTMLElement>('.box-tile[data-thumb]').forEach((tile) => {
    const record = thumbTiles.get(tile);
    if (record) unmountThumb(tile, record.id);
  });
  thumbObserver.disconnect();
}

function renderTile(record: FileRecord): HTMLDivElement {
  const meta: FileMeta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const name = displayName(record, meta);
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
  tile.setAttribute('aria-label', isFolder ? `Open folder ${name}` : `Open ${name}`);

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
  tile.querySelector('.box-name')!.textContent = name;
  tile.querySelector('.delete-btn')?.setAttribute('aria-label', `Delete ${name}`);
  tile.querySelector('.share-btn')?.setAttribute('aria-label', `Share ${name}`);

  const selectCheckbox = tile.querySelector('.box-select-checkbox') as HTMLInputElement;
  selectCheckbox.checked = selectedIds.has(record.id);
  selectCheckbox.setAttribute('aria-label', `Select ${name}`);
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
  tile.addEventListener('contextmenu', (e) => openItemContextMenu(e, record, tile));
  tile.querySelector('.delete-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
  });
  tile.querySelector('.share-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    shareFile(record);
  });

  if (!isFolder && kind === 'image') {
    thumbTiles.set(tile, record);
    thumbObserver.observe(tile);
  }

  return tile;
}

function renderListRow(record: FileRecord): HTMLDivElement {
  const meta: FileMeta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const name = displayName(record, meta);
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
  row.setAttribute('aria-label', isFolder ? `Open folder ${name}` : `Open ${name}`);

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
  row.querySelector('.file-row-text')!.textContent = name;
  row.querySelector('.file-row-type')!.textContent = fileTypeLabel(meta);
  row.querySelector('.file-share-btn')?.setAttribute('aria-label', `Share ${name}`);
  row.querySelector('.file-download-btn')?.setAttribute('aria-label', `Download ${name}`);
  row.querySelector('.file-delete-btn')!.setAttribute('aria-label', `Delete ${name}`);

  const rowCheckbox = row.querySelector('.file-row-checkbox') as HTMLInputElement;
  rowCheckbox.checked = selectedIds.has(record.id);
  rowCheckbox.setAttribute('aria-label', `Select ${name}`);
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
  row.addEventListener('contextmenu', (e) => openItemContextMenu(e, record, row));
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

let contextMenuEl: HTMLDivElement | null = null;

function closeContextMenu(): void {
  if (!contextMenuEl) return;
  contextMenuEl.remove();
  contextMenuEl = null;
  document.removeEventListener('pointerdown', onContextMenuOutside, true);
  document.removeEventListener('keydown', onContextMenuKey, true);
  window.removeEventListener('resize', closeContextMenu);
  window.removeEventListener('blur', closeContextMenu);
  window.removeEventListener('scroll', closeContextMenu, true);
}

function onContextMenuOutside(e: Event): void {
  if (contextMenuEl && !contextMenuEl.contains(e.target as Node)) closeContextMenu();
}

function onContextMenuKey(e: KeyboardEvent): void {
  if (!contextMenuEl) return;
  if (e.key === 'Escape') { e.preventDefault(); closeContextMenu(); return; }
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Home' && e.key !== 'End') return;
  e.preventDefault();
  const items = [...contextMenuEl.querySelectorAll<HTMLButtonElement>('button[role="menuitem"]')];
  if (!items.length) return;
  const i = items.indexOf(document.activeElement as HTMLButtonElement);
  let next = 0;
  if (e.key === 'ArrowDown') next = (i + 1) % items.length;
  else if (e.key === 'ArrowUp') next = (i - 1 + items.length) % items.length;
  else if (e.key === 'End') next = items.length - 1;
  items[next]?.focus();
}

function openItemContextMenu(e: MouseEvent, record: FileRecord, anchor: HTMLElement): void {
  e.preventDefault();
  e.stopPropagation();
  closeContextMenu();

  const targetIds = selectedIds.has(record.id) && selectedIds.size > 0 ? [...selectedIds] : [record.id];
  const single = targetIds.length === 1;
  const singleId = single ? targetIds[0] : undefined;
  const singleMeta = singleId !== undefined ? metaCache.get(singleId) : undefined;
  const singleRecord = singleId !== undefined ? records.find((r) => r.id === singleId) : undefined;
  const isFolder = !!singleMeta?.isFolder;
  const noun = single ? '' : ` ${targetIds.length} items`;

  type Entry = { label: string; icon: string; run: () => void; danger?: boolean } | 'sep';
  const entries: Entry[] = [];
  if (single && singleRecord) {
    entries.push({
      label: isFolder ? 'Open folder' : 'Open',
      icon: isFolder ? 'folder' : 'file',
      run: () => (isFolder ? navigateToFolder(singleRecord.id) : openTile(singleRecord.id)),
    });
    if (!isFolder) entries.push({ label: 'Share…', icon: 'share', run: () => shareFile(singleRecord) });
    entries.push('sep');
  }
  entries.push({ label: `Download${noun}`, icon: 'download', run: () => void downloadIds(targetIds) });
  entries.push({ label: `Move${noun}…`, icon: 'folder', run: () => void moveIds(targetIds) });
  entries.push('sep');
  entries.push({ label: `Delete${noun}`, icon: 'trash', danger: true, run: () => void deleteIds(targetIds) });

  const menu = document.createElement('div');
  menu.className = 'context-menu';
  menu.setAttribute('role', 'menu');
  for (const entry of entries) {
    if (entry === 'sep') {
      const sep = document.createElement('div');
      sep.className = 'context-menu-sep';
      sep.setAttribute('role', 'separator');
      menu.appendChild(sep);
      continue;
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute('role', 'menuitem');
    btn.className = 'context-menu-item' + (entry.danger ? ' danger' : '');
    btn.innerHTML = icon(entry.icon);
    const label = document.createElement('span');
    label.textContent = entry.label;
    btn.appendChild(label);
    btn.addEventListener('click', () => { closeContextMenu(); entry.run(); });
    menu.appendChild(btn);
  }
  document.body.appendChild(menu);
  contextMenuEl = menu;

  let x = e.clientX;
  let y = e.clientY;
  if (x === 0 && y === 0) {
    const r = anchor.getBoundingClientRect();
    x = r.left + 16;
    y = r.top + 16;
  }
  const { width, height } = menu.getBoundingClientRect();
  const margin = 8;
  menu.style.left = `${Math.max(margin, Math.min(x, window.innerWidth - width - margin))}px`;
  menu.style.top = `${Math.max(margin, Math.min(y, window.innerHeight - height - margin))}px`;

  document.addEventListener('pointerdown', onContextMenuOutside, true);
  document.addEventListener('keydown', onContextMenuKey, true);
  window.addEventListener('resize', closeContextMenu);
  window.addEventListener('blur', closeContextMenu);
  window.addEventListener('scroll', closeContextMenu, true);
  if (e.detail === 0 || (e.clientX === 0 && e.clientY === 0)) menu.querySelector<HTMLButtonElement>('button')?.focus();
}

export async function getDecryptedBytes(record: FileRecord, signal?: AbortSignal): Promise<Uint8Array> {
  const fileKey = fileKeyCache.get(record.id)!;
  const ciphertext = await api.downloadContent(record.id, undefined, signal);
  signal?.throwIfAborted();
  const meta = metaCache.get(record.id)!;
  return C.decryptContent(fileKey, record.content_iv, ciphertext, meta);
}

export async function getDecryptedBlob(record: FileRecord, signal?: AbortSignal): Promise<Blob> {
  const fileKey = fileKeyCache.get(record.id)!;
  const meta = metaCache.get(record.id)!;
  const { stream } = await api.openDownloadStream(record.id, undefined, signal);
  return C.streamToBlob(C.decryptToStream(fileKey, record.content_iv, stream, meta), meta.mime);
}

export async function getDecryptedUrl(record: FileRecord, signal?: AbortSignal): Promise<string> {
  const cached = objectUrlCache.get(record.id);
  if (cached) return cached;
  const blob = await getDecryptedBlob(record, signal);
  signal?.throwIfAborted();
  const existing = objectUrlCache.get(record.id);
  if (existing) return existing;
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
  if (nameTakenIn(currentFolderId, trimmed)) {
    showToast(`"${trimmed}" already exists here. Choose another name.`, 'error');
    return;
  }
  try {
    const payload = await C.encryptFolder(wrappingKeyRaw, trimmed, parentRefFor(currentFolderId));
    const created = await api.uploadFile(payload);
    await addUploadedRecord(created);
    await settleUploads([{ fields: payload, keepId: created.id }]);
    renderCurrentView();
    showToast('Folder created.');
  } catch (err) {
    showToast("Couldn't create folder. " + (err as Error).message, 'error');
  }
}

interface StaleEntry {
  record: FileRecord;
  meta: FileMeta | undefined;
  key: FileKey | undefined;
  successor: string;
  kind: HealKind;
  hidden: boolean;
}

const staleRecords = new Map<string, StaleEntry>();
const healKeep = new Set<string>();
const contentHashes = new Map<string, string>();
let hashBytesUsed = 0;
const HEAL_HASH_BUDGET = 256 * 1024 * 1024;
let healRunning = false;
const fingerprintOwner = new Map<string, string>();

function hideStale(id: string, successor: string, kind: HealKind, hidden: boolean): void {
  if (staleRecords.has(id) || healKeep.has(id)) return;
  const record = records.find((r) => r.id === id);
  if (!record) return;
  staleRecords.set(id, { record, meta: metaCache.get(id), key: fileKeyCache.get(id), successor, kind, hidden });
  if (!hidden) return;
  if (objectUrlCache.has(id)) { URL.revokeObjectURL(objectUrlCache.get(id)!); objectUrlCache.delete(id); }
  dropThumbnail(id);
  forgetFileKey(id);
  metaCache.delete(id);
  records = records.filter((r) => r.id !== id);
}

function hideIdenticalAmong(fresh: FileRecord[]): boolean {
  let changed = false;
  for (const r of fresh) {
    const fp = recordFingerprint(r);
    const owner = fingerprintOwner.get(fp);
    if (owner === undefined) { fingerprintOwner.set(fp, r.id); continue; }
    if (owner === r.id) continue;
    const [keep, drop] = owner < r.id ? [owner, r.id] : [r.id, owner];
    fingerprintOwner.set(fp, keep);
    if (!healKeep.has(drop)) { hideStale(drop, keep, 'identical', true); changed = true; }
  }
  return changed;
}

function planHeal(): void {
  const legacyParents = new Set<string>();
  for (const r of records) {
    const parentId = metaCache.get(r.id)?.parentId;
    if (fileKeyCache.get(r.id)?.format !== C.FILE_FORMAT_V2 && typeof parentId === 'string') legacyParents.add(parentId);
  }
  const items: HealItem[] = records.filter((r) => !healKeep.has(r.id)).map((r) => {
    const meta = metaCache.get(r.id);
    const v2 = fileKeyCache.get(r.id)?.format === C.FILE_FORMAT_V2;
    const isFolder = !!meta?.isFolder;
    return {
      id: r.id,
      nodeRef: nodeRefOf(r.id),
      from: v2 && typeof meta?.from === 'string' ? meta.from : null,
      rev: typeof meta?.rev === 'number' ? meta.rev : null,
      isFolder,
      folderMovable: isFolder && v2 && !legacyParents.has(r.id),
      fingerprint: recordFingerprint(r),
    };
  });
  for (const d of healPlan(items)) hideStale(d.id, d.successor, d.kind, d.kind === 'identical');
}

function keepAfterAll(id: string): void {
  const s = staleRecords.get(id);
  staleRecords.delete(id);
  healKeep.add(id);
  if (!s?.hidden) return;
  if (s.meta) metaCache.set(id, s.meta);
  if (s.key) void rememberFileKey(id, s.key);
  if (!records.some((r) => r.id === id)) records.push(s.record);
  renderCurrentView();
}

function isRetryable(err: unknown): boolean {
  if (err instanceof TypeError) return true;
  const status = (err as { status?: number } | null)?.status;
  if (typeof status === 'number') return status >= 500 || status === 429 || status === 408;
  return /network|stalled|timed? ?out|Failed to fetch/i.test(String((err as Error)?.message ?? err));
}

async function verifyReadable(record: FileRecord): Promise<void> {
  const key = fileKeyCache.get(record.id);
  const meta = metaCache.get(record.id);
  if (!key || !meta) throw new Error('not readable');
  const { stream } = await api.openDownloadStream(record.id);
  const reader = C.decryptToStream(key, record.content_iv, stream, meta).getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
  }
  if (total !== (meta.isFolder ? 0 : meta.size)) throw new Error('did not read back completely');
}

async function contentHashOf(record: FileRecord): Promise<string> {
  const known = contentHashes.get(record.id);
  if (known) return known;
  const key = fileKeyCache.get(record.id);
  const meta = metaCache.get(record.id);
  if (!key || !meta) throw new Error('not readable');
  const { stream } = await api.openDownloadStream(record.id);
  const h = await C.sha256OfStream(C.decryptToStream(key, record.content_iv, stream, meta));
  contentHashes.set(record.id, h);
  return h;
}

async function removeIdenticalSameNameCopies(generation: number): Promise<void> {
  const groups = new Map<string, FileRecord[]>();
  for (const r of records) {
    const meta = metaCache.get(r.id);
    if (!meta || meta.isFolder || !fileKeyCache.has(r.id)) continue;
    const k = `${parentIdOf(r.id) ?? ''}\u0000${meta.name}\u0000${decryptedSize(r, meta)}`;
    groups.set(k, [...(groups.get(k) ?? []), r]);
  }
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    group.sort((a, b) => (a.id < b.id ? -1 : 1));
    const firstOf = new Map<string, string>();
    for (const r of group) {
      if (generation !== loadGeneration || !getWrappingKeyRaw()) return;
      const size = decryptedSize(r, metaCache.get(r.id));
      if (!contentHashes.has(r.id)) {
        if (hashBytesUsed + size > HEAL_HASH_BUDGET) continue;
        hashBytesUsed += size;
      }
      let h: string;
      try { h = await contentHashOf(r); } catch { continue; }
      if (!firstOf.has(h)) { firstOf.set(h, r.id); continue; }
      try {
        await api.deleteFileWithRetry(r.id);
        removeRecordLocally(r.id);
      } catch {
      }
    }
  }
}

async function healVault(): Promise<void> {
  if (healRunning) return;
  healRunning = true;
  const generation = loadGeneration;
  try {
    planHeal();
    renderCurrentView();
    const verified = new Set<string>();
    for (const [id, s] of [...staleRecords]) {
      if (generation !== loadGeneration || !getWrappingKeyRaw()) return;
      if (!verified.has(s.successor)) {
        const succ = records.find((r) => r.id === s.successor);
        if (!succ) { keepAfterAll(id); continue; }
        try {
          await verifyReadable(succ);
          verified.add(s.successor);
        } catch (err) {
          if (!isRetryable(err)) keepAfterAll(id);
          continue;
        }
      }
      try {
        await api.deleteFileWithRetry(id);
      } catch {
        continue;
      }
      staleRecords.delete(id);
      if (!s.hidden) removeRecordLocally(id);
    }
    await removeIdenticalSameNameCopies(generation);
  } finally {
    healRunning = false;
  }
}

export async function healIdle(): Promise<void> {
  while (healRunning) await new Promise((r) => setTimeout(r, 50));
}

export function pendingCleanupCount(): number {
  return staleRecords.size;
}

export async function settleUploads(uploads: { fields: UploadFields; keepId: string }[]): Promise<void> {
  try {
    for (const id of await api.removeRepeatedUploads(uploads)) removeRecordLocally(id);
  } catch {
  }
}

export function removeRecordLocally(fileId: string): void {
  if (objectUrlCache.has(fileId)) { URL.revokeObjectURL(objectUrlCache.get(fileId)!); objectUrlCache.delete(fileId); }
  dropThumbnail(fileId);
  forgetFileKey(fileId);
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
      dropThumbnail(id);
      forgetFileKey(id);
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