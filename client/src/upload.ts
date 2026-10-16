import * as api from './api.js';
import { encryptPool } from './encrypt-pool.js';
import { depositSlot, chooseFilesBtn, newFolderBtn, fileInput, uploadQueue } from './dom.js';
import { prepareChunkedFile, paddedSize, CHUNK_SIZE, GCM_TAG_BYTES } from './crypto-encrypt-core.js';
import { getWrappingKeyRaw } from './state.js';
import { icon, showToast } from './utils.js';
import type { ChunkedFilePayload, EncryptedFilePayload } from './types.js';
import { addUploadedRecord, getCurrentFolderId, createFolder, getRecords, removeRecordLocally, settleUploads } from './gallery.js';
import type { UploadFields } from './dedupe-core.js';
import { parentRefFor, effectiveParentId, nodeRefOf } from './tree.js';
import { metaCache } from './state.js';
import { showLightbox, closeLightbox } from './lightbox.js';
import { freeName } from './dedupe-core.js';

chooseFilesBtn.addEventListener('click', () => fileInput.click());
depositSlot.addEventListener('click', (e) => {
  const target = e.target as HTMLElement;
  if (target === depositSlot || target.tagName === 'P' || target.tagName === 'H2') fileInput.click();
});
depositSlot.addEventListener('keydown', (e) => { if (e.key === 'Enter') fileInput.click(); });

newFolderBtn?.addEventListener('click', async () => {
  const name = window.prompt('Folder name:');
  if (name == null || !name.trim()) return;
  await createFolder(name);
});

fileInput.addEventListener('change', () => {
  handleFiles([...fileInput.files ?? []]);
  fileInput.value = '';
});

(['dragenter', 'dragover'] as const).forEach((evt) =>
  depositSlot.addEventListener(evt, (e) => { e.preventDefault(); depositSlot.classList.add('drag-over'); })
);
(['dragleave', 'drop'] as const).forEach((evt) =>
  depositSlot.addEventListener(evt, (e) => { e.preventDefault(); depositSlot.classList.remove('drag-over'); })
);
depositSlot.addEventListener('drop', (e) => {
  const files = [...(e.dataTransfer?.files ?? [])];
  if (files.length) handleFiles(files);
});

const MAX_VISIBLE_UPLOADS = 10;
const MAX_CONCURRENT_UPLOADS = 6;

interface UploadRowItem {
  el: HTMLDivElement;
}

let uploadRows: UploadRowItem[] = [];
let uploadMoreIndicator: HTMLDivElement | null = null;
let pendingRowCount = 0;

function getUploadMoreIndicator(): HTMLDivElement {
  if (!uploadMoreIndicator) {
    uploadMoreIndicator = document.createElement('div');
    uploadMoreIndicator.className = 'upload-more';
  }
  return uploadMoreIndicator;
}

function syncUploadQueueView(): void {
  const visible = uploadRows.slice(0, MAX_VISIBLE_UPLOADS);
  const hiddenStartedCount = uploadRows.length - visible.length;
  const hiddenCount = hiddenStartedCount + pendingRowCount;
  const indicator = getUploadMoreIndicator();

  for (const item of visible) {
    if (!item.el.isConnected) uploadQueue.insertBefore(item.el, indicator.isConnected ? indicator : null);
  }

  if (hiddenCount > 0) {
    indicator.textContent = `\u2026 +${hiddenCount} more`;
    if (!indicator.isConnected) uploadQueue.appendChild(indicator);
  } else if (indicator.isConnected) {
    indicator.remove();
  }
}

interface PlannedUpload {
  file: File;
  folderId: string | null;
  replaceIds: string[];
}

type ConflictChoice = 'skip' | 'keep' | 'replace';

const namesInFlight = new Map<string, Map<string, number>>();

function flightKey(folderId: string | null): string {
  return folderId ?? '';
}

function holdName(folderId: string | null, name: string): void {
  const m = namesInFlight.get(flightKey(folderId)) ?? new Map<string, number>();
  m.set(name, (m.get(name) ?? 0) + 1);
  namesInFlight.set(flightKey(folderId), m);
}

function releaseName(folderId: string | null, name: string): void {
  const m = namesInFlight.get(flightKey(folderId));
  if (!m) return;
  const n = (m.get(name) ?? 1) - 1;
  if (n > 0) m.set(name, n); else m.delete(name);
  if (!m.size) namesInFlight.delete(flightKey(folderId));
}

function existingByName(folderId: string | null): Map<string, { fileIds: string[]; hasFolder: boolean }> {
  const out = new Map<string, { fileIds: string[]; hasFolder: boolean }>();
  for (const r of getRecords()) {
    if (effectiveParentId(r.id) !== folderId) continue;
    const meta = metaCache.get(r.id);
    if (!meta?.name) continue;
    let e = out.get(meta.name);
    if (!e) out.set(meta.name, (e = { fileIds: [], hasFolder: false }));
    if (meta.isFolder) e.hasFolder = true; else e.fileIds.push(r.id);
  }
  return out;
}

function askAboutConflicts(names: string[], canReplace: boolean): Promise<ConflictChoice> {
  return new Promise((resolve) => {
    showLightbox(`
      <div class="settings-panel">
        <h2>Already in this folder</h2>
        <p class="subtitle" id="conflict-text"></p>
        <ul class="conflict-list" id="conflict-list"></ul>
        <div class="panel-actions">
          <button type="button" class="btn-primary" id="conflict-skip">Skip</button>
          <button type="button" id="conflict-keep">Keep both</button>
          ${canReplace ? '<button type="button" id="conflict-replace">Replace</button>' : ''}
        </div>
      </div>
    `);
    const n = names.length;
    document.getElementById('conflict-text')!.textContent = n === 1
      ? 'A file with this name is already here. Skip it, keep both (the new one gets a number), or replace the existing one?'
      : `${n} files have names that are already here. Skip them, keep both (the new ones get a number), or replace the existing ones?`;
    const list = document.getElementById('conflict-list')!;
    for (const name of names.slice(0, 8)) {
      const li = document.createElement('li');
      li.textContent = name;
      list.appendChild(li);
    }
    if (n > 8) {
      const li = document.createElement('li');
      li.textContent = `\u2026 and ${n - 8} more`;
      list.appendChild(li);
    }

    const lightboxEl = document.getElementById('lightbox')!;
    let settled = false;
    const finish = (choice: ConflictChoice) => {
      if (settled) return;
      settled = true;
      watcher.disconnect();
      if (!lightboxEl.classList.contains('hidden')) closeLightbox();
      resolve(choice);
    };
    const watcher = new MutationObserver(() => {
      if (lightboxEl.classList.contains('hidden') || !document.getElementById('conflict-list')) finish('skip');
    });
    watcher.observe(lightboxEl, { attributes: true, attributeFilter: ['class'], childList: true });
    document.getElementById('conflict-skip')!.addEventListener('click', () => finish('skip'));
    document.getElementById('conflict-keep')!.addEventListener('click', () => finish('keep'));
    document.getElementById('conflict-replace')?.addEventListener('click', () => finish('replace'));
    (document.getElementById('conflict-skip') as HTMLButtonElement).focus();
  });
}

async function planUploads(files: File[], folderId: string | null): Promise<PlannedUpload[]> {
  const existing = existingByName(folderId);
  const inFlight = namesInFlight.get(flightKey(folderId)) ?? new Map<string, number>();
  const seenInBatch = new Set<string>();
  const clashes: File[] = [];
  for (const f of files) {
    if (existing.has(f.name) || inFlight.has(f.name) || seenInBatch.has(f.name)) clashes.push(f);
    seenInBatch.add(f.name);
  }
  let choice: ConflictChoice = 'keep';
  if (clashes.length) {
    const canReplace = clashes.some((f) => (existing.get(f.name)?.fileIds.length ?? 0) > 0);
    choice = await askAboutConflicts([...new Set(clashes.map((f) => f.name))], canReplace);
  }

  const taken = new Set<string>([...existing.keys(), ...inFlight.keys()]);
  const replaced = new Set<string>();
  const plan: PlannedUpload[] = [];
  for (const f of files) {
    if (!clashes.includes(f)) {
      taken.add(f.name);
      plan.push({ file: f, folderId, replaceIds: [] });
      continue;
    }
    if (choice === 'skip') continue;
    const prior = existing.get(f.name);
    if (choice === 'replace' && prior && prior.fileIds.length && !prior.hasFolder && !inFlight.has(f.name) && !replaced.has(f.name)) {
      replaced.add(f.name);
      plan.push({ file: f, folderId, replaceIds: prior.fileIds.slice() });
      continue;
    }
    const name = freeName(f.name, taken);
    taken.add(name);
    plan.push({ file: name === f.name ? f : new File([f], name, { type: f.type, lastModified: f.lastModified }), folderId, replaceIds: [] });
  }
  return plan;
}

async function handleFiles(files: File[]): Promise<void> {
  const folderId = getCurrentFolderId();
  const plan = await planUploads(files, folderId);
  if (!plan.length) return;
  for (const p of plan) holdName(p.folderId, p.file.name);
  pendingRowCount += plan.length;
  syncUploadQueueView();

  const queue: PlannedUpload[] = [...plan];
  const finished: { fields: UploadFields; keepId: string }[] = [];
  const workerCount = Math.min(MAX_CONCURRENT_UPLOADS, queue.length);
  await Promise.all(Array.from({ length: workerCount }, () => runUploadWorker(queue, finished)));
  await settleUploads(finished);
}

async function runUploadWorker(queue: PlannedUpload[], finished: { fields: UploadFields; keepId: string }[]): Promise<void> {
  let item: PlannedUpload | undefined;
  while ((item = queue.shift())) {
    pendingRowCount--;
    const rowItem = createUploadRow(item.file);
    try {
      const done = await uploadOne(item, rowItem);
      if (done) finished.push(done);
    } finally {
      releaseName(item.folderId, item.file.name);
    }
  }
}

async function removeReplaced(item: PlannedUpload): Promise<void> {
  for (const id of item.replaceIds) {
    try {
      await api.deleteFileWithRetry(id);
      removeRecordLocally(id);
    } catch (err) {
      showToast(`"${item.file.name}" was uploaded, but the old one couldn't be removed (${(err as Error).message}). Delete it yourself.`, 'error');
    }
  }
}

function createUploadRow(file: File): UploadRowItem {
  const row = document.createElement('div');
  row.className = 'upload-row';
  row.innerHTML = `
    <span class="name"></span>
    <span class="status">Queued\u2026</span>
    <button type="button" class="btn-icon upload-cancel hidden" aria-label="Cancel upload" title="Cancel upload">${icon('close')}</button>
    <div class="bar"><div class="bar-fill"></div></div>
  `;
  row.querySelector('.name')!.textContent = file.name;
  const rowItem: UploadRowItem = { el: row };
  uploadRows.push(rowItem);
  syncUploadQueueView();
  return rowItem;
}

function setBarProgress(barEl: HTMLElement, fraction: number, { instant = false }: { instant?: boolean } = {}): void {
  const pct = `${Math.max(0, Math.min(100, Math.round(fraction * 100)))}%`;
  barEl.style.transition = instant ? 'none' : 'width 200ms ease';
  barEl.style.width = pct;
}

const pendingBarUpdates = new Map<HTMLElement, number>();
let barUpdateScheduled = false;

function scheduleBarProgress(barEl: HTMLElement, fraction: number): void {
  pendingBarUpdates.set(barEl, fraction);
  if (!barUpdateScheduled) {
    barUpdateScheduled = true;
    requestAnimationFrame(flushBarProgress);
  }
}

function flushBarProgress(): void {
  barUpdateScheduled = false;
  for (const [barEl, fraction] of pendingBarUpdates) {
    setBarProgress(barEl, fraction);
  }
  pendingBarUpdates.clear();
}

const RETRY_BASE_MS = 1000;
const RETRY_MAX_MS = 30000;

function retryDelay(attempt: number): number {
  return Math.min(RETRY_BASE_MS * 2 ** (attempt - 1), RETRY_MAX_MS);
}

async function waitWithCountdown(
  ms: number,
  statusEl: HTMLElement,
  isCancelled: () => boolean,
  reason?: string
): Promise<void> {
  const end = Date.now() + ms;
  statusEl.title = reason || '';
  while (Date.now() < end) {
    if (isCancelled()) return;
    const secsLeft = Math.max(1, Math.ceil((end - Date.now()) / 1000));
    statusEl.textContent = `Retry in ${secsLeft}s\u2026`;
    await new Promise((r) => setTimeout(r, 250));
  }
}

const UPLOAD_MEMORY_BUDGET_BYTES = 256 * 1024 * 1024;
let uploadMemoryInUse = 0;
const uploadMemoryWaiters: Array<() => void> = [];

interface MemoryReservation {
  shrinkTo(bytes: number): void;
  release(): void;
}

async function reserveUploadMemory(bytes: number): Promise<MemoryReservation> {
  let held = Math.min(bytes, UPLOAD_MEMORY_BUDGET_BYTES);
  while (uploadMemoryInUse > 0 && uploadMemoryInUse + held > UPLOAD_MEMORY_BUDGET_BYTES) {
    await new Promise<void>((resolve) => uploadMemoryWaiters.push(resolve));
  }
  uploadMemoryInUse += held;
  const wake = () => { for (const w of uploadMemoryWaiters.splice(0)) w(); };
  return {
    shrinkTo(next: number) {
      next = Math.min(next, held);
      uploadMemoryInUse -= held - next;
      held = next;
      wake();
    },
    release() {
      uploadMemoryInUse -= held;
      held = 0;
      wake();
    },
  };
}

function isChunkedUpload(file: File): boolean {
  return file.size > CHUNK_SIZE;
}

function encryptWorkingSet(file: File): number {
  return isChunkedUpload(file) ? 2 * (CHUNK_SIZE + GCM_TAG_BYTES) : 2 * paddedSize(file.size);
}

function uploadWorkingSet(file: File): number {
  return isChunkedUpload(file) ? 2 * (CHUNK_SIZE + GCM_TAG_BYTES) : paddedSize(file.size);
}

async function uploadOne(item: PlannedUpload, rowItem: UploadRowItem): Promise<{ fields: UploadFields; keepId: string } | null> {
  const reservation = await reserveUploadMemory(encryptWorkingSet(item.file));
  try {
    return await uploadOneWithinBudget(item, rowItem, reservation);
  } finally {
    reservation.release();
  }
}

async function uploadOneWithinBudget(item: PlannedUpload, rowItem: UploadRowItem, reservation: MemoryReservation): Promise<{ fields: UploadFields; keepId: string } | null> {
  const file = item.file;
  const row = rowItem.el;
  const statusEl = row.querySelector('.status') as HTMLElement;
  const barEl = row.querySelector('.bar-fill') as HTMLElement;
  const cancelBtn = row.querySelector('.upload-cancel') as HTMLElement;

  let encrypted: EncryptedFilePayload | ChunkedFilePayload | undefined;
  const controller = new AbortController();
  let cancelled = false;
  const cancelUpload = () => { cancelled = true; controller.abort(); };
  cancelBtn.classList.remove('hidden');
  cancelBtn.addEventListener('click', cancelUpload);

  const removeRow = () => {
    uploadRows = uploadRows.filter((r) => r !== rowItem);
    row.remove();
    syncUploadQueueView();
  };

  const finishCancelled = () => {
    if (encrypted && 'uploadId' in encrypted && encrypted.uploadId) void api.abortUpload(encrypted.uploadId);
    row.classList.add('error');
    statusEl.textContent = 'Cancelled';
    statusEl.removeAttribute('title');
    cancelBtn.classList.add('hidden');
    setTimeout(removeRow, 1800);
  };

  statusEl.textContent = 'Encrypting\u2026';
  try {
    const parent = parentRefFor(item.folderId);
    const from = item.replaceIds.length ? nodeRefOf(item.replaceIds[0]!) : null;
    const opts = from ? { from } : undefined;
    encrypted = isChunkedUpload(file)
      ? await prepareChunkedFile(getWrappingKeyRaw()!, file, parent, opts)
      : await encryptPool.encryptFile(getWrappingKeyRaw()!, file, parent, opts);
    reservation.shrinkTo(uploadWorkingSet(file));
  } catch (err) {
    row.classList.add('error');
    statusEl.textContent = 'Failed';
    cancelBtn.classList.add('hidden');
    showToast(`Couldn't encrypt "${file.name}". ${(err as Error).message}`, 'error');
    return null;
  }

  if (cancelled) { finishCancelled(); return null; }

  let attempt = 0;
  for (;;) {
    try {
      statusEl.textContent = attempt === 0 ? 'Uploading\u2026' : `Retrying\u2026 (attempt ${attempt + 1})`;
      statusEl.removeAttribute('title');
      setBarProgress(barEl, 0, { instant: true });
      const created = await api.uploadFile(encrypted!, (fraction) => {
        scheduleBarProgress(barEl, fraction);
      }, controller.signal);

      row.classList.remove('error');
      row.classList.add('done');
      statusEl.textContent = 'Done';
      cancelBtn.classList.add('hidden');
      setTimeout(removeRow, 1800);

      await addUploadedRecord(created);
      await removeReplaced(item);
      return { fields: encrypted!, keepId: created.id };
    } catch (err) {
      const error = err as Error;
      if (cancelled || error.name === 'AbortError') { finishCancelled(); return null; }

      attempt++;
      row.classList.add('error');
      if (attempt === 1) {
        showToast(`Upload of "${file.name}" failed. Retrying automatically\u2026`, 'error');
      }
      await waitWithCountdown(retryDelay(attempt), statusEl, () => cancelled, error.message);
      if (cancelled) { finishCancelled(); return null; }
      row.classList.remove('error');
    }
  }
}