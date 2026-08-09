import * as C from './crypto.js';
import * as api from './api.js';
import { depositSlot, chooseFilesBtn, newFolderBtn, fileInput, uploadQueue } from './dom.js';
import { getWrappingKeyRaw } from './state.js';
import { icon, showToast } from './utils.js';
import { refreshGallery, getCurrentFolderId, createFolder } from './gallery.js';

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
const MAX_CONCURRENT_UPLOADS = 3;

interface UploadRowItem {
  el: HTMLDivElement;
}

interface QueueItem {
  file: File;
  rowItem: UploadRowItem;
}

let uploadRows: UploadRowItem[] = [];
let uploadMoreIndicator: HTMLDivElement | null = null;

function getUploadMoreIndicator(): HTMLDivElement {
  if (!uploadMoreIndicator) {
    uploadMoreIndicator = document.createElement('div');
    uploadMoreIndicator.className = 'upload-more';
  }
  return uploadMoreIndicator;
}

function syncUploadQueueView(): void {
  const visible = uploadRows.slice(0, MAX_VISIBLE_UPLOADS);
  const hiddenCount = uploadRows.length - visible.length;
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

async function handleFiles(files: File[]): Promise<void> {
  const queue: QueueItem[] = files.map((file) => ({ file, rowItem: createUploadRow(file) }));
  const workerCount = Math.min(MAX_CONCURRENT_UPLOADS, queue.length);
  await Promise.all(Array.from({ length: workerCount }, () => runUploadWorker(queue)));
}

async function runUploadWorker(queue: QueueItem[]): Promise<void> {
  let item: QueueItem | undefined;
  while ((item = queue.shift())) {
    await uploadOne(item.file, item.rowItem);
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

async function uploadOne(file: File, rowItem: UploadRowItem): Promise<void> {
  const row = rowItem.el;
  const statusEl = row.querySelector('.status') as HTMLElement;
  const barEl = row.querySelector('.bar-fill') as HTMLElement;
  const cancelBtn = row.querySelector('.upload-cancel') as HTMLElement;

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
    row.classList.add('error');
    statusEl.textContent = 'Cancelled';
    statusEl.removeAttribute('title');
    cancelBtn.classList.add('hidden');
    setTimeout(removeRow, 1800);
  };

  statusEl.textContent = 'Encrypting\u2026';
  let encrypted;
  try {
    encrypted = await C.encryptFile(getWrappingKeyRaw()!, file, getCurrentFolderId());
  } catch (err) {
    row.classList.add('error');
    statusEl.textContent = 'Failed';
    cancelBtn.classList.add('hidden');
    showToast(`Couldn't encrypt "${file.name}". ${(err as Error).message}`, 'error');
    return;
  }

  if (cancelled) { finishCancelled(); return; }

  let attempt = 0;
  for (;;) {
    try {
      statusEl.textContent = attempt === 0 ? 'Uploading\u2026' : `Retrying\u2026 (attempt ${attempt + 1})`;
      statusEl.removeAttribute('title');
      setBarProgress(barEl, 0, { instant: true });
      await api.uploadFile(encrypted, (fraction) => {
        setBarProgress(barEl, fraction);
      }, controller.signal);

      row.classList.remove('error');
      row.classList.add('done');
      statusEl.textContent = 'Done';
      cancelBtn.classList.add('hidden');
      setTimeout(removeRow, 1800);

      await refreshGallery();
      return;
    } catch (err) {
      const error = err as Error;
      if (cancelled || error.name === 'AbortError') { finishCancelled(); return; }

      attempt++;
      row.classList.add('error');
      if (attempt === 1) {
        showToast(`Upload of "${file.name}" failed. Retrying automatically\u2026`, 'error');
      }
      await waitWithCountdown(retryDelay(attempt), statusEl, () => cancelled, error.message);
      if (cancelled) { finishCancelled(); return; }
      row.classList.remove('error');
    }
  }
}