import * as C from './crypto.js';
import * as api from './api.js';
import { depositSlot, chooseFilesBtn, fileInput, uploadQueue } from './dom.js';
import { getWrappingKeyRaw } from './state.js';
import { icon, showToast } from './utils.js';
import { refreshGallery } from './gallery.js';

chooseFilesBtn.addEventListener('click', () => fileInput.click());
depositSlot.addEventListener('click', (e) => { if (e.target === depositSlot || e.target.tagName === 'P' || e.target.tagName === 'H2') fileInput.click(); });
depositSlot.addEventListener('keydown', (e) => { if (e.key === 'Enter') fileInput.click(); });

fileInput.addEventListener('change', () => {
  handleFiles([...fileInput.files]);
  fileInput.value = '';
});

['dragenter', 'dragover'].forEach((evt) =>
  depositSlot.addEventListener(evt, (e) => { e.preventDefault(); depositSlot.classList.add('drag-over'); })
);
['dragleave', 'drop'].forEach((evt) =>
  depositSlot.addEventListener(evt, (e) => { e.preventDefault(); depositSlot.classList.remove('drag-over'); })
);
depositSlot.addEventListener('drop', (e) => {
  const files = [...(e.dataTransfer?.files ?? [])];
  if (files.length) handleFiles(files);
});

const MAX_VISIBLE_UPLOADS = 10;
const MAX_CONCURRENT_UPLOADS = 3;
let uploadRows = [];
let uploadMoreIndicator = null;

function getUploadMoreIndicator() {
  if (!uploadMoreIndicator) {
    uploadMoreIndicator = document.createElement('div');
    uploadMoreIndicator.className = 'upload-more';
  }
  return uploadMoreIndicator;
}

function syncUploadQueueView() {
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

async function handleFiles(files) {
  const queue = files.map((file) => ({ file, rowItem: createUploadRow(file) }));
  const workerCount = Math.min(MAX_CONCURRENT_UPLOADS, queue.length);
  await Promise.all(Array.from({ length: workerCount }, () => runUploadWorker(queue)));
}

async function runUploadWorker(queue) {
  let item;
  while ((item = queue.shift())) {
    await uploadOne(item.file, item.rowItem);
  }
}

function createUploadRow(file) {
  const row = document.createElement('div');
  row.className = 'upload-row';
  row.innerHTML = `
    <span class="name"></span>
    <span class="status">Queued\u2026</span>
    <button type="button" class="btn-icon upload-cancel hidden" aria-label="Cancel upload" title="Cancel upload">${icon('close')}</button>
    <div class="bar"><div class="bar-fill"></div></div>
  `;
  row.querySelector('.name').textContent = file.name;
  const rowItem = { el: row };
  uploadRows.push(rowItem);
  syncUploadQueueView();
  return rowItem;
}

function setBarProgress(barEl, fraction, { instant = false } = {}) {
  const pct = `${Math.max(0, Math.min(100, Math.round(fraction * 100)))}%`;
  barEl.getAnimations().forEach((a) => a.cancel());
  barEl.animate([{ width: pct }], { duration: instant ? 1 : 200, fill: 'forwards', easing: 'ease' });
}

const RETRY_BASE_MS = 1000;
const RETRY_MAX_MS = 30000;

function retryDelay(attempt) {
  return Math.min(RETRY_BASE_MS * 2 ** (attempt - 1), RETRY_MAX_MS);
}

async function waitWithCountdown(ms, statusEl, isCancelled, reason) {
  const end = Date.now() + ms;
  statusEl.title = reason || '';
  while (Date.now() < end) {
    if (isCancelled()) return;
    const secsLeft = Math.max(1, Math.ceil((end - Date.now()) / 1000));
    statusEl.textContent = `Retry in ${secsLeft}s\u2026`;
    await new Promise((r) => setTimeout(r, 250));
  }
}

async function uploadOne(file, rowItem) {
  const row = rowItem.el;
  const statusEl = row.querySelector('.status');
  const barEl = row.querySelector('.bar-fill');
  const cancelBtn = row.querySelector('.upload-cancel');

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
    encrypted = await C.encryptFile(getWrappingKeyRaw(), file);
  } catch (err) {
    row.classList.add('error');
    statusEl.textContent = 'Failed';
    cancelBtn.classList.add('hidden');
    showToast(`Couldn't encrypt "${file.name}". ${err.message}`, 'error');
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
      if (cancelled || err.name === 'AbortError') { finishCancelled(); return; }

      attempt++;
      row.classList.add('error');
      if (attempt === 1) {
        showToast(`Upload of "${file.name}" failed. Retrying automatically\u2026`, 'error');
      }
      await waitWithCountdown(retryDelay(attempt), statusEl, () => cancelled, err.message);
      if (cancelled) { finishCancelled(); return; }
      row.classList.remove('error');
    }
  }
}
