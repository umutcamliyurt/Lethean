import './theme.js';
import { getShareRecord, downloadShareContent, deleteSharedFile } from './api.js';
import { fromBase64, decryptMetadata, decryptContent } from './crypto-encrypt-core.js';
import type { FileMeta, ShareRecord } from './types.js';

function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

const statusEl = $('share-status');
const bodyEl = $('share-body');
const filenameEl = $('share-filename');
const filesizeEl = $('share-filesize');
const usageHintEl = $('share-usage-hint');
const deleteBtn = $<HTMLButtonElement>('share-delete-btn');
const downloadBtn = $<HTMLButtonElement>('share-download-btn');
const toastsEl = document.getElementById('toasts');

function showToast(message: string, type: 'info' | 'error' = 'info'): void {
  if (!toastsEl) return;
  const el = document.createElement('div');
  el.className = `toast${type === 'error' ? ' error' : ''}`;
  el.textContent = message;
  toastsEl.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

function showFailure(message: string): void {
  statusEl.textContent = message;
  statusEl.classList.add('error');
  bodyEl.classList.add('hidden');
}

function updateUsageHint(record: ShareRecord): void {
  const remaining = record.max_downloads - record.downloads_used;
  if (record.max_downloads === 1) {
    usageHintEl.textContent = remaining > 0
      ? 'This link works once. After downloading, it stops working.'
      : 'This link has now been used and will not work again.';
    return;
  }
  usageHintEl.textContent = remaining > 0
    ? `This link can still be downloaded ${remaining} more time${remaining === 1 ? '' : 's'} (of ${record.max_downloads} total). After that, it stops working.`
    : 'This link has now been fully used and will not work again.';
}

function parseFragment(): { token: string | null; keyB64: string | null } {
  const raw = window.location.hash.replace(/^#/, '');
  const params = new URLSearchParams(raw);
  return { token: params.get('t'), keyB64: params.get('k') };
}

async function init(): Promise<void> {
  const { token, keyB64 } = parseFragment();
  if (!token || !keyB64) {
    showFailure("This link is missing information it needs and can't be used.");
    return;
  }

  let fileKeyRaw: Uint8Array;
  try {
    fileKeyRaw = fromBase64(keyB64);
  } catch {
    showFailure('This link is malformed.');
    return;
  }

  let record: ShareRecord;
  let meta: FileMeta;
  try {
    record = await getShareRecord(token);
    meta = await decryptMetadata(fileKeyRaw, record.encrypted_metadata, record.metadata_iv);
  } catch {
    showFailure('This link is invalid, has expired, or has nothing left to offer.');
    return;
  }

  statusEl.classList.add('hidden');
  bodyEl.classList.remove('hidden');
  filenameEl.textContent = meta.name;
  const sizeLabel = typeof meta.unpaddedSize === 'number' ? formatBytes(meta.unpaddedSize) : '';

  const downloadsRemaining = () => record.max_downloads - record.downloads_used;

  const refreshSizeLabel = () => {
    const remaining = downloadsRemaining();
    const remainingLabel = record.max_downloads === 1
      ? ''
      : ` \u00b7 ${remaining} of ${record.max_downloads} download${record.max_downloads === 1 ? '' : 's'} left`;
    filesizeEl.textContent = sizeLabel + remainingLabel;
  };
  refreshSizeLabel();
  updateUsageHint(record);

  if (downloadsRemaining() <= 0) {
    downloadBtn.disabled = true;
    downloadBtn.textContent = 'No downloads left';
  }

  deleteBtn.classList.remove('hidden');

  downloadBtn.addEventListener('click', async () => {
    downloadBtn.disabled = true;
    downloadBtn.textContent = 'Downloading\u2026';
    try {
      const ciphertext = await downloadShareContent(token);
      const bytes = await decryptContent(fileKeyRaw, record.content_iv, ciphertext, meta.compressed, meta.unpaddedSize ?? null);
      const blob = new Blob([bytes as BlobPart], { type: meta.mime || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = meta.name;
      a.click();
      URL.revokeObjectURL(url);

      record.downloads_used += 1;
      const stillHasDownloadsLeft = downloadsRemaining() > 0;
      downloadBtn.textContent = stillHasDownloadsLeft ? 'Download again' : 'Downloaded';
      downloadBtn.disabled = !stillHasDownloadsLeft;
      refreshSizeLabel();
      updateUsageHint(record);
    } catch (err) {
      downloadBtn.disabled = downloadsRemaining() <= 0;
      downloadBtn.textContent = downloadsRemaining() <= 0 ? 'No downloads left' : 'Download';
      showToast("Download failed. " + (err as Error).message, 'error');
    }
  });

  deleteBtn.addEventListener('click', async () => {
    const confirmed = window.confirm(
      `Permanently delete "${meta.name}"? This removes the file entirely, for everyone \u2014 not just this link \u2014 and can't be undone.`
    );
    if (!confirmed) return;

    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting\u2026';
    try {
      await deleteSharedFile(token);
      deleteBtn.textContent = 'Deleted';
      downloadBtn.disabled = true;
      downloadBtn.textContent = 'File deleted';
      usageHintEl.textContent = 'This file has been permanently deleted and can no longer be downloaded.';
    } catch (err) {
      deleteBtn.disabled = false;
      deleteBtn.textContent = 'Delete this file';
      showToast("Couldn't delete this file. " + (err as Error).message, 'error');
    }
  });
}

init();