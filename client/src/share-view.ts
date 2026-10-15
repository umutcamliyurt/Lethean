import './theme.js';
import { getShareRecord, shareBlobRequest, deleteSharedFile } from './api.js';
import { fileKeyFromShareParams, decryptMetadata } from './crypto-encrypt-core.js';
import type { FileKey } from './crypto-encrypt-core.js';
import { downloadDecrypted } from './save-stream.js';
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

function formatRelativeExpiry(expiresAt: string): string {
  const diffMs = new Date(expiresAt).getTime() - Date.now();
  if (diffMs <= 0) return 'shortly';

  const minutes = Math.round(diffMs / 60_000);
  if (minutes < 1) return 'in less than a minute';
  if (minutes < 60) return `in ${minutes} minute${minutes === 1 ? '' : 's'}`;

  const hours = Math.round(diffMs / 3_600_000);
  if (hours < 24) return `in ${hours} hour${hours === 1 ? '' : 's'}`;

  const days = Math.round(diffMs / 86_400_000);
  return `in ${days} day${days === 1 ? '' : 's'}`;
}

function updateUsageHint(record: ShareRecord): void {
  const remaining = record.max_downloads - record.downloads_used;
  const expiryNote = record.expires_at
    ? ` It also expires ${formatRelativeExpiry(record.expires_at)}.`
    : '';
  if (record.max_downloads === 1) {
    usageHintEl.textContent = (remaining > 0
      ? 'This link works once. After downloading, it stops working.'
      : 'This link has now been used and will not work again.') + expiryNote;
    return;
  }
  usageHintEl.textContent = (remaining > 0
    ? `This link can still be downloaded ${remaining} more time${remaining === 1 ? '' : 's'} (of ${record.max_downloads} total). After that, it stops working.`
    : 'This link has now been fully used and will not work again.') + expiryNote;
}

function decodeIfStillEncoded(value: string): string {
  if (!/%[0-9A-Fa-f]{2}/.test(value)) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

interface ShareFragment {
  token: string | null;
  keyB64: string | null;
  version: string | null;
  bindingB64: string | null;
  deleteToken: string | null;
}

function parseFragment(): ShareFragment {
  const raw = window.location.hash.replace(/^#/, '');
  const params = new URLSearchParams(raw);
  const get = (name: string): string | null => {
    const value = params.get(name);
    return value !== null ? decodeIfStillEncoded(value) : null;
  };
  return {
    token: get('t'),
    keyB64: get('k'),
    version: get('v'),
    bindingB64: get('b'),
    deleteToken: get('d'),
  };
}

async function init(): Promise<void> {
  const { token, keyB64, version, bindingB64, deleteToken } = parseFragment();
  if (!token || !keyB64) {
    showFailure("This link is missing information it needs and can't be used.");
    return;
  }

  let fileKey: FileKey;
  try {
    fileKey = fileKeyFromShareParams(keyB64, version, bindingB64);
  } catch (err) {
    showFailure((err as Error).message === 'This share link needs a newer version of the app'
      ? 'This link needs a newer version of this app.'
      : 'This link is malformed.');
    return;
  }

  let record: ShareRecord;
  let meta: FileMeta;
  try {
    record = await getShareRecord(token);
    meta = await decryptMetadata(fileKey, record.encrypted_metadata, record.metadata_iv);
  } catch {
    showFailure('This link is invalid, has expired, or has nothing left to offer.');
    return;
  }

  statusEl.classList.add('hidden');
  bodyEl.classList.remove('hidden');
  filenameEl.textContent = meta.name;
  const trueSize = typeof meta.size === 'number' ? meta.size : meta.unpaddedSize;
  const sizeLabel = typeof trueSize === 'number' ? formatBytes(trueSize) : '';

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

  if (deleteToken) {
    deleteBtn.classList.remove('hidden');
  }

  downloadBtn.addEventListener('click', async () => {
    downloadBtn.disabled = true;
    downloadBtn.textContent = 'Downloading\u2026';
    try {
      const saved = await downloadDecrypted({
        request: shareBlobRequest(token),
        fileKey,
        contentIv: record.content_iv,
        meta,
      });
      if (!saved) {
        downloadBtn.disabled = false;
        downloadBtn.textContent = 'Download';
        return;
      }

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

    if (!deleteToken) return;
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting\u2026';
    try {
      await deleteSharedFile(deleteToken);
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