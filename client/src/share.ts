import * as api from './api.js';
import { lightbox } from './dom.js';
import { fileKeyCache, metaCache } from './state.js';
import { toBase64 } from './crypto-encrypt-core.js';
import { icon, escapeHtml, showToast } from './utils.js';
import type { FileRecord } from './types.js';


function onBackdropClick(e: MouseEvent): void {
  if (e.target === lightbox) closeShareModal();
}

function openShareModal(innerHtml: string): void {
  lightbox.innerHTML = `
    <button class="btn-icon lightbox-close" id="share-modal-close" aria-label="Close">${icon('close')}</button>
    ${innerHtml}
  `;
  lightbox.classList.remove('hidden');
  lightbox.classList.remove('has-nav');
  lightbox.tabIndex = -1;
  lightbox.focus({ preventScroll: true });
  document.getElementById('share-modal-close')!.addEventListener('click', closeShareModal);
  lightbox.addEventListener('click', onBackdropClick);
}

function closeShareModal(): void {
  lightbox.classList.add('hidden');
  lightbox.innerHTML = '';
  lightbox.removeEventListener('click', onBackdropClick);
}

function buildShareUrl(shareToken: string, fileKeyRaw: Uint8Array): string {
  const keyB64 = toBase64(fileKeyRaw);
  const basePath = window.location.pathname.replace(/[^/]*$/, '');
  const fragment = `t=${encodeURIComponent(shareToken)}&k=${encodeURIComponent(keyB64)}`;
  return `${window.location.origin}${basePath}share.html#${fragment}`;
}

const DOWNLOAD_COUNT_PRESETS = [1, 5, 10, 25];
const MAX_CUSTOM_DOWNLOADS = 1000;

function renderDownloadCountPicker(record: FileRecord, name: string): void {
  openShareModal(`
    <div class="lightbox-content share-modal">
      <h3>Share &ldquo;${escapeHtml(name)}&rdquo;</h3>
      <p class="field-hint">
        Anyone with the link can decrypt and download this one file &mdash; without your vault
        password. Choose how many times it can be downloaded before it stops working.
      </p>
      <div class="share-download-count" role="radiogroup" aria-label="Allowed downloads">
        ${DOWNLOAD_COUNT_PRESETS.map((n, i) => `
          <label class="share-count-option">
            <input type="radio" name="share-count" value="${n}" ${i === 0 ? 'checked' : ''}>
            <span>${n === 1 ? 'Once' : `${n}\u00d7`}</span>
          </label>
        `).join('')}
        <label class="share-count-option">
          <input type="radio" name="share-count" value="custom">
          <span>Custom</span>
        </label>
      </div>
      <input type="number" id="share-count-custom" class="hidden" min="1" max="${MAX_CUSTOM_DOWNLOADS}" step="1"
        placeholder="Number of downloads" aria-label="Custom number of downloads">
      <p class="field-hint share-delete-warning">
        Whoever opens this link will also be able to <strong>permanently delete the file</strong>
        &mdash; for everyone, not just their own access to it. This is built into every share link
        (it's for preventing abuse) and isn't optional.
      </p>
      <div class="share-link-row">
        <button type="button" class="btn-primary" id="share-create-btn">Create link</button>
      </div>
    </div>
  `);

  const customInput = document.getElementById('share-count-custom') as HTMLInputElement;
  const radios = Array.from(document.querySelectorAll<HTMLInputElement>('input[name="share-count"]'));
  for (const radio of radios) {
    radio.addEventListener('change', () => {
      customInput.classList.toggle('hidden', radio.value !== 'custom');
      if (radio.value === 'custom') customInput.focus();
    });
  }

  document.getElementById('share-create-btn')!.addEventListener('click', () => {
    const chosen = radios.find((r) => r.checked)?.value;
    let maxDownloads = 1;
    if (chosen === 'custom') {
      maxDownloads = Math.floor(Number(customInput.value));
      if (!Number.isFinite(maxDownloads) || maxDownloads < 1) {
        showToast('Enter a number of downloads of at least 1.', 'error');
        return;
      }
      maxDownloads = Math.min(maxDownloads, MAX_CUSTOM_DOWNLOADS);
    } else if (chosen) {
      maxDownloads = Number(chosen);
    }
    createAndShowLink(record, name, maxDownloads);
  });
}

async function createAndShowLink(record: FileRecord, name: string, maxDownloads: number): Promise<void> {
  const fileKeyRaw = fileKeyCache.get(record.id);
  if (!fileKeyRaw) {
    closeShareModal();
    showToast("Can't share this item yet \u2014 still loading.", 'error');
    return;
  }

  openShareModal(`
    <div class="lightbox-content share-modal">
      <div class="spinner spinner-lg"></div>
      <p>Creating share link\u2026</p>
    </div>
  `);

  try {
    const { shareToken, maxDownloads: confirmedMax } = await api.createFileShare(record.id, maxDownloads);
    renderShareLink(buildShareUrl(shareToken, fileKeyRaw), name, confirmedMax);
  } catch (err) {
    closeShareModal();
    showToast("Couldn't create a share link. " + (err as Error).message, 'error');
  }
}

function renderShareLink(url: string, name: string, maxDownloads: number): void {
  const usesLabel = maxDownloads === 1 ? 'once' : `up to ${maxDownloads} times`;
  openShareModal(`
    <div class="lightbox-content share-modal">
      <h3>Share &ldquo;${escapeHtml(name)}&rdquo;</h3>
      <p class="field-hint">
        Anyone with this link can decrypt and download this one file &mdash; without your vault
        password. It can be downloaded <strong>${usesLabel}</strong>; after that, the link stops working.
      </p>
      <p class="field-hint share-delete-warning">
        This link can also be used to <strong>permanently delete the file</strong> &mdash; for everyone,
        not just the link &mdash; at any point until it expires.
      </p>
      <div class="share-link-row">
        <input type="text" readonly id="share-link-input" value="${escapeHtml(url)}" aria-label="Share link">
        <button type="button" class="btn-primary" id="share-copy-btn">Copy</button>
      </div>
    </div>
  `);

  const input = document.getElementById('share-link-input') as HTMLInputElement;
  input.addEventListener('click', () => input.select());
  document.getElementById('share-copy-btn')!.addEventListener('click', async () => {
    input.select();
    try {
      await navigator.clipboard.writeText(url);
      showToast('Share link copied.');
    } catch {
      showToast('Could not auto-copy. The link is selected \u2014 copy it manually.', 'error');
    }
  });
}

export async function shareFile(record: FileRecord): Promise<void> {
  const meta = metaCache.get(record.id);
  if (!meta) {
    showToast("Can't share this item yet \u2014 still loading.", 'error');
    return;
  }
  if (meta.isFolder) {
    showToast("Folders can't be shared yet \u2014 only individual files.", 'error');
    return;
  }
  if (!fileKeyCache.get(record.id)) {
    showToast("Can't share this item yet \u2014 still loading.", 'error');
    return;
  }

  renderDownloadCountPicker(record, meta.name);
}
