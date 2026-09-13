import * as api from './api.js';
import { lightbox } from './dom.js';
import { fileKeyCache, metaCache } from './state.js';
import { toBase64 } from './crypto-encrypt-core.js';
import { icon, escapeHtml, showToast } from './utils.js';
import type { FileRecord } from './types.js';


function onBackdropClick(e: MouseEvent): void {
  if (e.target === lightbox) closeShareModal();
}

const SHARE_MODAL_SCROLL_ID = 'share-modal-scroll';
const SHARE_MODAL_VIEWPORT_MARGIN = 32;

function currentVisibleViewportHeight(): number {
  return window.visualViewport?.height ?? window.innerHeight;
}

function syncShareModalHeight(): void {
  const scrollEl = document.getElementById(SHARE_MODAL_SCROLL_ID);
  if (!scrollEl) return;
  const maxHeight = Math.max(160, currentVisibleViewportHeight() - SHARE_MODAL_VIEWPORT_MARGIN);
  scrollEl.style.maxHeight = `${maxHeight}px`;
}

function attachShareModalViewportSync(): void {
  detachShareModalViewportSync();
  syncShareModalHeight();
  window.visualViewport?.addEventListener('resize', syncShareModalHeight);
  window.addEventListener('resize', syncShareModalHeight);
}

function detachShareModalViewportSync(): void {
  window.visualViewport?.removeEventListener('resize', syncShareModalHeight);
  window.removeEventListener('resize', syncShareModalHeight);
}

function openShareModal(innerHtml: string): void {
  lightbox.innerHTML = `
    <button class="btn-icon lightbox-close" id="share-modal-close" aria-label="Close">${icon('close')}</button>
    <div id="${SHARE_MODAL_SCROLL_ID}" class="share-modal-scroll">
      ${innerHtml}
    </div>
  `;
  lightbox.classList.remove('hidden');
  lightbox.classList.remove('has-nav');
  lightbox.tabIndex = -1;
  lightbox.focus({ preventScroll: true });
  document.getElementById('share-modal-close')!.addEventListener('click', closeShareModal);
  lightbox.addEventListener('click', onBackdropClick);
  attachShareModalViewportSync();
}

function closeShareModal(): void {
  detachShareModalViewportSync();
  lightbox.classList.add('hidden');
  lightbox.innerHTML = '';
  lightbox.removeEventListener('click', onBackdropClick);
}

function buildShareUrl(shareToken: string, fileKeyRaw: Uint8Array, deleteToken?: string | null): string {
  const keyB64 = toBase64(fileKeyRaw);
  const basePath = window.location.pathname.replace(/[^/]*$/, '');
  const parts = [`t=${encodeURIComponent(shareToken)}`, `k=${encodeURIComponent(keyB64)}`];
  if (deleteToken) parts.push(`d=${encodeURIComponent(deleteToken)}`);
  return `${window.location.origin}${basePath}share.html#${parts.join('&')}`;
}

const DOWNLOAD_COUNT_PRESETS = [1, 5, 10, 25];
const MAX_CUSTOM_DOWNLOADS = 1000;

interface ExpiryOption { label: string; seconds: number | null }
const EXPIRY_PRESETS: ExpiryOption[] = [
  { label: '1 hour', seconds: 3600 },
  { label: '24 hours', seconds: 86400 },
  { label: '7 days', seconds: 7 * 86400 },
  { label: 'Server default', seconds: null },
];

function renderDownloadCountPicker(record: FileRecord, name: string): void {
  openShareModal(`
    <div class="lightbox-content share-modal">
      <h3>Share &ldquo;${escapeHtml(name)}&rdquo;</h3>
      <p class="field-hint">
        Anyone with the link can decrypt and download this one file.
      </p>

      <div class="share-section">
        <p class="share-section-label">Downloads allowed</p>
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
      </div>

      <div class="share-section">
        <p class="share-section-label">Link expires after</p>
        <div class="share-download-count" role="radiogroup" aria-label="Link expiry">
          ${EXPIRY_PRESETS.map((opt, i) => `
            <label class="share-count-option">
              <input type="radio" name="share-expiry" value="${opt.seconds ?? 'none'}" ${i === 0 ? 'checked' : ''}>
              <span>${opt.label}</span>
            </label>
          `).join('')}
        </div>
      </div>

      <div class="share-section">
        <p class="share-section-label">Permissions</p>
        <label class="share-checkbox-row" for="share-allow-delete">
          <input type="checkbox" id="share-allow-delete">
          <span class="share-checkbox-text">
            <strong>Allow deleting the file via this link</strong>
            <small>Off by default. Only enable this if that's actually the point of sharing it, e.g. handing off ownership.</small>
          </span>
        </label>
      </div>

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

  const expiryRadios = Array.from(document.querySelectorAll<HTMLInputElement>('input[name="share-expiry"]'));
  const allowDeleteCheckbox = document.getElementById('share-allow-delete') as HTMLInputElement;

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

    const chosenExpiry = expiryRadios.find((r) => r.checked)?.value;
    const expiresInSeconds = chosenExpiry && chosenExpiry !== 'none' ? Number(chosenExpiry) : null;

    createAndShowLink(record, name, {
      maxDownloads,
      expiresInSeconds,
      allowDelete: allowDeleteCheckbox.checked,
    });
  });
}

async function createAndShowLink(
  record: FileRecord,
  name: string,
  options: { maxDownloads: number; expiresInSeconds: number | null; allowDelete: boolean }
): Promise<void> {
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
    const { shareToken, deleteToken, maxDownloads: confirmedMax } = await api.createFileShare(record.id, options);
    const url = buildShareUrl(shareToken, fileKeyRaw, options.allowDelete ? deleteToken : null);
    renderShareLink(url, name, confirmedMax, options.expiresInSeconds, Boolean(options.allowDelete && deleteToken));
  } catch (err) {
    closeShareModal();
    showToast("Couldn't create a share link. " + (err as Error).message, 'error');
  }
}

function expiryValueLabel(expiresInSeconds: number | null): string {
  if (expiresInSeconds == null) return 'Server default';
  const hours = expiresInSeconds / 3600;
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? '' : 's'}`;
}

function renderShareLink(
  url: string,
  name: string,
  maxDownloads: number,
  expiresInSeconds: number | null,
  isDeletable: boolean
): void {
  openShareModal(`
    <div class="lightbox-content share-modal">
      <h3>Share &ldquo;${escapeHtml(name)}&rdquo;</h3>
      <p class="field-hint">
        Anyone with this link can decrypt and download this file.
      </p>

      <div class="share-summary">
        <div class="share-summary-item">
          <span class="label">Downloads</span>
          <span class="value">${maxDownloads === 1 ? 'Once' : `Up to ${maxDownloads}`}</span>
        </div>
        <div class="share-summary-item">
          <span class="label">Expires</span>
          <span class="value">${expiryValueLabel(expiresInSeconds)}</span>
        </div>
        <div class="share-summary-item">
          <span class="label">Deletable</span>
          <span class="value">${isDeletable ? 'Yes' : 'No'}</span>
        </div>
      </div>

      ${isDeletable ? `
        <p class="field-hint share-delete-warning">
          <span class="share-delete-warning-icon">${icon('trash')}</span>
          <span>This link also lets whoever opens it <strong>permanently delete the file</strong>.</span>
        </p>
      ` : ''}

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