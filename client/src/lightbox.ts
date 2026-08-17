import * as C from './crypto.js';
import * as api from './api.js';
import { lightbox, boxGrid } from './dom.js';
import { fileKeyCache, metaCache, objectUrlCache } from './state.js';
import {
  fileKind, previewKind, looksLikePdf, decryptedSize, formatBytes, icon, escapeHtml, showToast,
} from './utils.js';
import { visibleRecords, getRecords, getDecryptedBytes, getDecryptedUrl } from './gallery.js';
import type { FileMeta, FileRecord } from './types.js';

let lightboxMediaList: FileRecord[] = [];
let lightboxIndex = -1;
let lightboxNavLock = false;

let currentPreviewId: string | null = null;

let currentMediaCtx: { record: FileRecord; meta: FileMeta; url: string } | null = null;


interface VendorFullscreenDoc {
  webkitFullscreenElement?: Element | null;
  webkitFullscreenEnabled?: boolean;
  webkitExitFullscreen?: () => void;
  webkitCancelFullScreen?: () => void;
  mozFullScreenElement?: Element | null;
  mozFullScreenEnabled?: boolean;
  mozCancelFullScreen?: () => void;
  msFullscreenElement?: Element | null;
  msFullscreenEnabled?: boolean;
  msExitFullscreen?: () => void;
}

interface VendorFullscreenEl {
  webkitRequestFullscreen?: () => void;
  webkitRequestFullScreen?: () => void;
  webkitEnterFullscreen?: () => void;
  mozRequestFullScreen?: () => void;
  msRequestFullscreen?: () => void;
}

function getNativeFullscreenElement(): Element | null {
  const d = document as unknown as VendorFullscreenDoc;
  return document.fullscreenElement || d.webkitFullscreenElement || d.mozFullScreenElement || d.msFullscreenElement || null;
}

function isNativeFullscreenActive(): boolean {
  return !!getNativeFullscreenElement();
}

function supportsElementFullscreen(el: HTMLElement): boolean {
  const d = document as unknown as VendorFullscreenDoc;
  const enabled = document.fullscreenEnabled ?? d.webkitFullscreenEnabled ?? d.mozFullScreenEnabled ?? d.msFullscreenEnabled ?? false;
  if (!enabled) return false;
  const e = el as unknown as VendorFullscreenEl;
  return typeof el.requestFullscreen === 'function'
    || typeof e.webkitRequestFullscreen === 'function'
    || typeof e.webkitRequestFullScreen === 'function'
    || typeof e.mozRequestFullScreen === 'function'
    || typeof e.msRequestFullscreen === 'function';
}

async function requestFullscreenCompat(el: HTMLElement): Promise<void> {
  const e = el as unknown as VendorFullscreenEl;
  if (typeof el.requestFullscreen === 'function') {
    await el.requestFullscreen();
    return;
  }
  if (typeof e.webkitRequestFullscreen === 'function') { e.webkitRequestFullscreen(); return; }
  if (typeof e.webkitRequestFullScreen === 'function') { e.webkitRequestFullScreen(); return; }
  if (typeof e.mozRequestFullScreen === 'function') { e.mozRequestFullScreen(); return; }
  if (typeof e.msRequestFullscreen === 'function') { e.msRequestFullscreen(); return; }
  throw new Error('Fullscreen API not supported');
}

async function exitFullscreenCompat(): Promise<void> {
  const d = document as unknown as VendorFullscreenDoc;
  if (document.exitFullscreen) { await document.exitFullscreen(); return; }
  if (d.webkitExitFullscreen) { d.webkitExitFullscreen(); return; }
  if (d.webkitCancelFullScreen) { d.webkitCancelFullScreen(); return; }
  if (d.mozCancelFullScreen) { d.mozCancelFullScreen(); return; }
  if (d.msExitFullscreen) { d.msExitFullscreen(); return; }
}

function fixNativeFullscreenSizing(el: Element | null): void {
  if (!(el instanceof HTMLElement)) return;
  el.style.objectFit = 'contain';
  el.style.backgroundColor = '#000';
}

let pseudoFullscreenActive = false;

function applyPseudoFullscreenStyles(mediaEl: HTMLElement, active: boolean): void {
  if (active) {
    mediaEl.dataset.pseudoFsStyle = mediaEl.getAttribute('style') || '';
    Object.assign(mediaEl.style, {
      position: 'fixed',
      inset: '0',
      width: '100vw',
      height: '100dvh',
      maxWidth: 'none',
      maxHeight: 'none',
      objectFit: 'contain',
      background: '#000',
      zIndex: '2147483000',
      margin: '0',
    });
  } else {
    const prev = mediaEl.dataset.pseudoFsStyle;
    if (prev) mediaEl.setAttribute('style', prev);
    else mediaEl.removeAttribute('style');
    delete mediaEl.dataset.pseudoFsStyle;
  }
}

function layoutPseudoFullscreenChrome(active: boolean): void {
  const setFixed = (el: HTMLElement | null, styles: Partial<CSSStyleDeclaration>): void => {
    if (!el) return;
    if (active) {
      el.dataset.pseudoFsStyle = el.getAttribute('style') || '';
      Object.assign(el.style, { position: 'fixed', zIndex: '2147483001' }, styles);
    } else {
      const prev = el.dataset.pseudoFsStyle;
      if (prev) el.setAttribute('style', prev);
      else el.removeAttribute('style');
      delete el.dataset.pseudoFsStyle;
    }
  };

  setFixed(document.getElementById('lightbox-close'), { top: '12px', right: '12px' });
  setFixed(document.getElementById('lightbox-prev'), { top: '50%', left: '12px', transform: 'translateY(-50%)' });
  setFixed(document.getElementById('lightbox-next'), { top: '50%', right: '12px', transform: 'translateY(-50%)' });
  setFixed(lightbox.querySelector<HTMLElement>('.lightbox-meta'), { left: '0', right: '0', bottom: '0' });
}

function updateFullscreenButton(): void {
  const btn = document.getElementById('lightbox-fullscreen');
  if (!btn) return;
  const active = isNativeFullscreenActive() || pseudoFullscreenActive;
  btn.innerHTML = icon(active ? 'collapse' : 'expand');
  const label = active ? 'Exit full screen' : 'Full screen';
  btn.title = label;
  btn.setAttribute('aria-label', label);
}

async function tryNativeFullscreen(mediaEl: HTMLElement): Promise<boolean> {
  if (!supportsElementFullscreen(mediaEl)) return false;
  try {
    await Promise.race([
      requestFullscreenCompat(mediaEl),
      new Promise<void>((resolve) => setTimeout(resolve, 400)),
    ]);
  } catch {
    return false;
  }
  return getNativeFullscreenElement() === mediaEl;
}

async function toggleFullscreen(mediaEl: HTMLElement): Promise<void> {
  if (isNativeFullscreenActive()) {
    await exitFullscreenCompat().catch(() => {});
    return;
  }
  if (pseudoFullscreenActive) {
    applyPseudoFullscreenStyles(mediaEl, false);
    layoutPseudoFullscreenChrome(false);
    pseudoFullscreenActive = false;
    updateFullscreenButton();
    return;
  }

  if (await tryNativeFullscreen(mediaEl)) return;

  const legacyVideoEl = mediaEl as unknown as VendorFullscreenEl;
  if (mediaEl instanceof HTMLVideoElement && typeof legacyVideoEl.webkitEnterFullscreen === 'function') {
    try {
      legacyVideoEl.webkitEnterFullscreen!();
      return;
    } catch {
    }
  }

  pseudoFullscreenActive = true;
  applyPseudoFullscreenStyles(mediaEl, true);
  layoutPseudoFullscreenChrome(true);
  updateFullscreenButton();
}

document.addEventListener('fullscreenchange', () => {
  fixNativeFullscreenSizing(getNativeFullscreenElement());
  updateFullscreenButton();
});
document.addEventListener('webkitfullscreenchange', () => {
  fixNativeFullscreenSizing(getNativeFullscreenElement());
  updateFullscreenButton();
});
document.addEventListener('MSFullscreenChange', () => {
  fixNativeFullscreenSizing(getNativeFullscreenElement());
  updateFullscreenButton();
});

function isThumbnailedKind(meta: FileMeta | undefined | null): boolean {
  return fileKind(meta?.mime) === 'image';
}

function releaseEphemeralPreview(id: string | null): void {
  if (!id) return;
  const meta = metaCache.get(id);
  if (isThumbnailedKind(meta)) return;
  const url = objectUrlCache.get(id);
  if (url) {
    URL.revokeObjectURL(url);
    objectUrlCache.delete(id);
  }
}

function switchPreview(newId: string | null): void {
  if (currentPreviewId && currentPreviewId !== newId) releaseEphemeralPreview(currentPreviewId);
  currentPreviewId = newId;
}

const isCoarsePointerDevice = typeof window.matchMedia === 'function'
  && window.matchMedia('(pointer: coarse)').matches;
const MOBILE_INLINE_VIDEO_LIMIT_BYTES = 150 * 1024 * 1024;
const MOBILE_INLINE_PDF_LIMIT_BYTES = 150 * 1024 * 1024;
const TEXT_PREVIEW_MAX_BYTES = 2 * 1024 * 1024;

interface UnsafePdfError extends Error {
  unsafePdf?: boolean;
}

function isUnsafeToPreviewInline(record: FileRecord, meta: FileMeta | undefined | null): boolean {
  if (!isCoarsePointerDevice) return false;
  const size = decryptedSize(record, meta);
  if (fileKind(meta?.mime) === 'video' && size > MOBILE_INLINE_VIDEO_LIMIT_BYTES) return true;
  if (previewKind(meta) === 'pdf' && size > MOBILE_INLINE_PDF_LIMIT_BYTES) return true;
  return false;
}

export function mediaRecords(): FileRecord[] {
  return visibleRecords().filter((r) => {
    const meta = metaCache.get(r.id);
    if (fileKind(meta?.mime) === 'other') return false;
    if (isUnsafeToPreviewInline(r, meta)) return false;
    return true;
  });
}

export async function openTile(fileId: string): Promise<void> {
  const record = getRecords().find((r) => r.id === fileId);
  const meta = metaCache.get(fileId);
  if (!record || !meta) return;

  const kind = fileKind(meta.mime);
  const pKind = kind === 'other' ? previewKind(meta) : null;
  const skipInlinePreview = isUnsafeToPreviewInline(record, meta);
  const textTooLarge = pKind === 'text' && decryptedSize(record, meta) > TEXT_PREVIEW_MAX_BYTES;

  if (kind === 'other' && pKind && !skipInlinePreview && !textTooLarge) {
    await openOtherPreview(record, meta, pKind);
    return;
  }

  if (kind === 'other' || skipInlinePreview) {
    lightboxMediaList = [];
    lightboxIndex = -1;
    switchPreview(null);
    const tileEl = boxGrid.querySelector(`[data-id="${CSS.escape(fileId)}"]`);
    tileEl?.classList.add('opening');
    let note = '';
    if (skipInlinePreview && kind === 'video') {
      note = "This video is large \u2014 previewing it in-browser on a phone can crash the tab. Download it to watch in your device's player instead.";
    } else if (skipInlinePreview && pKind === 'pdf') {
      note = "This PDF is large \u2014 previewing it in-browser on a phone can be slow. Download it to view in your device's PDF viewer instead.";
    } else if (textTooLarge) {
      note = "This text file is large \u2014 download it to view the full contents.";
    }
    showLightbox(`
      <div class="lightbox-generic">
        ${icon(kind === 'video' ? 'video' : 'file')}
        <p class="lightbox-generic-name">${escapeHtml(meta.name)}</p>
        <p class="lightbox-generic-size">${formatBytes(decryptedSize(record, meta))} \u00b7 encrypted</p>
        ${note ? `<p class="lightbox-generic-note">${note}</p>` : ''}
        <button class="btn-primary lightbox-generic-btn" id="lightbox-download">Decrypt &amp; download</button>
      </div>
    `);
    document.getElementById('lightbox-download')!.addEventListener('click', () => downloadAndSave(record, meta));
    tileEl?.classList.remove('opening');
    return;
  }

  const list = mediaRecords();
  const index = list.findIndex((r) => r.id === fileId);
  await openMediaAt(list, index >= 0 ? index : 0);
}

async function openOtherPreview(record: FileRecord, meta: FileMeta, kind: 'pdf' | 'audio' | 'text'): Promise<void> {
  lightboxMediaList = [];
  lightboxIndex = -1;
  switchPreview(record.id);
  const tileEl = boxGrid.querySelector(`[data-id="${CSS.escape(record.id)}"]`);
  tileEl?.classList.add('decrypting');
  showLightbox(`<div class="lightbox-content"><div class="spinner spinner-lg"></div></div>`, { keepMedia: true });

  try {
    let inner: string;
    let objectUrl: string | null = null;

    if (kind === 'text') {
      const bytes = await getDecryptedBytes(record);
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      inner = `<pre class="lightbox-text" id="lightbox-media">${escapeHtml(text)}</pre>`;
    } else if (kind === 'pdf') {
      const bytes = await getDecryptedBytes(record);
      if (!looksLikePdf(bytes)) {
        const err: UnsafePdfError = new Error("This file is named/labeled as a PDF but its contents don't look like one, so it can't be previewed safely.");
        err.unsafePdf = true;
        throw err;
      }
      const blob = new Blob([bytes as BlobPart], { type: 'application/pdf' });
      objectUrl = URL.createObjectURL(blob);
      objectUrlCache.set(record.id, objectUrl);
      inner = `<iframe src="${objectUrl}" id="lightbox-media" title="${escapeHtml(meta.name)}" sandbox="allow-same-origin" referrerpolicy="no-referrer"></iframe>`;
    } else {
      objectUrl = await getDecryptedUrl(record);
      inner = `<audio src="${objectUrl}" controls autoplay id="lightbox-media"></audio>`;
    }

    showLightbox(`
      <div class="lightbox-content lightbox-content-${kind}">
        ${inner}
        <div class="lightbox-meta">
          <span class="fname">${escapeHtml(meta.name)}</span>
          <button class="btn-icon" id="lightbox-download" title="Download" aria-label="Download">${icon('download')}</button>
        </div>
      </div>
    `, { keepMedia: true });

    document.getElementById('lightbox-download')!.addEventListener('click', () => downloadAndSave(record, meta, objectUrl ?? undefined));
  } catch (err) {
    const unsafeErr = err as UnsafePdfError;
    if (unsafeErr.unsafePdf) {
      showLightbox(`
        <div class="lightbox-generic">
          ${icon('file')}
          <p class="lightbox-generic-name">${escapeHtml(meta.name)}</p>
          <p class="lightbox-generic-size">${formatBytes(decryptedSize(record, meta))} \u00b7 encrypted</p>
          <p class="lightbox-generic-note">${escapeHtml(unsafeErr.message)}</p>
          <button class="btn-primary lightbox-generic-btn" id="lightbox-download">Decrypt &amp; download</button>
        </div>
      `);
      document.getElementById('lightbox-download')!.addEventListener('click', () => downloadAndSave(record, meta));
    } else {
      showToast("Couldn't decrypt that file. " + (err as Error).message, 'error');
      closeLightbox();
    }
  } finally {
    tileEl?.classList.remove('decrypting', 'opening');
  }
}

function updateMediaMetaLabel(meta: FileMeta, showNav: boolean): void {
  const fnameEl = lightbox.querySelector('.lightbox-meta .fname');
  if (fnameEl) {
    fnameEl.textContent = showNav ? `${meta.name} \u00b7 ${lightboxIndex + 1}/${lightboxMediaList.length}` : meta.name;
  }
}

async function openMediaAt(list: FileRecord[], index: number): Promise<void> {
  if (!list.length) return;
  index = ((index % list.length) + list.length) % list.length;
  const record = list[index]!;
  const meta = metaCache.get(record.id);
  if (!record || !meta) return;

  lightboxMediaList = list;
  lightboxIndex = index;
  switchPreview(record.id);

  const kind = fileKind(meta.mime);
  const showNav = lightboxMediaList.length > 1;

  const existingMedia = !lightbox.classList.contains('hidden')
    ? (document.getElementById('lightbox-media') as (HTMLImageElement | HTMLVideoElement | null))
    : null;
  const existingHasNav = !!document.getElementById('lightbox-prev') || !!document.getElementById('lightbox-next');
  const canUpdateInPlace = !!existingMedia
    && ((kind === 'image' && existingMedia.tagName === 'IMG') || (kind === 'video' && existingMedia.tagName === 'VIDEO'))
    && existingHasNav === showNav;

  const wasNativeFullscreen = !canUpdateInPlace && isNativeFullscreenActive();
  const wasPseudoFullscreen = !canUpdateInPlace && pseudoFullscreenActive;

  const tileEl = boxGrid.querySelector(`[data-id="${CSS.escape(record.id)}"]`);
  tileEl?.classList.add('decrypting');

  if (!canUpdateInPlace) {
    lightbox.classList.toggle('has-nav', showNav);
    showLightbox(`<div class="lightbox-content"><div class="spinner spinner-lg"></div></div>`, { keepMedia: true });
  }

  try {
    const url = await getDecryptedUrl(record);
    currentMediaCtx = { record, meta, url };

    if (canUpdateInPlace && existingMedia) {
      existingMedia.src = url;
      if (existingMedia instanceof HTMLImageElement) {
        existingMedia.alt = meta.name;
      } else {
        existingMedia.load();
        existingMedia.play().catch(() => {});
      }
      updateMediaMetaLabel(meta, showNav);
    } else {
      const inner = kind === 'image'
        ? `<img src="${url}" alt="${escapeHtml(meta.name)}" id="lightbox-media">`
        : `<video src="${url}" controls autoplay id="lightbox-media"></video>`;
      showLightbox(`
        <div class="lightbox-content">
          ${showNav ? `<button class="btn-icon lightbox-nav lightbox-nav-prev" id="lightbox-prev" aria-label="Previous">${icon('chevronLeft')}</button>` : ''}
          ${inner}
          ${showNav ? `<button class="btn-icon lightbox-nav lightbox-nav-next" id="lightbox-next" aria-label="Next">${icon('chevronRight')}</button>` : ''}
          <div class="lightbox-meta">
            <span class="fname">${escapeHtml(meta.name)}${showNav ? ` \u00b7 ${lightboxIndex + 1}/${lightboxMediaList.length}` : ''}</span>
            <button class="btn-icon" id="lightbox-fullscreen" title="Full screen" aria-label="Full screen">${icon('expand')}</button>
            <button class="btn-icon" id="lightbox-download" title="Download" aria-label="Download">${icon('download')}</button>
          </div>
        </div>
      `, { keepMedia: true });

      document.getElementById('lightbox-download')!.addEventListener('click', () => {
        if (currentMediaCtx) downloadAndSave(currentMediaCtx.record, currentMediaCtx.meta, currentMediaCtx.url);
      });
      document.getElementById('lightbox-fullscreen')!.addEventListener('click', () => {
        const mediaEl = document.getElementById('lightbox-media') as (HTMLVideoElement | HTMLImageElement | null);
        if (mediaEl) toggleFullscreen(mediaEl);
      });
      document.getElementById('lightbox-prev')?.addEventListener('click', () => navigateLightbox(-1));
      document.getElementById('lightbox-next')?.addEventListener('click', () => navigateLightbox(1));
      updateFullscreenButton();

      const newMediaEl = document.getElementById('lightbox-media') as HTMLElement | null;
      if (newMediaEl && (wasNativeFullscreen || wasPseudoFullscreen)) {
        const restoredNative = wasNativeFullscreen && await tryNativeFullscreen(newMediaEl);
        if (!restoredNative) {
          pseudoFullscreenActive = true;
          applyPseudoFullscreenStyles(newMediaEl, true);
          layoutPseudoFullscreenChrome(true);
        }
        updateFullscreenButton();
      }
    }
  } catch (err) {
    showToast("Couldn't decrypt that file. " + (err as Error).message, 'error');
    closeLightbox();
  } finally {
    tileEl?.classList.remove('decrypting', 'opening');
  }
}

function navigateLightbox(delta: number): void {
  if (lightboxMediaList.length < 2 || lightboxIndex < 0) return;
  openMediaAt(lightboxMediaList, lightboxIndex + delta);
}

export function showLightbox(innerHtml: string, { keepMedia = false }: { keepMedia?: boolean } = {}): void {
  if (!keepMedia) {
    lightboxMediaList = [];
    lightboxIndex = -1;
    lightbox.classList.remove('has-nav');
    releaseEphemeralPreview(currentPreviewId);
    currentPreviewId = null;
  }
  lightbox.innerHTML = `
    <button class="btn-icon lightbox-close" id="lightbox-close" aria-label="Close">${icon('close')}</button>
    ${innerHtml}
  `;
  lightbox.classList.remove('hidden');
  lightbox.tabIndex = -1;
  lightbox.focus({ preventScroll: true });
  document.getElementById('lightbox-close')!.addEventListener('click', closeLightbox);
  lightbox.addEventListener('click', (e) => { if (e.target === lightbox) closeLightbox(); }, { once: true });
}

export function closeLightbox(): void {
  const av = lightbox.querySelector('video, audio') as (HTMLVideoElement | HTMLAudioElement | null);
  if (av) av.pause();
  if (isNativeFullscreenActive()) exitFullscreenCompat().catch(() => {});
  if (pseudoFullscreenActive) {
    const mediaEl = document.getElementById('lightbox-media') as HTMLElement | null;
    if (mediaEl) applyPseudoFullscreenStyles(mediaEl, false);
    layoutPseudoFullscreenChrome(false);
    pseudoFullscreenActive = false;
  }
  lightbox.classList.add('hidden');
  lightbox.classList.remove('has-nav');
  lightbox.innerHTML = '';
  lightboxMediaList = [];
  lightboxIndex = -1;
  releaseEphemeralPreview(currentPreviewId);
  currentPreviewId = null;
}

document.addEventListener('keydown', (e) => {
  if (lightbox.classList.contains('hidden')) return;
  if (e.key === 'Escape') {
    if (pseudoFullscreenActive) {
      const mediaEl = document.getElementById('lightbox-media') as HTMLElement | null;
      if (mediaEl) toggleFullscreen(mediaEl);
      return;
    }
    closeLightbox();
    return;
  }
  if (e.key === 'ArrowLeft') { e.preventDefault(); navigateLightbox(-1); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); navigateLightbox(1); }
});

lightbox.addEventListener('wheel', (e) => {
  if (lightboxMediaList.length < 2) return;
  if (Math.abs(e.deltaX) <= Math.abs(e.deltaY) || Math.abs(e.deltaX) < 24) return;
  e.preventDefault();
  if (lightboxNavLock) return;
  lightboxNavLock = true;
  navigateLightbox(e.deltaX > 0 ? 1 : -1);
  setTimeout(() => { lightboxNavLock = false; }, 350);
}, { passive: false });

let touchStartX: number | null = null;
let touchStartY: number | null = null;
lightbox.addEventListener('touchstart', (e) => {
  if (e.touches.length !== 1) return;
  touchStartX = e.touches[0]!.clientX;
  touchStartY = e.touches[0]!.clientY;
}, { passive: true });
lightbox.addEventListener('touchend', (e) => {
  if (touchStartX == null || lightboxMediaList.length < 2) { touchStartX = null; return; }
  const touch = e.changedTouches[0]!;
  const dx = touch.clientX - touchStartX;
  const dy = touch.clientY - (touchStartY ?? 0);
  touchStartX = null;
  if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy)) navigateLightbox(dx < 0 ? 1 : -1);
}, { passive: true });

export async function downloadAndSave(record: FileRecord, meta: FileMeta, existingUrl?: string): Promise<void> {
  let url = existingUrl;
  try {
    if (!url) {
      const fileKeyRaw = fileKeyCache.get(record.id)!;
      const ciphertext = await api.downloadContent(record.id);
      const bytes = await C.decryptContent(fileKeyRaw, record.content_iv, ciphertext, meta.compressed, meta.unpaddedSize ?? null);
      const blob = new Blob([bytes as BlobPart], { type: meta.mime });
      url = URL.createObjectURL(blob);
    }
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.name;
    a.click();
    if (!existingUrl) URL.revokeObjectURL(url);
  } catch (err) {
    showToast('Download failed. ' + (err as Error).message, 'error');
  }
}