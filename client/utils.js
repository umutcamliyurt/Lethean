import { toasts } from './dom.js';

export const TEXT_PREVIEW_MIME_WHITELIST = new Set([
  'application/json',
  'application/xml',
  'application/javascript',
  'application/x-javascript',
  'application/x-yaml',
  'application/ld+json',
  'application/x-sh',
  'application/toml',
]);

export const TEXT_PREVIEW_EXTENSIONS = new Set([
  'txt', 'md', 'markdown', 'csv', 'tsv', 'json', 'xml', 'yaml', 'yml', 'ini', 'conf', 'cfg', 'log',
  'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'rb', 'go', 'rs', 'java', 'c', 'h', 'cpp', 'hpp', 'cs',
  'php', 'sh', 'bash', 'zsh', 'sql', 'html', 'htm', 'css', 'scss', 'less', 'vue', 'svelte', 'toml',
  'env', 'gitignore', 'gitattributes', 'dockerfile', 'makefile', 'gemfile', 'rakefile',
]);

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46, 0x2d];

export function fileKind(mime) {
  if (mime?.startsWith('image/')) return 'image';
  if (mime?.startsWith('video/')) return 'video';
  return 'other';
}

export function fileExtension(name) {
  const clean = (name || '').toLowerCase();
  const dot = clean.lastIndexOf('.');
  return dot > 0 ? clean.slice(dot + 1) : clean.replace(/^\./, '');
}

export function previewKind(meta) {
  const mime = (meta?.mime || '').toLowerCase();
  if (mime === 'application/pdf') return 'pdf';
  if (mime.startsWith('audio/')) return 'audio';
  if (mime.startsWith('text/') || TEXT_PREVIEW_MIME_WHITELIST.has(mime)) return 'text';
  if (TEXT_PREVIEW_EXTENSIONS.has(fileExtension(meta?.name))) return 'text';
  return null;
}

export function looksLikePdf(bytes) {
  const scanLen = Math.min(bytes.length, 1024);
  for (let i = 0; i <= scanLen - PDF_MAGIC.length; i++) {
    let match = true;
    for (let j = 0; j < PDF_MAGIC.length; j++) {
      if (bytes[i + j] !== PDF_MAGIC[j]) { match = false; break; }
    }
    if (match) return true;
  }
  return false;
}

export function decryptedSize(record, meta) {
  if (typeof meta?.unpaddedSize === 'number') return meta.unpaddedSize;
  return record?.size ?? 0;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

export function showToast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast${type === 'error' ? ' error' : ''}`;
  el.textContent = message;
  toasts.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

export function icon(name) {
  const icons = {
    image: '<path d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.4"/><circle cx="8.5" cy="9.5" r="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M21 15l-5.5-5.5a1 1 0 0 0-1.4 0L4 19" stroke="currentColor" stroke-width="1.4"/>',
    video: '<rect x="3" y="6" width="14" height="12" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M21 9.5v5l-4-2.5v0z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>',
    file: '<path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.4"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.4"/>',
    play: '<circle cx="13" cy="13" r="12" fill="rgba(20,22,26,0.6)"/><path d="M10.5 8.5l7 4.5-7 4.5z" fill="white"/>',
    trash: '<path d="M4 6h14M9 6V4.5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1V6M6 6l.7 12a1 1 0 0 0 1 .9h6.6a1 1 0 0 0 1-.9L16 6" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>',
    download: '<path d="M10 3v10m0 0l-4-4m4 4l4-4M4 16v2a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-2" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
    close: '<path d="M5 5l14 14M19 5L5 19" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    chevronLeft: '<path d="M12.5 4.5L6 11l6.5 6.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
    chevronRight: '<path d="M7.5 4.5L14 11l-6.5 6.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
    expand: '<path d="M7 3H4a1 1 0 0 0-1 1v3M13 3h3a1 1 0 0 1 1 1v3M17 13v3a1 1 0 0 1-1 1h-3M3 13v3a1 1 0 0 0 1 1h3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  };
  return `<svg width="18" height="18" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">${icons[name] || ''}</svg>`;
}

export function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
