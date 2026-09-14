import { toasts } from './dom.js';
import type { FileKind, FileMeta, FileRecord, PreviewKind } from './types.js';

export const TEXT_PREVIEW_MIME_WHITELIST: Set<string> = new Set([
  'application/json',
  'application/xml',
  'application/javascript',
  'application/x-javascript',
  'application/x-yaml',
  'application/ld+json',
  'application/x-sh',
  'application/toml',
]);

export const TEXT_PREVIEW_EXTENSIONS: Set<string> = new Set([
  'txt', 'md', 'markdown', 'csv', 'tsv', 'json', 'xml', 'yaml', 'yml', 'ini', 'conf', 'cfg', 'log',
  'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'rb', 'go', 'rs', 'java', 'c', 'h', 'cpp', 'hpp', 'cs',
  'php', 'sh', 'bash', 'zsh', 'sql', 'css', 'scss', 'less', 'vue', 'svelte', 'toml',
  'env', 'gitignore', 'gitattributes', 'dockerfile', 'makefile', 'gemfile', 'rakefile',
]);

const TEXT_PREVIEW_MIME_BLOCKLIST: Set<string> = new Set([
  'text/html',
  'application/xhtml+xml',
]);
const TEXT_PREVIEW_EXTENSION_BLOCKLIST: Set<string> = new Set(['html', 'htm', 'xhtml', 'shtml', 'svg']);

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46, 0x2d];

export const isCoarsePointerDevice = typeof window.matchMedia === 'function'
  && window.matchMedia('(pointer: coarse)').matches;

export function fileKind(mime: string | undefined | null): FileKind {
  if (mime?.startsWith('image/')) return 'image';
  if (mime?.startsWith('video/')) return 'video';
  return 'other';
}

export function fileTypeLabel(meta: FileMeta | undefined | null): string {
  if (meta?.isFolder) return 'Folder';
  const kind = fileKind(meta?.mime);
  if (kind === 'image') return 'Image';
  if (kind === 'video') return 'Video';
  const sub = (meta?.mime || '').split('/')[1];
  return sub ? sub.replace('x-', '').toUpperCase() : 'File';
}

export function fileExtension(name: string | undefined | null): string {
  const clean = (name || '').toLowerCase();
  const dot = clean.lastIndexOf('.');
  return dot > 0 ? clean.slice(dot + 1) : clean.replace(/^\./, '');
}

export function previewKind(meta: FileMeta | undefined | null): PreviewKind {
  const mime = (meta?.mime || '').toLowerCase();
  const ext = fileExtension(meta?.name);
  if (mime === 'application/pdf') return 'pdf';
  if (mime.startsWith('audio/')) return 'audio';
  if (TEXT_PREVIEW_MIME_BLOCKLIST.has(mime) || TEXT_PREVIEW_EXTENSION_BLOCKLIST.has(ext)) return null;
  if (mime.startsWith('text/') || TEXT_PREVIEW_MIME_WHITELIST.has(mime)) return 'text';
  if (TEXT_PREVIEW_EXTENSIONS.has(ext)) return 'text';
  return null;
}

export function looksLikePdf(bytes: Uint8Array): boolean {
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

export function decryptedSize(record: FileRecord | undefined | null, meta: FileMeta | undefined | null): number {
  if (typeof meta?.unpaddedSize === 'number') return meta.unpaddedSize;
  return record?.size ?? 0;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

export function showToast(message: string, type: 'info' | 'error' = 'info'): void {
  const el = document.createElement('div');
  el.className = `toast${type === 'error' ? ' error' : ''}`;
  el.textContent = message;
  toasts.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

const ICONS: Record<string, string> = {
  image: '<path d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.4"/><circle cx="8.5" cy="9.5" r="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M21 15l-5.5-5.5a1 1 0 0 0-1.4 0L4 19" stroke="currentColor" stroke-width="1.4"/>',
  video: '<rect x="3" y="6" width="14" height="12" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M21 9.5v5l-4-2.5v0z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>',
  file: '<path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.4"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.4"/>',
  folder: '<path d="M3 6.5a1 1 0 0 1 1-1h4.4l1.6 2H16a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-10z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>',
  folderPlus: '<path d="M3 6.5a1 1 0 0 1 1-1h4.4l1.6 2H16a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-10z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M10 10.5v4M8 12.5h4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  play: '<circle cx="13" cy="13" r="12" fill="rgba(20,22,26,0.6)"/><path d="M10.5 8.5l7 4.5-7 4.5z" fill="white"/>',
  trash: '<path d="M4 6h14M9 6V4.5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1V6M6 6l.7 12a1 1 0 0 0 1 .9h6.6a1 1 0 0 0 1-.9L16 6" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>',
  download: '<path d="M10 3v10m0 0l-4-4m4 4l4-4M4 16v2a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-2" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  share: '<circle cx="15" cy="4.5" r="2.2" stroke="currentColor" stroke-width="1.4"/><circle cx="5" cy="10" r="2.2" stroke="currentColor" stroke-width="1.4"/><circle cx="15" cy="15.5" r="2.2" stroke="currentColor" stroke-width="1.4"/><path d="M7 8.8l6-3M7 11.2l6 3" stroke="currentColor" stroke-width="1.4"/>',
  close: '<path d="M5 5l14 14M19 5L5 19" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
  chevronLeft: '<path d="M12.5 4.5L6 11l6.5 6.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  chevronRight: '<path d="M7.5 4.5L14 11l-6.5 6.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  expand: '<path d="M7 3H4a1 1 0 0 0-1 1v3M13 3h3a1 1 0 0 1 1 1v3M17 13v3a1 1 0 0 1-1 1h-3M3 13v3a1 1 0 0 0 1 1h3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  collapse: '<path d="M8 3v3a1 1 0 0 1-1 1H4M12 3v3a1 1 0 0 0 1 1h3M17 12h-3a1 1 0 0 0-1 1v3M3 12h3a1 1 0 0 1 1 1v3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  edit: '<path d="M13.4 3.6l3 3L7.2 15.8H4.2v-3z" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linejoin="round" stroke-linecap="round"/><path d="M11.6 5.4l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  mdBold: '<text x="10" y="14.5" text-anchor="middle" font-size="12" font-weight="700" fill="currentColor">B</text>',
  mdItalic: '<text x="10" y="14.5" text-anchor="middle" font-size="12" font-weight="600" font-style="italic" fill="currentColor">I</text>',
  mdStrike: '<text x="10" y="14.5" text-anchor="middle" font-size="11" font-weight="600" fill="currentColor">S</text><path d="M4.5 10h11" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>',
  mdHeading: '<text x="10" y="14.5" text-anchor="middle" font-size="12" font-weight="700" fill="currentColor">H</text>',
  mdQuote: '<path d="M4.5 12.5v-2.3c0-1.9 1-3.1 2.6-3.6l.4 1.2c-1 .35-1.5 1-1.6 1.9h1.4v2.8H4.5zm6.5 0v-2.3c0-1.9 1-3.1 2.6-3.6l.4 1.2c-1 .35-1.5 1-1.6 1.9h1.4v2.8H11z" fill="currentColor"/>',
  mdCode: '<path d="M7.5 6L4 10l3.5 4M12.5 6L16 10l-3.5 4" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  mdLink: '<path d="M8.3 11.7a2.8 2.8 0 0 1 0-4l1.8-1.8a2.8 2.8 0 0 1 4 4l-.9.9" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/><path d="M11.7 8.3a2.8 2.8 0 0 1 0 4l-1.8 1.8a2.8 2.8 0 0 1-4-4l.9-.9" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>',
  mdListBullet: '<circle cx="4.5" cy="6" r="1" fill="currentColor"/><circle cx="4.5" cy="10" r="1" fill="currentColor"/><circle cx="4.5" cy="14" r="1" fill="currentColor"/><path d="M8 6h8M8 10h8M8 14h8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  mdListNumbered: '<text x="2.2" y="7.4" font-size="5.2" fill="currentColor">1</text><text x="2.2" y="11.4" font-size="5.2" fill="currentColor">2</text><text x="2.2" y="15.4" font-size="5.2" fill="currentColor">3</text><path d="M8 6h8M8 10h8M8 14h8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  mdHr: '<path d="M3.5 10h13" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
  save: '<path d="M4 3.5h9.5L16 6v10a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 4 16V4a.5.5 0 0 1 .5-.5z" stroke="currentColor" stroke-width="1.3" fill="none" stroke-linejoin="round"/><path d="M6.5 3.5v3.8h5V3.5" stroke="currentColor" stroke-width="1.3" fill="none"/><rect x="6.5" y="11" width="7" height="5" stroke="currentColor" stroke-width="1.3" fill="none"/>',
};

export function icon(name: string): string {
  return `<svg width="18" height="18" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">${ICONS[name] || ''}</svg>`;
}

export function escapeHtml(str: unknown): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}