import { getStoredServerUrl } from './storage.js';
import { safeDownloadName } from './save-stream.js';

export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

interface TauriGlobal {
  core: {
    invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
  };
  opener?: {
    openUrl: (url: string, openWith?: string) => Promise<void>;
  };
  dialog?: {
    save: (options?: Record<string, unknown>) => Promise<string | null>;
  };
  fs?: {
    writeFile: (path: string, data: Uint8Array) => Promise<void>;
  };
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
    __TAURI__?: TauriGlobal;
  }
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

export function isLocalDevPage(): boolean {
  return typeof window !== 'undefined'
    && window.location.port === '5500'
    && isLoopbackHost(window.location.hostname);
}

export function isAllowedServerUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.username || url.password || url.search || url.hash) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && isLoopbackHost(url.hostname);
}

export function resolveBaseUrl(): string {
  if (typeof window === 'undefined') return '';
  if (isLocalDevPage()) return 'http://localhost:8000';
  if (isTauri()) {
    const stored = getStoredServerUrl();
    return stored && isAllowedServerUrl(stored) ? stored : '';
  }
  return '';
}

export async function openExternal(url: string): Promise<void> {
  const opener = window.__TAURI__?.opener;
  if (opener) {
    try {
      await opener.openUrl(url);
      return;
    } catch (err) {
      console.warn('[platform] plugin-opener unavailable, falling back to window.open', err);
    }
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}

export async function saveBytes(rawFilename: string, mime: string, bytes: Uint8Array): Promise<void> {
  const filename = safeDownloadName(rawFilename);
  const { dialog, fs } = window.__TAURI__ ?? {};
  if (dialog && fs) {
    try {
      const path = await dialog.save({ defaultPath: filename });
      if (path == null) return;
      await fs.writeFile(path, bytes);
      return;
    } catch (err) {
      console.warn('[platform] native save failed, falling back to browser download', err);
    }
  }

  const blob = new Blob([bytes as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}
