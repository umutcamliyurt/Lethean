import { getStoredServerUrl } from './storage.js';

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

export function resolveBaseUrl(): string {
  if (typeof window === 'undefined') return '';
  if (window.location.port === '5500') return 'http://localhost:8000';
  if (isTauri()) return getStoredServerUrl();
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

export async function saveBytes(filename: string, mime: string, bytes: Uint8Array): Promise<void> {
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
