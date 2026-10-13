
import { decryptToStream } from './crypto-encrypt-core.js';
import type { FileMeta } from './types.js';

export interface BlobRequest {
  url: string;
  headers: Record<string, string>;
}

export interface EncryptedDownload {
  request: BlobRequest;
  fileKeyRaw: Uint8Array;
  contentIv: string;
  meta: Pick<FileMeta, 'name' | 'mime' | 'compressed' | 'unpaddedSize' | 'chunkSize'>;
}

interface TauriApis {
  dialog?: { save: (options?: Record<string, unknown>) => Promise<string | null> };
  fs?: { writeFile: (path: string, data: Uint8Array, options?: Record<string, unknown>) => Promise<void> };
}

const tauri = (): TauriApis | undefined => (window as unknown as { __TAURI__?: TauriApis }).__TAURI__;

export async function downloadDecrypted(d: EncryptedDownload): Promise<boolean> {
  const t = tauri();
  if (t?.dialog && t.fs) return saveWithTauri(t.dialog, t.fs, d);

  const worker = await activeDownloadWorker();
  if (worker) {
    const outcome = await downloadViaWorker(worker, d);
    if (outcome !== 'not-intercepted') return outcome === 'done';
  }
  return saveViaBlob(d);
}


const WORKER_WAIT_MS = 5_000;
const KEEPALIVE_MS = 20_000;

const registration: Promise<ServiceWorkerRegistration | null> =
  !tauri() && 'serviceWorker' in navigator && window.isSecureContext
    ? navigator.serviceWorker.register(new URL('./download-sw.js', import.meta.url)).catch(() => null)
    : Promise.resolve(null);

function within<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([p, new Promise<T>((r) => setTimeout(() => r(fallback), ms))]);
}

async function activeDownloadWorker(): Promise<{ sw: ServiceWorker; scope: string } | null> {
  const reg = await within(registration, WORKER_WAIT_MS, null);
  if (!reg) return null;
  if (reg.active) return { sw: reg.active, scope: reg.scope };
  const pending = reg.installing ?? reg.waiting;
  if (!pending) return null;
  const activated = new Promise<boolean>((resolve) => {
    pending.addEventListener('statechange', () => {
      if (pending.state === 'activated') resolve(true);
      if (pending.state === 'redundant') resolve(false);
    });
  });
  return (await within(activated, WORKER_WAIT_MS, false)) && reg.active ? { sw: reg.active, scope: reg.scope } : null;
}

type WorkerOutcome = 'done' | 'cancelled' | 'not-intercepted';

function downloadViaWorker(worker: { sw: ServiceWorker; scope: string }, d: EncryptedDownload): Promise<WorkerOutcome> {
  return new Promise((resolve, reject) => {
    const token = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
    const { port1, port2 } = new MessageChannel();
    let frame: HTMLIFrameElement | null = null;
    let keepalive: ReturnType<typeof setInterval> | undefined;
    const notIntercepted = setTimeout(() => settle(() => resolve('not-intercepted')), WORKER_WAIT_MS * 2);

    function settle(fn: () => void): void {
      clearTimeout(notIntercepted);
      clearInterval(keepalive);
      port1.onmessage = null;
      port1.close();
      setTimeout(() => frame?.remove(), 30_000);
      fn();
    }

    port1.onmessage = (e: MessageEvent<{ type: string; message?: string }>) => {
      switch (e.data.type) {
        case 'ready': {
          frame = document.createElement('iframe');
          frame.hidden = true;
          frame.src = new URL(`__download/${token}/${encodeURIComponent(d.meta.name)}`, worker.scope).href;
          document.body.appendChild(frame);
          break;
        }
        case 'started':
          clearTimeout(notIntercepted);
          keepalive = setInterval(() => worker.sw.postMessage({ type: 'keepalive' }), KEEPALIVE_MS);
          break;
        case 'done': settle(() => resolve('done')); break;
        case 'cancelled': settle(() => resolve('cancelled')); break;
        case 'error': settle(() => reject(new Error(e.data.message || 'Download failed'))); break;
      }
    };

    worker.sw.postMessage({
      type: 'prepare',
      token,
      job: {
        url: d.request.url,
        headers: d.request.headers,
        fileKeyRaw: d.fileKeyRaw,
        contentIv: d.contentIv,
        compressed: !!d.meta.compressed,
        unpaddedSize: d.meta.unpaddedSize ?? null,
        chunkSize: d.meta.chunkSize ?? null,
        filename: d.meta.name,
      },
    }, [port2]);
  });
}

async function openPlaintext(d: EncryptedDownload): Promise<ReadableStream<Uint8Array>> {
  const res = await fetch(d.request.url, { headers: d.request.headers, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok || !res.body) {
    let detail = res.statusText;
    try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch {  }
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return decryptToStream(d.fileKeyRaw, d.contentIv, res.body, d.meta);
}

async function saveWithTauri(
  dialog: NonNullable<TauriApis['dialog']>,
  fs: NonNullable<TauriApis['fs']>,
  d: EncryptedDownload
): Promise<boolean> {
  const path = await dialog.save({ defaultPath: d.meta.name });
  if (path == null) return false;
  const reader = (await openPlaintext(d)).getReader();
  let first = true;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      await fs.writeFile(path, value, first ? undefined : { append: true });
      first = false;
    }
    if (first) await fs.writeFile(path, new Uint8Array(0));
  } catch (err) {
    try { await reader.cancel(err); } catch {  }
    throw err;
  }
  return true;
}

async function saveViaBlob(d: EncryptedDownload): Promise<boolean> {
  const reader = (await openPlaintext(d)).getReader();
  const parts: Blob[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(new Blob([value as unknown as BlobPart]));
  }
  const url = URL.createObjectURL(new Blob(parts, { type: d.meta.mime || 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = d.meta.name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return true;
}
