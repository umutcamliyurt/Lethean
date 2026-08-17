import type { EncryptedFilePayload, FileRecord, ProgressCallback, UsageResponse } from './types.js';

const isLocalDev = window.location.port === '5500';
const BASE_URL = isLocalDev ? 'http://localhost:8000' : '';

if (!isLocalDev && window.isSecureContext !== true) {
  throw new Error('This app must be served over HTTPS — refusing to run over an insecure connection.');
}

let vaultId: string | null = null;
let accessToken: string | null = null;

export function setVaultId(id: string | null): void {
  vaultId = id;
}

export function setAccessToken(token: string | null): void {
  accessToken = token || null;
}

export function clearCredentials(): void {
  vaultId = null;
  accessToken = null;
}

function authHeaders(vaultIdOverride?: string): Record<string, string> {
  const id = vaultIdOverride ?? vaultId;
  return id ? { Authorization: `Bearer ${id}` } : {};
}

function privateFetch(input: string, init: RequestInit = {}): Promise<Response> {
  return fetch(input, { cache: 'no-store', referrerPolicy: 'no-referrer', ...init });
}

function assertSafeId(id: string): string {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) {
    throw new Error('Invalid file id');
  }
  return id;
}

interface ErrorDetailBody {
  detail?: string;
}

async function checkOk(res: Response, label: string): Promise<Response> {
  if (!res.ok) {
    let detail: string = res.statusText;
    try {
      const body = (await res.json()) as ErrorDetailBody;
      detail = body.detail ?? detail;
    } catch {
    }
    throw new Error(`${label}: ${detail}`);
  }
  return res;
}

const STALL_TIMEOUT_MS = 20000;
const RESPONSE_WAIT_TIMEOUT_MS = 120000;

export async function uploadFile(
  encrypted: EncryptedFilePayload,
  onProgress?: ProgressCallback,
  signal?: AbortSignal,
  vaultIdOverride?: string,
  accessTokenOverride?: string
): Promise<FileRecord> {
  const form = new FormData();
  form.append('content_iv', encrypted.contentIv);
  form.append('encrypted_metadata', encrypted.encryptedMetadata);
  form.append('metadata_iv', encrypted.metadataIv);
  form.append('wrapped_file_key', encrypted.wrappedFileKey);
  form.append('wrap_iv', encrypted.wrapIv);
  form.append('blob', new Blob([encrypted.ciphertext as BlobPart]));

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE_URL}/files`);
    for (const [k, v] of Object.entries(authHeaders(vaultIdOverride))) xhr.setRequestHeader(k, v);
    const tokenToSend = accessTokenOverride !== undefined ? accessTokenOverride : accessToken;
    if (tokenToSend) xhr.setRequestHeader('X-Access-Token', tokenToSend);

    let stalled = false;
    let watchdog: ReturnType<typeof setTimeout>;

    const armWatchdog = (timeoutMs: number) => {
      clearTimeout(watchdog);
      watchdog = setTimeout(() => {
        stalled = true;
        xhr.abort();
      }, timeoutMs);
    };
    const clearWatchdog = () => clearTimeout(watchdog);

    armWatchdog(STALL_TIMEOUT_MS);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
      if (e.lengthComputable && e.loaded >= e.total) {
        armWatchdog(RESPONSE_WAIT_TIMEOUT_MS);
      } else {
        armWatchdog(STALL_TIMEOUT_MS);
      }
    };

    xhr.onload = () => {
      clearWatchdog();
      if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText) as FileRecord);
      else {
        let detail: string = xhr.statusText;
        try {
          const body = JSON.parse(xhr.responseText) as ErrorDetailBody;
          detail = body.detail ?? detail;
        } catch {
        }
        reject(new Error(detail));
      }
    };

    xhr.onabort = () => {
      clearWatchdog();
      if (stalled) {
        reject(new Error('Upload stalled (no progress) — will retry'));
      } else {
        reject(new DOMException('Upload cancelled', 'AbortError'));
      }
    };

    if (signal) {
      if (signal.aborted) { xhr.abort(); return; }
      signal.addEventListener('abort', () => xhr.abort());
    }

    xhr.onerror = () => {
      clearWatchdog();
      reject(new Error('network error'));
    };

    xhr.send(form);
  });
}

export interface ListFilesOptions {
  offset?: number;
  limit?: number | null;
}

export async function listFiles({ offset = 0, limit = null }: ListFilesOptions = {}): Promise<FileRecord[]> {
  const params = new URLSearchParams();
  if (offset) params.set('offset', String(offset));
  if (limit != null) params.set('limit', String(limit));
  const qs = params.toString();
  const res = await privateFetch(`${BASE_URL}/files${qs ? `?${qs}` : ''}`, { headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Could not load files');
  return res.json() as Promise<FileRecord[]>;
}

export async function getUsage(): Promise<UsageResponse> {
  const res = await privateFetch(`${BASE_URL}/usage`, { headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Could not load usage');
  return res.json() as Promise<UsageResponse>;
}

const MAX_TRUSTED_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024;

export async function downloadContent(fileId: string, onProgress?: ProgressCallback): Promise<Uint8Array> {
  assertSafeId(fileId);
  const res = await privateFetch(`${BASE_URL}/files/${fileId}/blob`, { headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Download failed');

  const declared = Number(res.headers.get('Content-Length')) || 0;
  const total = declared > 0 && declared <= MAX_TRUSTED_CONTENT_LENGTH ? declared : 0;
  if (!onProgress || !total || !res.body) {
    return new Uint8Array(await res.arrayBuffer());
  }

  const out = new Uint8Array(total);
  const reader = res.body.getReader();
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (received + value.length > total) {
      throw new Error('Download failed: response exceeded declared length');
    }
    out.set(value, received);
    received += value.length;
    onProgress(received / total);
  }
  return received === total ? out : out.subarray(0, received);
}

export async function deleteFile(fileId: string): Promise<void> {
  assertSafeId(fileId);
  const res = await privateFetch(`${BASE_URL}/files/${fileId}`, { method: 'DELETE', headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Delete failed');
}

export async function wipeVault(vaultIdToWipe: string): Promise<void> {
  await sendShredSignal(vaultIdToWipe);
  clearCredentials();
}

export async function sendShredSignal(targetVaultId: string): Promise<void> {
  const res = await privateFetch(`${BASE_URL}/vault`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${targetVaultId}` },
    credentials: 'omit',
  });
  await checkOk(res, 'Shred signal failed');
}