import type {
  ChunkedFilePayload, DuressConfig, EncryptedFilePayload, FileRecord, ProgressCallback, UsageResponse, ShareCreateResponse, ShareRecord,
} from './types.js';
import { isTauri, resolveBaseUrl, isLocalDevPage } from './platform.js';

const isLocalDev = isLocalDevPage();
const BASE_URL = resolveBaseUrl();

if (!isLocalDev && !isTauri() && window.isSecureContext !== true) {
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
    const err = new Error(`${label}: ${detail}`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  return res;
}

export function isMissingEndpoint(err: unknown): boolean {
  const status = (err as { status?: number } | null)?.status;
  return status === 404 || status === 405;
}

const STALL_TIMEOUT_MS = 20000;
const RESPONSE_WAIT_TIMEOUT_MS = 120000;

interface XhrOptions {
  method: string;
  url: string;
  body?: XMLHttpRequestBodyInit | null;
  headers?: Record<string, string>;
  onProgress?: ProgressCallback;
  signal?: AbortSignal;
  vaultIdOverride?: string;
  accessTokenOverride?: string;
}

function sendXhr(o: XhrOptions): Promise<XMLHttpRequest> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(o.method, o.url);
    for (const [k, v] of Object.entries(authHeaders(o.vaultIdOverride))) xhr.setRequestHeader(k, v);
    const tokenToSend = o.accessTokenOverride !== undefined ? o.accessTokenOverride : accessToken;
    if (tokenToSend) xhr.setRequestHeader('X-Access-Token', tokenToSend);
    for (const [k, v] of Object.entries(o.headers ?? {})) xhr.setRequestHeader(k, v);

    let stalled = false;
    let watchdog: ReturnType<typeof setTimeout>;
    const { signal, onProgress } = o;

    const armWatchdog = (timeoutMs: number) => {
      clearTimeout(watchdog);
      watchdog = setTimeout(() => {
        stalled = true;
        xhr.abort();
      }, timeoutMs);
    };
    const onAbortSignal = () => xhr.abort();
    const cleanup = () => {
      clearTimeout(watchdog);
      signal?.removeEventListener('abort', onAbortSignal);
      xhr.upload.onprogress = null;
      xhr.onload = null;
      xhr.onabort = null;
      xhr.onerror = null;
    };

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
      cleanup();
      if (xhr.status >= 200 && xhr.status < 300) { resolve(xhr); return; }
      let detail: string = xhr.statusText;
      try {
        const body = JSON.parse(xhr.responseText) as ErrorDetailBody;
        detail = body.detail ?? detail;
      } catch {
      }
      if (xhr.status === 413) detail = 'Rejected by the server as too large (413). ' + detail;
      const err = new Error(detail) as Error & { status?: number };
      err.status = xhr.status;
      reject(err);
    };

    xhr.onabort = () => {
      cleanup();
      if (stalled) {
        reject(new Error('Upload stalled (no progress) \u2014 will retry'));
      } else {
        reject(new DOMException('Upload cancelled', 'AbortError'));
      }
    };

    if (signal) {
      if (signal.aborted) { cleanup(); reject(new DOMException('Upload cancelled', 'AbortError')); return; }
      signal.addEventListener('abort', onAbortSignal, { once: true });
    }

    xhr.onerror = () => {
      cleanup();
      reject(new Error('network error'));
    };

    xhr.send(o.body ?? null);
  });
}

const SINGLE_REQUEST_MAX_BYTES = 32 * 1024 * 1024 + 1024;
const MULTIPART_PART_BYTES = 32 * 1024 * 1024 + 16;

export async function uploadFile(
  encrypted: EncryptedFilePayload | ChunkedFilePayload,
  onProgress?: ProgressCallback,
  signal?: AbortSignal,
  vaultIdOverride?: string,
  accessTokenOverride?: string
): Promise<FileRecord> {
  const common = { signal, vaultIdOverride, accessTokenOverride };

  if ('ciphertext' in encrypted && byteLength(encrypted.ciphertext) <= SINGLE_REQUEST_MAX_BYTES) {
    const form = new FormData();
    form.append('content_iv', encrypted.contentIv);
    form.append('encrypted_metadata', encrypted.encryptedMetadata);
    form.append('metadata_iv', encrypted.metadataIv);
    form.append('wrapped_file_key', encrypted.wrappedFileKey);
    form.append('wrap_iv', encrypted.wrapIv);
    form.append('blob', asBlob(encrypted.ciphertext));
    const xhr = await sendXhr({ method: 'POST', url: `${BASE_URL}/files`, body: form, onProgress, ...common });
    return JSON.parse(xhr.responseText) as FileRecord;
  }

  const payload: ChunkedFilePayload = 'readPart' in encrypted ? encrypted : wrapCiphertextAsParts(encrypted);
  const totalBytes = payload.totalSize;

  let received = new Set<number>();
  if (payload.uploadId && !isSafeUploadId(payload.uploadId)) payload.uploadId = undefined;
  if (payload.uploadId) {
    try {
      const st = await sendXhr({ method: 'GET', url: `${BASE_URL}/files/uploads/${payload.uploadId}`, ...common });
      received = new Set((JSON.parse(st.responseText) as { received: number[] }).received);
    } catch (err) {
      if ((err as { status?: number }).status === 404) { payload.uploadId = undefined; } else throw err;
    }
  }
  if (!payload.uploadId) {
    received.clear();
    let init: XMLHttpRequest;
    try {
      init = await sendXhr({
      method: 'POST',
      url: `${BASE_URL}/files/uploads`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content_iv: payload.contentIv,
        encrypted_metadata: payload.encryptedMetadata,
        metadata_iv: payload.metadataIv,
        wrapped_file_key: payload.wrappedFileKey,
        wrap_iv: payload.wrapIv,
        part_count: payload.partCount,
        part_size: payload.partSize,
        total_size: totalBytes,
      }),
      ...common,
      });
    } catch (err) {
      if (!isMissingEndpoint(err)) throw err;

      return uploadSingleRequest(payload, onProgress, common);
    }
    const uploadId = (JSON.parse(init.responseText) as { upload_id: unknown }).upload_id;
    if (!isSafeUploadId(uploadId)) throw new Error('Server returned an invalid upload id');
    payload.uploadId = uploadId;
  }

  let doneBytes = 0;
  for (let i = 0; i < payload.partCount; i++) {
    const partLen = i === payload.partCount - 1 ? totalBytes - i * payload.partSize : payload.partSize;
    if (received.has(i)) { doneBytes += partLen; continue; }
    const part = await payload.readPart(i);
    await sendXhr({
      method: 'PUT',
      url: `${BASE_URL}/files/uploads/${payload.uploadId}/parts/${i}`,
      headers: { 'Content-Type': 'application/octet-stream' },
      body: part as unknown as XMLHttpRequestBodyInit,
      onProgress: onProgress ? (f) => onProgress((doneBytes + f * part.length) / totalBytes) : undefined,
      ...common,
    });
    doneBytes += part.length;
    onProgress?.(doneBytes / totalBytes);
  }

  const done = await sendXhr({ method: 'POST', url: `${BASE_URL}/files/uploads/${payload.uploadId}/complete`, ...common });
  return JSON.parse(done.responseText) as FileRecord;
}

async function uploadSingleRequest(
  payload: ChunkedFilePayload,
  onProgress: ProgressCallback | undefined,
  common: { signal?: AbortSignal; vaultIdOverride?: string; accessTokenOverride?: string }
): Promise<FileRecord> {
  const parts: Blob[] = [];
  for (let i = 0; i < payload.partCount; i++) parts.push(new Blob([(await payload.readPart(i)) as BlobPart]));
  const form = new FormData();
  form.append('content_iv', payload.contentIv);
  form.append('encrypted_metadata', payload.encryptedMetadata);
  form.append('metadata_iv', payload.metadataIv);
  form.append('wrapped_file_key', payload.wrappedFileKey);
  form.append('wrap_iv', payload.wrapIv);
  form.append('blob', new Blob(parts));
  const xhr = await sendXhr({ method: 'POST', url: `${BASE_URL}/files`, body: form, onProgress, ...common });
  return JSON.parse(xhr.responseText) as FileRecord;
}

function byteLength(data: Uint8Array | Blob): number {
  return data instanceof Blob ? data.size : data.length;
}

function asBlob(data: Uint8Array | Blob): Blob {
  return data instanceof Blob ? data : new Blob([data as BlobPart]);
}

function wrapCiphertextAsParts(e: EncryptedFilePayload): ChunkedFilePayload {
  const { ciphertext, ...fields } = e;
  if (ciphertext instanceof Blob) return ciphertextBlobAsParts(fields, ciphertext);
  const partCount = Math.max(1, Math.ceil(ciphertext.length / MULTIPART_PART_BYTES));
  return {
    ...fields,
    partCount,
    partSize: MULTIPART_PART_BYTES,
    totalSize: ciphertext.length,
    readPart: async (i) => ciphertext.subarray(i * MULTIPART_PART_BYTES, (i + 1) * MULTIPART_PART_BYTES),
  };
}

export function ciphertextBlobAsParts(
  fields: Omit<EncryptedFilePayload, 'ciphertext'>,
  blob: Blob
): ChunkedFilePayload {
  const partCount = Math.max(1, Math.ceil(blob.size / MULTIPART_PART_BYTES));
  return {
    ...fields,
    partCount,
    partSize: MULTIPART_PART_BYTES,
    totalSize: blob.size,
    readPart: async (i) => new Uint8Array(await blob.slice(i * MULTIPART_PART_BYTES, (i + 1) * MULTIPART_PART_BYTES).arrayBuffer()),
  };
}

export const SINGLE_UPLOAD_MAX_BYTES = SINGLE_REQUEST_MAX_BYTES;

function isSafeUploadId(id: unknown): id is string {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id);
}

export async function abortUpload(uploadId: string): Promise<void> {
  if (!isSafeUploadId(uploadId)) return;
  try {
    await privateFetch(`${BASE_URL}/files/uploads/${uploadId}`, { method: 'DELETE', headers: authHeaders(), credentials: 'omit' });
  } catch {
  }
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

export async function getUsage(vaultIdOverride?: string): Promise<UsageResponse> {
  const res = await privateFetch(`${BASE_URL}/usage`, { headers: authHeaders(vaultIdOverride), credentials: 'omit' });
  await checkOk(res, 'Could not load usage');
  return res.json() as Promise<UsageResponse>;
}

const MAX_TRUSTED_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024;

async function readBodyWithProgress(res: Response, onProgress?: ProgressCallback): Promise<Uint8Array> {
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

export function fileBlobRequest(fileId: string): { url: string; headers: Record<string, string> } {
  assertSafeId(fileId);
  return { url: new URL(`${BASE_URL}/files/${fileId}/blob`, window.location.href).href, headers: authHeaders() };
}

export function shareBlobRequest(shareToken: string): { url: string; headers: Record<string, string> } {
  assertSafeShareToken(shareToken);
  return { url: new URL(`${BASE_URL}/share/${shareToken}/blob`, window.location.href).href, headers: {} };
}

export interface DownloadStream {
  stream: ReadableStream<Uint8Array>;

  total: number;
}

function bodyAsStream(res: Response, onProgress?: ProgressCallback): DownloadStream {
  if (!res.body) throw new Error('Download failed: empty response');
  const declared = Number(res.headers.get('Content-Length')) || 0;
  if (!onProgress || !declared) return { stream: res.body, total: declared };
  let received = 0;
  const counted = res.body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      received += chunk.length;
      onProgress(Math.min(1, received / declared));
      controller.enqueue(chunk);
    },
  }));
  return { stream: counted, total: declared };
}

export async function openDownloadStream(fileId: string, onProgress?: ProgressCallback, signal?: AbortSignal): Promise<DownloadStream> {
  assertSafeId(fileId);
  const res = await privateFetch(`${BASE_URL}/files/${fileId}/blob`, { headers: authHeaders(), credentials: 'omit', signal });
  await checkOk(res, 'Download failed');
  return bodyAsStream(res, onProgress);
}

export async function downloadContent(fileId: string, onProgress?: ProgressCallback, signal?: AbortSignal): Promise<Uint8Array> {
  assertSafeId(fileId);
  const res = await privateFetch(`${BASE_URL}/files/${fileId}/blob`, { headers: authHeaders(), credentials: 'omit', signal });
  await checkOk(res, 'Download failed');
  return readBodyWithProgress(res, onProgress);
}

export async function deleteFile(fileId: string, vaultIdOverride?: string): Promise<void> {
  assertSafeId(fileId);
  const res = await privateFetch(`${BASE_URL}/files/${fileId}`, { method: 'DELETE', headers: authHeaders(vaultIdOverride), credentials: 'omit' });
  await checkOk(res, 'Delete failed');
}

export interface RewrapEntry {
  fileId: string;
  wrappedFileKey: string;
  wrapIv: string;
}

export interface VaultRotateResult {
  filesMoved: number;
  tokensRebound: number;
}

export async function rotateVault(newVaultId: string, rewraps: RewrapEntry[]): Promise<VaultRotateResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...authHeaders() };
  if (accessToken) headers['X-Access-Token'] = accessToken;

  const res = await privateFetch(`${BASE_URL}/vault/rotate`, {
    method: 'POST',
    headers,
    credentials: 'omit',
    body: JSON.stringify({
      new_vault_id: newVaultId,
      rewraps: rewraps.map((r) => ({
        file_id: r.fileId,
        wrapped_file_key: r.wrappedFileKey,
        wrap_iv: r.wrapIv,
      })),
    }),
  });
  await checkOk(res, "Couldn't change vault password");
  const data = (await res.json()) as { files_moved: number; tokens_rebound: number };
  return { filesMoved: data.files_moved, tokensRebound: data.tokens_rebound };
}

export async function wipeVault(vaultIdToWipe: string): Promise<void> {
  await sendShredSignal(vaultIdToWipe);
  clearCredentials();
}

export interface RemoteDuress {
  config: DuressConfig;

  written?: boolean;
}

export async function getDuressBlob(token: string, opts: { vaultId?: string; signal?: AbortSignal } = {}): Promise<RemoteDuress> {
  const headers: Record<string, string> = { 'X-Access-Token': token };
  if (opts.vaultId) headers.Authorization = `Bearer ${opts.vaultId}`;
  const res = await privateFetch(`${BASE_URL}/duress`, { headers, credentials: 'omit', signal: opts.signal });
  await checkOk(res, 'Could not load duress settings');
  const body = (await res.json()) as { blob: string; written?: boolean };
  return { config: JSON.parse(body.blob) as DuressConfig, written: body.written };
}

export async function putDuressBlob(config: DuressConfig, shredHash: string | undefined, auth: { vaultId: string; token: string }): Promise<void> {
  const res = await privateFetch(`${BASE_URL}/duress`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${auth.vaultId}`, 'X-Access-Token': auth.token },
    credentials: 'omit',
    body: JSON.stringify({ blob: JSON.stringify(config), shred_hash: shredHash ?? null }),
  });
  await checkOk(res, 'Could not save duress settings');
}

export async function shredBySecret(secretB64: string): Promise<void> {
  const res = await privateFetch(`${BASE_URL}/vault/shred`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'omit',
    body: JSON.stringify({ secret: secretB64 }),
  });
  await checkOk(res, 'Shred signal failed');
}

export async function sendShredSignal(targetVaultId: string): Promise<void> {
  const res = await privateFetch(`${BASE_URL}/vault`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${targetVaultId}` },
    credentials: 'omit',
  });
  await checkOk(res, 'Shred signal failed');
}

function assertSafeShareToken(token: string): string {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{8,256}$/.test(token)) {
    throw new Error('Invalid share link');
  }
  return token;
}

export interface CreateShareOptions {
  maxDownloads?: number;
  expiresInSeconds?: number | null;
  allowDelete?: boolean;
}

export async function createFileShare(fileId: string, options: CreateShareOptions = {}): Promise<ShareCreateResponse> {
  assertSafeId(fileId);
  const { maxDownloads, expiresInSeconds, allowDelete = false } = options;
  const params = new URLSearchParams();
  if (maxDownloads != null) params.set('max_downloads', String(maxDownloads));
  if (expiresInSeconds != null) params.set('expires_in', String(expiresInSeconds));
  params.set('allow_delete', String(allowDelete));
  const qs = params.toString();
  const res = await privateFetch(`${BASE_URL}/files/${fileId}/share?${qs}`, {
    method: 'POST',
    headers: authHeaders(),
    credentials: 'omit',
  });
  await checkOk(res, 'Could not create share link');
  return res.json() as Promise<ShareCreateResponse>;
}

export async function revokeFileShare(fileId: string): Promise<void> {
  assertSafeId(fileId);
  const res = await privateFetch(`${BASE_URL}/files/${fileId}/share`, {
    method: 'DELETE',
    headers: authHeaders(),
    credentials: 'omit',
  });
  await checkOk(res, 'Could not revoke share link');
}

export async function getShareRecord(shareToken: string): Promise<ShareRecord> {
  assertSafeShareToken(shareToken);
  const res = await privateFetch(`${BASE_URL}/share/${shareToken}`, { credentials: 'omit' });
  await checkOk(res, 'This link is invalid or has expired');
  return res.json() as Promise<ShareRecord>;
}

export async function downloadShareContent(shareToken: string, onProgress?: ProgressCallback): Promise<Uint8Array> {
  assertSafeShareToken(shareToken);
  const res = await privateFetch(`${BASE_URL}/share/${shareToken}/blob`, { credentials: 'omit' });
  await checkOk(res, 'This link is invalid, has expired, or has no downloads left');
  return readBodyWithProgress(res, onProgress);
}

export async function deleteSharedFile(shareToken: string): Promise<void> {
  assertSafeShareToken(shareToken);
  const res = await privateFetch(`${BASE_URL}/share/${shareToken}`, {
    method: 'DELETE',
    credentials: 'omit',
  });
  await checkOk(res, "Couldn't delete this file");
}