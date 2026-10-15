
import { fileBlobRequest, openDownloadStream } from './api.js';
import { decryptToStream, streamToBlob, toContentKey } from './crypto-encrypt-core.js';
import { fileKeyCache } from './state.js';
import { makeThumbnail } from './thumbnail-core.js';
import type { FileMeta, FileRecord } from './types.js';

const THUMB_TARGET = Math.round(Math.min(512, 240 * Math.min(2, window.devicePixelRatio || 1)));
const THUMB_CONCURRENCY = Math.max(1, Math.min(3, (navigator.hardwareConcurrency || 2) - 1));
const CACHE_BUDGET_BYTES = 48 * 1024 * 1024;
const MAX_SOURCE_BYTES = 64 * 1024 * 1024;

interface Entry { url: string; bytes: number; refs: number }

const cache = new Map<string, Entry>();
let cacheBytes = 0;
const inflight = new Map<string, Promise<string | null>>();
const failed = new Set<string>();

export function canThumbnail(record: FileRecord, meta: FileMeta): boolean {
  const size = typeof meta.unpaddedSize === 'number' ? meta.unpaddedSize : record.size ?? 0;
  return size <= MAX_SOURCE_BYTES && !failed.has(record.id);
}

export async function acquireThumbnail(record: FileRecord, meta: FileMeta, stillWanted: () => boolean): Promise<string | null> {
  const id = record.id;
  const hit = cache.get(id);
  if (hit) {
    cache.delete(id);
    cache.set(id, hit);
    hit.refs++;
    return hit.url;
  }
  if (!canThumbnail(record, meta)) return null;

  let job = inflight.get(id);
  if (!job) {
    const generation = cacheGeneration;
    job = schedule(() => (stillWanted() && generation === cacheGeneration ? generate(record, meta) : Promise.resolve(null)))
      .then((blob) => (blob && generation === cacheGeneration ? store(id, blob) : null))
      .catch(() => { failed.add(id); return null; })
      .finally(() => inflight.delete(id));
    inflight.set(id, job);
  }
  const url = await job;
  const entry = url ? cache.get(id) : undefined;
  if (!entry) return null;
  entry.refs++;
  return entry.url;
}

export function releaseThumbnail(id: string): void {
  const entry = cache.get(id);
  if (entry && entry.refs > 0) entry.refs--;
  evict();
}

export function dropThumbnail(id: string): void {
  const entry = cache.get(id);
  if (!entry) return;
  cache.delete(id);
  cacheBytes -= entry.bytes;
  URL.revokeObjectURL(entry.url);
}

let cacheGeneration = 0;

export function clearThumbnails(): void {
  cacheGeneration++;
  inflight.clear();
  for (const entry of cache.values()) URL.revokeObjectURL(entry.url);
  cache.clear();
  cacheBytes = 0;
  failed.clear();
  queue.length = 0;
}

function store(id: string, blob: Blob): string {
  const url = URL.createObjectURL(blob);
  cache.set(id, { url, bytes: blob.size, refs: 0 });
  cacheBytes += blob.size;
  evict();
  return url;
}

function evict(): void {
  if (cacheBytes <= CACHE_BUDGET_BYTES) return;
  for (const [id, entry] of cache) {
    if (cacheBytes <= CACHE_BUDGET_BYTES) break;
    if (entry.refs > 0) continue;
    cache.delete(id);
    cacheBytes -= entry.bytes;
    URL.revokeObjectURL(entry.url);
  }
}

const queue: Array<() => void> = [];
let running = 0;

function schedule<T>(task: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const run = () => {
      running++;
      task().then(resolve, reject).finally(() => {
        running--;
        queue.shift()?.();
      });
    };
    if (running < THUMB_CONCURRENCY) run();
    else queue.push(run);
  });
}

async function decryptOriginal(record: FileRecord, meta: FileMeta): Promise<Blob> {
  const { stream } = await openDownloadStream(record.id);
  return streamToBlob(decryptToStream(fileKeyCache.get(record.id)!, record.content_iv, stream, meta), meta.mime);
}

let workers: Worker[] | null = null;
let workersUnsupported = false;
const idleWorkers: Worker[] = [];
let nextJobId = 1;

function getWorker(): Worker | null {
  if (workersUnsupported) return null;
  if (!workers) {
    try {
      workers = Array.from({ length: THUMB_CONCURRENCY }, () =>
        new Worker(new URL('./thumb-worker.js', import.meta.url), { type: 'module' }));
      idleWorkers.push(...workers);
    } catch {
      workersUnsupported = true;
      return null;
    }
  }
  return idleWorkers.pop() ?? null;
}

async function generate(record: FileRecord, meta: FileMeta): Promise<Blob | null> {
  if (meta.mime === 'image/svg+xml') {
    return decryptOriginal(record, meta);
  }
  const worker = getWorker();
  if (worker) {
    const result = await runInWorker(worker, record, meta);
    idleWorkers.push(worker);
    if (result !== 'unsupported') return result;
    workersUnsupported = true;
  }
  const image = await decryptOriginal(record, meta);
  return makeThumbnail(image, THUMB_TARGET, (w, h) => Object.assign(document.createElement('canvas'), { width: w, height: h }));
}

async function runInWorker(worker: Worker, record: FileRecord, meta: FileMeta): Promise<Blob | 'unsupported'> {
  const id = nextJobId++;
  const contentKey = await toContentKey(fileKeyCache.get(record.id)!);
  return new Promise((resolve, reject) => {
    const onMessage = (e: MessageEvent<{ id: number; ok: boolean; thumb?: Blob; error?: string; unsupported?: boolean }>) => {
      if (e.data.id !== id) return;
      worker.removeEventListener('message', onMessage);
      worker.removeEventListener('error', onError);
      if (e.data.ok && e.data.thumb) resolve(e.data.thumb);
      else if (e.data.unsupported) resolve('unsupported');
      else reject(new Error(e.data.error || 'Thumbnail failed'));
    };
    const onError = () => {
      worker.removeEventListener('message', onMessage);
      worker.removeEventListener('error', onError);
      resolve('unsupported');
    };
    worker.addEventListener('message', onMessage);
    worker.addEventListener('error', onError);
    worker.postMessage({
      id,
      request: fileBlobRequest(record.id),
      contentKey,
      contentIv: record.content_iv,
      meta: { mime: meta.mime, compressed: meta.compressed, unpaddedSize: meta.unpaddedSize, chunkSize: meta.chunkSize, size: meta.size },
      target: THUMB_TARGET,
    });
  });
}
