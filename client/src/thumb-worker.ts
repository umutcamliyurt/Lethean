import { decryptToStream, streamToBlob } from './crypto-encrypt-core.js';
import { makeThumbnail } from './thumbnail-core.js';
import type { FileMeta } from './types.js';
import type { ContentKey } from './crypto-encrypt-core.js';

interface ThumbJob {
  id: number;
  request: { url: string; headers: Record<string, string> };
  contentKey: ContentKey;
  contentIv: string;
  meta: Pick<FileMeta, 'mime' | 'compressed' | 'unpaddedSize' | 'chunkSize' | 'size'>;
  target: number;
}

self.onmessage = async (event: MessageEvent<ThumbJob>) => {
  const job = event.data;
  try {
    if (typeof OffscreenCanvas === 'undefined' || typeof createImageBitmap === 'undefined') {
      self.postMessage({ id: job.id, ok: false, unsupported: true });
      return;
    }
    const res = await fetch(job.request.url, { headers: job.request.headers, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
    const image = await streamToBlob(decryptToStream(job.contentKey, job.contentIv, res.body, job.meta), job.meta.mime);
    const thumb = await makeThumbnail(image, job.target, (w, h) => new OffscreenCanvas(w, h));
    self.postMessage({ id: job.id, ok: true, thumb });
  } catch (err) {
    self.postMessage({ id: job.id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};

export {};
