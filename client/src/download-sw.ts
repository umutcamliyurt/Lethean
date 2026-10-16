
(() => {
  interface Job {
    url: string;
    headers: Record<string, string>;
    contentKeyRaw: Uint8Array;
    format: number;
    contentIv: string;
    compressed: boolean;
    unpaddedSize: number | null;
    chunkSize: number | null;
    size: number | null;
    filename: string;
    port: MessagePort;
    expires: number;
  }

  interface ExtendableEvt { waitUntil(p: Promise<unknown>): void }
  interface FetchEvt extends ExtendableEvt { request: Request; respondWith(r: Response | Promise<Response>): void }
  interface MessageEvt extends ExtendableEvt { data: unknown; ports: readonly MessagePort[] }
  interface Scope {
    registration: { scope: string };
    addEventListener(type: 'install' | 'activate', fn: (e: ExtendableEvt) => void): void;
    addEventListener(type: 'message', fn: (e: MessageEvt) => void): void;
    addEventListener(type: 'fetch', fn: (e: FetchEvt) => void): void;
    skipWaiting(): Promise<void>;
  }

  const scope = self as unknown as Scope;
  const ROUTE = '__download/';
  const JOB_TTL_MS = 60_000;
  const GCM_TAG = 16;
  const FORMAT_LEGACY = 1;
  const FORMAT_V2 = 2;
  const enc = new TextEncoder();
  const AAD_CONTENT_V2 = enc.encode('lethean|content|v2');
  const AAD_CHUNK_V2 = enc.encode('lethean|chunk|v2|');

  const CHUNK_SIZE_V2 = 32 * 1024 * 1024;
  const PADDING_BUCKETS = [16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576].map((k) => k * 1024);
  const PADDING_STEP_BEYOND_MAX = 256 * 1024 * 1024;
  function paddedSize(n: number): number {
    for (const b of PADDING_BUCKETS) if (n <= b) return b;
    return Math.ceil(n / PADDING_STEP_BEYOND_MAX) * PADDING_STEP_BEYOND_MAX;
  }
  const isSize = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  function assertZero(bytes: Uint8Array, from: number): void {
    for (let i = from; i < bytes.length; i++) if (bytes[i] !== 0) throw new Error('File is corrupt (padding)');
  }

  function chunkAad(format: number, index: number, isLast: boolean): Uint8Array {
    const head = format === FORMAT_V2 ? AAD_CHUNK_V2 : new Uint8Array(0);
    const aad = new Uint8Array(head.length + 5);
    aad.set(head, 0);
    new DataView(aad.buffer).setUint32(head.length, index, false);
    aad[head.length + 4] = isLast ? 1 : 0;
    return aad;
  }
  const jobs = new Map<string, Job>();

  scope.addEventListener('install', (e) => e.waitUntil(scope.skipWaiting()));

  const TOKEN_RE = /^[0-9a-f]{32}$/;
  let purgeTimer: ReturnType<typeof setTimeout> | null = null;

  function purgeExpired(): void {
    const now = Date.now();
    for (const [t, j] of jobs) if (j.expires <= now) jobs.delete(t);
    if (purgeTimer) { clearTimeout(purgeTimer); purgeTimer = null; }
    if (jobs.size) purgeTimer = setTimeout(purgeExpired, JOB_TTL_MS);
  }

  scope.addEventListener('message', (e) => {
    const msg = e.data as { type?: string; token?: string; job?: Omit<Job, 'port' | 'expires'> };
    if (msg?.type === 'cancel') {
      if (typeof msg.token === 'string') jobs.delete(msg.token);
      purgeExpired();
      return;
    }
    if (msg?.type === 'clear') {
      jobs.clear();
      purgeExpired();
      return;
    }
    if (msg?.type !== 'prepare' || typeof msg.token !== 'string' || !TOKEN_RE.test(msg.token) || !msg.job || !e.ports[0]) return;
    if (msg.job.format !== FORMAT_LEGACY && msg.job.format !== FORMAT_V2) return;
    if (!(msg.job.contentKeyRaw instanceof Uint8Array) || msg.job.contentKeyRaw.length !== 32) return;
    if (msg.job.unpaddedSize != null && !isSize(msg.job.unpaddedSize)) return;
    if (msg.job.chunkSize != null && (!isSize(msg.job.chunkSize) || msg.job.chunkSize === 0)) return;
    if (msg.job.format === FORMAT_V2) {
      if (!isSize(msg.job.size) || !isSize(msg.job.unpaddedSize)) return;
      if (msg.job.chunkSize != null && (msg.job.chunkSize !== CHUNK_SIZE_V2 || msg.job.compressed || msg.job.unpaddedSize !== msg.job.size)) return;
      if (msg.job.chunkSize == null && !msg.job.compressed && msg.job.unpaddedSize !== msg.job.size) return;
    }
    jobs.set(msg.token, { ...msg.job, port: e.ports[0], expires: Date.now() + JOB_TTL_MS });
    purgeExpired();
    e.ports[0].postMessage({ type: 'ready' });
  });

  scope.addEventListener('fetch', (e) => {
    const url = new URL(e.request.url);
    const base = new URL(ROUTE, scope.registration.scope).pathname;
    if (!url.pathname.startsWith(base)) return;
    const token = url.pathname.slice(base.length).split('/')[0] ?? '';
    const job = jobs.get(token);
    if (!job) return;
    jobs.delete(token);
    if (job.expires <= Date.now()) return;
    e.respondWith(serve(job).catch((err) => {
      job.port.postMessage({ type: 'error', message: (err as Error)?.message || 'Download failed' });
      return new Response(null, { status: 500 });
    }));
  });

  function wellFormed(s: string): string {
    return String(s).replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '�');
  }

  async function serve(job: Job): Promise<Response> {
    const { port } = job;
    port.postMessage({ type: 'started' });
    let res: Response;
    try {
      res = await fetch(job.url, { headers: job.headers, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    } catch (err) {
      port.postMessage({ type: 'error', message: 'Network error' });
      return new Response(null, { status: 502 });
    }
    if (!res.ok || !res.body) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch {  }
      port.postMessage({ type: 'error', message: detail || `HTTP ${res.status}` });
      return new Response(null, { status: res.status || 502 });
    }

    const key = await crypto.subtle.importKey('raw', job.contentKeyRaw as unknown as BufferSource, 'AES-GCM', false, ['decrypt']);
    const plaintext = res.body.pipeThrough(job.chunkSize ? chunkedDecryptor(job, key) : wholeFileDecryptor(job, key));

    const reader = plaintext.getReader();
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) { controller.close(); port.postMessage({ type: 'done' }); return; }
          controller.enqueue(value);
        } catch (err) {
          port.postMessage({ type: 'error', message: (err as Error).message || 'Download failed' });
          controller.error(err);
        }
      },
      cancel(reason) {
        port.postMessage({ type: 'cancelled' });
        return reader.cancel(reason);
      },
    });

    const filename = wellFormed(job.filename || 'download');
    const ascii = filename.replace(/[^\x20-\x7e]|["\\]/g, '_');
    const headers = new Headers({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    if (job.format === FORMAT_V2 && job.size != null) headers.set('Content-Length', String(job.size));
    else if (!job.compressed && job.unpaddedSize != null) headers.set('Content-Length', String(job.unpaddedSize));
    return new Response(body, { headers });
  }

  function fromBase64(b64: string): Uint8Array {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }

  function chunkedDecryptor(job: Job, key: CryptoKey): TransformStream<Uint8Array, Uint8Array> {
    const chunkSize = job.chunkSize!;
    const total = job.unpaddedSize ?? 0;
    const sealedSize = chunkSize + GCM_TAG;
    const count = Math.max(1, Math.ceil(total / chunkSize));
    const prefix = fromBase64(job.contentIv);
    if (prefix.length !== 8) throw new Error('Corrupt chunked file header');
    let buf = new Uint8Array(sealedSize);
    let filled = 0;
    let index = 0;

    async function open(controller: TransformStreamDefaultController<Uint8Array>): Promise<void> {
      if (index >= count) throw new Error('File has unexpected trailing data');
      const iv = new Uint8Array(12);
      iv.set(prefix, 0);
      new DataView(iv.buffer).setUint32(8, index, false);
      const aad = chunkAad(job.format, index, index === count - 1);
      let plain: Uint8Array;
      try {
        plain = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv, additionalData: aad as unknown as BufferSource, tagLength: 128 }, key, buf as unknown as BufferSource));
      } catch {
        throw new Error('File is corrupt or has been tampered with');
      }
      const take = Math.min(chunkSize, total - index * chunkSize);
      if (job.format === FORMAT_V2) assertZero(plain, take);
      controller.enqueue(plain.subarray(0, take));
      index++;
      buf = new Uint8Array(sealedSize);
      filled = 0;
    }

    return new TransformStream<Uint8Array, Uint8Array>({
      async transform(bytes, controller) {
        let off = 0;
        while (off < bytes.length) {
          const take = Math.min(bytes.length - off, sealedSize - filled);
          buf.set(bytes.subarray(off, off + take), filled);
          filled += take;
          off += take;
          if (filled === sealedSize) await open(controller);
        }
      },
      flush() {
        if (filled !== 0 || index !== count) throw new Error('File is truncated or corrupt');
      },
    }, undefined, { highWaterMark: 1 });
  }

  function wholeFileDecryptor(job: Job, key: CryptoKey): TransformStream<Uint8Array, Uint8Array> {
    const parts: Uint8Array[] = [];
    return new TransformStream<Uint8Array, Uint8Array>({
      transform(bytes) { parts.push(bytes); },
      async flush(controller) {
        const ct = new Uint8Array(await new Blob(parts as unknown as BlobPart[]).arrayBuffer());
        parts.length = 0;
        let plain: Uint8Array;
        try {
          const params: AesGcmParams = { name: 'AES-GCM', iv: fromBase64(job.contentIv) as unknown as BufferSource, tagLength: 128 };
          if (job.format === FORMAT_V2) params.additionalData = AAD_CONTENT_V2 as unknown as BufferSource;
          plain = new Uint8Array(await crypto.subtle.decrypt(params, key, ct as unknown as BufferSource));
        } catch {
          throw new Error('File is corrupt or has been tampered with');
        }
        if (job.format === FORMAT_V2) {
          const n = job.unpaddedSize!;
          if (plain.length !== paddedSize(n)) throw new Error('File is corrupt (padding)');
          assertZero(plain, n);
          plain = plain.subarray(0, n);
          if (job.compressed) {
            const limit = job.size!;
            const reader = new Blob([plain as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
            let total = 0;
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              total += value.length;
              if (total > limit) {
                await reader.cancel().catch(() => {});
                throw new Error('File is corrupt (decompressed size mismatch)');
              }
              controller.enqueue(value);
            }
            if (total !== limit) throw new Error('File is corrupt (decompressed size mismatch)');
            return;
          }
          controller.enqueue(plain);
          return;
        }
        if (job.unpaddedSize != null && job.unpaddedSize <= plain.length) plain = plain.subarray(0, job.unpaddedSize);
        if (job.compressed) {
          plain = new Uint8Array(await new Response(
            new Blob([plain as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer());
        }
        controller.enqueue(plain);
      },
    });
  }
})();
