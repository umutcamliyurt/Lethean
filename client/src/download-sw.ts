
(() => {
  interface Job {
    url: string;
    headers: Record<string, string>;
    fileKeyRaw: Uint8Array;
    contentIv: string;
    compressed: boolean;
    unpaddedSize: number | null;
    chunkSize: number | null;
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
  const jobs = new Map<string, Job>();

  scope.addEventListener('install', (e) => e.waitUntil(scope.skipWaiting()));

  scope.addEventListener('message', (e) => {
    const msg = e.data as { type?: string; token?: string; job?: Omit<Job, 'port' | 'expires'> };
    if (msg?.type !== 'prepare' || !msg.token || !msg.job || !e.ports[0]) return;
    const now = Date.now();
    for (const [t, j] of jobs) if (j.expires < now) jobs.delete(t);
    jobs.set(msg.token, { ...msg.job, port: e.ports[0], expires: now + JOB_TTL_MS });
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
    e.respondWith(serve(job));
  });

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

    const key = await crypto.subtle.importKey('raw', job.fileKeyRaw as unknown as BufferSource, 'AES-GCM', false, ['decrypt']);
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

    const ascii = job.filename.replace(/[^\x20-\x7e]|["\\]/g, '_');
    const headers = new Headers({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(job.filename)}`,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    if (!job.compressed && job.unpaddedSize != null) headers.set('Content-Length', String(job.unpaddedSize));
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
    let buf = new Uint8Array(sealedSize);
    let filled = 0;
    let index = 0;

    async function open(controller: TransformStreamDefaultController<Uint8Array>): Promise<void> {
      if (index >= count) throw new Error('File has unexpected trailing data');
      const iv = new Uint8Array(12);
      iv.set(prefix, 0);
      new DataView(iv.buffer).setUint32(8, index, false);
      const aad = new Uint8Array(5);
      new DataView(aad.buffer).setUint32(0, index, false);
      aad[4] = index === count - 1 ? 1 : 0;
      let plain: Uint8Array;
      try {
        plain = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, buf as unknown as BufferSource));
      } catch {
        throw new Error('File is corrupt or has been tampered with');
      }
      controller.enqueue(plain.subarray(0, Math.min(chunkSize, total - index * chunkSize)));
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
          plain = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: fromBase64(job.contentIv) as unknown as BufferSource, tagLength: 128 }, key, ct as unknown as BufferSource));
        } catch {
          throw new Error('File is corrupt or has been tampered with');
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
