import type { ChunkedFilePayload, EncryptedFilePayload, FileMeta } from './types.js';
import { FOLDER_MIME } from './types.js';

export function randomBytes(len: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(len));
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export function fromBase64(b64: string): Uint8Array {
  let normalized = b64.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const remainder = normalized.length % 4;
  if (remainder === 2) normalized += '==';
  else if (remainder === 3) normalized += '=';
  else if (remainder === 1) throw new Error('Invalid base64 string');

  let binary: string;
  try {
    binary = atob(normalized);
  } catch {
    throw new Error('Invalid base64 string');
  }
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function utf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function asBlobPart(bytes: Uint8Array): BlobPart {
  return bytes as unknown as BlobPart;
}

export const canCompress = typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined';

export async function compressBytes(bytes: Uint8Array): Promise<Uint8Array | null> {
  if (!canCompress) return null;
  const stream = new Blob([asBlobPart(bytes)]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const INCOMPRESSIBLE_MIME = /^(?:image\/(?:jpeg|png|gif|webp|avif|heic|heif|jxl)|video\/|audio\/(?:mpeg|mp4|aac|ogg|opus|webm|flac|x-m4a)|application\/(?:zip|gzip|x-gzip|x-7z-compressed|x-rar-compressed|vnd\.rar|x-bzip2|x-xz|zstd|x-zstd|epub\+zip|vnd\.openxmlformats-officedocument\.|vnd\.oasis\.opendocument\.))/i;

async function gzipIfSmaller(file: File, limit: number): Promise<{ chunks: Uint8Array[]; length: number } | null> {
  const reader = file.stream().pipeThrough(new CompressionStream('gzip')).getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return { chunks, length };
    length += value.length;
    if (length >= limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
}

async function readIntoPadded(file: File): Promise<{ padded: Uint8Array; length: number }> {
  const padded = new Uint8Array(paddedSize(file.size));
  const reader = file.stream().getReader();
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (length + value.length > file.size) {
      await reader.cancel().catch(() => {});
      throw new Error('File changed while it was being read');
    }
    padded.set(value, length);
    length += value.length;
  }
  return { padded, length };
}

export async function readPaddedContent(file: File): Promise<{ padded: Uint8Array; unpaddedSize: number; compressed: boolean }> {
  if (canCompress && file.size > 0 && !INCOMPRESSIBLE_MIME.test(file.type)) {
    try {
      const gz = await gzipIfSmaller(file, file.size);
      if (gz) {
        const padded = new Uint8Array(paddedSize(gz.length));
        let off = 0;
        for (const c of gz.chunks) { padded.set(c, off); off += c.length; }
        gz.chunks.length = 0;
        return { padded, unpaddedSize: gz.length, compressed: true };
      }
    } catch {
    }
  }
  const { padded, length } = await readIntoPadded(file);
  return { padded, unpaddedSize: length, compressed: false };
}

export async function decompressBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([asBlobPart(bytes)]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export const PADDING_BUCKETS = [
  16 * 1024,
  64 * 1024,
  256 * 1024,
  1024 * 1024,
  4 * 1024 * 1024,
  16 * 1024 * 1024,
  64 * 1024 * 1024,
  256 * 1024 * 1024,
  1024 * 1024 * 1024,
];
export const PADDING_STEP_BEYOND_MAX = 256 * 1024 * 1024;

export function paddedSize(n: number): number {
  for (const bucket of PADDING_BUCKETS) {
    if (n <= bucket) return bucket;
  }
  return Math.ceil(n / PADDING_STEP_BEYOND_MAX) * PADDING_STEP_BEYOND_MAX;
}

export function padToBucket(bytes: Uint8Array): Uint8Array {
  const target = paddedSize(bytes.length);
  if (target === bytes.length) return bytes;
  const padded = new Uint8Array(target);
  padded.set(bytes);
  return padded;
}

export function stripPadding(bytes: Uint8Array, realLength?: number | null): Uint8Array {
  if (typeof realLength !== 'number' || realLength < 0 || realLength > bytes.length) {
    return bytes;
  }
  return realLength === bytes.length ? bytes : bytes.subarray(0, realLength);
}

export const METADATA_PADDING_BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096];

export function paddedMetadataSize(n: number): number {
  for (const bucket of METADATA_PADDING_BUCKETS) {
    if (n <= bucket) return bucket;
  }
  const step = METADATA_PADDING_BUCKETS[METADATA_PADDING_BUCKETS.length - 1]!;
  return Math.ceil(n / step) * step;
}

export function padMetadataBytes(bytes: Uint8Array): Uint8Array {
  const target = paddedMetadataSize(bytes.length + 4);
  const out = new Uint8Array(target);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

export function unpadMetadataBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length < 4) return bytes;
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  if (len > bytes.length - 4) return bytes.subarray(4);
  return bytes.subarray(4, 4 + len);
}

export async function importAesKey(rawBytes: Uint8Array, usages: KeyUsage[] = ['encrypt', 'decrypt']): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', asBufferSource(rawBytes), 'AES-GCM', false, usages);
}

export function generateAesKeyRaw(): Uint8Array {
  return randomBytes(32);
}

export interface AesGcmEncryptResult {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

export async function aesGcmEncrypt(key: CryptoKey, plaintextBytes: Uint8Array): Promise<AesGcmEncryptResult> {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: asBufferSource(iv), tagLength: 128 }, key, asBufferSource(plaintextBytes));
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

export async function aesGcmDecrypt(key: CryptoKey, ivBytes: Uint8Array, ciphertextBytes: Uint8Array): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: asBufferSource(ivBytes), tagLength: 128 }, key, asBufferSource(ciphertextBytes));
  return new Uint8Array(plaintext);
}

export async function unwrapFileKey(
  wrappingKeyRawBytes: Uint8Array,
  wrappedFileKeyB64: string,
  wrapIvB64: string
): Promise<Uint8Array> {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['decrypt']);
  return aesGcmDecrypt(wrappingKey, fromBase64(wrapIvB64), fromBase64(wrappedFileKeyB64));
}

export async function decryptMetadata(
  fileKeyRawBytes: Uint8Array,
  encryptedMetadataB64: string,
  metadataIvB64: string
): Promise<FileMeta> {
  const fileKey = await importAesKey(fileKeyRawBytes, ['decrypt']);
  const bytes = await aesGcmDecrypt(fileKey, fromBase64(metadataIvB64), fromBase64(encryptedMetadataB64));
  return JSON.parse(new TextDecoder().decode(unpadMetadataBytes(bytes))) as FileMeta;
}

export interface EncryptedMetadata {
  encryptedMetadata: string;
  metadataIv: string;
}

export async function encryptMetadata(
  fileKeyRawBytes: Uint8Array,
  meta: FileMeta
): Promise<EncryptedMetadata> {
  const fileKey = await importAesKey(fileKeyRawBytes, ['encrypt']);
  const metadataBytes = padMetadataBytes(utf8(JSON.stringify(meta)));
  const { iv, ciphertext } = await aesGcmEncrypt(fileKey, metadataBytes);
  return { encryptedMetadata: toBase64(ciphertext), metadataIv: toBase64(iv) };
}

export const CHUNK_SIZE = 32 * 1024 * 1024;
export const GCM_TAG_BYTES = 16;
const CHUNK_IV_PREFIX_BYTES = 8;

function chunkIv(prefix: Uint8Array, index: number): Uint8Array {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(CHUNK_IV_PREFIX_BYTES, index, false);
  return iv;
}

function chunkAad(index: number, isLast: boolean): Uint8Array {
  const aad = new Uint8Array(5);
  new DataView(aad.buffer).setUint32(0, index, false);
  aad[4] = isLast ? 1 : 0;
  return aad;
}

async function decryptChunked(
  fileKey: CryptoKey,
  contentIvB64: string,
  ciphertext: Uint8Array,
  chunkSize: number,
  unpaddedSize: number
): Promise<Uint8Array> {
  const prefix = fromBase64(contentIvB64);
  if (prefix.length !== CHUNK_IV_PREFIX_BYTES) throw new Error('Corrupt chunked file header');
  const sealed = chunkSize + GCM_TAG_BYTES;
  const count = Math.max(1, Math.ceil(unpaddedSize / chunkSize));
  if (ciphertext.length !== count * sealed) throw new Error('File is truncated or corrupt');

  const out = new Uint8Array(unpaddedSize);
  for (let i = 0; i < count; i++) {
    const part = ciphertext.subarray(i * sealed, (i + 1) * sealed);
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(chunkIv(prefix, i)), additionalData: asBufferSource(chunkAad(i, i === count - 1)), tagLength: 128 },
      fileKey,
      asBufferSource(part)
    ));
    const take = Math.min(chunkSize, unpaddedSize - i * chunkSize);
    out.set(plain.subarray(0, take), i * chunkSize);
  }
  return out;
}

export function decryptChunkedStream(
  fileKeyRawBytes: Uint8Array,
  contentIvB64: string,
  source: ReadableStream<Uint8Array>,
  chunkSize: number,
  unpaddedSize: number
): ReadableStream<Uint8Array> {
  const sealedSize = chunkSize + GCM_TAG_BYTES;
  const count = Math.max(1, Math.ceil(unpaddedSize / chunkSize));
  const reader = source.getReader();
  let fileKey: CryptoKey;
  let prefix: Uint8Array;
  let index = 0;
  let pending: Uint8Array | null = null;

  async function nextBytes(): Promise<Uint8Array | null> {
    if (pending && pending.length) { const p = pending; pending = null; return p; }
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return null;
      if (value.length) return value;
    }
  }

  return new ReadableStream<Uint8Array>({
    async start() {
      prefix = fromBase64(contentIvB64);
      if (prefix.length !== CHUNK_IV_PREFIX_BYTES) throw new Error('Corrupt chunked file header');
      fileKey = await importAesKey(fileKeyRawBytes, ['decrypt']);
    },
    async pull(controller) {
      const sealed = new Uint8Array(sealedSize);
      let filled = 0;
      while (filled < sealedSize) {
        const bytes = await nextBytes();
        if (!bytes) throw new Error('File is truncated or corrupt');
        const take = Math.min(bytes.length, sealedSize - filled);
        sealed.set(bytes.subarray(0, take), filled);
        filled += take;
        if (take < bytes.length) pending = bytes.subarray(take);
      }
      const isLast = index === count - 1;
      let plain: Uint8Array;
      try {
        plain = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: asBufferSource(chunkIv(prefix, index)), additionalData: asBufferSource(chunkAad(index, isLast)), tagLength: 128 },
          fileKey,
          asBufferSource(sealed)
        ));
      } catch {
        throw new Error('File is corrupt or has been tampered with');
      }
      const take = Math.min(chunkSize, unpaddedSize - index * chunkSize);
      controller.enqueue(take === plain.length ? plain : plain.subarray(0, take));
      index++;
      if (isLast) {
        if (await nextBytes()) throw new Error('File has unexpected trailing data');
        controller.close();
        reader.releaseLock();
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  }, { highWaterMark: 1 });
}

export function decryptToStream(
  fileKeyRawBytes: Uint8Array,
  contentIvB64: string,
  source: ReadableStream<Uint8Array>,
  meta: Pick<FileMeta, 'compressed' | 'unpaddedSize' | 'chunkSize'>
): ReadableStream<Uint8Array> {
  if (meta.chunkSize) {
    if (typeof meta.unpaddedSize !== 'number') throw new Error('Corrupt chunked file metadata');
    return decryptChunkedStream(fileKeyRawBytes, contentIvB64, source, meta.chunkSize, meta.unpaddedSize);
  }
  let done = false;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (done) return;
      done = true;
      const ciphertext = new Uint8Array(await new Response(source).arrayBuffer());
      controller.enqueue(await decryptContent(fileKeyRawBytes, contentIvB64, ciphertext, meta.compressed, meta.unpaddedSize ?? null));
      controller.close();
    },
    cancel(reason) {
      return source.cancel(reason);
    },
  });
}

export async function streamToBlob(stream: ReadableStream<Uint8Array>, type = ''): Promise<Blob> {
  const parts: Blob[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(new Blob([asBlobPart(value)]));
  }
  return new Blob(parts, { type });
}

export async function decryptContent(
  fileKeyRawBytes: Uint8Array,
  contentIvB64: string,
  ciphertextBytes: Uint8Array,
  compressed = false,
  unpaddedSize: number | null = null,
  chunkSize: number | null = null
): Promise<Uint8Array> {
  const fileKey = await importAesKey(fileKeyRawBytes, ['decrypt']);
  if (chunkSize) {
    if (unpaddedSize == null) throw new Error('Corrupt chunked file metadata');
    return decryptChunked(fileKey, contentIvB64, ciphertextBytes, chunkSize, unpaddedSize);
  }
  let bytes = await aesGcmDecrypt(fileKey, fromBase64(contentIvB64), ciphertextBytes);
  bytes = stripPadding(bytes, unpaddedSize);
  return compressed ? decompressBytes(bytes) : bytes;
}

export async function encryptFile(
  wrappingKeyRawBytes: Uint8Array,
  file: File,
  parentId: string | null = null
): Promise<EncryptedFilePayload> {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['encrypt']);

  const fileKeyRaw = generateAesKeyRaw();
  const fileKey = await importAesKey(fileKeyRaw);

  const { padded: paddedContentBytes, unpaddedSize, compressed } = await readPaddedContent(file);

  const metadataBytes = padMetadataBytes(utf8(JSON.stringify({
    name: file.name,
    mime: file.type || 'application/octet-stream',
    compressed,
    unpaddedSize,
    parentId,
  })));
  const { iv: metadataIv, ciphertext: metadataCt } = await aesGcmEncrypt(fileKey, metadataBytes);

  const { iv: contentIv, ciphertext } = await aesGcmEncrypt(fileKey, paddedContentBytes);

  const { iv: wrapIv, ciphertext: wrappedKey } = await aesGcmEncrypt(wrappingKey, fileKeyRaw);

  return {
    ciphertext,
    contentIv: toBase64(contentIv),
    encryptedMetadata: toBase64(metadataCt),
    metadataIv: toBase64(metadataIv),
    wrappedFileKey: toBase64(wrappedKey),
    wrapIv: toBase64(wrapIv),
  };
}

export async function prepareChunkedFile(
  wrappingKeyRawBytes: Uint8Array,
  file: File,
  parentId: string | null = null
): Promise<ChunkedFilePayload> {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['encrypt']);
  const fileKeyRaw = generateAesKeyRaw();
  const fileKey = await importAesKey(fileKeyRaw, ['encrypt']);
  const prefix = randomBytes(CHUNK_IV_PREFIX_BYTES);

  const metadataBytes = padMetadataBytes(utf8(JSON.stringify({
    name: file.name,
    mime: file.type || 'application/octet-stream',
    compressed: false,
    unpaddedSize: file.size,
    chunkSize: CHUNK_SIZE,
    parentId,
  })));
  const { iv: metadataIv, ciphertext: metadataCt } = await aesGcmEncrypt(fileKey, metadataBytes);
  const { iv: wrapIv, ciphertext: wrappedKey } = await aesGcmEncrypt(wrappingKey, fileKeyRaw);

  const partCount = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  if (partCount > 0xffffffff) throw new Error('File is too large');

  const readPart = async (index: number): Promise<Uint8Array> => {
    const start = index * CHUNK_SIZE;
    const slice = new Uint8Array(await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer());
    let plain: Uint8Array = slice;
    if (slice.length !== CHUNK_SIZE) {
      plain = new Uint8Array(CHUNK_SIZE);
      plain.set(slice);
    }
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: asBufferSource(chunkIv(prefix, index)), additionalData: asBufferSource(chunkAad(index, index === partCount - 1)), tagLength: 128 },
      fileKey,
      asBufferSource(plain)
    );
    return new Uint8Array(sealed);
  };

  return {
    contentIv: toBase64(prefix),
    encryptedMetadata: toBase64(metadataCt),
    metadataIv: toBase64(metadataIv),
    wrappedFileKey: toBase64(wrappedKey),
    wrapIv: toBase64(wrapIv),
    partCount,
    partSize: CHUNK_SIZE + GCM_TAG_BYTES,
    totalSize: partCount * (CHUNK_SIZE + GCM_TAG_BYTES),
    readPart,
  };
}

export async function encryptFolder(
  wrappingKeyRawBytes: Uint8Array,
  name: string,
  parentId: string | null = null
): Promise<EncryptedFilePayload> {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['encrypt']);

  const fileKeyRaw = generateAesKeyRaw();
  const fileKey = await importAesKey(fileKeyRaw);

  const metadataBytes = padMetadataBytes(utf8(JSON.stringify({
    name,
    mime: FOLDER_MIME,
    isFolder: true,
    parentId,
  })));
  const { iv: metadataIv, ciphertext: metadataCt } = await aesGcmEncrypt(fileKey, metadataBytes);

  const { iv: contentIv, ciphertext } = await aesGcmEncrypt(fileKey, new Uint8Array(0));

  const { iv: wrapIv, ciphertext: wrappedKey } = await aesGcmEncrypt(wrappingKey, fileKeyRaw);

  return {
    ciphertext,
    contentIv: toBase64(contentIv),
    encryptedMetadata: toBase64(metadataCt),
    metadataIv: toBase64(metadataIv),
    wrappedFileKey: toBase64(wrappedKey),
    wrapIv: toBase64(wrapIv),
  };
}