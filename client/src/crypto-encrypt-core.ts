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

export async function aesGcmEncrypt(key: CryptoKey, plaintextBytes: Uint8Array, aad?: Uint8Array): Promise<AesGcmEncryptResult> {
  const iv = randomBytes(12);
  const params: AesGcmParams = { name: 'AES-GCM', iv: asBufferSource(iv), tagLength: 128 };
  if (aad) params.additionalData = asBufferSource(aad);
  const ciphertext = await crypto.subtle.encrypt(params, key, asBufferSource(plaintextBytes));
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

export async function aesGcmDecrypt(key: CryptoKey, ivBytes: Uint8Array, ciphertextBytes: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const params: AesGcmParams = { name: 'AES-GCM', iv: asBufferSource(ivBytes), tagLength: 128 };
  if (aad) params.additionalData = asBufferSource(aad);
  const plaintext = await crypto.subtle.decrypt(params, key, asBufferSource(ciphertextBytes));
  return new Uint8Array(plaintext);
}

export const FILE_FORMAT_LEGACY = 1;
export const FILE_FORMAT_V2 = 2;
export type FileFormat = typeof FILE_FORMAT_LEGACY | typeof FILE_FORMAT_V2;

export const FILE_KEY_BYTES = 32;
export const RECORD_BINDING_BYTES = 16;
const NODE_REF_BYTES = 16;
const NODE_REF_RE = /^[A-Za-z0-9_-]{22}$/;
const RECORD_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const WRAP_V2_MAGIC = utf8('LTH2');
const WRAP_V2_BYTES = WRAP_V2_MAGIC.length + FILE_KEY_BYTES + RECORD_BINDING_BYTES;

const HKDF_INFO_METADATA_V2 = 'lethean|file-metadata|v2';
const HKDF_INFO_CONTENT_V2 = 'lethean|file-content|v2';
const HKDF_INFO_NODE_REF_V2 = 'lethean|node-ref|v2';
const AAD_METADATA_V2 = utf8('lethean|metadata|v2|');
const AAD_CONTENT_V2 = utf8('lethean|content|v2');
const AAD_CHUNK_V2 = utf8('lethean|chunk|v2|');

export interface FileKey {
  raw: Uint8Array;
  format: FileFormat;
  binding?: Uint8Array;
}

export interface ContentKey {
  contentKeyRaw: Uint8Array;
  format: FileFormat;
}

type ContentKeyLike = FileKey | ContentKey;

export interface ParentRef {
  id: string;
  ref: string;
}

export type ContentMeta = Pick<FileMeta, 'compressed' | 'unpaddedSize' | 'chunkSize' | 'size'>;

export interface NewRecordOptions {
  from?: string;
}

function optionFields(opts: NewRecordOptions | undefined): Pick<FileMeta, 'from'> {
  return opts?.from !== undefined ? { from: opts.from } : {};
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function safeMime(type: string): string {
  return type && type.length <= 255 ? type : 'application/octet-stream';
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function assertFormat(format: unknown): asserts format is FileFormat {
  if (format !== FILE_FORMAT_LEGACY && format !== FILE_FORMAT_V2) throw new Error('Unsupported file format');
}

function assertFileKey(k: FileKey): void {
  if (!k || !(k.raw instanceof Uint8Array) || k.raw.length !== FILE_KEY_BYTES) throw new Error('Invalid file key');
  assertFormat(k.format);
  if (k.format === FILE_FORMAT_V2) {
    if (!(k.binding instanceof Uint8Array) || k.binding.length !== RECORD_BINDING_BYTES) throw new Error('Invalid file key');
  } else if (k.binding !== undefined) {
    throw new Error('Invalid file key');
  }
}

export function newFileKey(): FileKey {
  return { raw: generateAesKeyRaw(), format: FILE_FORMAT_V2, binding: randomBytes(RECORD_BINDING_BYTES) };
}

export function rebindFileKey(k: FileKey): FileKey {
  assertFileKey(k);
  if (k.format !== FILE_FORMAT_V2) return k;
  return { raw: k.raw, format: FILE_FORMAT_V2, binding: randomBytes(RECORD_BINDING_BYTES) };
}

export function fileKeyFromShareParams(rawB64: string, version: string | null, bindingB64: string | null): FileKey {
  const raw = fromBase64(rawB64);
  let key: FileKey;
  if (version === null) {
    if (bindingB64 !== null) throw new Error('Malformed share link');
    key = { raw, format: FILE_FORMAT_LEGACY };
  } else if (version === String(FILE_FORMAT_V2)) {
    if (bindingB64 === null) throw new Error('Malformed share link');
    key = { raw, format: FILE_FORMAT_V2, binding: fromBase64(bindingB64) };
  } else {
    throw new Error('This share link needs a newer version of the app');
  }
  assertFileKey(key);
  return key;
}

export function shareParamsForFileKey(k: FileKey): Array<[string, string]> {
  assertFileKey(k);
  const params: Array<[string, string]> = [['k', toBase64(k.raw)]];
  if (k.format === FILE_FORMAT_V2) {
    params.push(['v', String(FILE_FORMAT_V2)], ['b', toBase64(k.binding!)]);
  }
  return params;
}

function wrapPlaintext(k: FileKey): Uint8Array {
  assertFileKey(k);
  return k.format === FILE_FORMAT_V2 ? concat(WRAP_V2_MAGIC, k.raw, k.binding!) : k.raw;
}

export async function wrapFileKey(
  wrappingKeyRawBytes: Uint8Array,
  k: FileKey
): Promise<{ wrappedFileKey: string; wrapIv: string }> {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['encrypt']);
  const { iv, ciphertext } = await aesGcmEncrypt(wrappingKey, wrapPlaintext(k));
  return { wrappedFileKey: toBase64(ciphertext), wrapIv: toBase64(iv) };
}

export async function unwrapFileKey(
  wrappingKeyRawBytes: Uint8Array,
  wrappedFileKeyB64: string,
  wrapIvB64: string
): Promise<FileKey> {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['decrypt']);
  const pt = await aesGcmDecrypt(wrappingKey, fromBase64(wrapIvB64), fromBase64(wrappedFileKeyB64));
  if (pt.length === FILE_KEY_BYTES) {
    return { raw: pt, format: FILE_FORMAT_LEGACY };
  }
  if (pt.length === WRAP_V2_BYTES && WRAP_V2_MAGIC.every((b, i) => pt[i] === b)) {
    const keyEnd = WRAP_V2_MAGIC.length + FILE_KEY_BYTES;
    return { raw: pt.slice(WRAP_V2_MAGIC.length, keyEnd), format: FILE_FORMAT_V2, binding: pt.slice(keyEnd) };
  }
  throw new Error('Unsupported file key format');
}

async function hkdfBytes(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', asBufferSource(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: asBufferSource(utf8(info)) },
    base,
    FILE_KEY_BYTES * 8
  );
  return new Uint8Array(bits);
}

export async function nodeRef(k: FileKey): Promise<string> {
  assertFileKey(k);
  return toBase64Url((await hkdfBytes(k.raw, HKDF_INFO_NODE_REF_V2)).subarray(0, NODE_REF_BYTES));
}

export async function contentKeyRaw(k: FileKey): Promise<Uint8Array> {
  assertFileKey(k);
  return k.format === FILE_FORMAT_V2 ? hkdfBytes(k.raw, HKDF_INFO_CONTENT_V2) : k.raw;
}

export async function toContentKey(k: FileKey): Promise<ContentKey> {
  return { contentKeyRaw: await contentKeyRaw(k), format: k.format };
}

async function contentCryptoKey(k: ContentKeyLike, usages: KeyUsage[]): Promise<CryptoKey> {
  if ('contentKeyRaw' in k) {
    assertFormat(k.format);
    if (!(k.contentKeyRaw instanceof Uint8Array) || k.contentKeyRaw.length !== FILE_KEY_BYTES) throw new Error('Invalid content key');
    return importAesKey(k.contentKeyRaw, usages);
  }
  return importAesKey(await contentKeyRaw(k), usages);
}

async function metadataCipher(k: FileKey, usages: KeyUsage[]): Promise<{ key: CryptoKey; aad?: Uint8Array }> {
  assertFileKey(k);
  if (k.format === FILE_FORMAT_V2) {
    return {
      key: await importAesKey(await hkdfBytes(k.raw, HKDF_INFO_METADATA_V2), usages),
      aad: concat(AAD_METADATA_V2, k.binding!),
    };
  }
  return { key: await importAesKey(k.raw, usages) };
}

function singleContentAad(format: FileFormat): Uint8Array | undefined {
  return format === FILE_FORMAT_V2 ? AAD_CONTENT_V2 : undefined;
}

const isSize = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

export function validateV2Meta(meta: FileMeta): void {
  const bad = (why: string): never => { throw new Error(`Corrupt file metadata (${why})`); };
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) bad('not an object');
  if (typeof meta.name !== 'string' || meta.name.length === 0 || meta.name.length > 4096) bad('name');
  if (typeof meta.mime !== 'string' || meta.mime.length > 255) bad('mime');
  if (meta.isFolder !== undefined && typeof meta.isFolder !== 'boolean') bad('isFolder');
  if (meta.compressed !== undefined && typeof meta.compressed !== 'boolean') bad('compressed');

  if (meta.parentId === undefined || meta.parentId === null) {
    if (meta.pref !== undefined) bad('pref without parent');
  } else {
    if (typeof meta.parentId !== 'string' || !RECORD_ID_RE.test(meta.parentId)) bad('parentId');
    if (typeof meta.pref !== 'string' || !NODE_REF_RE.test(meta.pref)) bad('pref');
  }

  if (meta.from !== undefined && (typeof meta.from !== 'string' || !NODE_REF_RE.test(meta.from))) bad('from');

  if (meta.isFolder) {
    if (meta.mime !== FOLDER_MIME) bad('folder mime');
    if (meta.compressed || meta.chunkSize !== undefined || meta.unpaddedSize !== undefined || meta.size !== undefined) bad('folder fields');
    return;
  }
  if (!isSize(meta.size)) bad('size');
  if (!isSize(meta.unpaddedSize)) bad('unpaddedSize');
  if (meta.chunkSize !== undefined) {
    if (meta.chunkSize !== CHUNK_SIZE) bad('chunkSize');
    if (meta.compressed) bad('compressed chunked file');
    if (meta.unpaddedSize !== meta.size) bad('chunked size');
    if (Math.ceil(meta.size! / CHUNK_SIZE) > 0xffffffff) bad('too many chunks');
  } else if (!meta.compressed && meta.unpaddedSize !== meta.size) {
    bad('uncompressed size');
  }
}

function unpadMetadataStrict(bytes: Uint8Array): Uint8Array {
  if (bytes.length < 4) throw new Error('Corrupt file metadata (padding)');
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  if (len > bytes.length - 4 || bytes.length !== paddedMetadataSize(len + 4)) throw new Error('Corrupt file metadata (padding)');
  assertZero(bytes, 4 + len, 'Corrupt file metadata (padding)');
  return bytes.subarray(4, 4 + len);
}

function assertZero(bytes: Uint8Array, from: number, message: string): void {
  for (let i = from; i < bytes.length; i++) {
    if (bytes[i] !== 0) throw new Error(message);
  }
}

export async function decryptMetadata(
  fileKey: FileKey,
  encryptedMetadataB64: string,
  metadataIvB64: string
): Promise<FileMeta> {
  const { key, aad } = await metadataCipher(fileKey, ['decrypt']);
  const bytes = await aesGcmDecrypt(key, fromBase64(metadataIvB64), fromBase64(encryptedMetadataB64), aad);
  if (fileKey.format === FILE_FORMAT_V2) {
    const meta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(unpadMetadataStrict(bytes))) as FileMeta;
    validateV2Meta(meta);
    return meta;
  }
  const meta = JSON.parse(new TextDecoder().decode(unpadMetadataBytes(bytes))) as FileMeta;
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) throw new Error('Corrupt file metadata');
  if (typeof meta.name !== 'string') meta.name = String(meta.name ?? '');
  if (typeof meta.mime !== 'string') meta.mime = 'application/octet-stream';
  return meta;
}

export interface EncryptedMetadata {
  encryptedMetadata: string;
  metadataIv: string;
}

export async function encryptMetadata(
  fileKey: FileKey,
  meta: FileMeta
): Promise<EncryptedMetadata> {
  if (fileKey.format === FILE_FORMAT_V2) validateV2Meta(meta);
  const { key, aad } = await metadataCipher(fileKey, ['encrypt']);
  const metadataBytes = padMetadataBytes(utf8(JSON.stringify(meta)));
  const { iv, ciphertext } = await aesGcmEncrypt(key, metadataBytes, aad);
  return { encryptedMetadata: toBase64(ciphertext), metadataIv: toBase64(iv) };
}

export function parentFields(parent: ParentRef | null): Pick<FileMeta, 'parentId' | 'pref'> {
  if (!parent) return { parentId: null };
  if (!RECORD_ID_RE.test(parent.id) || !NODE_REF_RE.test(parent.ref)) throw new Error('Invalid parent folder');
  return { parentId: parent.id, pref: parent.ref };
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

function chunkAad(format: FileFormat, index: number, isLast: boolean): Uint8Array {
  const head = format === FILE_FORMAT_V2 ? AAD_CHUNK_V2 : new Uint8Array(0);
  const aad = new Uint8Array(head.length + 5);
  aad.set(head, 0);
  new DataView(aad.buffer).setUint32(head.length, index, false);
  aad[head.length + 4] = isLast ? 1 : 0;
  return aad;
}

function chunkCount(chunkSize: number, unpaddedSize: number): number {
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0 || !isSize(unpaddedSize)) throw new Error('Corrupt chunked file metadata');
  const count = Math.max(1, Math.ceil(unpaddedSize / chunkSize));
  if (count > 0xffffffff) throw new Error('Corrupt chunked file metadata');
  return count;
}

function takeFromChunk(format: FileFormat, plain: Uint8Array, take: number): Uint8Array {
  if (format === FILE_FORMAT_V2 && take < plain.length) assertZero(plain.subarray(take), 0, 'File is corrupt (padding)');
  return take === plain.length ? plain : plain.subarray(0, take);
}

async function decryptChunked(
  fileKey: ContentKeyLike,
  contentIvB64: string,
  ciphertext: Uint8Array,
  chunkSize: number,
  unpaddedSize: number
): Promise<Uint8Array> {
  const key = await contentCryptoKey(fileKey, ['decrypt']);
  const prefix = fromBase64(contentIvB64);
  if (prefix.length !== CHUNK_IV_PREFIX_BYTES) throw new Error('Corrupt chunked file header');
  const sealed = chunkSize + GCM_TAG_BYTES;
  const count = chunkCount(chunkSize, unpaddedSize);
  if (ciphertext.length !== count * sealed) throw new Error('File is truncated or corrupt');

  const out = new Uint8Array(unpaddedSize);
  for (let i = 0; i < count; i++) {
    const part = ciphertext.subarray(i * sealed, (i + 1) * sealed);
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(chunkIv(prefix, i)), additionalData: asBufferSource(chunkAad(fileKey.format, i, i === count - 1)), tagLength: 128 },
      key,
      asBufferSource(part)
    ));
    const take = Math.min(chunkSize, unpaddedSize - i * chunkSize);
    out.set(takeFromChunk(fileKey.format, plain, take), i * chunkSize);
  }
  return out;
}

export function decryptChunkedStream(
  fileKey: ContentKeyLike,
  contentIvB64: string,
  source: ReadableStream<Uint8Array>,
  chunkSize: number,
  unpaddedSize: number
): ReadableStream<Uint8Array> {
  const count = chunkCount(chunkSize, unpaddedSize);
  const sealedSize = chunkSize + GCM_TAG_BYTES;
  const reader = source.getReader();
  let key: CryptoKey;
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
      key = await contentCryptoKey(fileKey, ['decrypt']);
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
          { name: 'AES-GCM', iv: asBufferSource(chunkIv(prefix, index)), additionalData: asBufferSource(chunkAad(fileKey.format, index, isLast)), tagLength: 128 },
          key,
          asBufferSource(sealed)
        ));
      } catch {
        throw new Error('File is corrupt or has been tampered with');
      }
      const take = Math.min(chunkSize, unpaddedSize - index * chunkSize);
      controller.enqueue(takeFromChunk(fileKey.format, plain, take));
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
  fileKey: ContentKeyLike,
  contentIvB64: string,
  source: ReadableStream<Uint8Array>,
  meta: ContentMeta
): ReadableStream<Uint8Array> {
  if (meta.chunkSize) {
    if (typeof meta.unpaddedSize !== 'number') throw new Error('Corrupt chunked file metadata');
    return decryptChunkedStream(fileKey, contentIvB64, source, meta.chunkSize, meta.unpaddedSize);
  }
  let done = false;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (done) return;
      done = true;
      const ciphertext = new Uint8Array(await new Response(source).arrayBuffer());
      controller.enqueue(await decryptContent(fileKey, contentIvB64, ciphertext, meta));
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

async function decompressExactly(bytes: Uint8Array, expected: number): Promise<Uint8Array> {
  const reader = new Blob([asBlobPart(bytes)]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > expected) {
      await reader.cancel().catch(() => {});
      throw new Error('File is corrupt (decompressed size mismatch)');
    }
    parts.push(value);
  }
  if (total !== expected) throw new Error('File is corrupt (decompressed size mismatch)');
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export async function decryptContent(
  fileKey: ContentKeyLike,
  contentIvB64: string,
  ciphertextBytes: Uint8Array,
  meta: ContentMeta = {}
): Promise<Uint8Array> {
  const unpaddedSize = meta.unpaddedSize ?? null;
  if (meta.chunkSize) {
    if (unpaddedSize == null) throw new Error('Corrupt chunked file metadata');
    return decryptChunked(fileKey, contentIvB64, ciphertextBytes, meta.chunkSize, unpaddedSize);
  }
  const key = await contentCryptoKey(fileKey, ['decrypt']);
  let bytes = await aesGcmDecrypt(key, fromBase64(contentIvB64), ciphertextBytes, singleContentAad(fileKey.format));

  if (fileKey.format === FILE_FORMAT_V2) {
    if (unpaddedSize == null) {
      if (bytes.length !== 0) throw new Error('File is corrupt (padding)');
      return bytes;
    }
    if (bytes.length !== paddedSize(unpaddedSize)) throw new Error('File is corrupt (padding)');
    assertZero(bytes, unpaddedSize, 'File is corrupt (padding)');
    bytes = bytes.subarray(0, unpaddedSize);
    if (!meta.compressed) return bytes;
    if (!isSize(meta.size)) throw new Error('Corrupt file metadata (size)');
    return decompressExactly(bytes, meta.size);
  }

  bytes = stripPadding(bytes, unpaddedSize);
  return meta.compressed ? decompressBytes(bytes) : bytes;
}

async function sealSingleContent(fileKey: FileKey, plaintext: Uint8Array): Promise<AesGcmEncryptResult> {
  const key = await contentCryptoKey(fileKey, ['encrypt']);
  return aesGcmEncrypt(key, plaintext, singleContentAad(fileKey.format));
}

export async function encryptFile(
  wrappingKeyRawBytes: Uint8Array,
  file: File,
  parent: ParentRef | null = null,
  opts?: NewRecordOptions
): Promise<EncryptedFilePayload> {
  const fileKey = newFileKey();

  const { padded: paddedContentBytes, unpaddedSize, compressed } = await readPaddedContent(file);

  const { encryptedMetadata, metadataIv } = await encryptMetadata(fileKey, {
    name: file.name || 'Untitled',
    mime: safeMime(file.type),
    compressed,
    unpaddedSize,
    size: file.size,
    ...parentFields(parent),
    ...optionFields(opts),
  });

  const { iv: contentIv, ciphertext } = await sealSingleContent(fileKey, paddedContentBytes);

  const { wrappedFileKey, wrapIv } = await wrapFileKey(wrappingKeyRawBytes, fileKey);

  return {
    ciphertext,
    contentIv: toBase64(contentIv),
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrapIv,
  };
}

export async function prepareChunkedFile(
  wrappingKeyRawBytes: Uint8Array,
  file: File,
  parent: ParentRef | null = null,
  opts?: NewRecordOptions
): Promise<ChunkedFilePayload> {
  const fileKey = newFileKey();
  const key = await contentCryptoKey(fileKey, ['encrypt']);
  const prefix = randomBytes(CHUNK_IV_PREFIX_BYTES);

  const partCount = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  if (partCount > 0xffffffff) throw new Error('File is too large');

  const { encryptedMetadata, metadataIv } = await encryptMetadata(fileKey, {
    name: file.name || 'Untitled',
    mime: safeMime(file.type),
    compressed: false,
    unpaddedSize: file.size,
    size: file.size,
    chunkSize: CHUNK_SIZE,
    ...parentFields(parent),
    ...optionFields(opts),
  });
  const { wrappedFileKey, wrapIv } = await wrapFileKey(wrappingKeyRawBytes, fileKey);

  const readPart = async (index: number): Promise<Uint8Array> => {
    const start = index * CHUNK_SIZE;
    const slice = new Uint8Array(await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer());
    let plain: Uint8Array = slice;
    if (slice.length !== CHUNK_SIZE) {
      plain = new Uint8Array(CHUNK_SIZE);
      plain.set(slice);
    }
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: asBufferSource(chunkIv(prefix, index)), additionalData: asBufferSource(chunkAad(fileKey.format, index, index === partCount - 1)), tagLength: 128 },
      key,
      asBufferSource(plain)
    );
    return new Uint8Array(sealed);
  };

  return {
    contentIv: toBase64(prefix),
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrapIv,
    partCount,
    partSize: CHUNK_SIZE + GCM_TAG_BYTES,
    totalSize: partCount * (CHUNK_SIZE + GCM_TAG_BYTES),
    readPart,
  };
}

export async function encryptFolder(
  wrappingKeyRawBytes: Uint8Array,
  name: string,
  parent: ParentRef | null = null,
  opts?: NewRecordOptions
): Promise<EncryptedFilePayload> {
  const fileKey = newFileKey();

  const { encryptedMetadata, metadataIv } = await encryptMetadata(fileKey, {
    name,
    mime: FOLDER_MIME,
    isFolder: true,
    ...parentFields(parent),
    ...optionFields(opts),
  });

  const { iv: contentIv, ciphertext } = await sealSingleContent(fileKey, new Uint8Array(0));

  const { wrappedFileKey, wrapIv } = await wrapFileKey(wrappingKeyRawBytes, fileKey);

  return {
    ciphertext,
    contentIv: toBase64(contentIv),
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrapIv,
  };
}
