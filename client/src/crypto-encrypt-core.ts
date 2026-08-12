import type { EncryptedFilePayload, FileMeta } from './types.js';
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
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
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

export async function readAndMaybeCompressFile(file: File): Promise<{ bytes: Uint8Array; compressed: boolean }> {
  if (!canCompress) {
    return { bytes: new Uint8Array(await file.arrayBuffer()), compressed: false };
  }
  try {
    const [rawStream, gzipStream] = file.stream().tee();
    const rawPromise = new Response(rawStream).arrayBuffer();
    const compressedPromise = new Response(gzipStream.pipeThrough(new CompressionStream('gzip'))).arrayBuffer();
    const [rawBuf, gzippedBuf] = await Promise.all([rawPromise, compressedPromise]);
    if (gzippedBuf.byteLength < rawBuf.byteLength) {
      return { bytes: new Uint8Array(gzippedBuf), compressed: true };
    }
    return { bytes: new Uint8Array(rawBuf), compressed: false };
  } catch {
    return { bytes: new Uint8Array(await file.arrayBuffer()), compressed: false };
  }
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

export async function decryptContent(
  fileKeyRawBytes: Uint8Array,
  contentIvB64: string,
  ciphertextBytes: Uint8Array,
  compressed = false,
  unpaddedSize: number | null = null
): Promise<Uint8Array> {
  const fileKey = await importAesKey(fileKeyRawBytes, ['decrypt']);
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

  const { bytes: contentBytes, compressed } = await readAndMaybeCompressFile(file);

  const unpaddedSize = contentBytes.length;
  const paddedContentBytes = padToBucket(contentBytes);

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