import { argon2id } from 'hash-wasm';
import { AhoCorasick } from './ahocorasick.js';
import { FOLDER_MIME } from './types.js';
import type { DuressConfig, EncryptedFilePayload, FileMeta, PasswordValidationResult, UnlockResult } from './types.js';

const ARGON2_PARAMS = {
  parallelism: 1,
  iterations: 4,
  memorySize: 98304,
  hashLength: 32,
  outputType: 'binary' as const,
};

function randomBytes(len: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(len));
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}
function asBlobPart(bytes: Uint8Array): BlobPart {
  return bytes as unknown as BlobPart;
}

const canCompress = typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined';

async function compressBytes(bytes: Uint8Array): Promise<Uint8Array | null> {
  if (!canCompress) return null;
  const stream = new Blob([asBlobPart(bytes)]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decompressBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([asBlobPart(bytes)]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function timingSafeEqualHex(aHex: string, bHex: string): boolean {
  if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
  if (aHex.length !== bHex.length) {
    let dummy = 0;
    for (let i = 0; i < aHex.length; i++) dummy |= aHex.charCodeAt(i);
    return false;
  }
  let diff = 0;
  for (let i = 0; i < aHex.length; i++) {
    diff |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  }
  return diff === 0;
}

const PADDING_BUCKETS = [
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
const PADDING_STEP_BEYOND_MAX = 256 * 1024 * 1024;

function paddedSize(n: number): number {
  for (const bucket of PADDING_BUCKETS) {
    if (n <= bucket) return bucket;
  }
  return Math.ceil(n / PADDING_STEP_BEYOND_MAX) * PADDING_STEP_BEYOND_MAX;
}

function padToBucket(bytes: Uint8Array): Uint8Array {
  const target = paddedSize(bytes.length);
  if (target === bytes.length) return bytes;
  const padded = new Uint8Array(target);
  padded.set(bytes);
  return padded;
}

function stripPadding(bytes: Uint8Array, realLength?: number | null): Uint8Array {
  if (typeof realLength !== 'number' || realLength < 0 || realLength > bytes.length) {
    return bytes;
  }
  return realLength === bytes.length ? bytes : bytes.subarray(0, realLength);
}

const METADATA_PADDING_BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096];

function paddedMetadataSize(n: number): number {
  for (const bucket of METADATA_PADDING_BUCKETS) {
    if (n <= bucket) return bucket;
  }
  const step = METADATA_PADDING_BUCKETS[METADATA_PADDING_BUCKETS.length - 1]!;
  return Math.ceil(n / step) * step;
}

function padMetadataBytes(bytes: Uint8Array): Uint8Array {
  const target = paddedMetadataSize(bytes.length + 4);
  const out = new Uint8Array(target);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function unpadMetadataBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length < 4) return bytes;
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  if (len > bytes.length - 4) return bytes.subarray(4);
  return bytes.subarray(4, 4 + len);
}

async function deriveSalt(Salt: string | null | undefined): Promise<Uint8Array> {
  const bytes = await crypto.subtle.digest('SHA-256', asBufferSource(utf8('e2ee-vault|salt|v1|' + (Salt || ''))));
  return new Uint8Array(bytes);
}

export function generateSalt(): string {
  return toHex(randomBytes(10));
}

export async function deriveMasterKey(password: string, Salt: string | null | undefined): Promise<Uint8Array> {
  const salt = await deriveSalt(Salt);
  const hash = await argon2id({ password, salt, ...ARGON2_PARAMS });
  return new Uint8Array(hash);
}

async function hkdf(masterKeyBytes: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey('raw', asBufferSource(masterKeyBytes), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: asBufferSource(utf8(info)) },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

export async function deriveVaultId(masterKeyBytes: Uint8Array): Promise<string> {
  const bytes = await hkdf(masterKeyBytes, 'e2ee-vault|vault-id|v1', 32);
  return toHex(bytes);
}

export async function deriveWrappingKey(masterKeyBytes: Uint8Array): Promise<Uint8Array> {
  return hkdf(masterKeyBytes, 'e2ee-vault|wrap|v1', 32);
}

export async function unlockVault(password: string, Salt: string | null | undefined): Promise<UnlockResult> {
  const masterKey = await deriveMasterKey(password, Salt);
  const [vaultId, wrappingKeyRaw] = await Promise.all([
    deriveVaultId(masterKey),
    deriveWrappingKey(masterKey),
  ]);
  return { vaultId, wrappingKeyRaw };
}

async function importAesKey(rawBytes: Uint8Array, usages: KeyUsage[] = ['encrypt', 'decrypt']): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', asBufferSource(rawBytes), 'AES-GCM', false, usages);
}

function generateAesKeyRaw(): Uint8Array {
  return randomBytes(32);
}

interface AesGcmEncryptResult {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

async function aesGcmEncrypt(key: CryptoKey, plaintextBytes: Uint8Array): Promise<AesGcmEncryptResult> {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: asBufferSource(iv), tagLength: 128 }, key, asBufferSource(plaintextBytes));
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

async function aesGcmDecrypt(key: CryptoKey, ivBytes: Uint8Array, ciphertextBytes: Uint8Array): Promise<Uint8Array> {
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

  const rawContentBytes = new Uint8Array(await file.arrayBuffer());
  let contentBytes: Uint8Array = rawContentBytes;
  let compressed = false;
  try {
    const gzipped = await compressBytes(rawContentBytes);
    if (gzipped && gzipped.length < rawContentBytes.length) {
      contentBytes = gzipped;
      compressed = true;
    }
  } catch {
  }

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

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', asBufferSource(bytes)));
}

const DURESS_KDF_PARAMS = {
  parallelism: 1,
  iterations: ARGON2_PARAMS.iterations,
  memorySize: ARGON2_PARAMS.memorySize,
  hashLength: 32,
  outputType: 'binary' as const,
};

async function deriveDuressKey(input: string, saltBytes: Uint8Array, domain: string): Promise<Uint8Array> {
  const domainSalt = await sha256(concatBytes(utf8(domain), saltBytes));
  const hash = await argon2id({ password: input, salt: domainSalt, ...DURESS_KDF_PARAMS });
  return new Uint8Array(hash);
}

export async function setupDuress(duressCode: string, realVaultId: string): Promise<DuressConfig> {
  const salt = randomBytes(16);
  const verifierBytes = await deriveDuressKey(duressCode, salt, 'e2ee-vault|duress-verifier|v1');

  const wrapKeyBytes = await deriveDuressKey(duressCode, salt, 'e2ee-vault|duress-wrap|v1');
  const wrapKey = await importAesKey(wrapKeyBytes, ['encrypt']);
  const { iv, ciphertext } = await aesGcmEncrypt(wrapKey, utf8(realVaultId));

  return {
    salt: toBase64(salt),
    verifier: toHex(verifierBytes),
    encVaultId: toBase64(ciphertext),
    iv: toBase64(iv),
  };
}

export function randomVaultIdShaped(): string {
  return toHex(randomBytes(32));
}

export function generateDecoyDuressConfig(): DuressConfig {
  const fakeVaultIdLen = 64;
  return {
    salt: toBase64(randomBytes(16)),
    verifier: toHex(randomBytes(32)),
    encVaultId: toBase64(randomBytes(fakeVaultIdLen + 16)),
    iv: toBase64(randomBytes(12)),
  };
}

export async function checkDuress(input: string, duressConfig: DuressConfig): Promise<string | null> {
  try {
    const saltBytes = fromBase64(duressConfig.salt);
    const verifierBytes = await deriveDuressKey(input, saltBytes, 'e2ee-vault|duress-verifier|v1');
    const matches = timingSafeEqualHex(toHex(verifierBytes), duressConfig.verifier);

    const wrapKeyBytes = await deriveDuressKey(input, saltBytes, 'e2ee-vault|duress-wrap|v1');
    const wrapKey = await importAesKey(wrapKeyBytes, ['decrypt']);
    let vaultId: string | null = null;
    try {
      const vaultIdBytes = await aesGcmDecrypt(wrapKey, fromBase64(duressConfig.iv), fromBase64(duressConfig.encVaultId));
      vaultId = new TextDecoder().decode(vaultIdBytes);
    } catch {
      vaultId = null;
    }

    return matches ? vaultId : null;
  } catch {
    return null;
  }
}

function memoizeWithRetry<T>(factory: () => Promise<T>): () => Promise<T> {
  let cached: Promise<T> | null = null;
  return () => {
    if (!cached) {
      cached = factory().catch((err) => {
        cached = null;
        console.warn('[crypto] common-password dictionary unavailable, retrying next call:', err);
        throw err;
      });
    }
    return cached;
  };
}

const loadCommonPasswordsRaw = memoizeWithRetry(async (): Promise<string> => {
  const res = await fetch(new URL('./common_passwords.txt', import.meta.url));
  if (!res.ok) throw new Error(`Failed to load common-password list: HTTP ${res.status}`);
  return res.text();
});

function parseWordList(raw: string): string[] {
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  return raw
    .split(/\r\n|\r|\n/)
    .map((w) => w.trim())
    .filter(Boolean);
}

const getCommonPasswordSet = memoizeWithRetry(async (): Promise<Set<string>> => {
  const raw = await loadCommonPasswordsRaw();
  return new Set(parseWordList(raw));
});

const LEET_MAP: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };
function deleetify(str: string): string {
  let out = '';
  for (const ch of str) out += LEET_MAP[ch] ?? ch;
  return out;
}

async function isCommonPassword(password: string): Promise<boolean> {
  const dict = await getCommonPasswordSet();
  const lower = password.toLowerCase();

  const candidates = new Set<string>([lower]);
  const stripped = lower.replace(/[\d\W_]+$/u, '');
  if (stripped) candidates.add(stripped);
  const deleeted = deleetify(lower);
  candidates.add(deleeted);
  const deleetedStripped = deleetify(stripped);
  if (deleetedStripped) candidates.add(deleetedStripped);

  for (const candidate of candidates) {
    if (dict.has(candidate)) return true;
  }
  return false;
}

const getDictionaryMatcher = memoizeWithRetry(async (): Promise<AhoCorasick> => {
  const raw = await loadCommonPasswordsRaw();
  const words = parseWordList(raw).filter((w) => w.length >= 5 && w.length <= 20 && /^[a-z]+$/.test(w));
  return new AhoCorasick(words);
});

if (typeof requestIdleCallback === 'function') {
  requestIdleCallback(() => { getDictionaryMatcher().catch(() => {}); });
} else if (typeof window !== 'undefined') {
  setTimeout(() => { getDictionaryMatcher().catch(() => {}); }, 0);
}

const DICTIONARY_COVERAGE_REJECT_RATIO = 0.6;
const DICTIONARY_COVERAGE_LENIENT_WORD_COUNT = 5;
const DICTIONARY_COVERAGE_LENIENT_MIN_LENGTH = 30;

async function hasSignificantDictionaryCoverage(password: string): Promise<boolean> {
  const matcher = await getDictionaryMatcher();
  const lower = password.toLowerCase();
  const deleeted = deleetify(lower);

  const plain = matcher.analyze(lower);
  const unleeted = deleeted === lower ? plain : matcher.analyze(deleeted);
  const { coverageRatio, wordCount } = plain.coverageRatio >= unleeted.coverageRatio ? plain : unleeted;

  if (coverageRatio < DICTIONARY_COVERAGE_REJECT_RATIO) return false;
  if (
    wordCount >= DICTIONARY_COVERAGE_LENIENT_WORD_COUNT &&
    password.length >= DICTIONARY_COVERAGE_LENIENT_MIN_LENGTH
  ) {
    return false;
  }
  return true;
}

function hasSequentialRun(password: string, runLength = 5): boolean {
  const lower = password.toLowerCase();
  const sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - runLength; i++) {
      const fwd = seq.slice(i, i + runLength);
      const rev = fwd.split('').reverse().join('');
      if (lower.includes(fwd) || lower.includes(rev)) return true;
    }
  }
  return false;
}

function isMostlyRepeatedChars(password: string): boolean {
  const counts: Record<string, number> = {};
  for (const ch of password) counts[ch] = (counts[ch] || 0) + 1;
  let maxCount = 0;
  for (const c of Object.values(counts)) if (c > maxCount) maxCount = c;
  return maxCount / password.length > 0.5 && password.length > 3;
}

const PASSWORD_STRENGTH_CHECK_LIMIT = 1024;

export async function validatePasswordStrength(password: string): Promise<PasswordValidationResult> {
  const errors: string[] = [];
  password = password || '';
  const checkSlice = password.length > PASSWORD_STRENGTH_CHECK_LIMIT
    ? password.slice(0, PASSWORD_STRENGTH_CHECK_LIMIT)
    : password;

  if (password.length < 12) {
    errors.push('Use at least 12 characters (longer passwords are safer than short complex ones).');
  }
  if (password.length > 256) {
    errors.push('Password is unreasonably long (max 256 characters).');
  }

  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (password.length < 20 && classes < 3) {
    errors.push('Mix at least 3 of: lowercase, uppercase, numbers, symbols — or use a longer password (20+ characters).');
  }
  if (hasSequentialRun(checkSlice)) {
    errors.push('Avoid simple sequences like "abcdef" or "12345".');
  }
  if (isMostlyRepeatedChars(checkSlice)) {
    errors.push('Avoid passwords made mostly of one repeated character.');
  }

  try {
    if (await isCommonPassword(checkSlice)) {
      errors.push('This password (or a close variant of it) is known to be common or previously breached. Choose something less predictable.');
    } else if (await hasSignificantDictionaryCoverage(checkSlice)) {
      errors.push('This password is mostly made up of common dictionary words strung together, which is easy to guess. Add more, less predictable words, or mix in numbers/symbols.');
    }
  } catch (err) {
    console.error('[crypto] Could not check password against breach dictionary; rejecting until this can be verified.', err);
    errors.push("Couldn't verify this password against the breach dictionary (network or deployment issue). Try again in a moment.");
  }

  let score = 0;
  if (password.length >= 16) score++;
  if (password.length >= 20) score++;
  if (password.length >= 24 || classes >= 3) score++;
  if (password.length >= 28 && classes >= 3) score++;
  if (errors.some((e) => e.includes('common') || e.includes('sequence') || e.includes('repeated') || e.includes('breach') || e.includes('dictionary words'))) {
    score = Math.min(score, 1);
  }

  return { valid: errors.length === 0, score: Math.min(score, 4), errors };
}
