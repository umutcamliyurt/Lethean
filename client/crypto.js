import { argon2id } from './vendor/hash-wasm.esm.min.js';

const ARGON2_PARAMS = {
  parallelism: 1,
  iterations: 4,
  memorySize: 98304,
  hashLength: 32,
  outputType: 'binary',
};


function randomBytes(len) {
  return crypto.getRandomValues(new Uint8Array(len));
}

function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8(str) {
  return new TextEncoder().encode(str);
}

const canCompress = typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined';

async function compressBytes(bytes) {
  if (!canCompress) return null;
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decompressBytes(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function timingSafeEqualHex(aHex, bHex) {
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

function paddedSize(n) {
  for (const bucket of PADDING_BUCKETS) {
    if (n <= bucket) return bucket;
  }
  return Math.ceil(n / PADDING_STEP_BEYOND_MAX) * PADDING_STEP_BEYOND_MAX;
}

function padToBucket(bytes) {
  const target = paddedSize(bytes.length);
  if (target === bytes.length) return bytes;
  const padded = new Uint8Array(target);
  padded.set(bytes);
  return padded;
}

function stripPadding(bytes, realLength) {
  if (typeof realLength !== 'number' || realLength < 0 || realLength > bytes.length) {
    return bytes;
  }
  return realLength === bytes.length ? bytes : bytes.subarray(0, realLength);
}


async function deriveSalt(password) {
  const bytes = await crypto.subtle.digest('SHA-256', utf8('e2ee-vault|salt|v1|' + password));
  return new Uint8Array(bytes);
}

export async function deriveMasterKey(password) {
  const salt = await deriveSalt(password);
  const hash = await argon2id({ password, salt, ...ARGON2_PARAMS });
  return new Uint8Array(hash);
}


async function hkdf(masterKeyBytes, info, length = 32) {
  const baseKey = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

export async function deriveVaultId(masterKeyBytes) {
  const bytes = await hkdf(masterKeyBytes, 'e2ee-vault|vault-id|v1', 32);
  return toHex(bytes);
}

export async function deriveWrappingKey(masterKeyBytes) {
  return hkdf(masterKeyBytes, 'e2ee-vault|wrap|v1', 32);
}

export async function unlockVault(password) {
  const masterKey = await deriveMasterKey(password);
  const [vaultId, wrappingKeyRaw] = await Promise.all([
    deriveVaultId(masterKey),
    deriveWrappingKey(masterKey),
  ]);
  return { vaultId, wrappingKeyRaw };
}


async function importAesKey(rawBytes, usages = ['encrypt', 'decrypt']) {
  return crypto.subtle.importKey('raw', rawBytes, 'AES-GCM', false, usages);
}

function generateAesKeyRaw() {
  return randomBytes(32);
}

async function aesGcmEncrypt(key, plaintextBytes) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintextBytes);
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

async function aesGcmDecrypt(key, ivBytes, ciphertextBytes) {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes, tagLength: 128 }, key, ciphertextBytes);
  return new Uint8Array(plaintext);
}


export async function unwrapFileKey(wrappingKeyRawBytes, wrappedFileKeyB64, wrapIvB64) {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['decrypt']);
  return aesGcmDecrypt(wrappingKey, fromBase64(wrapIvB64), fromBase64(wrappedFileKeyB64));
}


export async function decryptMetadata(fileKeyRawBytes, encryptedMetadataB64, metadataIvB64) {
  const fileKey = await importAesKey(fileKeyRawBytes, ['decrypt']);
  const bytes = await aesGcmDecrypt(fileKey, fromBase64(metadataIvB64), fromBase64(encryptedMetadataB64));
  return JSON.parse(new TextDecoder().decode(bytes));
}


export async function decryptContent(fileKeyRawBytes, contentIvB64, ciphertextBytes, compressed = false, unpaddedSize = null) {
  const fileKey = await importAesKey(fileKeyRawBytes, ['decrypt']);
  let bytes = await aesGcmDecrypt(fileKey, fromBase64(contentIvB64), ciphertextBytes);
  bytes = stripPadding(bytes, unpaddedSize);
  return compressed ? decompressBytes(bytes) : bytes;
}


export async function encryptFile(wrappingKeyRawBytes, file) {
  const wrappingKey = await importAesKey(wrappingKeyRawBytes, ['encrypt']);

  const fileKeyRaw = generateAesKeyRaw();
  const fileKey = await importAesKey(fileKeyRaw);

  const rawContentBytes = new Uint8Array(await file.arrayBuffer());
  let contentBytes = rawContentBytes;
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

  const metadataBytes = utf8(JSON.stringify({
    name: file.name,
    mime: file.type || 'application/octet-stream',
    compressed,
    unpaddedSize,
  }));
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


function concatBytes(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

const DURESS_KDF_PARAMS = {
  parallelism: 1,
  iterations: 3,
  memorySize: 19456,
  hashLength: 32,
  outputType: 'binary',
};

async function deriveDuressKey(input, saltBytes, domain) {
  const domainSalt = await sha256(concatBytes(utf8(domain), saltBytes));
  const hash = await argon2id({ password: input, salt: domainSalt, ...DURESS_KDF_PARAMS });
  return new Uint8Array(hash);
}

export async function setupDuress(duressCode, realVaultId) {
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

export function randomVaultIdShaped() {
  return toHex(randomBytes(32));
}

export function generateDecoyDuressConfig() {
  const fakeVaultIdLen = 64;
  return {
    salt: toBase64(randomBytes(16)),
    verifier: toHex(randomBytes(32)),
    encVaultId: toBase64(randomBytes(fakeVaultIdLen + 16)),
    iv: toBase64(randomBytes(12)),
  };
}

export async function checkDuress(input, duressConfig) {
  try {
    const saltBytes = fromBase64(duressConfig.salt);
    const verifierBytes = await deriveDuressKey(input, saltBytes, 'e2ee-vault|duress-verifier|v1');
    const matches = timingSafeEqualHex(toHex(verifierBytes), duressConfig.verifier);

    const wrapKeyBytes = await deriveDuressKey(input, saltBytes, 'e2ee-vault|duress-wrap|v1');
    const wrapKey = await importAesKey(wrapKeyBytes, ['decrypt']);
    let vaultId = null;
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

function hasSequentialRun(password, runLength = 5) {
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

function isMostlyRepeatedChars(password) {
  const counts = {};
  for (const ch of password) counts[ch] = (counts[ch] || 0) + 1;
  const maxCount = Math.max(...Object.values(counts));
  return maxCount / password.length > 0.5 && password.length > 3;
}

export function validatePasswordStrength(password) {
  const errors = [];
  password = password || '';

  if (password.length < 12) {
    errors.push('Use at least 12 characters (longer passphrases are safer than short complex ones).');
  }
  if (password.length > 256) {
    errors.push('Passphrase is unreasonably long (max 256 characters).');
  }

  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (password.length < 20 && classes < 3) {
    errors.push('Mix at least 3 of: lowercase, uppercase, numbers, symbols — or use a longer passphrase (20+ characters).');
  }
  if (hasSequentialRun(password)) {
    errors.push('Avoid simple sequences like "abcdef" or "12345".');
  }
  if (isMostlyRepeatedChars(password)) {
    errors.push('Avoid passphrases made mostly of one repeated character.');
  }

  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (password.length >= 20 || classes >= 3) score++;
  if (password.length >= 24 && classes >= 3) score++;
  if (errors.some((e) => e.includes('common') || e.includes('sequence') || e.includes('repeated'))) {
    score = Math.min(score, 1);
  }

  return { valid: errors.length === 0, score: Math.min(score, 4), errors };
}