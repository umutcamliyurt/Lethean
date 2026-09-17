
import * as api from './api.js';
import * as C from './crypto.js';
import { fileKeyCache, metaCache } from './state.js';
import { getRecords } from './gallery.js';
import { importAesKey, aesGcmEncrypt, toBase64 } from './crypto-encrypt-core.js';
import type { RewrapEntry } from './api.js';

export interface RotationResult {
  vaultId: string;
  wrappingKeyRaw: Uint8Array;
  kdfVersion: number;
  filesMoved: number;
}

async function rewrapAllFilesTo(newWrap: Uint8Array): Promise<RewrapEntry[]> {
  const newWrappingKey = await importAesKey(newWrap, ['encrypt']);
  const records = getRecords();
  const rewraps: RewrapEntry[] = [];

  for (const record of records) {
    const fileKeyRaw = fileKeyCache.get(record.id);
    if (!fileKeyRaw) {
      const name = metaCache.get(record.id)?.name ?? record.id;
      throw new Error(`"${name}" isn't fully loaded yet — wait for the gallery to finish loading and try again.`);
    }
    const { iv: wrapIv, ciphertext: wrappedKey } = await aesGcmEncrypt(newWrappingKey, fileKeyRaw);
    rewraps.push({ fileId: record.id, wrappedFileKey: toBase64(wrappedKey), wrapIv: toBase64(wrapIv) });
  }

  return rewraps;
}

export async function rotateVaultPassword(
  oldPassword: string,
  newPassword: string,
  accessToken: string | null,
  oldKdfVersion: number,
  expectedOldVaultId: string
): Promise<RotationResult> {
  const { vaultId: oldVaultId } = await C.unlockVault(oldPassword, accessToken, oldKdfVersion);
  if (oldVaultId !== expectedOldVaultId) {
    throw new Error('Current password is incorrect.');
  }

  const { valid, errors } = await C.validatePasswordStrength(newPassword);
  if (!valid) throw new Error(errors[0] || 'New password is too weak.');

  const newKdfVersion = C.CURRENT_KDF_VERSION;
  const { vaultId: newVaultId, wrappingKeyRaw: newWrap } = await C.unlockVault(newPassword, accessToken, newKdfVersion);
  if (newVaultId === oldVaultId) {
    throw new Error('New password must be different from the current one.');
  }

  const rewraps = await rewrapAllFilesTo(newWrap);
  const { filesMoved } = await api.rotateVault(newVaultId, rewraps);

  return { vaultId: newVaultId, wrappingKeyRaw: newWrap, kdfVersion: newKdfVersion, filesMoved };
}

export async function rotateVaultAccessToken(
  password: string,
  oldAccessToken: string,
  newAccessToken: string,
  oldKdfVersion: number,
  expectedOldVaultId: string
): Promise<RotationResult> {
  const { vaultId: oldVaultId } = await C.unlockVault(password, oldAccessToken, oldKdfVersion);
  if (oldVaultId !== expectedOldVaultId) {
    throw new Error('Current password is incorrect.');
  }

  if (!newAccessToken) {
    throw new Error('New access token is required.');
  }
  if (newAccessToken === oldAccessToken) {
    throw new Error('New access token must be different from the current one.');
  }

  const newKdfVersion = C.CURRENT_KDF_VERSION;
  const { vaultId: newVaultId, wrappingKeyRaw: newWrap } = await C.unlockVault(password, newAccessToken, newKdfVersion);
  if (newVaultId === oldVaultId) {
    throw new Error('New access token must be different from the current one.');
  }

  const rewraps = await rewrapAllFilesTo(newWrap);
  const { filesMoved } = await api.rotateVault(newVaultId, rewraps);

  return { vaultId: newVaultId, wrappingKeyRaw: newWrap, kdfVersion: newKdfVersion, filesMoved };
}
