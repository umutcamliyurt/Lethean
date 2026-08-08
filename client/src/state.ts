import type { FileMeta } from './types.js';

let wrappingKeyRaw: Uint8Array | null = null;
let currentVaultId: string | null = null;

export function getWrappingKeyRaw(): Uint8Array | null {
  return wrappingKeyRaw;
}
export function setWrappingKeyRaw(value: Uint8Array | null): void {
  wrappingKeyRaw = value;
}

export function getCurrentVaultId(): string | null {
  return currentVaultId;
}
export function setCurrentVaultId(value: string | null): void {
  currentVaultId = value;
}

export const fileKeyCache: Map<string, Uint8Array> = new Map();
export const metaCache: Map<string, FileMeta> = new Map();
export const objectUrlCache: Map<string, string> = new Map();
