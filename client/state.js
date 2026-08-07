
let wrappingKeyRaw = null;
let currentVaultId = null;

export function getWrappingKeyRaw() {
  return wrappingKeyRaw;
}
export function setWrappingKeyRaw(value) {
  wrappingKeyRaw = value;
}

export function getCurrentVaultId() {
  return currentVaultId;
}
export function setCurrentVaultId(value) {
  currentVaultId = value;
}

export const fileKeyCache = new Map();
export const metaCache = new Map();
export const objectUrlCache = new Map();
