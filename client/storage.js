import * as C from './crypto.js';

const LS_SETUP_KEY = 'vault.setupComplete';
const LS_DURESS_KEY = 'vault.duress';
const LS_ACCESS_TOKEN_KEY = 'vault.accessToken';
const LS_SALT_KEY = 'vault.salt';
const LS_VIEW_MODE_KEY = 'vault.viewMode';

export function isSetupComplete() {
  return localStorage.getItem(LS_SETUP_KEY) === '1';
}
export function markSetupComplete() {
  localStorage.setItem(LS_SETUP_KEY, '1');
}

export function getStoredAccessToken() {
  return localStorage.getItem(LS_ACCESS_TOKEN_KEY) || '';
}
export function setStoredAccessToken(token) {
  if (token) localStorage.setItem(LS_ACCESS_TOKEN_KEY, token);
  else localStorage.removeItem(LS_ACCESS_TOKEN_KEY);
}

export function getStoredSalt() {
  return localStorage.getItem(LS_SALT_KEY) || '';
}
export function setStoredSalt(salt) {
  if (salt) localStorage.setItem(LS_SALT_KEY, salt);
  else localStorage.removeItem(LS_SALT_KEY);
}

export function loadDuressConfig() {
  try {
    const raw = localStorage.getItem(LS_DURESS_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
  }
  const decoy = C.generateDecoyDuressConfig();
  localStorage.setItem(LS_DURESS_KEY, JSON.stringify(decoy));
  return decoy;
}
export function saveDuressConfig(cfg) {
  localStorage.setItem(LS_DURESS_KEY, JSON.stringify(cfg));
}
export function resetDuressConfig() {
  saveDuressConfig(C.generateDecoyDuressConfig());
}

export function getStoredViewMode() {
  return localStorage.getItem(LS_VIEW_MODE_KEY) === 'list' ? 'list' : 'grid';
}
export function setStoredViewMode(mode) {
  localStorage.setItem(LS_VIEW_MODE_KEY, mode);
}
