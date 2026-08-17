import * as C from './crypto.js';
import type { DuressConfig, ViewMode } from './types.js';

const LS_SETUP_KEY = 'vault.setupComplete';
const LS_DURESS_KEY = 'vault.duress';
const LS_ACCESS_TOKEN_KEY = 'vault.accessToken';
const LS_SALT_KEY = 'vault.salt';
const LS_VIEW_MODE_KEY = 'vault.viewMode';
const LS_THEME_KEY = 'vault.theme';
const LS_CONFIRMED_MARKERS_KEY = 'vault.confirmedMarkers';
const DEFAULT_THEME_ID = 'noir';
const MAX_CONFIRMED_MARKERS = 50;

export function isSetupComplete(): boolean {
  return localStorage.getItem(LS_SETUP_KEY) === '1';
}
export function markSetupComplete(): void {
  localStorage.setItem(LS_SETUP_KEY, '1');
}

export function getStoredAccessToken(): string {
  return localStorage.getItem(LS_ACCESS_TOKEN_KEY) || '';
}
export function setStoredAccessToken(token: string): void {
  if (token) localStorage.setItem(LS_ACCESS_TOKEN_KEY, token);
  else localStorage.removeItem(LS_ACCESS_TOKEN_KEY);
}

export function getStoredSalt(): string {
  return localStorage.getItem(LS_SALT_KEY) || '';
}
export function setStoredSalt(salt: string): void {
  if (salt) localStorage.setItem(LS_SALT_KEY, salt);
  else localStorage.removeItem(LS_SALT_KEY);
}

export function loadDuressConfig(): DuressConfig {
  try {
    const raw = localStorage.getItem(LS_DURESS_KEY);
    if (raw) return JSON.parse(raw) as DuressConfig;
  } catch {
  }
  const decoy = C.generateDecoyDuressConfig();
  localStorage.setItem(LS_DURESS_KEY, JSON.stringify(decoy));
  return decoy;
}
export function saveDuressConfig(cfg: DuressConfig): void {
  localStorage.setItem(LS_DURESS_KEY, JSON.stringify(cfg));
}
export function resetDuressConfig(): void {
  saveDuressConfig(C.generateDecoyDuressConfig());
}

export function getStoredViewMode(): ViewMode {
  return localStorage.getItem(LS_VIEW_MODE_KEY) === 'list' ? 'list' : 'grid';
}
export function setStoredViewMode(mode: ViewMode): void {
  localStorage.setItem(LS_VIEW_MODE_KEY, mode);
}

export function getStoredTheme(): string {
  return localStorage.getItem(LS_THEME_KEY) || DEFAULT_THEME_ID;
}
export function setStoredTheme(id: string): void {
  localStorage.setItem(LS_THEME_KEY, id);
}

function loadConfirmedMarkers(): string[] {
  try {
    const raw = localStorage.getItem(LS_CONFIRMED_MARKERS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) return parsed.filter((m): m is string => typeof m === 'string');
    }
  } catch {
  }
  return [];
}

export function isVaultConfirmed(marker: string): boolean {
  return loadConfirmedMarkers().includes(marker);
}

export function markVaultConfirmed(marker: string): void {
  const markers = loadConfirmedMarkers();
  if (markers.includes(marker)) return;
  markers.push(marker);
  while (markers.length > MAX_CONFIRMED_MARKERS) markers.shift();
  localStorage.setItem(LS_CONFIRMED_MARKERS_KEY, JSON.stringify(markers));
}