import { getStoredTheme } from './storage.js';

export interface ThemeVars {
  bg: string;
  surface: string;
  surface2: string;
  border: string;
  text: string;
  dim: string;
  faint: string;
}

export interface ThemeDef {
  id: string;
  name: string;
  vars: ThemeVars;
  accent: string;
}

export const THEMES: ThemeDef[] = [
  {
    id: 'noir',
    name: 'Noir',
    vars: {
      bg: '#0a0a0a', surface: '#161616', surface2: '#1e1e1e',
      border: '#2a2a2a', text: '#f0f0f0', dim: '#8a8a8a', faint: '#555555',
    },
    accent: '#8a8a8a',
  },
  {
    id: 'mocha',
    name: 'Mocha',
    vars: {
      bg: '#1b1310', surface: '#261c17', surface2: '#31241d',
      border: '#4a352a', text: '#f2e6da', dim: '#b08d74', faint: '#6e5646',
    },
    accent: '#8a5a3c',
  },
  {
    id: 'cappuccino',
    name: 'Cappuccino',
    vars: {
      bg: '#2a2019', surface: '#362a21', surface2: '#43352a',
      border: '#5c4a3a', text: '#f5e8d8', dim: '#c4a37f', faint: '#8a715a',
    },
    accent: '#c9a06c',
  },
  {
    id: 'latte',
    name: 'Latte',
    vars: {
      bg: '#f5efe6', surface: '#ffffff', surface2: '#efe6d8',
      border: '#ddd0bd', text: '#2c2117', dim: '#7a6a56', faint: '#a89880',
    },
    accent: '#a9744f',
  },
  {
    id: 'matcha',
    name: 'Matcha',
    vars: {
      bg: '#141b13', surface: '#1c261a', surface2: '#243020',
      border: '#37452f', text: '#e9f1e2', dim: '#8fa680', faint: '#516347',
    },
    accent: '#5a9451',
  },
  {
    id: 'midnight',
    name: 'Midnight',
    vars: {
      bg: '#0a0d16', surface: '#131829', surface2: '#1a2036',
      border: '#2a3350', text: '#e8ecfa', dim: '#8b93b8', faint: '#4f597e',
    },
    accent: '#4f6bd9',
  },
  {
    id: 'espresso',
    name: 'Espresso',
    vars: {
      bg: '#150e0b', surface: '#1f1611', surface2: '#291d16',
      border: '#3d2c22', text: '#f5ece2', dim: '#a88b72', faint: '#5c4433',
    },
    accent: '#6b4226',
  },
  {
    id: 'rose',
    name: 'Rose',
    vars: {
      bg: '#160f13', surface: '#20161c', surface2: '#2b1e25',
      border: '#402a34', text: '#f5e6ee', dim: '#b98aa0', faint: '#6b4a58',
    },
    accent: '#c2568b',
  },
  {
    id: 'slate',
    name: 'Slate',
    vars: {
      bg: '#0d1117', surface: '#161b22', surface2: '#1e242c',
      border: '#30363d', text: '#e6edf3', dim: '#8b98a5', faint: '#4b5563',
    },
    accent: '#5b8dd9',
  },
  {
    id: 'forest',
    name: 'Forest',
    vars: {
      bg: '#0e1512', surface: '#17201b', surface2: '#1f2b23',
      border: '#2f4034', text: '#e7f0ea', dim: '#8fae9b', faint: '#4d6357',
    },
    accent: '#3f8f5f',
  },
  {
    id: 'plum',
    name: 'Plum',
    vars: {
      bg: '#150f1a', surface: '#1f1726', surface2: '#2a1f33',
      border: '#3f2f4d', text: '#f0e6f5', dim: '#a98cc0', faint: '#5f4a72',
    },
    accent: '#9457c9',
  },
  {
    id: 'sand',
    name: 'Sand',
    vars: {
      bg: '#f2ece1', surface: '#fffdf9', surface2: '#e9e0d0',
      border: '#d8cbb0', text: '#2b241a', dim: '#8a7c62', faint: '#b0a488',
    },
    accent: '#c17f3b',
  },
];

export const DEFAULT_THEME_ID = 'noir';

const VAR_MAP: Record<keyof ThemeVars, string> = {
  bg: '--bg',
  surface: '--surface',
  surface2: '--surface-2',
  border: '--border',
  text: '--text',
  dim: '--dim',
  faint: '--faint',
};

export function getTheme(id: string | null | undefined): ThemeDef {
  return THEMES.find((t) => t.id === id) || THEMES[0]!;
}

export function applyTheme(id: string | null | undefined): void {
  const theme = getTheme(id);
  const root = document.documentElement.style;
  for (const key of Object.keys(VAR_MAP) as (keyof ThemeVars)[]) {
    root.setProperty(VAR_MAP[key], theme.vars[key]);
  }
  document.documentElement.dataset.theme = theme.id;
}

applyTheme(getStoredTheme());