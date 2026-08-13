export function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el as T;
}

export const authScreen = $<HTMLDivElement>('auth-screen');
export const appScreen = $<HTMLDivElement>('app-screen');
export const authForm = $<HTMLFormElement>('auth-form');
export const authSubmit = $<HTMLButtonElement>('auth-submit');
export const authStatus = $<HTMLDivElement>('auth-status');
export const passwordInput = $<HTMLInputElement>('password');
export const confirmField = $<HTMLDivElement>('confirm-field');
export const passwordConfirmInput = $<HTMLInputElement>('password-confirm');
export const accessTokenInput = $<HTMLInputElement>('access-token');
export const saltInput = $<HTMLInputElement>('salt');

export const depositSlot = $<HTMLDivElement>('deposit-slot');
export const chooseFilesBtn = $<HTMLButtonElement>('choose-files-btn');
export const newFolderBtn = $<HTMLButtonElement>('new-folder-btn');
export const fileInput = $<HTMLInputElement>('file-input');
export const uploadQueue = $<HTMLDivElement>('upload-queue');
export const breadcrumbEl = $<HTMLDivElement>('breadcrumb');
export const boxGrid = $<HTMLDivElement>('box-grid');
export const fileListEl = $<HTMLDivElement>('file-list');
export const fileListBody = $<HTMLDivElement>('file-list-body');
export const viewGridBtn = $<HTMLButtonElement>('view-grid-btn');
export const viewListBtn = $<HTMLButtonElement>('view-list-btn');
export const emptyState = $<HTMLDivElement>('empty-state');
export const gridLabel = $<HTMLParagraphElement>('grid-label');
export const searchInput = $<HTMLInputElement>('search-input');
export const searchClearBtn = $<HTMLButtonElement>('search-clear');
export const gridSentinel = $<HTMLDivElement>('grid-sentinel');
export const usagePill = $<HTMLSpanElement>('usage-pill');
export const logoutBtn = $<HTMLButtonElement>('logout-btn');
export const tokenBtn = $<HTMLButtonElement>('token-btn');
export const saltBtn = $<HTMLButtonElement>('salt-btn');
export const duressBtn = $<HTMLButtonElement>('duress-btn');
export const sourceBtn = $<HTMLButtonElement>('source-btn');
export const settingsBtn = $<HTMLButtonElement>('settings-btn');
export const settingsMenu = $<HTMLDivElement>('settings-menu');
export const lightbox = $<HTMLDivElement>('lightbox');
export const toasts = $<HTMLDivElement>('toasts');