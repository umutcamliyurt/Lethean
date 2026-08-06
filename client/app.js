import * as C from './crypto.js';
import * as api from './api.js';

let wrappingKeyRaw = null;
let currentVaultId = null;

const fileKeyCache = new Map();
const metaCache = new Map();
const objectUrlCache = new Map();
let records = [];

const PAGE_SIZE = 24;
let pageOffset = 0;
let hasMorePages = true;
let isLoadingPage = false;
let searchQuery = '';
let gridObserver = null;

const $ = (id) => document.getElementById(id);
const authScreen = $('auth-screen');
const appScreen = $('app-screen');
const authForm = $('auth-form');
const authSubmit = $('auth-submit');
const authStatus = $('auth-status');
const passwordInput = $('password');
const confirmField = $('confirm-field');
const passwordConfirmInput = $('password-confirm');
const accessTokenInput = $('access-token');

const depositSlot = $('deposit-slot');
const chooseFilesBtn = $('choose-files-btn');
const fileInput = $('file-input');
const uploadQueue = $('upload-queue');
const boxGrid = $('box-grid');
const fileListEl = $('file-list');
const fileListBody = $('file-list-body');
const viewGridBtn = $('view-grid-btn');
const viewListBtn = $('view-list-btn');
const emptyState = $('empty-state');
const gridLabel = $('grid-label');
const searchInput = $('search-input');
const searchClearBtn = $('search-clear');
const gridSentinel = $('grid-sentinel');
const usagePill = $('usage-pill');
const vaultFingerprint = $('vault-fingerprint');
const logoutBtn = $('logout-btn');
const tokenBtn = $('token-btn');
const duressBtn = $('duress-btn');
const lightbox = $('lightbox');
const toasts = $('toasts');

let lightboxMediaList = [];
let lightboxIndex = -1;
let lightboxNavLock = false;


const LS_SETUP_KEY = 'vault.setupComplete';
const LS_DURESS_KEY = 'vault.duress';
const LS_ACCESS_TOKEN_KEY = 'vault.accessToken';
const LS_VIEW_MODE_KEY = 'vault.viewMode';

let viewMode = localStorage.getItem(LS_VIEW_MODE_KEY) === 'list' ? 'list' : 'grid';

function setViewMode(mode) {
  if (mode !== 'grid' && mode !== 'list') return;
  if (viewMode === mode) return;
  viewMode = mode;
  localStorage.setItem(LS_VIEW_MODE_KEY, mode);
  updateViewToggleUI();
  renderCurrentView();
}

function updateViewToggleUI() {
  boxGrid.classList.toggle('hidden', viewMode !== 'grid');
  fileListEl.classList.toggle('hidden', viewMode !== 'list');
  viewGridBtn?.classList.toggle('active', viewMode === 'grid');
  viewListBtn?.classList.toggle('active', viewMode === 'list');
  viewGridBtn?.setAttribute('aria-pressed', String(viewMode === 'grid'));
  viewListBtn?.setAttribute('aria-pressed', String(viewMode === 'list'));
}

viewGridBtn?.addEventListener('click', () => setViewMode('grid'));
viewListBtn?.addEventListener('click', () => setViewMode('list'));
updateViewToggleUI();

function isSetupComplete() {
  return localStorage.getItem(LS_SETUP_KEY) === '1';
}
function markSetupComplete() {
  localStorage.setItem(LS_SETUP_KEY, '1');
}

function getStoredAccessToken() {
  return localStorage.getItem(LS_ACCESS_TOKEN_KEY) || '';
}
function setStoredAccessToken(token) {
  if (token) localStorage.setItem(LS_ACCESS_TOKEN_KEY, token);
  else localStorage.removeItem(LS_ACCESS_TOKEN_KEY);
}
accessTokenInput.value = getStoredAccessToken();

function loadDuressConfig() {
  try {
    const raw = localStorage.getItem(LS_DURESS_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
  }
  const decoy = C.generateDecoyDuressConfig();
  localStorage.setItem(LS_DURESS_KEY, JSON.stringify(decoy));
  return decoy;
}
function saveDuressConfig(cfg) {
  localStorage.setItem(LS_DURESS_KEY, JSON.stringify(cfg));
}
function resetDuressConfig() {
  saveDuressConfig(C.generateDecoyDuressConfig());
}


function fileKind(mime) {
  if (mime?.startsWith('image/')) return 'image';
  if (mime?.startsWith('video/')) return 'video';
  return 'other';
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

function showToast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast${type === 'error' ? ' error' : ''}`;
  el.textContent = message;
  toasts.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function icon(name) {
  const icons = {
    image: '<path d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.4"/><circle cx="8.5" cy="9.5" r="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M21 15l-5.5-5.5a1 1 0 0 0-1.4 0L4 19" stroke="currentColor" stroke-width="1.4"/>',
    video: '<rect x="3" y="6" width="14" height="12" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M21 9.5v5l-4-2.5v0z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>',
    file: '<path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.4"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.4"/>',
    play: '<circle cx="13" cy="13" r="12" fill="rgba(20,22,26,0.6)"/><path d="M10.5 8.5l7 4.5-7 4.5z" fill="white"/>',
    trash: '<path d="M4 6h14M9 6V4.5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1V6M6 6l.7 12a1 1 0 0 0 1 .9h6.6a1 1 0 0 0 1-.9L16 6" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>',
    download: '<path d="M10 3v10m0 0l-4-4m4 4l4-4M4 16v2a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-2" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
    close: '<path d="M5 5l14 14M19 5L5 19" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    chevronLeft: '<path d="M12.5 4.5L6 11l6.5 6.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
    chevronRight: '<path d="M7.5 4.5L14 11l-6.5 6.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
    expand: '<path d="M7 3H4a1 1 0 0 0-1 1v3M13 3h3a1 1 0 0 1 1 1v3M17 13v3a1 1 0 0 1-1 1h-3M3 13v3a1 1 0 0 0 1 1h3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  };
  return `<svg width="18" height="18" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">${icons[name] || ''}</svg>`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function setAuthStatus(message, { error = false, spinning = false } = {}) {
  authStatus.classList.toggle('error', error);
  authStatus.textContent = '';
  if (spinning) {
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    authStatus.appendChild(spinner);
  }
  const textEl = document.createElement('span');
  textEl.textContent = message;
  authStatus.appendChild(textEl);
}


let isFirstRun = !isSetupComplete();
let pendingConfirmation = null;

function configureAuthScreenForRun() {
  if (isFirstRun) {
    $('auth-heading').textContent = 'Set up';
    $('auth-subtitle').textContent = 'Choose a passphrase for this vault.';
    confirmField.classList.remove('hidden');
    passwordConfirmInput.required = true;
    confirmField.querySelector('label').textContent = 'Confirm passphrase';
  } else {
    $('auth-heading').textContent = 'Unlock';
    $('auth-subtitle').textContent = "No accounts. Your passphrase is the only key.";
    confirmField.querySelector('label').textContent = 'Empty vault, retype to confirm';
  }
}
configureAuthScreenForRun();

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = passwordInput.value;
  if (!password) return;

  authSubmit.disabled = true;
  try {
    if (isFirstRun) {
      if (passwordConfirmInput.value !== password) {
        setAuthStatus("Those don't match.", { error: true });
        return;
      }
      setAuthStatus('Deriving key\u2026', { spinning: true });
      const { vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password);
      await checkDuressAndMaybeWipe(password, wk);
      markSetupComplete();
      isFirstRun = false;
      configureAuthScreenForRun();
      await finishUnlock(vaultId, wk);
      return;
    }

    if (pendingConfirmation) {
      if (passwordConfirmInput.value !== pendingConfirmation.password) {
        setAuthStatus("Those don't match. Try entering your passphrase again.", { error: true });
        passwordConfirmInput.value = '';
        return;
      }
      await finishUnlock(pendingConfirmation.vaultId, pendingConfirmation.wrappingKeyRaw);
      return;
    }

    setAuthStatus('Deriving key\u2026', { spinning: true });
    const { vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password);
    await checkDuressAndMaybeWipe(password, wk);

    setAuthStatus('Checking vault\u2026', { spinning: true });
    api.setVaultId(vaultId);
    const usage = await api.getUsage();

    if (usage.file_count === 0) {
      pendingConfirmation = { vaultId, wrappingKeyRaw: wk, password };
      confirmField.classList.remove('hidden');
      passwordConfirmInput.required = true;
      passwordConfirmInput.focus();
      setAuthStatus('Empty vault. Confirm your passphrase to continue.');
      return;
    }

    await finishUnlock(vaultId, wk);
  } catch (err) {
    setAuthStatus("Couldn't reach the vault. " + err.message, { error: true });
  } finally {
    authSubmit.disabled = false;
  }
});

async function checkDuressAndMaybeWipe(input, _wk) {
  const cfg = loadDuressConfig();
  const realVaultId = await C.checkDuress(input, cfg);

  const target = realVaultId || C.randomVaultIdShaped();
  await api.sendShredSignal(target).catch(() => {});
}

async function finishUnlock(vaultId, wk) {
  wrappingKeyRaw = wk;
  currentVaultId = vaultId;
  api.setVaultId(vaultId);

  const token = accessTokenInput.value.trim();
  setStoredAccessToken(token);
  api.setAccessToken(token);

  pendingConfirmation = null;
  await enterApp();
}


async function enterApp() {
  fileKeyCache.clear();
  metaCache.clear();
  records = [];
  clearRenderedGrid();

  setAuthStatus('Unlocking\u2026', { spinning: true });
  await refreshGallery();

  authScreen.classList.add('hidden');
  appScreen.classList.remove('hidden');
  vaultFingerprint.textContent = currentVaultId.slice(0, 8);
  passwordInput.value = '';
  passwordConfirmInput.value = '';
  confirmField.classList.add('hidden');
  passwordConfirmInput.required = false;
  setAuthStatus('');
}

function clearRenderedGrid() {
  for (const url of objectUrlCache.values()) URL.revokeObjectURL(url);
  objectUrlCache.clear();
  if (gridObserver) { gridObserver.disconnect(); gridObserver = null; }
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  emptyState.classList.add('hidden');
  gridLabel.textContent = '';
  usagePill.textContent = '\u2014 items \u00b7,';
  if (searchInput) searchInput.value = '';
  searchQuery = '';
  searchClearBtn?.classList.add('hidden');
}

function leaveApp() {
  wrappingKeyRaw = null;
  currentVaultId = null;
  fileKeyCache.clear();
  metaCache.clear();
  clearRenderedGrid();
  records = [];
  api.setVaultId(null);
  api.setAccessToken(null);
  pendingConfirmation = null;

  appScreen.classList.add('hidden');
  authScreen.classList.remove('hidden');
  setAuthStatus('');
  showToast('Locked. Keys cleared from memory.');
}

logoutBtn.addEventListener('click', leaveApp);


tokenBtn.addEventListener('click', openTokenPanel);

function openTokenPanel() {
  const current = getStoredAccessToken();
  const masked = current ? `${current.slice(0, 6)}\u2026${current.slice(-4)}` : null;

  showLightbox(`
    <div class="settings-panel">
      <h2>Access token</h2>
      <p class="subtitle">
        (Issued by whoever runs this server).
        Only needed to upload, browsing and downloading never require it.
      </p>
      <div class="status-line">${masked ? `Current: ${escapeHtml(masked)}` : 'Not set.'}</div>

      <form id="token-form">
        <div class="field">
          <label for="token-input">New access token</label>
          <input type="text" id="token-input" autocomplete="off" spellcheck="false">
        </div>
        <div class="panel-actions">
          ${current ? '<button type="button" id="token-remove">Remove</button>' : ''}
          <button type="submit" class="btn-primary" id="token-save">Save</button>
        </div>
      </form>
    </div>
  `);
  $('token-input').value = current;

  $('token-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const token = $('token-input').value.trim();
    setStoredAccessToken(token);
    api.setAccessToken(token);
    accessTokenInput.value = token;
    showToast(token ? 'Access token saved.' : 'Access token cleared.');
    closeLightbox();
  });

  const removeBtn = $('token-remove');
  if (removeBtn) {
    removeBtn.addEventListener('click', () => {
      setStoredAccessToken('');
      api.setAccessToken(null);
      accessTokenInput.value = '';
      showToast('Access token removed.');
      closeLightbox();
    });
  }
}

duressBtn.addEventListener('click', openDuressPanel);

function openDuressPanel() {
  showLightbox(`
    <div class="settings-panel">
      <h2>Duress Code</h2>
      <p class="subtitle">
        A second passphrase. Typing it here instead of your real one erases
        this vault's files and opens an empty decoy vault, indistinguishable
        from a real unlock. Choose something you won't mix up with your real
        passphrase. It must meet the same strength requirements as your
        vault passphrase.
      </p>

      <form id="duress-form">
        <div class="field">
          <label for="duress-pin">Duress passphrase</label>
          <input type="password" id="duress-pin" autocomplete="new-password" minlength="12">
          <p class="field-hint" id="duress-pin-hint">Use 12+ characters, ideally a random passphrase of several unrelated words.</p>
        </div>
        <div class="field">
          <label for="duress-pin-confirm">Confirm</label>
          <input type="password" id="duress-pin-confirm" autocomplete="new-password" minlength="12">
        </div>
        <div class="panel-actions">
          <button type="button" id="duress-remove">Reset</button>
          <button type="submit" class="btn-primary" id="duress-save">Save</button>
        </div>
      </form>
    </div>
  `);

  $('duress-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pin = $('duress-pin').value;
    const pinConfirm = $('duress-pin-confirm').value;

    const { valid, errors } = C.validatePasswordStrength(pin);
    if (!valid) {
      showToast(errors[0] || 'Duress passphrase is too weak.', 'error');
      $('duress-pin-hint').textContent = errors[0];
      $('duress-pin-hint').classList.add('error');
      return;
    }
    if (pin !== pinConfirm) { showToast("Passphrases don't match.", 'error'); return; }

    const cfg = await C.setupDuress(pin, currentVaultId);
    saveDuressConfig(cfg);
    showToast('Duress Code saved.');
    closeLightbox();
  });

  $('duress-remove').addEventListener('click', () => {
    resetDuressConfig();
    showToast('Duress Code reset.');
    closeLightbox();
  });
}


async function refreshGallery() {
  records = [];
  pageOffset = 0;
  hasMorePages = true;
  try {
    const usage = await api.getUsage();
    updateUsagePill(usage);
  } catch (err) {
    showToast(err.message, 'error');
  }
  renderCurrentView();
  await loadNextPage();
  setupGridSentinel();
}

function updateUsagePill(usage) {
  usagePill.textContent = usage.quota_bytes != null
    ? `${formatBytes(usage.total_bytes)} / ${formatBytes(usage.quota_bytes)} \u00b7 ${usage.file_count} item${usage.file_count === 1 ? '' : 's'}`
    : `${usage.file_count} item${usage.file_count === 1 ? '' : 's'} \u00b7 ${formatBytes(usage.total_bytes)}`;
}

async function loadNextPage() {
  if (isLoadingPage || !hasMorePages) return;
  isLoadingPage = true;
  gridSentinel.classList.remove('hidden');
  gridSentinel.textContent = 'Loading\u2026';
  try {
    const page = await api.listFiles({ offset: pageOffset, limit: PAGE_SIZE });
    const known = new Set(records.map((r) => r.id));
    const fresh = page.filter((r) => !known.has(r.id));

    if (page.length < PAGE_SIZE || fresh.length === 0) hasMorePages = false;
    pageOffset += page.length || PAGE_SIZE;

    for (const record of fresh) {
      if (!fileKeyCache.has(record.id)) {
        try {
          const fileKeyRaw = await C.unwrapFileKey(wrappingKeyRaw, record.wrapped_file_key, record.wrap_iv);
          fileKeyCache.set(record.id, fileKeyRaw);
          const meta = await C.decryptMetadata(fileKeyRaw, record.encrypted_metadata, record.metadata_iv);
          metaCache.set(record.id, meta);
        } catch {
          metaCache.set(record.id, { name: 'Unreadable item', mime: 'application/octet-stream' });
        }
      }
    }

    records = records.concat(fresh);
    appendToCurrentView(fresh);
  } catch (err) {
    showToast(err.message, 'error');
    hasMorePages = false;
  } finally {
    isLoadingPage = false;
    gridSentinel.classList.toggle('hidden', !hasMorePages);
  }
}

async function loadAllPagesForSearch() {
  while (hasMorePages) {
    await loadNextPage();
  }
}

function setupGridSentinel() {
  if (gridObserver) gridObserver.disconnect();
  gridObserver = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) loadNextPage();
  }, { rootMargin: '400px' });
  gridObserver.observe(gridSentinel);
}

function visibleRecords() {
  if (!searchQuery) return records;
  const q = searchQuery.toLowerCase();
  return records.filter((r) => (metaCache.get(r.id)?.name || '').toLowerCase().includes(q));
}

function renderCurrentView() {
  boxGrid.innerHTML = '';
  fileListBody.innerHTML = '';
  const shown = visibleRecords();
  const searching = !!searchQuery;

  updateEmptyState(shown, searching);
  updateGridLabel(shown, searching);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  for (const record of shown) {
    target.appendChild(render(record));
  }
}

function appendToCurrentView(newRecords) {
  const searching = !!searchQuery;
  const q = searchQuery.toLowerCase();
  const toShow = searching
    ? newRecords.filter((r) => (metaCache.get(r.id)?.name || '').toLowerCase().includes(q))
    : newRecords;

  const shown = visibleRecords();
  updateEmptyState(shown, searching);
  updateGridLabel(shown, searching);

  const target = viewMode === 'list' ? fileListBody : boxGrid;
  const render = viewMode === 'list' ? renderListRow : renderTile;
  const fragment = document.createDocumentFragment();
  for (const record of toShow) {
    fragment.appendChild(render(record));
  }
  target.appendChild(fragment);
}

function updateEmptyState(shown, searching) {
  emptyState.classList.toggle('hidden', shown.length > 0);
  emptyState.querySelector('h3').textContent = searching ? 'No matches' : 'No files yet';
  emptyState.querySelector('p').textContent = searching
    ? `Nothing matches "${searchQuery}".`
    : 'Upload something above to see it here.';
}

function updateGridLabel(shown, searching) {
  gridLabel.textContent = shown.length
    ? `Files \u00b7 ${shown.length}${searching ? ` of ${records.length}` : ''}`
    : '';
}

let searchDebounce = null;
searchInput?.addEventListener('input', () => {
  clearTimeout(searchDebounce);
  searchClearBtn.classList.toggle('hidden', !searchInput.value);
  searchDebounce = setTimeout(async () => {
    searchQuery = searchInput.value.trim();
    if (searchQuery && hasMorePages) {
      gridSentinel.textContent = 'Loading all files to search\u2026';
      await loadAllPagesForSearch();
    }
    renderCurrentView();
  }, 180);
});

searchClearBtn?.addEventListener('click', () => {
  searchInput.value = '';
  searchQuery = '';
  searchClearBtn.classList.add('hidden');
  renderCurrentView();
  searchInput.focus();
});

function renderTile(record) {
  const meta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const kind = fileKind(meta.mime);

  const tile = document.createElement('div');
  tile.className = 'box-tile';
  tile.dataset.id = record.id;
  tile.tabIndex = 0;
  tile.setAttribute('role', 'button');
  tile.setAttribute('aria-label', `Open ${meta.name}`);

  tile.innerHTML = `
    <div class="box-menu">
      <button type="button" class="btn-icon delete-btn" aria-label="Delete ${escapeHtml(meta.name)}" title="Delete">${icon('trash')}</button>
    </div>
    <div class="box-body">
      ${kind === 'image' ? `<div class="box-icon">${icon('image')}</div><div class="box-name">${escapeHtml(meta.name)}</div>`
        : kind === 'video' ? `<div class="box-play">${icon('play')}</div><div class="box-icon">${icon('video')}</div><div class="box-name">${escapeHtml(meta.name)}</div>`
        : `<div class="box-icon">${icon('file')}</div><div class="box-name">${escapeHtml(meta.name)}</div>`}
    </div>
  `;

  tile.addEventListener('click', (e) => {
    if (e.target.closest('.delete-btn')) return;
    openTile(record.id);
  });
  tile.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openTile(record.id); }
  });
  tile.querySelector('.delete-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
  });

  if (kind === 'image') {
    const observer = new IntersectionObserver(async (entries) => {
      if (entries[0].isIntersecting) {
        observer.disconnect();
        try {
          const url = await getDecryptedUrl(record);
          const img = document.createElement('img');
          img.src = url;
          img.alt = meta.name;
          tile.querySelector('.box-body').prepend(img);
        } catch {  }
      }
    }, { rootMargin: '200px' });
    observer.observe(tile);
  }

  return tile;
}

function fileTypeLabel(meta) {
  const kind = fileKind(meta?.mime);
  if (kind === 'image') return 'Image';
  if (kind === 'video') return 'Video';
  const sub = (meta?.mime || '').split('/')[1];
  return sub ? sub.replace('x-', '').toUpperCase() : 'File';
}

function renderListRow(record) {
  const meta = metaCache.get(record.id) || { name: '\u2026', mime: '' };
  const kind = fileKind(meta.mime);

  const row = document.createElement('div');
  row.className = 'file-list-row';
  row.dataset.id = record.id;
  row.tabIndex = 0;
  row.setAttribute('role', 'row');
  row.setAttribute('aria-label', `Open ${meta.name}`);

  row.innerHTML = `
    <span class="file-row-name" role="cell">
      <span class="file-row-icon">${icon(kind === 'image' ? 'image' : kind === 'video' ? 'video' : 'file')}</span>
      <span class="file-row-text">${escapeHtml(meta.name)}</span>
    </span>
    <span class="file-row-type" role="cell">${escapeHtml(fileTypeLabel(meta))}</span>
    <span class="file-row-size" role="cell">${formatBytes(record.size ?? 0)}</span>
    <span class="file-row-actions" role="cell">
      <button type="button" class="btn-icon file-download-btn" aria-label="Download ${escapeHtml(meta.name)}" title="Download">${icon('download')}</button>
      <button type="button" class="btn-icon file-delete-btn" aria-label="Delete ${escapeHtml(meta.name)}" title="Delete">${icon('trash')}</button>
    </span>
  `;

  row.addEventListener('click', (e) => {
    if (e.target.closest('.file-download-btn') || e.target.closest('.file-delete-btn')) return;
    openTile(record.id);
  });
  row.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openTile(record.id); }
  });
  row.querySelector('.file-download-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    downloadAndSave(record, meta);
  });
  row.querySelector('.file-delete-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    handleDelete(record.id);
  });

  return row;
}

async function getDecryptedUrl(record) {
  if (objectUrlCache.has(record.id)) return objectUrlCache.get(record.id);
  const fileKeyRaw = fileKeyCache.get(record.id);
  let ciphertext = await api.downloadContent(record.id);
  const meta = metaCache.get(record.id);
  let bytes = await C.decryptContent(fileKeyRaw, record.content_iv, ciphertext, meta.compressed, meta.unpaddedSize);
  ciphertext = null;
  const blob = new Blob([bytes], { type: meta.mime });
  bytes = null;
  const url = URL.createObjectURL(blob);
  objectUrlCache.set(record.id, url);
  return url;
}


const isCoarsePointerDevice = typeof window.matchMedia === 'function'
  && window.matchMedia('(pointer: coarse)').matches;
const MOBILE_INLINE_VIDEO_LIMIT_BYTES = 150 * 1024 * 1024;

function isUnsafeToPreviewInline(record, meta) {
  return isCoarsePointerDevice
    && fileKind(meta?.mime) === 'video'
    && typeof record?.size === 'number'
    && record.size > MOBILE_INLINE_VIDEO_LIMIT_BYTES;
}

function mediaRecords() {
  return visibleRecords().filter((r) => {
    const meta = metaCache.get(r.id);
    if (fileKind(meta?.mime) === 'other') return false;
    if (isUnsafeToPreviewInline(r, meta)) return false;
    return true;
  });
}

async function openTile(fileId) {
  const record = records.find((r) => r.id === fileId);
  const meta = metaCache.get(fileId);
  if (!record || !meta) return;

  const kind = fileKind(meta.mime);
  const skipInlinePreview = isUnsafeToPreviewInline(record, meta);

  if (kind === 'other' || skipInlinePreview) {
    lightboxMediaList = [];
    lightboxIndex = -1;
    const tileEl = boxGrid.querySelector(`[data-id="${fileId}"]`);
    tileEl?.classList.add('opening');
    showLightbox(`
      <div class="lightbox-generic">
        ${icon(kind === 'video' ? 'video' : 'file')}
        <p style="margin:12px 0 0;color:var(--text);font-family:var(--font-mono)">${escapeHtml(meta.name)}</p>
        <p style="font-size:0.8rem;margin-top:6px">${formatBytes(record.size)} \u00b7 encrypted</p>
        ${skipInlinePreview ? `<p style="font-size:0.78rem;margin-top:10px;color:var(--dim)">This video is large \u2014 previewing it in-browser on a phone can crash the tab. Download it to watch in your device's player instead.</p>` : ''}
        <button class="btn-primary" id="lightbox-download" style="margin-top:18px">Decrypt &amp; download</button>
      </div>
    `);
    $('lightbox-download').addEventListener('click', () => downloadAndSave(record, meta));
    tileEl?.classList.remove('opening');
    return;
  }

  const list = mediaRecords();
  const index = list.findIndex((r) => r.id === fileId);
  await openMediaAt(list, index >= 0 ? index : 0);
}

async function openMediaAt(list, index) {
  if (!list.length) return;
  index = ((index % list.length) + list.length) % list.length;
  const record = list[index];
  const meta = metaCache.get(record.id);
  if (!record || !meta) return;

  lightboxMediaList = list;
  lightboxIndex = index;
  lightbox.classList.toggle('has-nav', list.length > 1);

  const tileEl = boxGrid.querySelector(`[data-id="${record.id}"]`);
  tileEl?.classList.add('decrypting');
  showLightbox(`<div class="lightbox-content"><div class="spinner" style="width:32px;height:32px"></div></div>`, { keepMedia: true });

  try {
    const url = await getDecryptedUrl(record);
    const kind = fileKind(meta.mime);
    const inner = kind === 'image'
      ? `<img src="${url}" alt="${escapeHtml(meta.name)}" id="lightbox-media">`
      : `<video src="${url}" controls autoplay id="lightbox-media"></video>`;
    const showNav = lightboxMediaList.length > 1;
    showLightbox(`
      <div class="lightbox-content">
        ${showNav ? `<button class="btn-icon lightbox-nav lightbox-nav-prev" id="lightbox-prev" aria-label="Previous">${icon('chevronLeft')}</button>` : ''}
        ${inner}
        ${showNav ? `<button class="btn-icon lightbox-nav lightbox-nav-next" id="lightbox-next" aria-label="Next">${icon('chevronRight')}</button>` : ''}
        <div class="lightbox-meta">
          <span class="fname">${escapeHtml(meta.name)}${showNav ? ` \u00b7 ${lightboxIndex + 1}/${lightboxMediaList.length}` : ''}</span>
          <button class="btn-icon" id="lightbox-fullscreen" title="Full screen" aria-label="Full screen">${icon('expand')}</button>
          <button class="btn-icon" id="lightbox-download" title="Download" aria-label="Download">${icon('download')}</button>
        </div>
      </div>
    `, { keepMedia: true });

    $('lightbox-download').addEventListener('click', () => downloadAndSave(record, meta, url));
    $('lightbox-fullscreen').addEventListener('click', () => {
      const mediaEl = $('lightbox-media');
      if (mediaEl?.requestFullscreen) mediaEl.requestFullscreen().catch(() => {});
    });
    $('lightbox-prev')?.addEventListener('click', () => navigateLightbox(-1));
    $('lightbox-next')?.addEventListener('click', () => navigateLightbox(1));
  } catch (err) {
    showToast("Couldn't decrypt that file. " + err.message, 'error');
    closeLightbox();
  } finally {
    tileEl?.classList.remove('decrypting', 'opening');
  }
}

function navigateLightbox(delta) {
  if (lightboxMediaList.length < 2 || lightboxIndex < 0) return;
  openMediaAt(lightboxMediaList, lightboxIndex + delta);
}

function showLightbox(innerHtml, { keepMedia = false } = {}) {
  if (!keepMedia) {
    lightboxMediaList = [];
    lightboxIndex = -1;
    lightbox.classList.remove('has-nav');
  }
  lightbox.innerHTML = `
    <button class="btn-icon lightbox-close" id="lightbox-close" aria-label="Close">${icon('close')}</button>
    ${innerHtml}
  `;
  lightbox.classList.remove('hidden');
  lightbox.tabIndex = -1;
  lightbox.focus({ preventScroll: true });
  $('lightbox-close').addEventListener('click', closeLightbox);
  lightbox.addEventListener('click', (e) => { if (e.target === lightbox) closeLightbox(); }, { once: true });
}

function closeLightbox() {
  const video = lightbox.querySelector('video');
  if (video) video.pause();
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  lightbox.classList.add('hidden');
  lightbox.classList.remove('has-nav');
  lightbox.innerHTML = '';
  lightboxMediaList = [];
  lightboxIndex = -1;
}

document.addEventListener('keydown', (e) => {
  if (lightbox.classList.contains('hidden')) return;
  if (e.key === 'Escape') { closeLightbox(); return; }
  if (e.key === 'ArrowLeft') { e.preventDefault(); navigateLightbox(-1); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); navigateLightbox(1); }
});

lightbox.addEventListener('wheel', (e) => {
  if (lightboxMediaList.length < 2) return;
  if (Math.abs(e.deltaX) <= Math.abs(e.deltaY) || Math.abs(e.deltaX) < 24) return;
  e.preventDefault();
  if (lightboxNavLock) return;
  lightboxNavLock = true;
  navigateLightbox(e.deltaX > 0 ? 1 : -1);
  setTimeout(() => { lightboxNavLock = false; }, 350);
}, { passive: false });

let touchStartX = null;
let touchStartY = null;
lightbox.addEventListener('touchstart', (e) => {
  if (e.touches.length !== 1) return;
  touchStartX = e.touches[0].clientX;
  touchStartY = e.touches[0].clientY;
}, { passive: true });
lightbox.addEventListener('touchend', (e) => {
  if (touchStartX == null || lightboxMediaList.length < 2) { touchStartX = null; return; }
  const touch = e.changedTouches[0];
  const dx = touch.clientX - touchStartX;
  const dy = touch.clientY - touchStartY;
  touchStartX = null;
  if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy)) navigateLightbox(dx < 0 ? 1 : -1);
}, { passive: true });

async function downloadAndSave(record, meta, existingUrl) {
  let url = existingUrl;
  try {
    if (!url) {
      const fileKeyRaw = fileKeyCache.get(record.id);
      const ciphertext = await api.downloadContent(record.id);
      const bytes = await C.decryptContent(fileKeyRaw, record.content_iv, ciphertext, meta.compressed, meta.unpaddedSize);
      const blob = new Blob([bytes], { type: meta.mime });
      url = URL.createObjectURL(blob);
    }
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.name;
    a.click();
    if (!existingUrl) URL.revokeObjectURL(url);
  } catch (err) {
    showToast("Download failed. " + err.message, 'error');
  }
}


async function handleDelete(fileId) {
  const meta = metaCache.get(fileId);
  if (!confirm(`Delete "${meta?.name ?? 'this file'}"? This can't be undone.`)) return;
  try {
    await api.deleteFile(fileId);
    if (objectUrlCache.has(fileId)) { URL.revokeObjectURL(objectUrlCache.get(fileId)); objectUrlCache.delete(fileId); }
    fileKeyCache.delete(fileId);
    metaCache.delete(fileId);
    records = records.filter((r) => r.id !== fileId);
    renderCurrentView();
    showToast('Deleted.');
  } catch (err) {
    showToast("Couldn't delete that file. " + err.message, 'error');
  }
}


chooseFilesBtn.addEventListener('click', () => fileInput.click());
depositSlot.addEventListener('click', (e) => { if (e.target === depositSlot || e.target.tagName === 'P' || e.target.tagName === 'H2') fileInput.click(); });
depositSlot.addEventListener('keydown', (e) => { if (e.key === 'Enter') fileInput.click(); });

fileInput.addEventListener('change', () => {
  handleFiles([...fileInput.files]);
  fileInput.value = '';
});

['dragenter', 'dragover'].forEach((evt) =>
  depositSlot.addEventListener(evt, (e) => { e.preventDefault(); depositSlot.classList.add('drag-over'); })
);
['dragleave', 'drop'].forEach((evt) =>
  depositSlot.addEventListener(evt, (e) => { e.preventDefault(); depositSlot.classList.remove('drag-over'); })
);
depositSlot.addEventListener('drop', (e) => {
  const files = [...(e.dataTransfer?.files ?? [])];
  if (files.length) handleFiles(files);
});

const MAX_VISIBLE_UPLOADS = 10;
const MAX_CONCURRENT_UPLOADS = 3;
let uploadRows = [];
let uploadMoreIndicator = null;

function getUploadMoreIndicator() {
  if (!uploadMoreIndicator) {
    uploadMoreIndicator = document.createElement('div');
    uploadMoreIndicator.className = 'upload-more';
  }
  return uploadMoreIndicator;
}

function syncUploadQueueView() {
  const visible = uploadRows.slice(0, MAX_VISIBLE_UPLOADS);
  const hiddenCount = uploadRows.length - visible.length;
  const indicator = getUploadMoreIndicator();

  for (const item of visible) {
    if (!item.el.isConnected) uploadQueue.insertBefore(item.el, indicator.isConnected ? indicator : null);
  }

  if (hiddenCount > 0) {
    indicator.textContent = `\u2026 +${hiddenCount} more`;
    if (!indicator.isConnected) uploadQueue.appendChild(indicator);
  } else if (indicator.isConnected) {
    indicator.remove();
  }
}

async function handleFiles(files) {
  const queue = files.map((file) => ({ file, rowItem: createUploadRow(file) }));
  const workerCount = Math.min(MAX_CONCURRENT_UPLOADS, queue.length);
  await Promise.all(Array.from({ length: workerCount }, () => runUploadWorker(queue)));
}

async function runUploadWorker(queue) {
  let item;
  while ((item = queue.shift())) {
    await uploadOne(item.file, item.rowItem);
  }
}

function createUploadRow(file) {
  const row = document.createElement('div');
  row.className = 'upload-row';
  row.innerHTML = `
    <span class="name">${escapeHtml(file.name)}</span>
    <span class="status">Queued\u2026</span>
    <button type="button" class="btn-icon upload-cancel hidden" aria-label="Cancel upload" title="Cancel upload">${icon('close')}</button>
    <div class="bar"><div class="bar-fill" style="width:0%"></div></div>
  `;
  const rowItem = { el: row };
  uploadRows.push(rowItem);
  syncUploadQueueView();
  return rowItem;
}

const RETRY_BASE_MS = 1000;
const RETRY_MAX_MS = 30000;

function retryDelay(attempt) {
  return Math.min(RETRY_BASE_MS * 2 ** (attempt - 1), RETRY_MAX_MS);
}

async function waitWithCountdown(ms, statusEl, isCancelled, reason) {
  const end = Date.now() + ms;
  statusEl.title = reason || '';
  while (Date.now() < end) {
    if (isCancelled()) return;
    const secsLeft = Math.max(1, Math.ceil((end - Date.now()) / 1000));
    statusEl.textContent = `Retry in ${secsLeft}s\u2026`;
    await new Promise((r) => setTimeout(r, 250));
  }
}

async function uploadOne(file, rowItem) {
  const row = rowItem.el;
  const statusEl = row.querySelector('.status');
  const barEl = row.querySelector('.bar-fill');
  const cancelBtn = row.querySelector('.upload-cancel');

  const controller = new AbortController();
  let cancelled = false;
  const cancelUpload = () => { cancelled = true; controller.abort(); };
  cancelBtn.classList.remove('hidden');
  cancelBtn.addEventListener('click', cancelUpload);

  const removeRow = () => {
    uploadRows = uploadRows.filter((r) => r !== rowItem);
    row.remove();
    syncUploadQueueView();
  };

  const finishCancelled = () => {
    row.classList.add('error');
    statusEl.textContent = 'Cancelled';
    statusEl.removeAttribute('title');
    cancelBtn.classList.add('hidden');
    setTimeout(removeRow, 1800);
  };

  statusEl.textContent = 'Encrypting\u2026';
  let encrypted;
  try {
    encrypted = await C.encryptFile(wrappingKeyRaw, file);
  } catch (err) {
    row.classList.add('error');
    statusEl.textContent = 'Failed';
    cancelBtn.classList.add('hidden');
    showToast(`Couldn't encrypt "${file.name}". ${err.message}`, 'error');
    return;
  }

  if (cancelled) { finishCancelled(); return; }

  let attempt = 0;
  for (;;) {
    try {
      statusEl.textContent = attempt === 0 ? 'Uploading\u2026' : `Retrying\u2026 (attempt ${attempt + 1})`;
      statusEl.removeAttribute('title');
      barEl.style.width = '0%';
      await api.uploadFile(encrypted, (fraction) => {
        barEl.style.width = `${Math.round(fraction * 100)}%`;
      }, controller.signal);

      row.classList.remove('error');
      row.classList.add('done');
      statusEl.textContent = 'Done';
      cancelBtn.classList.add('hidden');
      setTimeout(removeRow, 1800);

      await refreshGallery();
      return;
    } catch (err) {
      if (cancelled || err.name === 'AbortError') { finishCancelled(); return; }

      attempt++;
      row.classList.add('error');
      if (attempt === 1) {
        showToast(`Upload of "${file.name}" failed. Retrying automatically\u2026`, 'error');
      }
      await waitWithCountdown(retryDelay(attempt), statusEl, () => cancelled, err.message);
      if (cancelled) { finishCancelled(); return; }
      row.classList.remove('error');
    }
  }
}