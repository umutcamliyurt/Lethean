import * as C from './crypto.js';
import * as api from './api.js';

let wrappingKeyRaw = null;
let currentVaultId = null;

const fileKeyCache = new Map();
const metaCache = new Map();
const objectUrlCache = new Map();
let records = [];

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
const emptyState = $('empty-state');
const gridLabel = $('grid-label');
const usagePill = $('usage-pill');
const vaultFingerprint = $('vault-fingerprint');
const logoutBtn = $('logout-btn');
const tokenBtn = $('token-btn');
const duressBtn = $('duress-btn');
const lightbox = $('lightbox');
const toasts = $('toasts');


const LS_SETUP_KEY = 'vault.setupComplete';
const LS_DURESS_KEY = 'vault.duress';
const LS_ACCESS_TOKEN_KEY = 'vault.accessToken';

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
  boxGrid.innerHTML = '';
  emptyState.classList.add('hidden');
  gridLabel.textContent = '';
  usagePill.textContent = '\u2014 items \u00b7,';
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
  try {
    const [list, usage] = await Promise.all([api.listFiles(), api.getUsage()]);
    records = list;
    usagePill.textContent = usage.quota_bytes != null
      ? `${formatBytes(usage.total_bytes)} / ${formatBytes(usage.quota_bytes)} \u00b7 ${usage.file_count} item${usage.file_count === 1 ? '' : 's'}`
      : `${usage.file_count} item${usage.file_count === 1 ? '' : 's'} \u00b7 ${formatBytes(usage.total_bytes)}`;

    for (const record of records) {
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

    renderGrid();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderGrid() {
  boxGrid.innerHTML = '';
  emptyState.classList.toggle('hidden', records.length > 0);
  gridLabel.textContent = records.length ? `Files \u00b7 ${records.length}` : '';

  for (const record of records) {
    boxGrid.appendChild(renderTile(record));
  }
}

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

async function getDecryptedUrl(record) {
  if (objectUrlCache.has(record.id)) return objectUrlCache.get(record.id);
  const fileKeyRaw = fileKeyCache.get(record.id);
  const ciphertext = await api.downloadContent(record.id);
  const bytes = await C.decryptContent(fileKeyRaw, record.content_iv, ciphertext);
  const meta = metaCache.get(record.id);
  const blob = new Blob([bytes], { type: meta.mime });
  const url = URL.createObjectURL(blob);
  objectUrlCache.set(record.id, url);
  return url;
}


async function openTile(fileId) {
  const record = records.find((r) => r.id === fileId);
  const meta = metaCache.get(fileId);
  if (!record || !meta) return;

  const tileEl = boxGrid.querySelector(`[data-id="${fileId}"]`);
  tileEl?.classList.add('opening');

  const kind = fileKind(meta.mime);

  if (kind === 'other') {
    showLightbox(`
      <div class="lightbox-generic">
        ${icon('file')}
        <p style="margin:12px 0 0;color:var(--text);font-family:var(--font-mono)">${escapeHtml(meta.name)}</p>
        <p style="font-size:0.8rem;margin-top:6px">${formatBytes(record.size)} \u00b7 encrypted</p>
        <button class="btn-primary" id="lightbox-download" style="margin-top:18px">Decrypt &amp; download</button>
      </div>
    `);
    $('lightbox-download').addEventListener('click', () => downloadAndSave(record, meta));
    return;
  }

  tileEl?.classList.add('decrypting');
  showLightbox(`<div class="lightbox-content"><div class="spinner" style="width:32px;height:32px"></div></div>`);

  try {
    const url = await getDecryptedUrl(record);
    const inner = kind === 'image'
      ? `<img src="${url}" alt="${escapeHtml(meta.name)}">`
      : `<video src="${url}" controls autoplay></video>`;
    showLightbox(`
      <div class="lightbox-content">
        ${inner}
        <div class="lightbox-meta">
          <span class="fname">${escapeHtml(meta.name)}</span>
          <button class="btn-icon" id="lightbox-download" title="Download" aria-label="Download">${icon('download')}</button>
        </div>
      </div>
    `);
    $('lightbox-download').addEventListener('click', () => downloadAndSave(record, meta, url));
  } catch (err) {
    showToast("Couldn't decrypt that file. " + err.message, 'error');
    closeLightbox();
  } finally {
    tileEl?.classList.remove('decrypting', 'opening');
  }
}

function showLightbox(innerHtml) {
  lightbox.innerHTML = `
    <button class="btn-icon lightbox-close" id="lightbox-close" aria-label="Close">${icon('close')}</button>
    ${innerHtml}
  `;
  lightbox.classList.remove('hidden');
  $('lightbox-close').addEventListener('click', closeLightbox);
  lightbox.addEventListener('click', (e) => { if (e.target === lightbox) closeLightbox(); }, { once: true });
}

function closeLightbox() {
  const video = lightbox.querySelector('video');
  if (video) video.pause();
  lightbox.classList.add('hidden');
  lightbox.innerHTML = '';
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !lightbox.classList.contains('hidden')) closeLightbox();
});

async function downloadAndSave(record, meta, existingUrl) {
  let url = existingUrl;
  try {
    if (!url) {
      const fileKeyRaw = fileKeyCache.get(record.id);
      const ciphertext = await api.downloadContent(record.id);
      const bytes = await C.decryptContent(fileKeyRaw, record.content_iv, ciphertext);
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
    renderGrid();
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

async function handleFiles(files) {
  for (const file of files) uploadOne(file);
}

async function uploadOne(file) {
  const row = document.createElement('div');
  row.className = 'upload-row';
  row.innerHTML = `
    <span class="name">${escapeHtml(file.name)}</span>
    <span class="status">Encrypting\u2026</span>
    <div class="bar"><div class="bar-fill" style="width:0%"></div></div>
  `;
  uploadQueue.appendChild(row);
  const statusEl = row.querySelector('.status');
  const barEl = row.querySelector('.bar-fill');

  try {
    const encrypted = await C.encryptFile(wrappingKeyRaw, file);

    statusEl.textContent = 'Uploading\u2026';
    await api.uploadFile(encrypted, (fraction) => {
      barEl.style.width = `${Math.round(fraction * 100)}%`;
    });

    row.classList.add('done');
    statusEl.textContent = 'Done';
    setTimeout(() => row.remove(), 1800);

    await refreshGallery();
  } catch (err) {
    row.classList.add('error');
    statusEl.textContent = 'Failed';
    showToast(`Couldn't upload "${file.name}". ${err.message}`, 'error');
  }
}