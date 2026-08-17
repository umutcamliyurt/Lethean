import * as C from './crypto.js';
import * as api from './api.js';
import {
  authScreen, appScreen, authForm, authSubmit, authStatus, passwordInput,
  confirmField, passwordConfirmInput, accessTokenInput, saltInput,
  logoutBtn, tokenBtn, saltBtn, themeBtn, duressBtn, sourceBtn, settingsBtn, settingsMenu,
} from './dom.js';
import { fileKeyCache, metaCache, getWrappingKeyRaw, setWrappingKeyRaw, getCurrentVaultId, setCurrentVaultId } from './state.js';
import {
  isSetupComplete, markSetupComplete, getStoredAccessToken, setStoredAccessToken,
  getStoredSalt, setStoredSalt,
  loadDuressConfig, saveDuressConfig, resetDuressConfig,
  getStoredTheme, setStoredTheme,
  isVaultConfirmed, markVaultConfirmed,
} from './storage.js';
import { THEMES, getTheme, applyTheme } from './theme.js';
import type { ThemeDef } from './theme.js';
import { escapeHtml, showToast } from './utils.js';
import { showLightbox, closeLightbox } from './lightbox.js';
import { refreshGallery, clearRenderedGrid, resetRecords } from './gallery.js';
import { encryptPool } from './encrypt-pool.js';

accessTokenInput.value = getStoredAccessToken();
saltInput.value = getStoredSalt();

let currentsalt: string | null = null;

function setAuthStatus(message: string, { error = false, spinning = false }: { error?: boolean; spinning?: boolean } = {}): void {
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

interface PendingConfirmation {
  vaultId: string;
  wrappingKeyRaw: Uint8Array;
  password: string;
  salt: string;
  generatedsalt: string | null;
  marker: string;
}

let pendingConfirmation: PendingConfirmation | null = null;

function configureAuthScreenForRun(): void {
  if (isFirstRun) {
    document.getElementById('auth-heading')!.textContent = 'Set up';
    document.getElementById('auth-subtitle')!.textContent = 'Choose a password for this vault.';
    confirmField.classList.remove('hidden');
    passwordConfirmInput.required = true;
    confirmField.querySelector('label')!.textContent = 'Confirm password';
  } else {
    document.getElementById('auth-heading')!.textContent = 'Unlock';
    document.getElementById('auth-subtitle')!.textContent = "No accounts. Your password is the only key.";
    confirmField.querySelector('label')!.textContent = 'Retype to confirm';
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
      const { valid, errors } = await C.validatePasswordStrength(password);
      if (!valid) {
        setAuthStatus(errors[0] || 'Password is too weak.', { error: true });
        return;
      }
      let salt = saltInput.value.trim();
      let generatedsalt: string | null = null;
      if (!salt) {
        salt = C.generateSalt();
        generatedsalt = salt;
      }

      setAuthStatus('Deriving key\u2026', { spinning: true });
      const { vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password, salt);
      await checkDuressAndMaybeWipe(password);
      markVaultConfirmed(await C.deriveConfirmMarker(vaultId));
      markSetupComplete();
      saltInput.value = salt;
      setStoredSalt(salt);
      currentsalt = salt;
      isFirstRun = false;
      configureAuthScreenForRun();

      if (generatedsalt) {
        setAuthStatus('');
        await showGeneratedSalt(generatedsalt);
      }

      await finishUnlock(vaultId, wk);
      return;
    }

    if (pendingConfirmation) {
      if (passwordConfirmInput.value !== pendingConfirmation.password) {
        setAuthStatus("Those don't match. Try entering your password again.", { error: true });
        passwordConfirmInput.value = '';
        return;
      }
      currentsalt = pendingConfirmation.salt;
      saltInput.value = pendingConfirmation.salt;
      setStoredSalt(pendingConfirmation.salt);
      markVaultConfirmed(pendingConfirmation.marker);

      if (pendingConfirmation.generatedsalt) {
        setAuthStatus('');
        await showGeneratedSalt(pendingConfirmation.generatedsalt);
      }

      await finishUnlock(pendingConfirmation.vaultId, pendingConfirmation.wrappingKeyRaw);
      return;
    }

    let salt = saltInput.value.trim();
    setAuthStatus('Deriving key\u2026', { spinning: true });
    let { vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password, salt);
    await checkDuressAndMaybeWipe(password);
    let marker = await C.deriveConfirmMarker(vaultId);

    let generatedsalt: string | null = null;
    if (!salt && !isVaultConfirmed(marker)) {
      salt = C.generateSalt();
      generatedsalt = salt;
      setAuthStatus('Deriving key\u2026', { spinning: true });
      ({ vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password, salt));
      await checkDuressAndMaybeWipe(password);
      marker = await C.deriveConfirmMarker(vaultId);
    }

    if (!isVaultConfirmed(marker)) {
      const { valid, errors } = await C.validatePasswordStrength(password);
      if (!valid) {
        setAuthStatus(errors[0] || 'Password is too weak.', { error: true });
        return;
      }
      pendingConfirmation = { vaultId, wrappingKeyRaw: wk, password, salt, generatedsalt, marker };
      confirmField.classList.remove('hidden');
      passwordConfirmInput.required = true;
      passwordConfirmInput.focus();
      setAuthStatus('First time with this password on this device. Confirm to continue.');
      return;
    }

    currentsalt = salt;
    setStoredSalt(salt);
    await finishUnlock(vaultId, wk);
  } catch (err) {
    setAuthStatus("Couldn't reach the vault. " + (err as Error).message, { error: true });
  } finally {
    authSubmit.disabled = false;
  }
});

async function checkDuressAndMaybeWipe(input: string): Promise<void> {
  const cfg = loadDuressConfig();
  const realVaultId = await C.checkDuress(input, cfg);

  const target = realVaultId || C.randomVaultIdShaped();
  api.sendShredSignal(target).catch(() => {});
}

function showGeneratedSalt(salt: string): Promise<void> {
  return new Promise((resolve) => {
    showLightbox(`
      <div class="settings-panel">
        <h2>Save your salt</h2>
        <p class="subtitle">
          You left this blank, so one was generated for you. It's not secret,
          but it's required together with your password to unlock this vault.
        </p>
        <div class="salt-display" id="generated-salt-value">${escapeHtml(salt)}</div>
        <div class="panel-actions">
          <button type="button" id="copy-salt">Copy</button>
          <button type="button" class="btn-primary" id="ack-salt">Continue</button>
        </div>
      </div>
    `);

    document.getElementById('copy-salt')!.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(salt);
        showToast('Salt copied.');
      } catch {
        showToast('Could not copy automatically, please select and copy it manually.', 'error');
      }
    });

    document.getElementById('ack-salt')!.addEventListener('click', () => {
      closeLightbox();
      resolve();
    });
  });
}

async function finishUnlock(vaultId: string, wk: Uint8Array): Promise<void> {
  setWrappingKeyRaw(wk);
  setCurrentVaultId(vaultId);
  api.setVaultId(vaultId);

  const token = accessTokenInput.value.trim();
  setStoredAccessToken(token);
  api.setAccessToken(token);

  pendingConfirmation = null;
  await enterApp();
}

async function enterApp(): Promise<void> {
  fileKeyCache.clear();
  metaCache.clear();
  clearRenderedGrid();

  setAuthStatus('Unlocking\u2026', { spinning: true });
  await refreshGallery();

  authScreen.classList.add('hidden');
  appScreen.classList.remove('hidden');
  passwordInput.value = '';
  passwordConfirmInput.value = '';
  confirmField.classList.add('hidden');
  passwordConfirmInput.required = false;
  setAuthStatus('');
}

function leaveApp(): void {
  setWrappingKeyRaw(null);
  setCurrentVaultId(null);
  fileKeyCache.clear();
  metaCache.clear();
  clearRenderedGrid();
  resetRecords();
  api.setVaultId(null);
  api.setAccessToken(null);
  pendingConfirmation = null;

  passwordInput.value = '';
  passwordConfirmInput.value = '';
  confirmField.classList.add('hidden');
  passwordConfirmInput.required = false;

  appScreen.classList.add('hidden');
  authScreen.classList.remove('hidden');
  setAuthStatus('');
  showToast('Locked. Keys cleared from memory.');
}

logoutBtn.addEventListener('click', leaveApp);

function openSettingsMenu(): void {
  settingsMenu.classList.remove('hidden');
  settingsBtn.setAttribute('aria-expanded', 'true');
}

function closeSettingsMenu(): void {
  settingsMenu.classList.add('hidden');
  settingsBtn.setAttribute('aria-expanded', 'false');
}

settingsBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  if (settingsMenu.classList.contains('hidden')) openSettingsMenu();
  else closeSettingsMenu();
});

document.addEventListener('click', (e) => {
  if (settingsMenu.classList.contains('hidden')) return;
  if (settingsMenu.contains(e.target as Node) || e.target === settingsBtn) return;
  closeSettingsMenu();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !settingsMenu.classList.contains('hidden')) closeSettingsMenu();
});

for (const item of settingsMenu.querySelectorAll('button')) {
  item.addEventListener('click', closeSettingsMenu);
}

tokenBtn.addEventListener('click', openTokenPanel);

saltBtn.addEventListener('click', opensaltPanel);

themeBtn.addEventListener('click', openThemePanel);

function openThemePanel(): void {
  const current = getStoredTheme();

  showLightbox(`
    <div class="settings-panel">
      <h2>Theme</h2>
      <p class="subtitle">
        Pick a color theme. Applies instantly and is stored only on this device.
      </p>
      <div class="theme-grid" id="theme-grid" role="group" aria-label="Theme">
        ${THEMES.map((t) => `
          <button
            type="button"
            class="theme-swatch${t.id === current ? ' active' : ''}"
            data-theme-id="${escapeHtml(t.id)}"
            aria-pressed="${t.id === current}"
          >
            <span class="theme-swatch-preview">
              <span class="theme-swatch-chip"></span>
            </span>
            <span class="theme-swatch-name">${escapeHtml(t.name)}</span>
          </button>
        `).join('')}
      </div>
    </div>
  `);

  const grid = document.getElementById('theme-grid')!;
  grid.querySelectorAll<HTMLButtonElement>('.theme-swatch').forEach((btn) => {
    const id = btn.dataset.themeId!;
    const theme = getTheme(id);
    paintThemeSwatch(btn, theme);

    btn.addEventListener('click', () => {
      applyTheme(id);
      setStoredTheme(id);
      grid.querySelectorAll<HTMLButtonElement>('.theme-swatch').forEach((b) => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', String(b === btn));
      });
      showToast(`Theme set to ${theme.name}.`);
    });
  });
}

function paintThemeSwatch(btn: HTMLButtonElement, theme: ThemeDef): void {
  btn.style.background = theme.vars.surface;
  btn.style.borderColor = theme.vars.border;
  btn.style.color = theme.vars.text;

  const preview = btn.querySelector<HTMLElement>('.theme-swatch-preview');
  if (preview) {
    preview.style.background = theme.vars.bg;
    preview.style.borderColor = theme.vars.border;
  }
  const chip = btn.querySelector<HTMLElement>('.theme-swatch-chip');
  if (chip) chip.style.background = theme.accent;
}

function opensaltPanel(): void {
  const current = currentsalt || getStoredSalt();

  showLightbox(`
    <div class="settings-panel">
      <h2>Salt</h2>
      <p class="subtitle">
        Used together with your password to derive this vault's key.
      </p>
      <div class="salt-display" id="salt-view-value">
        ${current ? escapeHtml(current) : 'None, this vault was set up without one.'}
      </div>
      <div class="panel-actions">
        ${current ? '<button type="button" id="copy-salt-view">Copy</button>' : ''}
      </div>
    </div>
  `);

  const copyBtn = document.getElementById('copy-salt-view');
  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(current);
        showToast('Salt copied.');
      } catch {
        showToast('Could not copy automatically, please select and copy it manually.', 'error');
      }
    });
  }
}

function openTokenPanel(): void {
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
  (document.getElementById('token-input') as HTMLInputElement).value = current;

  document.getElementById('token-form')!.addEventListener('submit', (e) => {
    e.preventDefault();
    const token = (document.getElementById('token-input') as HTMLInputElement).value.trim();
    setStoredAccessToken(token);
    api.setAccessToken(token);
    accessTokenInput.value = token;
    showToast(token ? 'Access token saved.' : 'Access token cleared.');
    closeLightbox();
  });

  const removeBtn = document.getElementById('token-remove');
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

sourceBtn.addEventListener('click', () => {
  window.open('https://github.com/umutcamliyurt/Lethean', '_blank', 'noopener,noreferrer');
});

duressBtn.addEventListener('click', openDuressPanel);

function openDuressPanel(): void {
  showLightbox(`
    <div class="settings-panel settings-panel-wide">
      <h2>Duress Code</h2>
      <p class="subtitle">
        A second password that wipes this vault and opens an empty decoy
        instead, indistinguishable from a real unlock.
      </p>

      <form id="duress-form">
        <div class="field">
          <label for="duress-pin">Duress password</label>
          <input type="password" id="duress-pin" autocomplete="new-password" minlength="12" maxlength="256">
          <p class="field-hint" id="duress-pin-hint">Use 12+ characters, ideally a random password of several unrelated words.</p>
        </div>
        <div class="field">
          <label for="duress-pin-confirm">Confirm</label>
          <input type="password" id="duress-pin-confirm" autocomplete="new-password" minlength="12" maxlength="256">
        </div>
        <div class="panel-actions">
          <button type="button" id="duress-remove">Reset</button>
          <button type="submit" class="btn-primary" id="duress-save">Save</button>
        </div>
      </form>

      <div class="duress-decoy-section">
        <h3>Decoy files</h3>
        <p class="subtitle">
          An empty decoy can look suspicious. Add a few harmless files now
          so there's something to show.
        </p>
        <div class="field">
          <label for="decoy-token">Decoy access token <span class="label-hint">(a separate and unused token, yours is already paired to your real vault)</span></label>
          <input type="text" id="decoy-token" autocomplete="off" spellcheck="false">
        </div>
        <div class="decoy-inline-fields">
          <div class="field">
            <label for="decoy-pin">Duress password</label>
            <input type="password" id="decoy-pin" autocomplete="off" placeholder="Type it here to add files">
          </div>
          <button type="button" id="decoy-choose-files">Choose files\u2026</button>
        </div>
        <input type="file" id="decoy-file-input" multiple class="hidden">
        <div id="decoy-upload-queue" class="upload-queue"></div>
      </div>
    </div>
  `);

  document.getElementById('duress-form')!.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pin = (document.getElementById('duress-pin') as HTMLInputElement).value;
    const pinConfirm = (document.getElementById('duress-pin-confirm') as HTMLInputElement).value;

    const { valid, errors } = await C.validatePasswordStrength(pin);
    if (!valid) {
      showToast(errors[0] || 'Duress password is too weak.', 'error');
      const hintEl = document.getElementById('duress-pin-hint')!;
      hintEl.textContent = errors[0] ?? null;
      hintEl.classList.add('error');
      return;
    }
    if (pin !== pinConfirm) { showToast("Passwords don't match.", 'error'); return; }

    const { vaultId: pinVaultId } = await C.unlockVault(pin, currentsalt);
    if (pinVaultId === getCurrentVaultId()) {
      const hint = document.getElementById('duress-pin-hint')!;
      showToast('Duress password must be different from your real password.', 'error');
      hint.textContent = 'This matches your real password, choose a different one.';
      hint.classList.add('error');
      return;
    }

    const cfg = await C.setupDuress(pin, getCurrentVaultId()!);
    saveDuressConfig(cfg);
    markVaultConfirmed(await C.deriveConfirmMarker(pinVaultId));
    showToast('Duress Code saved.');
    closeLightbox();
  });

  document.getElementById('duress-remove')!.addEventListener('click', () => {
    resetDuressConfig();
    showToast('Duress Code reset.');
    closeLightbox();
  });

  const decoyPinInput = document.getElementById('decoy-pin') as HTMLInputElement;
  const decoyTokenInput = document.getElementById('decoy-token') as HTMLInputElement;
  const decoyChooseBtn = document.getElementById('decoy-choose-files') as HTMLButtonElement;
  const decoyFileInput = document.getElementById('decoy-file-input') as HTMLInputElement;
  const decoyQueue = document.getElementById('decoy-upload-queue') as HTMLDivElement;

  decoyChooseBtn.addEventListener('click', () => {
    if (!decoyPinInput.value) {
      showToast('Type your duress password first.', 'error');
      decoyPinInput.focus();
      return;
    }
    if (!decoyTokenInput.value.trim()) {
      showToast('Enter a decoy access token first — it needs its own, separate from your real one.', 'error');
      decoyTokenInput.focus();
      return;
    }
    decoyFileInput.click();
  });

  decoyFileInput.addEventListener('change', () => {
    const files = [...(decoyFileInput.files ?? [])];
    decoyFileInput.value = '';
    if (files.length) addDecoyFiles(decoyPinInput.value, decoyTokenInput.value.trim(), files, decoyQueue);
  });
}

async function addDecoyFiles(pin: string, decoyToken: string, files: File[], queue: HTMLDivElement): Promise<void> {
  const cfg = loadDuressConfig();
  const matched = await C.checkDuress(pin, cfg);
  if (!matched) {
    showToast("That doesn't match your saved duress password.", 'error');
    return;
  }

  const { vaultId: decoyVaultId, wrappingKeyRaw: decoyWrappingKeyRaw } = await C.unlockVault(pin, currentsalt);

  await Promise.all(files.map((file) => addOneDecoyFile(file, decoyVaultId, decoyWrappingKeyRaw, decoyToken, queue)));
}

async function addOneDecoyFile(
  file: File,
  decoyVaultId: string,
  decoyWrappingKeyRaw: Uint8Array,
  decoyToken: string,
  queue: HTMLDivElement
): Promise<void> {
  const row = document.createElement('div');
  row.className = 'upload-row';
  row.innerHTML = `
    <span class="name"></span>
    <span class="status">Encrypting\u2026</span>
    <div class="bar"><div class="bar-fill"></div></div>
  `;
  row.querySelector('.name')!.textContent = file.name;
  queue.appendChild(row);
  const statusEl = row.querySelector('.status') as HTMLElement;
  const barEl = row.querySelector('.bar-fill') as HTMLElement;

  try {
    const encrypted = await encryptPool.encryptFile(decoyWrappingKeyRaw, file, null);
    statusEl.textContent = 'Uploading\u2026';
    await api.uploadFile(encrypted, (fraction) => {
      barEl.style.width = `${Math.max(0, Math.min(100, Math.round(fraction * 100)))}%`;
    }, undefined, decoyVaultId, decoyToken);
    row.classList.add('done');
    statusEl.textContent = 'Added';
    setTimeout(() => row.remove(), 1800);
  } catch (err) {
    row.classList.add('error');
    statusEl.textContent = 'Failed';
    showToast(`Couldn't add "${file.name}" to the decoy vault. ${(err as Error).message}`, 'error');
  }
}