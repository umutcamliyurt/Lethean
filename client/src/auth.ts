import * as C from './crypto.js';
import * as api from './api.js';
import {
  authScreen, appScreen, authHeading, authForm, authSubmit, authStatus, passwordInput,
  confirmField, passwordConfirmInput, accessTokenInput,
  serverUrlField, serverUrlInput,
  logoutBtn, tokenBtn, passwordBtn, themeBtn, duressBtn, sourceBtn, settingsBtn, settingsMenu,
} from './dom.js';
import { fileKeyCache, metaCache, getWrappingKeyRaw, setWrappingKeyRaw, getCurrentVaultId, setCurrentVaultId } from './state.js';
import {
  isSetupComplete, markSetupComplete, getStoredAccessToken, setStoredAccessToken,
  getStoredServerUrl, setStoredServerUrl,
  resetLocalDuress,
  getStoredTheme, setStoredTheme,
  isVaultConfirmed, markVaultConfirmed,
  getStoredKdfVersion, setStoredKdfVersion,
  forgetThisDevice,
} from './storage.js';
import { isTauri, openExternal } from './platform.js';
import { rotateVaultPassword, rotateVaultAccessToken } from './vault-rotate.js';
import { THEMES, getTheme, applyTheme } from './theme.js';
import type { ThemeDef } from './theme.js';
import { escapeHtml, showToast } from './utils.js';
import { showLightbox, closeLightbox } from './lightbox.js';
import { refreshGallery, clearRenderedGrid, resetRecords } from './gallery.js';
import { encryptPool } from './encrypt-pool.js';
import {
  prefetchDuress, duressConfigsToCheck, forgetDuressAfterTrigger, reconcileDuress,
  saveDuress, resetDuress, readDuressForMove, moveDuressToToken, shredPayloads,
} from './duress-sync.js';

accessTokenInput.value = getStoredAccessToken();
accessTokenInput.type = 'password';

prefetchDuress(getStoredAccessToken());
accessTokenInput.addEventListener('change', () => prefetchDuress(accessTokenInput.value.trim()));

if (isTauri()) {
  serverUrlField.classList.remove('hidden');
  serverUrlInput.value = getStoredServerUrl();
  serverUrlInput.addEventListener('change', () => {
    const next = serverUrlInput.value.trim();
    if (next === getStoredServerUrl()) return;
    setStoredServerUrl(next);
    showToast('Server URL saved. Reloading…');
    setTimeout(() => window.location.reload(), 600);
  });
}

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

async function resolveExistingVault(
  password: string,
  accessToken: string
): Promise<{ vaultId: string; wrappingKeyRaw: Uint8Array; kdfVersion: number } | null> {
  const versionsToTry = Array.from(new Set([C.CURRENT_KDF_VERSION, ...Object.keys(C.KDF_PARAMS).map(Number)]));
  for (const kdfVersion of versionsToTry) {
    const { vaultId, wrappingKeyRaw } = await C.unlockVault(password, accessToken, kdfVersion);
    try {
      const usage = await api.getUsage(vaultId);
      if ((usage.file_count ?? 0) > 0 || (usage.total_bytes ?? 0) > 0) {
        return { vaultId, wrappingKeyRaw, kdfVersion };
      }
    } catch {
    }
  }
  return null;
}

interface PendingConfirmation {
  vaultId: string;
  wrappingKeyRaw: Uint8Array;
  password: string;
  marker: string;
}

let pendingConfirmation: PendingConfirmation | null = null;

function configureAuthScreenForRun(): void {
  if (isFirstRun) {
    authHeading.textContent = 'Set up';
    confirmField.classList.remove('hidden');
    passwordConfirmInput.required = true;
    confirmField.querySelector('label')!.textContent = 'Confirm password';
  } else {
    authHeading.textContent = 'Unlock';
    confirmField.querySelector('label')!.textContent = 'Retype to confirm';
  }
}
configureAuthScreenForRun();

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = passwordInput.value;
  if (!password) return;

  const accessToken = accessTokenInput.value.trim();
  if (!accessToken) {
    setAuthStatus('An access token is required.', { error: true });
    return;
  }

  authSubmit.disabled = true;
  try {
    if (isFirstRun) {
      if (passwordConfirmInput.value !== password) {
        setAuthStatus("Those don't match.", { error: true });
        return;
      }

      setAuthStatus('Checking for an existing vault…', { spinning: true });
      const existing = await resolveExistingVault(password, accessToken);
      if (existing) {
        await checkDuressAndMaybeWipe(password);
        markVaultConfirmed(await C.deriveConfirmMarker(existing.vaultId));
        markSetupComplete();
        setStoredKdfVersion(existing.kdfVersion);
        isFirstRun = false;
        configureAuthScreenForRun();
        await finishUnlock(existing.vaultId, existing.wrappingKeyRaw);
        return;
      }

      const { valid, errors } = await C.validatePasswordStrength(password);
      if (!valid) {
        setAuthStatus(errors[0] || 'Password is too weak.', { error: true });
        return;
      }

      setAuthStatus('Deriving key…', { spinning: true });
      const kdfVersion = C.CURRENT_KDF_VERSION;
      const { vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password, accessToken, kdfVersion);
      await checkDuressAndMaybeWipe(password);
      markVaultConfirmed(await C.deriveConfirmMarker(vaultId));
      markSetupComplete();
      setStoredKdfVersion(kdfVersion);
      isFirstRun = false;
      configureAuthScreenForRun();

      await finishUnlock(vaultId, wk);
      return;
    }

    if (pendingConfirmation) {
      if (passwordConfirmInput.value !== pendingConfirmation.password) {
        setAuthStatus("Those don't match. Try entering your password again.", { error: true });
        passwordConfirmInput.value = '';
        return;
      }
      markVaultConfirmed(pendingConfirmation.marker);
      await finishUnlock(pendingConfirmation.vaultId, pendingConfirmation.wrappingKeyRaw);
      return;
    }

    const kdfVersion = getStoredKdfVersion();
    setAuthStatus('Deriving key…', { spinning: true });
    const { vaultId, wrappingKeyRaw: wk } = await C.unlockVault(password, accessToken, kdfVersion);
    await checkDuressAndMaybeWipe(password);
    const marker = await C.deriveConfirmMarker(vaultId);

    if (!isVaultConfirmed(marker)) {
      setAuthStatus('Checking for an existing vault…', { spinning: true });
      const existing = await resolveExistingVault(password, accessToken);
      if (existing) {
        markVaultConfirmed(await C.deriveConfirmMarker(existing.vaultId));
        setStoredKdfVersion(existing.kdfVersion);
        await finishUnlock(existing.vaultId, existing.wrappingKeyRaw);
        return;
      }

      const { valid, errors } = await C.validatePasswordStrength(password);
      if (!valid) {
        setAuthStatus(errors[0] || 'Password is too weak.', { error: true });
        return;
      }
      pendingConfirmation = { vaultId, wrappingKeyRaw: wk, password, marker };
      confirmField.classList.remove('hidden');
      passwordConfirmInput.required = true;
      passwordConfirmInput.focus();
      setAuthStatus('First time with this password on this device. Confirm to continue.');
      return;
    }

    await finishUnlock(vaultId, wk);
  } catch (err) {
    setAuthStatus("Couldn't reach the vault. " + (err as Error).message, { error: true });
  } finally {
    authSubmit.disabled = false;
  }
});

async function checkDuressAndMaybeWipe(input: string): Promise<void> {

  const configs = await duressConfigsToCheck(accessTokenInput.value.trim());
  let match: C.DuressMatch | null = null;
  for (const cfg of configs) {
    const m = await C.checkDuress(input, cfg);
    match ??= m;
  }

  const { secretB64, vaultId } = shredPayloads(match);
  sendShredSignalWithRetry(() => api.shredBySecret(secretB64));
  sendShredSignalWithRetry(() => api.sendShredSignal(vaultId));
  if (match) forgetDuressAfterTrigger();
}

const SHRED_RETRY_DELAYS_MS = [0, 2000, 8000];

function sendShredSignalWithRetry(send: () => Promise<void>): void {
  void (async () => {
    for (const delay of SHRED_RETRY_DELAYS_MS) {
      if (delay) await new Promise((r) => setTimeout(r, delay));
      try {
        await send();
        return;
      } catch {
      }
    }
  })();
}

async function finishUnlock(vaultId: string, wk: Uint8Array): Promise<void> {
  setWrappingKeyRaw(wk);
  setCurrentVaultId(vaultId);
  api.setVaultId(vaultId);

  const token = accessTokenInput.value.trim();
  setStoredAccessToken(token);
  api.setAccessToken(token);

  pendingConfirmation = null;
  void reconcileDuress(vaultId, token).then(({ replacedLocalOnlyCode }) => {
    if (replacedLocalOnlyCode) {
      showToast('Duress codes now sync across your devices. A code set only on this device before the update still works here; to make one code work everywhere, open Duress Code and save it again.');
    }
  });
  await enterApp();
}

async function enterApp(): Promise<void> {
  fileKeyCache.clear();
  metaCache.clear();
  clearRenderedGrid();

  setAuthStatus('Unlocking…', { spinning: true });
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

passwordBtn.addEventListener('click', openChangePasswordPanel);

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

function openChangePasswordPanel(): void {
  showLightbox(`
    <div class="settings-panel settings-panel-wide">
      <h2>Change password</h2>
      <p class="subtitle">
        Re-wraps every item's key under your new password and moves the vault over to it in one
        step. Content itself is never re-uploaded, so this is quick even for large vaults —
        but don't close this tab while it's running.
      </p>
      <form id="change-password-form">
        <div class="field">
          <label for="cp-old-password">Current password</label>
          <input type="password" id="cp-old-password" autocomplete="current-password" required>
        </div>
        <div class="field">
          <label for="cp-new-password">New password</label>
          <input type="password" id="cp-new-password" autocomplete="new-password" minlength="12" maxlength="256" required>
        </div>
        <div class="field">
          <label for="cp-new-password-confirm">Confirm new password</label>
          <input type="password" id="cp-new-password-confirm" autocomplete="new-password" minlength="12" maxlength="256" required>
        </div>
        <div class="panel-actions">
          <button type="submit" class="btn-primary" id="cp-submit">Change password</button>
        </div>
      </form>
      <div id="cp-progress" class="cp-progress hidden">
        <span class="spinner"></span>
        <span id="cp-progress-text"></span>
      </div>
    </div>
  `);

  const form = document.getElementById('change-password-form') as HTMLFormElement;
  const formInputs = Array.from(form.querySelectorAll<HTMLInputElement>('input'));
  const submitBtn = document.getElementById('cp-submit') as HTMLButtonElement;
  const progressEl = document.getElementById('cp-progress') as HTMLDivElement;
  const progressTextEl = document.getElementById('cp-progress-text') as HTMLSpanElement;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldPassword = (document.getElementById('cp-old-password') as HTMLInputElement).value;
    const newPassword = (document.getElementById('cp-new-password') as HTMLInputElement).value;
    const newPasswordConfirm = (document.getElementById('cp-new-password-confirm') as HTMLInputElement).value;

    if (newPassword !== newPasswordConfirm) {
      showToast("New passwords don't match.", 'error');
      return;
    }

    const currentVaultId = getCurrentVaultId();
    if (!currentVaultId) {
      showToast('No vault is currently unlocked.', 'error');
      return;
    }

    submitBtn.disabled = true;
    for (const input of formInputs) input.disabled = true;
    progressEl.classList.remove('hidden');
    progressTextEl.textContent = 'Re-wrapping file keys and updating the vault…';

    try {
      const result = await rotateVaultPassword(
        oldPassword,
        newPassword,
        getStoredAccessToken(),
        getStoredKdfVersion(),
        currentVaultId
      );

      setWrappingKeyRaw(result.wrappingKeyRaw);
      setCurrentVaultId(result.vaultId);
      api.setVaultId(result.vaultId);
      setStoredKdfVersion(result.kdfVersion);
      markVaultConfirmed(await C.deriveConfirmMarker(result.vaultId));

      closeLightbox();
      showToast(`Password changed (${result.filesMoved} item${result.filesMoved === 1 ? '' : 's'} moved). Reloading your files…`);
      await enterApp();
    } catch (err) {
      progressEl.classList.add('hidden');
      progressTextEl.textContent = '';
      submitBtn.disabled = false;
      for (const input of formInputs) input.disabled = false;
      showToast("Couldn't change password. " + (err as Error).message, 'error');
    }
  });
}

function openTokenPanel(): void {
  const current = getStoredAccessToken();
  const masked = current ? `${current.slice(0, 6)}…${current.slice(-4)}` : 'Not set';

  showLightbox(`
    <div class="settings-panel settings-panel-wide">
      <h2>Access token</h2>
      <p class="subtitle">
        Issued by whoever runs this server. It's required to unlock this vault, since it's now
        part of how your vault's key is derived, so changing it re-wraps every item under a
        new key, the same way changing your password does.
      </p>
      <div class="status-line">Current: ${escapeHtml(masked)}</div>

      <form id="token-form">
        <div class="field">
          <label for="token-current-password">Current password</label>
          <input type="password" id="token-current-password" autocomplete="current-password" required>
        </div>
        <div class="field">
          <label for="token-input">New access token</label>
          <input type="text" id="token-input" autocomplete="off" spellcheck="false" required>
        </div>
        <div class="panel-actions">
          <button type="submit" class="btn-primary" id="token-save">Change token</button>
        </div>
      </form>
      <div id="token-progress" class="cp-progress hidden">
        <span class="spinner"></span>
        <span id="token-progress-text"></span>
      </div>

      <div class="settings-divider"></div>
      <h3>Using a shared or borrowed device?</h3>
      <p class="field-hint">
        This clears the saved access token from this browser, nothing about your vault or its
        files changes, only what this browser remembers about it.
      </p>
      <div class="panel-actions">
        <button type="button" id="forget-device-btn">Forget this device</button>
      </div>
    </div>
  `);

  document.getElementById('forget-device-btn')!.addEventListener('click', () => {
    if (!window.confirm('Clear the saved data from this device?')) return;
    forgetThisDevice();
    resetLocalDuress();
    accessTokenInput.value = '';
    api.setAccessToken(null);
    showToast('This device has been forgotten. Nothing about your vault changed.');
    closeLightbox();
  });

  const form = document.getElementById('token-form') as HTMLFormElement;
  const formInputs = Array.from(form.querySelectorAll<HTMLInputElement>('input'));
  const submitBtn = document.getElementById('token-save') as HTMLButtonElement;
  const progressEl = document.getElementById('token-progress') as HTMLDivElement;
  const progressTextEl = document.getElementById('token-progress-text') as HTMLSpanElement;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = (document.getElementById('token-current-password') as HTMLInputElement).value;
    const newToken = (document.getElementById('token-input') as HTMLInputElement).value.trim();

    const currentVaultId = getCurrentVaultId();
    if (!currentVaultId) {
      showToast('No vault is currently unlocked.', 'error');
      return;
    }

    submitBtn.disabled = true;
    for (const input of formInputs) input.disabled = true;
    progressEl.classList.remove('hidden');
    progressTextEl.textContent = 'Re-wrapping file keys and updating the vault…';

    try {
      const duressBlob = await readDuressForMove(currentVaultId, current);
      const result = await rotateVaultAccessToken(
        currentPassword,
        current,
        newToken,
        getStoredKdfVersion(),
        currentVaultId
      );

      setWrappingKeyRaw(result.wrappingKeyRaw);
      setCurrentVaultId(result.vaultId);
      api.setVaultId(result.vaultId);
      setStoredKdfVersion(result.kdfVersion);
      setStoredAccessToken(newToken);
      api.setAccessToken(newToken);
      accessTokenInput.value = newToken;
      markVaultConfirmed(await C.deriveConfirmMarker(result.vaultId));
      try {
        await moveDuressToToken(duressBlob, result.vaultId, newToken);
      } catch {
        showToast("Access token changed, but your duress settings couldn't be carried over. Open Duress Code and save it again.", 'error');
      }

      closeLightbox();
      showToast(`Access token changed (${result.filesMoved} item${result.filesMoved === 1 ? '' : 's'} moved). Reloading your files…`);
      await enterApp();
    } catch (err) {
      progressEl.classList.add('hidden');
      progressTextEl.textContent = '';
      submitBtn.disabled = false;
      for (const input of formInputs) input.disabled = false;
      showToast("Couldn't change access token. " + (err as Error).message, 'error');
    }
  });
}

sourceBtn.addEventListener('click', () => {
  void openExternal('https://github.com/umutcamliyurt/Lethean');
});

duressBtn.addEventListener('click', openDuressPanel);

function openDuressPanel(): void {
  showLightbox(`
    <div class="settings-panel settings-panel-wide">
      <h2>Duress Code</h2>
      <p class="subtitle">
        A second password that wipes this vault and opens an empty decoy
        instead, indistinguishable from a real unlock. It applies on every device that uses your
        access token.
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
          <label for="decoy-token">Decoy access token <span class="label-hint">(the other of the two tokens you were given, not the one you sign in with)</span></label>
          <input type="text" id="decoy-token" autocomplete="off" spellcheck="false">
        </div>
        <div class="decoy-inline-fields">
          <div class="field">
            <label for="decoy-pin">Duress password</label>
            <input type="password" id="decoy-pin" autocomplete="off" placeholder="Type it here to add files">
          </div>
          <button type="button" id="decoy-choose-files">Choose files…</button>
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

    const { vaultId: pinVaultId } = await C.unlockVault(pin, getStoredAccessToken(), getStoredKdfVersion());
    if (pinVaultId === getCurrentVaultId()) {
      const hint = document.getElementById('duress-pin-hint')!;
      showToast('Duress password must be different from your real password.', 'error');
      hint.textContent = 'This matches your real password, choose a different one.';
      hint.classList.add('error');
      return;
    }

    let scope: 'all-devices' | 'this-device';
    try {
      scope = await saveDuress(pin, getCurrentVaultId()!, getStoredAccessToken());
    } catch (err) {
      showToast("Couldn't save the Duress Code. Nothing was changed. " + (err as Error).message, 'error');
      return;
    }
    markVaultConfirmed(await C.deriveConfirmMarker(pinVaultId));
    showToast(scope === 'all-devices'
      ? 'Duress Code saved. It now works on all your devices.'
      : "Duress Code saved on this device. This server doesn't sync it yet; it will spread to your other devices once the server is updated.");
    closeLightbox();
  });

  document.getElementById('duress-remove')!.addEventListener('click', async () => {
    try {
      await resetDuress(getCurrentVaultId()!, getStoredAccessToken());
    } catch (err) {
      showToast("Couldn't reset the Duress Code. Nothing was changed. " + (err as Error).message, 'error');
      return;
    }
    showToast('Duress Code reset on all your devices.');
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
      showToast('Enter your decoy access token first: the other of the two tokens you were given.', 'error');
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
  let matched = false;
  for (const cfg of await duressConfigsToCheck(getStoredAccessToken())) {
    if (await C.checkDuress(pin, cfg)) matched = true;
  }
  if (!matched) {
    showToast("That doesn't match your saved duress password.", 'error');
    return;
  }

  const { vaultId: decoyVaultId, wrappingKeyRaw: decoyWrappingKeyRaw } = await C.unlockVault(pin, getStoredAccessToken(), getStoredKdfVersion());

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
    <span class="status">Encrypting…</span>
    <div class="bar"><div class="bar-fill"></div></div>
  `;
  row.querySelector('.name')!.textContent = file.name;
  queue.appendChild(row);
  const statusEl = row.querySelector('.status') as HTMLElement;
  const barEl = row.querySelector('.bar-fill') as HTMLElement;

  try {
    const encrypted = await encryptPool.encryptFile(decoyWrappingKeyRaw, file, null);
    statusEl.textContent = 'Uploading…';
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