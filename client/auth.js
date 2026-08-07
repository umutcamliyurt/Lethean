import * as C from './crypto.js';
import * as api from './api.js';
import {
  authScreen, appScreen, authForm, authSubmit, authStatus, passwordInput,
  confirmField, passwordConfirmInput, accessTokenInput, vaultFingerprint,
  logoutBtn, tokenBtn, duressBtn,
} from './dom.js';
import { fileKeyCache, metaCache, getWrappingKeyRaw, setWrappingKeyRaw, getCurrentVaultId, setCurrentVaultId } from './state.js';
import {
  isSetupComplete, markSetupComplete, getStoredAccessToken, setStoredAccessToken,
  loadDuressConfig, saveDuressConfig, resetDuressConfig,
} from './storage.js';
import { escapeHtml, showToast } from './utils.js';
import { showLightbox, closeLightbox } from './lightbox.js';
import { refreshGallery, clearRenderedGrid, resetRecords } from './gallery.js';

accessTokenInput.value = getStoredAccessToken();

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
    document.getElementById('auth-heading').textContent = 'Set up';
    document.getElementById('auth-subtitle').textContent = 'Choose a passphrase for this vault.';
    confirmField.classList.remove('hidden');
    passwordConfirmInput.required = true;
    confirmField.querySelector('label').textContent = 'Confirm passphrase';
  } else {
    document.getElementById('auth-heading').textContent = 'Unlock';
    document.getElementById('auth-subtitle').textContent = "No accounts. Your passphrase is the only key.";
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
      const { valid, errors } = C.validatePasswordStrength(password);
      if (!valid) {
        setAuthStatus(errors[0] || 'Passphrase is too weak.', { error: true });
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
  setWrappingKeyRaw(wk);
  setCurrentVaultId(vaultId);
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
  clearRenderedGrid();

  setAuthStatus('Unlocking\u2026', { spinning: true });
  await refreshGallery();

  authScreen.classList.add('hidden');
  appScreen.classList.remove('hidden');
  vaultFingerprint.textContent = getCurrentVaultId().slice(0, 8);
  passwordInput.value = '';
  passwordConfirmInput.value = '';
  confirmField.classList.add('hidden');
  passwordConfirmInput.required = false;
  setAuthStatus('');
}

function leaveApp() {
  setWrappingKeyRaw(null);
  setCurrentVaultId(null);
  fileKeyCache.clear();
  metaCache.clear();
  clearRenderedGrid();
  resetRecords();
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
  document.getElementById('token-input').value = current;

  document.getElementById('token-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const token = document.getElementById('token-input').value.trim();
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
          <input type="password" id="duress-pin" autocomplete="new-password" minlength="12" maxlength="256">
          <p class="field-hint" id="duress-pin-hint">Use 12+ characters, ideally a random passphrase of several unrelated words.</p>
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
    </div>
  `);

  document.getElementById('duress-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pin = document.getElementById('duress-pin').value;
    const pinConfirm = document.getElementById('duress-pin-confirm').value;

    const { valid, errors } = C.validatePasswordStrength(pin);
    if (!valid) {
      showToast(errors[0] || 'Duress passphrase is too weak.', 'error');
      document.getElementById('duress-pin-hint').textContent = errors[0];
      document.getElementById('duress-pin-hint').classList.add('error');
      return;
    }
    if (pin !== pinConfirm) { showToast("Passphrases don't match.", 'error'); return; }

    const cfg = await C.setupDuress(pin, getCurrentVaultId());
    saveDuressConfig(cfg);
    showToast('Duress Code saved.');
    closeLightbox();
  });

  document.getElementById('duress-remove').addEventListener('click', () => {
    resetDuressConfig();
    showToast('Duress Code reset.');
    closeLightbox();
  });
}
