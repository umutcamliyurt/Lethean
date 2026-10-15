import * as api from './api.js';
import { settingsMenu, settingsBtn, duressBtn } from './dom.js';
import { fileKeyCache, metaCache, getWrappingKeyRaw } from './state.js';
import { encryptFolder, prepareChunkedFile, decryptToStream, CHUNK_SIZE } from './crypto-encrypt-core.js';
import { encryptPool } from './encrypt-pool.js';
import { effectiveParentId, parentRefFor } from './tree.js';
import { showLightbox } from './lightbox.js';
import { showToast } from './utils.js';
import {
  getRecords, addUploadedRecord, getDecryptedBlob, relocateRecord, deleteRecord, ensureFullyLoaded,
  legacyRecords, getQuarantined, admitQuarantined, recheckLegacyState, isStrictMode, rerender,
} from './gallery.js';
import { upgradeLegacyItems } from './upgrade-engine.js';
import type { UpgradeDeps, UpgradeReport } from './upgrade-engine.js';
import type { FileRecord } from './types.js';

let running = false;

const upgradeBtn = document.createElement('button');
upgradeBtn.type = 'button';
upgradeBtn.setAttribute('role', 'menuitem');
upgradeBtn.id = 'upgrade-btn';
upgradeBtn.textContent = 'Upgrade Vault';
settingsMenu.insertBefore(upgradeBtn, duressBtn);
upgradeBtn.addEventListener('click', () => {
  settingsMenu.classList.add('hidden');
  settingsBtn.setAttribute('aria-expanded', 'false');
  void openUpgradePanel();
});

async function verifyRecord(record: FileRecord): Promise<void> {
  const key = fileKeyCache.get(record.id);
  const meta = metaCache.get(record.id);
  if (!key || !meta) throw new Error('Upgraded copy could not be read back');
  const { stream } = await api.openDownloadStream(record.id);
  const reader = decryptToStream(key, record.content_iv, stream, meta).getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
  }
  const expected = meta.isFolder ? 0 : meta.size;
  if (total !== expected) throw new Error('Upgraded copy did not read back completely');
}

function deps(onProgress: UpgradeDeps['onProgress']): UpgradeDeps {
  const wrappingKey = (): Uint8Array => {
    const key = getWrappingKeyRaw();
    if (!key) throw new Error('Vault is locked.');
    return key;
  };
  return {
    records: getRecords,
    keyOf: (id) => fileKeyCache.get(id),
    metaOf: (id) => metaCache.get(id),
    parentOf: effectiveParentId,
    parentRef: parentRefFor,
    readPlaintext: (record) => getDecryptedBlob(record),
    encryptFile: (file, parent, opts) => (file.size > CHUNK_SIZE
      ? prepareChunkedFile(wrappingKey(), file, parent, opts)
      : encryptPool.encryptFile(wrappingKey(), file, parent, opts)),
    encryptFolder: (name, parent, opts) => encryptFolder(wrappingKey(), name, parent, opts),
    upload: (payload) => api.uploadFile(payload),
    adopt: addUploadedRecord,
    verify: verifyRecord,
    relocate: relocateRecord,
    remove: deleteRecord,
    stillUnlocked: () => getWrappingKeyRaw() !== null,
    onProgress,
  };
}

function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function describe(report: UpgradeReport): string {
  const parts = [`Upgraded ${report.upgraded} item${report.upgraded === 1 ? '' : 's'}.`];
  if (report.failed.length) parts.push(`${report.failed.length} couldn't be upgraded and were left as they were (first: "${report.failed[0]!.name}": ${report.failed[0]!.error}). Run the upgrade again to retry.`);
  if (report.foldersKept) parts.push(`${report.foldersKept} old folder${report.foldersKept === 1 ? ' was' : 's were'} kept because something inside couldn't be upgraded.`);
  if (report.stopped) parts.push('The upgrade stopped because the vault was locked. Run it again to continue; nothing was lost.');
  return parts.join(' ');
}

async function openUpgradePanel(): Promise<void> {
  showLightbox(`
    <div class="settings-panel settings-panel-wide">
      <h2>Upgrade Vault</h2>
      <p class="subtitle" id="upgrade-status">Checking your vault…</p>
      <div id="upgrade-details"></div>
      <div class="panel-actions">
        <button type="button" class="btn-primary hidden" id="upgrade-start">Upgrade</button>
      </div>
      <div id="upgrade-progress" class="cp-progress hidden">
        <span class="spinner"></span>
        <span id="upgrade-progress-text"></span>
      </div>
    </div>
  `);

  if (running) {
    setText('upgrade-status', 'An upgrade is already running. Keep this tab open until it finishes.');
    return;
  }
  const complete = await ensureFullyLoaded();
  if (!complete) {
    setText('upgrade-status', "Your vault didn't finish loading, so it can't be upgraded safely right now. Try again in a moment.");
    return;
  }

  const legacyCount = legacyRecords().length;
  const hiddenCount = getQuarantined().length;
  const details = document.getElementById('upgrade-details')!;
  const startBtn = document.getElementById('upgrade-start') as HTMLButtonElement;

  if (!legacyCount && !hiddenCount) {
    setText('upgrade-status', isStrictMode()
      ? 'Everything in this vault uses the current format, and this device will refuse items in the old format from now on.'
      : 'Everything in this vault uses the current format.');
    return;
  }

  setText('upgrade-status', legacyCount
    ? `${legacyCount} item${legacyCount === 1 ? ' uses' : 's use'} the old format, which a malicious server can tamper with (it can present a file's name as its contents, or move old items between folders). Upgrading re-encrypts them in the current format.`
    : 'All visible items use the current format.');

  const notes = document.createElement('ul');
  notes.className = 'field-hint';
  for (const text of [
    'Each item is re-encrypted on this device and uploaded again, so this uses bandwidth, and needs free space for one extra copy of the largest item.',
    'Each old copy is deleted only after its replacement has been downloaded and checked.',
    'Share links to upgraded items stop working. Create new ones afterwards.',
    'Folders keep their current arrangement. If you can, check that it looks right first.',
    'Keep this tab open. If it\'s interrupted, run the upgrade again and it continues where it left off.',
  ]) {
    const li = document.createElement('li');
    li.textContent = text;
    notes.appendChild(li);
  }
  details.appendChild(notes);

  let includeHidden: HTMLInputElement | null = null;
  if (hiddenCount) {
    const box = document.createElement('label');
    box.className = 'share-checkbox-row';
    includeHidden = document.createElement('input');
    includeHidden.type = 'checkbox';
    const text = document.createElement('span');
    text.className = 'share-checkbox-text';
    const strong = document.createElement('strong');
    strong.textContent = `Also upgrade ${hiddenCount} hidden outdated item${hiddenCount === 1 ? '' : 's'}`;
    const small = document.createElement('small');
    small.textContent = 'These appeared after this vault was upgraded, so this device hid them. They may be old copies the server restored, or files uploaded by an outdated version of the app. Only include them if you expect them; upgrading makes them part of your vault.';
    text.append(strong, small);
    box.append(includeHidden, text);
    details.appendChild(box);
  }

  const refreshButton = () => {
    const n = legacyCount + (includeHidden?.checked ? hiddenCount : 0);
    startBtn.textContent = `Upgrade ${n} item${n === 1 ? '' : 's'}`;
    startBtn.disabled = n === 0;
  };
  includeHidden?.addEventListener('change', refreshButton);
  refreshButton();
  startBtn.classList.remove('hidden');

  startBtn.addEventListener('click', async () => {
    if (running) return;
    running = true;
    startBtn.disabled = true;
    if (includeHidden) includeHidden.disabled = true;
    document.getElementById('upgrade-progress')!.classList.remove('hidden');
    try {
      if (includeHidden?.checked) await admitQuarantined();
      const report = await upgradeLegacyItems(deps((done, total, name) => {
        setText('upgrade-progress-text', name ? `Upgrading ${Math.min(done + 1, total)} of ${total}: ${name}` : 'Finishing…');
      }));
      const summary = describe(report);
      setText('upgrade-status', summary);
      showToast(summary, report.failed.length || report.stopped ? 'error' : 'info');
    } catch (err) {
      const message = `Upgrade stopped: ${(err as Error).message}. Nothing was deleted without a verified replacement; run it again to continue.`;
      setText('upgrade-status', message);
      showToast(message, 'error');
    } finally {
      running = false;
      document.getElementById('upgrade-progress')?.classList.add('hidden');
      details.textContent = '';
      startBtn.classList.add('hidden');
      rerender();
      recheckLegacyState();
    }
  });
}
