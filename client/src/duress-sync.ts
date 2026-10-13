import * as api from './api.js';
import * as C from './crypto.js';
import { loadLocalDuress, saveLocalDuress, resetLocalDuress } from './storage.js';
import { toBase64 } from './crypto-encrypt-core.js';
import type { DuressConfig } from './types.js';

const FETCH_TIMEOUT_MS = 4000;
const LS_CONFLICT_NOTICE_KEY = 'vault.duressConflictNoticed';
const UNLOCK_WAIT_MS = 3000;

let prefetch: { token: string; promise: Promise<DuressConfig | null> } | null = null;

const sameConfig = (a: DuressConfig, b: DuressConfig) =>
  a.salt === b.salt && a.verifier === b.verifier && a.encVaultId === b.encVaultId && a.iv === b.iv;

function isValidConfig(c: unknown): c is DuressConfig {
  const x = c as DuressConfig;
  return !!x && typeof x.salt === 'string' && typeof x.verifier === 'string'
    && typeof x.encVaultId === 'string' && typeof x.iv === 'string';
}

export function prefetchDuress(token: string): void {
  if (!token || prefetch?.token === token) return;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  const promise = api.getDuressBlob(token, { signal: controller.signal })
    .then(({ config }) => {
      if (!isValidConfig(config)) return null;

      if (loadLocalDuress().synced) saveLocalDuress(config, true);
      return config;
    })
    .catch(() => null)
    .finally(() => clearTimeout(timer));
  prefetch = { token, promise };
}

export async function duressConfigsToCheck(token: string): Promise<DuressConfig[]> {
  prefetchDuress(token);
  const remote = prefetch ? await Promise.race([prefetch.promise, new Promise<null>((r) => setTimeout(() => r(null), UNLOCK_WAIT_MS))]) : null;
  const local = loadLocalDuress();
  if (!remote) return [local.config];
  if (!local.synced && !sameConfig(local.config, remote)) return [remote, local.config];
  return [remote];
}

export function forgetDuressAfterTrigger(): void {
  resetLocalDuress();
  prefetch = null;
}

export async function reconcileDuress(vaultId: string, token: string): Promise<{ replacedLocalOnlyCode: boolean }> {
  let remote: api.RemoteDuress;
  try {
    remote = await api.getDuressBlob(token, { vaultId });
  } catch {
    return { replacedLocalOnlyCode: false };
  }
  if (!isValidConfig(remote.config)) return { replacedLocalOnlyCode: false };
  const local = loadLocalDuress();

  if (remote.written === undefined) {
    if (local.synced) saveLocalDuress(remote.config, true);
    return { replacedLocalOnlyCode: false };
  }

  const randomShredHash = async () => C.sha256Hex(crypto.getRandomValues(new Uint8Array(C.SHRED_SECRET_BYTES)));

  if (!remote.written) {

    const config = local.synced ? C.generateDecoyDuressConfig() : local.config;
    try {
      await api.putDuressBlob(config, await randomShredHash(), { vaultId, token });
      saveLocalDuress(config, true);
    } catch {

    }
    return { replacedLocalOnlyCode: false };
  }

  if (!local.synced) {
    if (sameConfig(local.config, remote.config)) {
      saveLocalDuress(remote.config, true);
      return { replacedLocalOnlyCode: false };
    }

    let notify = false;
    try {
      notify = localStorage.getItem(LS_CONFLICT_NOTICE_KEY) !== '1';
      localStorage.setItem(LS_CONFLICT_NOTICE_KEY, '1');
    } catch {
    }
    return { replacedLocalOnlyCode: notify };
  }

  saveLocalDuress(remote.config, true);
  return { replacedLocalOnlyCode: false };
}

export async function saveDuress(duressCode: string, vaultId: string, token: string): Promise<'all-devices' | 'this-device'> {
  const { config, shredSecret } = await C.setupDuress(duressCode);
  try {
    await api.putDuressBlob(config, await C.sha256Hex(shredSecret), { vaultId, token });
  } catch (err) {
    if (!api.isMissingEndpoint(err)) throw err;
    saveLocalDuress(await C.setupLegacyDuress(duressCode, vaultId), false);
    prefetch = null;
    return 'this-device';
  }
  saveLocalDuress(config, true);
  prefetch = null;
  return 'all-devices';
}

export async function resetDuress(vaultId: string, token: string): Promise<void> {
  const config = C.generateDecoyDuressConfig();
  const fakeSecret = crypto.getRandomValues(new Uint8Array(C.SHRED_SECRET_BYTES));
  try {
    await api.putDuressBlob(config, await C.sha256Hex(fakeSecret), { vaultId, token });
  } catch (err) {
    if (!api.isMissingEndpoint(err)) throw err;
    saveLocalDuress(config, false);
    prefetch = null;
    return;
  }
  saveLocalDuress(config, true);
  prefetch = null;
}

export async function readDuressForMove(vaultId: string, token: string): Promise<DuressConfig> {
  try {
    const { config } = await api.getDuressBlob(token, { vaultId });
    if (isValidConfig(config)) return config;
  } catch {
  }
  return loadLocalDuress().config;
}

export async function moveDuressToToken(config: DuressConfig, newVaultId: string, newToken: string): Promise<void> {
  await api.putDuressBlob(config, undefined, { vaultId: newVaultId, token: newToken });
  saveLocalDuress(config, true);
  prefetch = null;
}

export function shredPayloads(match: C.DuressMatch | null): { secretB64: string; vaultId: string } {
  return {
    secretB64: toBase64(match?.kind === 'secret' ? match.secret : crypto.getRandomValues(new Uint8Array(C.SHRED_SECRET_BYTES))),
    vaultId: match?.kind === 'legacy-vault' ? match.vaultId : C.randomVaultIdShaped(),
  };
}