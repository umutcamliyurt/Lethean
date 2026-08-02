const isLocalDev = window.location.port === '5500';
const BASE_URL = isLocalDev ? 'http://localhost:8000' : '';

if (!isLocalDev && window.isSecureContext === false) {
  throw new Error('This app must be served over HTTPS — refusing to run over an insecure connection.');
}

let vaultId = null;
let accessToken = null;

export function setVaultId(id) {
  vaultId = id;
}

export function setAccessToken(token) {
  accessToken = token || null;
}

export function clearCredentials() {
  vaultId = null;
  accessToken = null;
}

function authHeaders() {
  return vaultId ? { Authorization: `Bearer ${vaultId}` } : {};
}

function assertSafeId(id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) {
    throw new Error('Invalid file id');
  }
  return id;
}

async function checkOk(res, label) {
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail ?? detail; } catch {  }
    throw new Error(`${label}: ${detail}`);
  }
  return res;
}

export async function uploadFile(encrypted, onProgress) {
  const form = new FormData();
  form.append('content_iv', encrypted.contentIv);
  form.append('encrypted_metadata', encrypted.encryptedMetadata);
  form.append('metadata_iv', encrypted.metadataIv);
  form.append('wrapped_file_key', encrypted.wrappedFileKey);
  form.append('wrap_iv', encrypted.wrapIv);
  form.append('blob', new Blob([encrypted.ciphertext]));

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE_URL}/files`);
    for (const [k, v] of Object.entries(authHeaders())) xhr.setRequestHeader(k, v);
    if (accessToken) xhr.setRequestHeader('X-Access-Token', accessToken);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
      else {
        let detail = xhr.statusText;
        try { detail = JSON.parse(xhr.responseText).detail ?? detail; } catch {  }
        reject(new Error(detail));
      }
    };
    xhr.onerror = () => reject(new Error('network error'));
    xhr.send(form);
  });
}

export async function listFiles({ offset = 0, limit = null } = {}) {
  const params = new URLSearchParams();
  if (offset) params.set('offset', String(offset));
  if (limit != null) params.set('limit', String(limit));
  const qs = params.toString();
  const res = await fetch(`${BASE_URL}/files${qs ? `?${qs}` : ''}`, { headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Could not load files');
  return res.json();
}

export async function getUsage() {
  const res = await fetch(`${BASE_URL}/usage`, { headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Could not load usage');
  return res.json();
}

export async function downloadContent(fileId, onProgress) {
  assertSafeId(fileId);
  const res = await fetch(`${BASE_URL}/files/${fileId}/blob`, { headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Download failed');

  const total = Number(res.headers.get('Content-Length')) || 0;
  if (!onProgress || !total || !res.body) {
    return new Uint8Array(await res.arrayBuffer());
  }

  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    onProgress(received / total);
  }
  const out = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

export async function deleteFile(fileId) {
  assertSafeId(fileId);
  const res = await fetch(`${BASE_URL}/files/${fileId}`, { method: 'DELETE', headers: authHeaders(), credentials: 'omit' });
  await checkOk(res, 'Delete failed');
}

export async function wipeVault(vaultIdToWipe) {
  await sendShredSignal(vaultIdToWipe);
  clearCredentials();
}

export async function sendShredSignal(targetVaultId) {
  const res = await fetch(`${BASE_URL}/vault`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${targetVaultId}` },
    credentials: 'omit',
  });
  await checkOk(res, 'Shred signal failed');
}