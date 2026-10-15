
import { encryptFile, encryptFolder } from './crypto-encrypt-core.js';
import type { EncryptedFilePayload } from './types.js';
import type { ParentRef, NewRecordOptions } from './crypto-encrypt-core.js';

interface EncryptFileRequest {
  id: number;
  kind: 'file';
  wrappingKeyRaw: Uint8Array;
  file: File;
  parent: ParentRef | null;
  opts?: NewRecordOptions;
}

interface EncryptFolderRequest {
  id: number;
  kind: 'folder';
  wrappingKeyRaw: Uint8Array;
  name: string;
  parent: ParentRef | null;
  opts?: NewRecordOptions;
}

type EncryptRequest = EncryptFileRequest | EncryptFolderRequest;

interface EncryptSuccess {
  id: number;
  ok: true;
  result: EncryptedFilePayload;
}

interface EncryptFailure {
  id: number;
  ok: false;
  error: string;
}

self.onmessage = async (event: MessageEvent<EncryptRequest>) => {
  const req = event.data;
  try {
    const result = req.kind === 'file'
      ? await encryptFile(req.wrappingKeyRaw, req.file, req.parent, req.opts)
      : await encryptFolder(req.wrappingKeyRaw, req.name, req.parent, req.opts);

    const ciphertext = result.ciphertext instanceof Blob
      ? result.ciphertext
      : new Blob([result.ciphertext as BlobPart], { type: 'application/octet-stream' });
    const response: EncryptSuccess = { id: req.id, ok: true, result: { ...result, ciphertext } };
    self.postMessage(response);
  } catch (err) {
    const response: EncryptFailure = {
      id: req.id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
    self.postMessage(response);
  }
};

export {};
