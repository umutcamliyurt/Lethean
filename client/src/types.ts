
export const FOLDER_MIME = 'application/x-lethean-folder';

export interface FileMeta {
  name: string;
  mime: string;
  compressed?: boolean;
  unpaddedSize?: number;
  isFolder?: boolean;
  parentId?: string | null;
}

export interface FileRecord {
  id: string;
  content_iv: string;
  encrypted_metadata: string;
  metadata_iv: string;
  wrapped_file_key: string;
  wrap_iv: string;
  size?: number;
  [key: string]: unknown;
}

export interface EncryptedFilePayload {
  ciphertext: Uint8Array;
  contentIv: string;
  encryptedMetadata: string;
  metadataIv: string;
  wrappedFileKey: string;
  wrapIv: string;
}

export interface UsageResponse {
  file_count: number;
  total_bytes: number;
  quota_bytes?: number | null;
}

export interface UnlockResult {
  vaultId: string;
  wrappingKeyRaw: Uint8Array;
}

export interface PasswordValidationResult {
  valid: boolean;
  score: number;
  errors: string[];
}

export interface DuressConfig {
  salt: string;
  verifier: string;
  encVaultId: string;
  iv: string;
  kdfVersion?: number;
}

export type PreviewKind = 'pdf' | 'audio' | 'text' | null;
export type FileKind = 'image' | 'video' | 'other';
export type ViewMode = 'grid' | 'list';

export type ProgressCallback = (fraction: number) => void;

export interface ShareCreateResponse {
  shareToken: string;
  deleteToken?: string | null;
  expiresAt?: string | null;
  maxDownloads: number;
}

export interface ShareRecord {
  content_iv: string;
  encrypted_metadata: string;
  metadata_iv: string;
  downloads_used: number;
  max_downloads: number;
  expires_at: string;
  deletable: boolean;
}
