export type VaultView = 'gallery' | 'passwords' | 'settings';

export interface SessionStatus {
  initialized: boolean;
  locked: boolean;
  autoLockSeconds: number;
  deleteSourceAfterImport: boolean;
}

export interface GalleryItem {
  id: string;
  mimeType: 'image/jpeg' | 'image/png' | 'video/mp4' | 'video/webm';
  fileSizeBytes: number;
  timestampAdded: number;
  width?: number | null;
  height?: number | null;
  durationMs?: number | null;
  thumbnailAvailable: boolean;
}

export interface GalleryPage {
  items: GalleryItem[];
  nextCursor?: string | null;
}

export interface ImportMediaItemResult {
  sourceIndex: number;
  id?: string | null;
  sourceRemoved: boolean;
  warning?: string | null;
  error?: string | null;
}

export interface ImportMediaResult {
  items: ImportMediaItemResult[];
  sourceRemovalEnabled: boolean;
}

export interface MediaStreamHandle {
  url: string;
  token: string;
}

export type CredentialType = 'login' | 'secure_note' | 'totp';

export interface CredentialSummary {
  id: string;
  recordType: CredentialType;
  title: string;
  username?: string | null;
  favorite: boolean;
  updatedAt: number;
}

export interface CredentialPage {
  items: CredentialSummary[];
  nextCursor?: string | null;
}

export interface CredentialInput {
  id?: string;
  recordType: CredentialType;
  title: string;
  username?: string;
  password?: string;
  websites: string[];
  notes?: string;
  totpSecret?: string;
  favorite: boolean;
}

export interface CredentialDetail extends CredentialInput {
  id: string;
  createdAt: number;
  updatedAt: number;
}

export interface GeneratedPassword {
  password: string;
  entropyBits: number;
}

export interface TotpCode {
  code: string;
  remainingSeconds: number;
}
