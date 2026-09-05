export type VaultView = 'gallery' | 'passwords' | 'projects' | 'settings';

export interface SessionStatus {
  initialized: boolean;
  locked: boolean;
  autoLockSeconds: number;
  deleteSourceAfterImport: boolean;
  lockOnBlur: boolean;
  lockOnSuspend: boolean;
  clipboardTimeoutSeconds: number;
  recoveryConfigured: boolean;
  recentlyReauthenticated: boolean;
}

export interface RecoveryKey {
  recoveryKey: string;
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

export type CredentialType = 'login' | 'secure_note' | 'totp' | 'secret';
export type CredentialScope = 'central' | 'project';

export interface CredentialField {
  name: string;
  value: string;
  hidden: boolean;
}

export interface PasswordHistoryEntry {
  password: string;
  changedAt: number;
}

export interface CredentialSummary {
  id: string;
  recordType: CredentialType;
  title: string;
  scope: CredentialScope;
  project?: string | null;
  environment?: string | null;
  folder?: string | null;
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
  scope: CredentialScope;
  project?: string;
  environment?: string;
  folder?: string;
  username?: string;
  password?: string;
  secretValue?: string;
  websites: string[];
  notes?: string;
  totpSecret?: string;
  customFields: CredentialField[];
  favorite: boolean;
}

export interface CredentialDetail extends CredentialInput {
  id: string;
  passwordHistory: PasswordHistoryEntry[];
  createdAt: number;
  updatedAt: number;
}

export interface GeneratedPassword {
  password: string;
  entropyBits: number;
}

export interface PasswordGeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  minNumbers: number;
  minSymbols: number;
}

export interface TotpCode {
  code: string;
  remainingSeconds: number;
}

export interface ProjectRegistration {
  id: string;
  name: string;
  root: string;
  environments: string[];
  requiredKeys: string[];
  createdAt: number;
  updatedAt: number;
}

export interface ProjectInspection {
  root: string;
  suggestedName: string;
  exampleExists: boolean;
  requiredKeys: string[];
  plaintextEnvFiles: string[];
}

export interface ProjectEnvironmentStatus {
  projectId: string;
  environment: string;
  presentKeys: string[];
  missingKeys: string[];
  plaintextEnvFiles: string[];
}

export interface ProjectEnvImportResult {
  importedKeys: string[];
  existingKeys: string[];
  sourceRemoved: boolean;
  rotationRecommended: boolean;
}

export interface ProjectCommandResult {
  pid: number;
  injectedKeys: string[];
}
