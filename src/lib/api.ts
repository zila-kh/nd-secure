import { convertFileSrc, invoke } from '@tauri-apps/api/core';
import type {
  CredentialDetail,
  CredentialInput,
  CredentialPage,
  GalleryPage,
  GeneratedPassword,
  ImportMediaResult,
  SessionStatus,
  TotpCode
} from './types';

export const vaultApi = {
  status: () => invoke<SessionStatus>('session_status'),
  initialize: (password: string, autoLockSeconds = 300) =>
    invoke<SessionStatus>('initialize_vault', {
      password,
      autoLockSeconds
    }),
  unlock: (password: string) => invoke<SessionStatus>('unlock_vault', { password }),
  lock: () => invoke<SessionStatus>('lock_vault'),
  setAutoLock: (autoLockSeconds: number) =>
    invoke<SessionStatus>('set_auto_lock', { autoLockSeconds }),
  setDeleteSourceAfterImport: (enabled: boolean) =>
    invoke<SessionStatus>('set_delete_source_after_import', { enabled }),

  galleryPage: (cursor: string | null = null, limit = 100) =>
    invoke<GalleryPage>('gallery_page', { cursor, limit }),
  importMedia: (sources: string[]) => invoke<ImportMediaResult>('import_media', { sources }),
  deleteMedia: (id: string) => invoke<void>('delete_media', { id }),

  credentialPage: (
    cursor: string | null = null,
    limit = 100,
    search = '',
    project: string | null = null,
    environment: string | null = null
  ) => invoke<CredentialPage>('credential_page', { cursor, limit, search, project, environment }),
  credentialDetail: (id: string) => invoke<CredentialDetail>('credential_detail', { id }),
  saveCredential: (input: CredentialInput) =>
    invoke<CredentialDetail>('save_credential', { input }),
  deleteCredential: (id: string) => invoke<void>('delete_credential', { id }),
  copyCredentialField: (id: string, field: 'username' | 'password' | 'secret' | 'notes') =>
    invoke<void>('copy_credential_field', { id, field }),
  generatePassword: (length = 20, symbols = true) =>
    invoke<GeneratedPassword>('generate_password', { length, symbols }),
  totpCode: (id: string) => invoke<TotpCode>('credential_totp', { id })
};

export function mediaUrl(id: string): string {
  return convertFileSrc(`/media/${id}`, 'vault');
}

export function thumbnailUrl(id: string): string {
  return convertFileSrc(`/thumbnail/${id}`, 'vault');
}
