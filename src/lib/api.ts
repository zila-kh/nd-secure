import { convertFileSrc, invoke } from '@tauri-apps/api/core';
import type {
  CredentialDetail,
  CredentialInput,
  CredentialPage,
  GalleryPage,
  GeneratedPassword,
  ImportMediaResult,
  MediaStreamHandle,
  PasswordGeneratorOptions,
  RecoveryKey,
  SessionStatus,
  TotpCode
} from './types';

export const vaultApi = {
  status: () => invoke<SessionStatus>('session_status'),
  initialize: (password: string, autoLockSeconds = 300) =>
    invoke<SessionStatus>('initialize_vault', { password, autoLockSeconds }),
  unlock: (password: string) => invoke<SessionStatus>('unlock_vault', { password }),
  reauthenticate: (password: string) => invoke<SessionStatus>('reauthenticate_vault', { password }),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    invoke<SessionStatus>('change_master_password', { currentPassword, newPassword }),
  createRecoveryKey: (password: string) => invoke<RecoveryKey>('create_recovery_key', { password }),
  disableRecovery: (password: string) => invoke<SessionStatus>('disable_recovery', { password }),
  recover: (recoveryKey: string, newPassword: string) =>
    invoke<SessionStatus>('recover_vault', { recoveryKey, newPassword }),
  lock: () => invoke<SessionStatus>('lock_vault'),
  setAutoLock: (autoLockSeconds: number) =>
    invoke<SessionStatus>('set_auto_lock', { autoLockSeconds }),
  setDeleteSourceAfterImport: (enabled: boolean) =>
    invoke<SessionStatus>('set_delete_source_after_import', { enabled }),
  setSecurityPreferences: (
    lockOnBlur: boolean,
    lockOnSuspend: boolean,
    clipboardTimeoutSeconds: number
  ) =>
    invoke<SessionStatus>('set_security_preferences', {
      lockOnBlur,
      lockOnSuspend,
      clipboardTimeoutSeconds
    }),

  galleryPage: (cursor: string | null = null, limit = 100) =>
    invoke<GalleryPage>('gallery_page', { cursor, limit }),
  importMedia: (sources: string[]) => invoke<ImportMediaResult>('import_media', { sources }),
  deleteMedia: (id: string) => invoke<void>('delete_media', { id }),
  openMediaStream: (id: string) => invoke<MediaStreamHandle>('open_media_stream', { id }),
  closeMediaStream: (token: string) => invoke<void>('close_media_stream', { token }),

  credentialPage: (
    cursor: string | null = null,
    limit = 100,
    search = '',
    project: string | null = null,
    environment: string | null = null
  ) => invoke<CredentialPage>('credential_page', { cursor, limit, search, project, environment }),
  credentialTrashPage: (cursor: string | null = null, limit = 100) =>
    invoke<CredentialPage>('credential_trash_page', { cursor, limit }),
  credentialDetail: (id: string) => invoke<CredentialDetail>('credential_detail', { id }),
  saveCredential: (input: CredentialInput) => invoke<CredentialDetail>('save_credential', { input }),
  deleteCredential: (id: string) => invoke<void>('delete_credential', { id }),
  restoreCredential: (id: string) => invoke<void>('restore_credential', { id }),
  purgeCredential: (id: string) => invoke<void>('purge_credential', { id }),
  emptyCredentialTrash: () => invoke<number>('empty_credential_trash'),
  copyCredentialField: (id: string, field: string) =>
    invoke<void>('copy_credential_field', { id, field }),
  generatePassword: (length = 20, symbols = true) =>
    invoke<GeneratedPassword>('generate_password', { length, symbols }),
  generatePasswordAdvanced: (options: PasswordGeneratorOptions) =>
    invoke<GeneratedPassword>('generate_password_advanced', { options }),
  totpCode: (id: string) => invoke<TotpCode>('credential_totp', { id })
};

export function mediaUrl(id: string): string {
  return convertFileSrc(`/media/${id}`, 'vault');
}

export function thumbnailUrl(id: string): string {
  return convertFileSrc(`/thumbnail/${id}`, 'vault');
}
