<script lang="ts">
  import { confirm } from '@tauri-apps/plugin-dialog';
  import {
    Clipboard,
    Clock3,
    Database,
    HardDrive,
    KeyRound,
    LoaderCircle,
    MonitorOff,
    ShieldAlert,
    ShieldCheck,
    Trash2
  } from 'lucide-svelte';
  import { onDestroy } from 'svelte';
  import { vaultApi } from '../api';
  import type { SessionStatus, VaultHealthReport } from '../types';
  import Button from './ui/Button.svelte';
  import Card from './ui/Card.svelte';
  import Input from './ui/Input.svelte';

  export let status: SessionStatus;
  export let onStatus: (status: SessionStatus) => void;

  let saving = false;
  let savingSourcePolicy = false;
  let savingLifecycle = false;
  let passwordBusy = false;
  let recoveryBusy = false;
  let healthBusy = false;
  let healthReport: VaultHealthReport | null = null;
  let error = '';
  let success = '';
  let autoLockSeconds = status.autoLockSeconds;
  let deleteSourceAfterImport = status.deleteSourceAfterImport;
  let lockOnBlur = status.lockOnBlur;
  let lockOnSuspend = status.lockOnSuspend;
  let clipboardTimeoutSeconds = status.clipboardTimeoutSeconds;
  let currentPassword = '';
  let newPassword = '';
  let confirmNewPassword = '';
  let recoveryPassword = '';
  let generatedRecoveryKey = '';

  $: if (!saving) autoLockSeconds = status.autoLockSeconds;
  $: if (!savingSourcePolicy) deleteSourceAfterImport = status.deleteSourceAfterImport;
  $: if (!savingLifecycle) {
    lockOnBlur = status.lockOnBlur;
    lockOnSuspend = status.lockOnSuspend;
    clipboardTimeoutSeconds = status.clipboardTimeoutSeconds;
  }

  async function updateAutoLock() {
    saving = true;
    try {
      const next = await vaultApi.setAutoLock(Number(autoLockSeconds));
      onStatus(next);
      error = '';
      success = 'Automatic lock policy updated.';
    } catch (cause) {
      error = String(cause);
      success = '';
    } finally {
      saving = false;
    }
  }

  async function updateSourcePolicy() {
    const requested = deleteSourceAfterImport;
    const previous = status.deleteSourceAfterImport;
    savingSourcePolicy = true;
    try {
      if (requested) {
        const approved = await confirm(
          'After each encrypted import is authenticated and committed, ND Secure will try to remove the selected original. This is destructive and is not secure erasure. If identity verification or deletion fails, the original is retained and a warning is shown.',
          { title: 'Remove originals after import?', kind: 'warning' }
        );
        if (!approved) {
          deleteSourceAfterImport = previous;
          return;
        }
      }

      const next = await vaultApi.setDeleteSourceAfterImport(requested);
      deleteSourceAfterImport = next.deleteSourceAfterImport;
      onStatus(next);
      error = '';
      success = 'Source-file policy updated.';
    } catch (cause) {
      deleteSourceAfterImport = previous;
      error = String(cause);
      success = '';
    } finally {
      savingSourcePolicy = false;
    }
  }

  async function updateLifecycle() {
    savingLifecycle = true;
    try {
      const next = await vaultApi.setSecurityPreferences(
        lockOnBlur,
        lockOnSuspend,
        Number(clipboardTimeoutSeconds)
      );
      onStatus(next);
      error = '';
      success = 'Lifecycle and clipboard protections updated.';
    } catch (cause) {
      error = String(cause);
      success = '';
    } finally {
      savingLifecycle = false;
    }
  }

  async function changePassword() {
    if (newPassword !== confirmNewPassword) return;
    passwordBusy = true;
    try {
      const next = await vaultApi.changeMasterPassword(currentPassword, newPassword);
      onStatus(next);
      currentPassword = '';
      newPassword = '';
      confirmNewPassword = '';
      error = '';
      success = 'Master password changed. Vault data keys were not re-encrypted.';
    } catch (cause) {
      error = String(cause);
      success = '';
    } finally {
      passwordBusy = false;
    }
  }

  async function createRecovery() {
    recoveryBusy = true;
    generatedRecoveryKey = '';
    try {
      if (status.recoveryConfigured) {
        const approved = await confirm(
          'Creating a new recovery key invalidates the previous recovery key. Continue only if you are ready to replace your offline copy.',
          { title: 'Replace recovery key?', kind: 'warning' }
        );
        if (!approved) return;
      }
      const recovery = await vaultApi.createRecoveryKey(recoveryPassword);
      generatedRecoveryKey = recovery.recoveryKey;
      recoveryPassword = '';
      onStatus(await vaultApi.status());
      error = '';
      success = 'Recovery key created. Store it offline before leaving this screen.';
    } catch (cause) {
      error = String(cause);
      success = '';
    } finally {
      recoveryBusy = false;
    }
  }

  async function disableRecovery() {
    const approved = await confirm(
      'This removes the recovery envelope. Your existing printed/saved recovery key will stop working immediately.',
      { title: 'Disable vault recovery?', kind: 'warning' }
    );
    if (!approved) return;
    recoveryBusy = true;
    try {
      const next = await vaultApi.disableRecovery(recoveryPassword);
      onStatus(next);
      recoveryPassword = '';
      generatedRecoveryKey = '';
      error = '';
      success = 'Offline recovery disabled.';
    } catch (cause) {
      error = String(cause);
      success = '';
    } finally {
      recoveryBusy = false;
    }
  }

  async function runHealthCheck() {
    healthBusy = true;
    healthReport = null;
    error = '';
    success = '';
    try {
      healthReport = await vaultApi.healthCheck();
      if (healthReport.healthy) {
        success = 'Full vault integrity check passed.';
      } else {
        error = `Vault integrity check found ${healthReport.totalIssues} issue${healthReport.totalIssues === 1 ? '' : 's'}. Review the report below before relying on this copy.`;
      }
    } catch (cause) {
      error = `Unable to complete vault integrity check: ${String(cause)}`;
    } finally {
      healthBusy = false;
    }
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }

  onDestroy(() => {
    currentPassword = '';
    newPassword = '';
    confirmNewPassword = '';
    recoveryPassword = '';
    generatedRecoveryKey = '';
  });
</script>

<section class="animate-fadeIn h-full overflow-auto pb-10">
  <header class="mb-5">
    <h2 class="text-2xl font-semibold tracking-tight">Security Settings</h2>
    <p class="text-sm text-muted-foreground">Envelope encryption, recovery, local lifecycle locks, integrity verification, and import safety for this device.</p>
  </header>

  {#if error}
    <div class="mb-4 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}
  {#if success}
    <div class="mb-4 rounded-lg border border-primary/30 bg-primary/10 px-4 py-3 text-sm text-foreground">{success}</div>
  {/if}

  <div class="grid gap-4 lg:grid-cols-2">
    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><Clock3 size={20} /></div>
        <div>
          <h3 class="font-medium">Automatic lock</h3>
          <p class="text-xs text-muted-foreground">Idle Rust sessions expire and zeroize their root key.</p>
        </div>
      </div>
      <label class="block space-y-2 text-sm">
        <span>Lock after inactivity</span>
        <select
          bind:value={autoLockSeconds}
          on:change={updateAutoLock}
          disabled={saving}
          class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <option value={60}>1 minute</option>
          <option value={300}>5 minutes</option>
          <option value={900}>15 minutes</option>
          <option value={1800}>30 minutes</option>
          <option value={3600}>1 hour</option>
        </select>
      </label>
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><Clipboard size={20} /></div>
        <div>
          <h3 class="font-medium">Lifecycle and clipboard</h3>
          <p class="text-xs text-muted-foreground">Reduce plaintext exposure when attention leaves the vault.</p>
        </div>
      </div>
      <div class="space-y-3 text-sm">
        <label class="flex items-start gap-3 rounded-lg border border-border p-3">
          <input type="checkbox" bind:checked={lockOnBlur} on:change={updateLifecycle} disabled={savingLifecycle} class="mt-0.5 h-4 w-4 accent-primary" />
          <span><span class="block font-medium">Lock when the app loses focus</span><span class="text-xs text-muted-foreground">Useful on shared desktops; can be inconvenient during normal switching.</span></span>
        </label>
        <label class="flex items-start gap-3 rounded-lg border border-border p-3">
          <input type="checkbox" bind:checked={lockOnSuspend} on:change={updateLifecycle} disabled={savingLifecycle} class="mt-0.5 h-4 w-4 accent-primary" />
          <span><span class="block font-medium">Lock on mobile suspension/background</span><span class="text-xs text-muted-foreground">Enabled by default and enforced in Rust where Tauri reports suspension.</span></span>
        </label>
        <label class="block space-y-2">
          <span>Clear copied secrets after</span>
          <select bind:value={clipboardTimeoutSeconds} on:change={updateLifecycle} disabled={savingLifecycle} class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm">
            <option value={10}>10 seconds</option>
            <option value={30}>30 seconds</option>
            <option value={60}>1 minute</option>
            <option value={120}>2 minutes</option>
          </select>
          <span class="block text-xs text-muted-foreground">ND Secure only clears the clipboard if it still contains the exact secret it copied.</span>
        </label>
      </div>
    </Card>

    <Card className="p-5 lg:col-span-2">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><KeyRound size={20} /></div>
        <div>
          <h3 class="font-medium">Master password and vault root key</h3>
          <p class="text-xs text-muted-foreground">The password protects a wrapping key for the vault root key; changing it does not rewrite gallery or credential ciphertext.</p>
        </div>
      </div>
      <form on:submit|preventDefault={changePassword} class="grid gap-3 md:grid-cols-3">
        <label class="space-y-1.5"><span class="text-xs font-medium">Current master password</span><Input type="password" bind:value={currentPassword} autocomplete="current-password" required /></label>
        <label class="space-y-1.5"><span class="text-xs font-medium">New master password</span><Input type="password" bind:value={newPassword} autocomplete="new-password" minlength={12} required /></label>
        <label class="space-y-1.5"><span class="text-xs font-medium">Confirm new password</span><Input type="password" bind:value={confirmNewPassword} autocomplete="new-password" minlength={12} required /></label>
        <div class="md:col-span-3 flex flex-wrap items-center justify-between gap-3">
          <p class="text-xs text-muted-foreground">A fresh salt and Argon2id password key are generated atomically; HKDF separates the AES wrapping key. The encrypted root key remains stable.</p>
          <Button type="submit" disabled={passwordBusy || currentPassword.length < 12 || newPassword.length < 12 || newPassword !== confirmNewPassword}>Change master password</Button>
        </div>
        {#if confirmNewPassword && newPassword !== confirmNewPassword}<p class="text-sm text-destructive md:col-span-3">New passwords do not match.</p>{/if}
      </form>
    </Card>

    <Card className="p-5 lg:col-span-2">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><ShieldCheck size={20} /></div>
        <div>
          <h3 class="font-medium">Offline recovery key</h3>
          <p class="text-xs text-muted-foreground">Optional recovery envelope for resetting a forgotten master password without a server.</p>
        </div>
      </div>
      <div class="space-y-3">
        <div class="flex flex-col gap-2 sm:flex-row">
          <Input type="password" bind:value={recoveryPassword} autocomplete="current-password" placeholder="Confirm current master password" className="flex-1" />
          <Button on:click={createRecovery} disabled={recoveryBusy || recoveryPassword.length < 12}>{status.recoveryConfigured ? 'Replace recovery key' : 'Create recovery key'}</Button>
          {#if status.recoveryConfigured}<Button variant="destructive" on:click={disableRecovery} disabled={recoveryBusy || recoveryPassword.length < 12}>Disable recovery</Button>{/if}
        </div>
        <p class="text-xs text-muted-foreground">The recovery key is never persisted by ND Secure. It is present in the webview only while you generate, view, or enter it. Replacing it invalidates the old one. Anyone with the key and your vault files can reset the master password.</p>
        {#if generatedRecoveryKey}
          <div class="rounded-lg border border-primary/30 bg-primary/10 p-4">
            <div class="mb-2 text-sm font-medium">Save this key offline now — it will not be shown again</div>
            <code class="block select-all break-all rounded bg-background p-3 text-xs">{generatedRecoveryKey}</code>
            <p class="mt-2 text-xs text-muted-foreground">Prefer paper or an independently encrypted offline location. Do not store it inside this same vault.</p>
          </div>
        {/if}
      </div>
    </Card>

    <Card className="p-5 lg:col-span-2">
      <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="rounded-lg bg-primary/15 p-2 text-primary"><Database size={20} /></div>
          <div>
            <h3 class="font-medium">Full vault integrity check</h3>
            <p class="text-xs text-muted-foreground">Authenticate encrypted content and validate both SQLite vault indexes.</p>
          </div>
        </div>
        <Button on:click={runHealthCheck} disabled={healthBusy}>
          {#if healthBusy}<LoaderCircle size={16} class="animate-spin" />{/if}
          {healthBusy ? 'Checking vault…' : 'Run integrity check'}
        </Button>
      </div>
      <p class="text-sm text-muted-foreground">
        The scan runs in Rust. It performs SQLite structural checks, decrypts and authenticates credential records, and verifies every encrypted media chunk and available thumbnail in both the active vault and Trash. Plaintext content is not returned to the webview. Avoid editing the vault while a scan is running for the clearest result.
      </p>

      {#if healthReport}
        <div class={`mt-4 rounded-lg border p-4 ${healthReport.healthy ? 'border-primary/30 bg-primary/10' : 'border-destructive/40 bg-destructive/10'}`}>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="font-medium">{healthReport.healthy ? 'Integrity check passed' : 'Integrity check found issues'}</div>
            <div class="text-xs text-muted-foreground">{new Date(healthReport.checkedAt * 1000).toLocaleString()}</div>
          </div>
          <div class="mt-3 grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-5">
            <div><span class="block text-xs text-muted-foreground">Gallery</span>{healthReport.galleryItems}</div>
            <div><span class="block text-xs text-muted-foreground">Media Trash</span>{healthReport.galleryTrashItems}</div>
            <div><span class="block text-xs text-muted-foreground">Credentials</span>{healthReport.credentialItems}</div>
            <div><span class="block text-xs text-muted-foreground">Credential Trash</span>{healthReport.credentialTrashItems}</div>
            <div><span class="block text-xs text-muted-foreground">Verified media</span>{formatBytes(healthReport.verifiedMediaBytes)}</div>
          </div>

          {#if !healthReport.healthy}
            <div class="mt-4 space-y-2">
              <div class="text-xs font-medium">{healthReport.totalIssues} issue{healthReport.totalIssues === 1 ? '' : 's'} detected</div>
              {#each healthReport.issues as issue}
                <div class="rounded border border-destructive/30 bg-background/60 px-3 py-2 text-xs">
                  <span class="font-medium">{issue.area}</span>
                  {#if issue.id}<span class="ml-1 text-muted-foreground">· {issue.id}</span>{/if}
                  <div class="mt-1 text-muted-foreground">{issue.message}</div>
                </div>
              {/each}
              {#if healthReport.totalIssues > healthReport.issues.length}
                <div class="text-xs text-muted-foreground">Only the first {healthReport.issues.length} issues are shown.</div>
              {/if}
            </div>
          {/if}
        </div>
      {/if}
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><Trash2 size={20} /></div>
        <div>
          <h3 class="font-medium">Original source handling</h3>
          <p class="text-xs text-muted-foreground">Safe default: keep every selected original.</p>
        </div>
      </div>
      <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-3">
        <input
          type="checkbox"
          bind:checked={deleteSourceAfterImport}
          on:change={updateSourcePolicy}
          disabled={savingSourcePolicy}
          class="mt-0.5 h-4 w-4 rounded border-input accent-primary"
        />
        <span class="space-y-1 text-sm">
          <span class="block font-medium">Remove original after verified import</span>
          <span class="block text-xs leading-relaxed text-muted-foreground">
            Off by default. Desktop files must pass same-file and hash checks; Android documents must pass same-URI length and hash checks. Deletion is requested only after the encrypted container and index transaction succeed, and providers or file systems may refuse it.
          </span>
        </span>
      </label>
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><ShieldCheck size={20} /></div>
        <div>
          <h3 class="font-medium">Key isolation</h3>
          <p class="text-xs text-muted-foreground">One wrapped vault root, separate cryptographic domains.</p>
        </div>
      </div>
      <ul class="space-y-2 text-sm text-muted-foreground">
        <li>New vaults use a random 256-bit root key wrapped by an Argon2id + HKDF-derived AES key.</li>
        <li>Gallery and credentials use separate HKDF-derived domain keys.</li>
        <li>The unwrapped root key and password-derived key material remain in Rust and are not returned to the webview.</li>
      </ul>
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><HardDrive size={20} /></div>
        <div>
          <h3 class="font-medium">Encrypted storage</h3>
          <p class="text-xs text-muted-foreground">Application-private data directory only.</p>
        </div>
      </div>
      <p class="text-sm text-muted-foreground">
        Media and generated image thumbnails are stored as independently authenticated encrypted chunks. Deleted media remains encrypted in recoverable Trash until explicitly purged. Credential payloads, folders, custom fields, password history, project names, and environment names are encrypted per record. Original media names and source paths are not retained.
      </p>
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><MonitorOff size={20} /></div>
        <div>
          <h3 class="font-medium">Screen-capture protection</h3>
          <p class="text-xs text-muted-foreground">Best-effort operating-system protection is requested.</p>
        </div>
      </div>
      <p class="text-sm text-muted-foreground">
        The app marks its main window as content-protected where the platform supports it. This cannot block a privileged operating-system user, debugger, compromised device, external camera, or every screenshot and recording service.
      </p>
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><ShieldAlert size={20} /></div>
        <div>
          <h3 class="font-medium">Unlocked-memory boundary</h3>
          <p class="text-xs text-muted-foreground">Plaintext must exist in memory to be viewed or edited.</p>
        </div>
      </div>
      <p class="text-sm text-muted-foreground">
        Swap, hibernation, process dumps, injected code, accessibility services, and device-memory acquisition may expose plaintext while the vault is unlocked. Lock the vault when it is not actively in use.
      </p>
    </Card>

    <Card className="p-5 lg:col-span-2">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><Database size={20} /></div>
        <div>
          <h3 class="font-medium">Metadata notice</h3>
          <p class="text-xs text-muted-foreground">Content is encrypted, but some operational metadata remains visible.</p>
        </div>
      </div>
      <p class="text-sm text-muted-foreground">
        UUIDs, item counts, record types, record state (active/trash), timestamps, active-media MIME types, active-media sizes, and thumbnail availability remain visible in SQLite. Trashed-media descriptive metadata is authenticated and encrypted. Passwords, usernames, notes, websites, custom fields, project/environment names, TOTP seeds, media bytes, and thumbnail pixels are encrypted.
      </p>
    </Card>
  </div>
</section>