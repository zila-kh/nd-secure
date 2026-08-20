<script lang="ts">
  import { confirm } from '@tauri-apps/plugin-dialog';
  import { Clock3, Database, HardDrive, MonitorOff, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-svelte';
  import { vaultApi } from '../api';
  import type { SessionStatus } from '../types';
  import Card from './ui/Card.svelte';

  export let status: SessionStatus;
  export let onStatus: (status: SessionStatus) => void;

  let saving = false;
  let savingSourcePolicy = false;
  let error = '';
  let autoLockSeconds = status.autoLockSeconds;
  let deleteSourceAfterImport = status.deleteSourceAfterImport;

  $: if (!saving) autoLockSeconds = status.autoLockSeconds;
  $: if (!savingSourcePolicy) deleteSourceAfterImport = status.deleteSourceAfterImport;

  async function updateAutoLock() {
    saving = true;
    try {
      const next = await vaultApi.setAutoLock(Number(autoLockSeconds));
      onStatus(next);
      error = '';
    } catch (cause) {
      error = String(cause);
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
    } catch (cause) {
      deleteSourceAfterImport = previous;
      error = String(cause);
    } finally {
      savingSourcePolicy = false;
    }
  }
</script>

<section class="animate-fadeIn h-full overflow-auto pb-10">
  <header class="mb-5">
    <h2 class="text-2xl font-semibold tracking-tight">Security Settings</h2>
    <p class="text-sm text-muted-foreground">Local security, import safety, and session behavior for this device.</p>
  </header>

  {#if error}
    <div class="mb-4 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}

  <div class="grid gap-4 lg:grid-cols-2">
    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><Clock3 size={20} /></div>
        <div>
          <h3 class="font-medium">Automatic lock</h3>
          <p class="text-xs text-muted-foreground">Idle commands cause the Rust key session to expire.</p>
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
          <p class="text-xs text-muted-foreground">One unlock, separate cryptographic domains.</p>
        </div>
      </div>
      <ul class="space-y-2 text-sm text-muted-foreground">
        <li>Gallery and credentials use separate HKDF-derived root keys.</li>
        <li>The master key is not persisted or sent to JavaScript.</li>
        <li>Android suspension invalidates the unlocked Rust session.</li>
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
        Media and generated image thumbnails are stored as independently authenticated encrypted chunks. Credential payloads are encrypted per record. Original media names and source paths are not retained.
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
        UUIDs, item counts, record types, timestamps, media MIME types, media sizes, and thumbnail availability remain visible in SQLite. Passwords, usernames, notes, websites, TOTP seeds, media bytes, and thumbnail pixels are encrypted.
      </p>
    </Card>
  </div>
</section>
