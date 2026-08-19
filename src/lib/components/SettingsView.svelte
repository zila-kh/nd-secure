<script lang="ts">
  import { Clock3, Database, HardDrive, ShieldCheck } from 'lucide-svelte';
  import { vaultApi } from '../api';
  import type { SessionStatus } from '../types';
  import Card from './ui/Card.svelte';

  export let status: SessionStatus;
  export let onStatus: (status: SessionStatus) => void;

  let saving = false;
  let error = '';
  let autoLockSeconds = status.autoLockSeconds;

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
</script>

<section class="animate-fadeIn h-full overflow-auto pb-10">
  <header class="mb-5">
    <h2 class="text-2xl font-semibold tracking-tight">Security Settings</h2>
    <p class="text-sm text-muted-foreground">Local security and session behavior for this device.</p>
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
        Media is stored as independently authenticated encrypted chunks. Credential payloads are encrypted per record.
        Original media names and source paths are not retained.
      </p>
    </Card>

    <Card className="p-5">
      <div class="mb-4 flex items-center gap-3">
        <div class="rounded-lg bg-primary/15 p-2 text-primary"><Database size={20} /></div>
        <div>
          <h3 class="font-medium">Metadata notice</h3>
          <p class="text-xs text-muted-foreground">The current MVP protects content, not every access pattern.</p>
        </div>
      </div>
      <p class="text-sm text-muted-foreground">
        UUIDs, item counts, record types, timestamps, media MIME types, and media sizes remain visible in SQLite.
        Passwords, usernames, notes, websites, TOTP seeds, and media bytes are encrypted.
      </p>
    </Card>
  </div>
</section>
