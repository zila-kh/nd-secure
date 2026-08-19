<script lang="ts">
  import {
    Clipboard,
    Eye,
    EyeOff,
    LoaderCircle,
    RefreshCw,
    Save,
    Trash2,
    X
  } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { CredentialDetail, CredentialInput, CredentialType, TotpCode } from '../types';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import Textarea from './ui/Textarea.svelte';

  export let detail: CredentialDetail | null = null;
  export let onClose: () => void;
  export let onSaved: (saved: CredentialDetail) => void;
  export let onDeleted: (id: string) => void;

  let recordType: CredentialType = detail?.recordType ?? 'login';
  let title = detail?.title ?? '';
  let username = detail?.username ?? '';
  let password = detail?.password ?? '';
  let websites = detail?.websites?.join('\n') ?? '';
  let notes = detail?.notes ?? '';
  let totpSecret = detail?.totpSecret ?? '';
  let favorite = detail?.favorite ?? false;
  let revealPassword = false;
  let busy = false;
  let error = '';
  let totp: TotpCode | null = null;
  let totpTimer: ReturnType<typeof setInterval> | undefined;
  let revealTimer: ReturnType<typeof setTimeout> | undefined;

  async function save() {
    busy = true;
    error = '';
    const input: CredentialInput = {
      id: detail?.id,
      recordType,
      title: title.trim(),
      username: username.trim() || undefined,
      password: password || undefined,
      websites: websites
        .split('\n')
        .map((value) => value.trim())
        .filter(Boolean),
      notes: notes || undefined,
      totpSecret: totpSecret.trim() || undefined,
      favorite
    };

    try {
      const saved = await vaultApi.saveCredential(input);
      onSaved(saved);
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  function schedulePasswordHide() {
    if (revealTimer) clearTimeout(revealTimer);
    revealTimer = setTimeout(() => (revealPassword = false), 15_000);
  }

  function togglePassword() {
    revealPassword = !revealPassword;
    if (revealPassword) schedulePasswordHide();
  }

  async function generatePassword() {
    try {
      const generated = await vaultApi.generatePassword(24, true);
      password = generated.password;
      revealPassword = true;
      schedulePasswordHide();
    } catch (cause) {
      error = String(cause);
    }
  }

  async function copy(field: 'username' | 'password' | 'notes') {
    if (!detail) return;
    try {
      await vaultApi.copyCredentialField(detail.id, field);
    } catch (cause) {
      error = String(cause);
    }
  }

  async function remove() {
    if (!detail) return;
    busy = true;
    try {
      await vaultApi.deleteCredential(detail.id);
      onDeleted(detail.id);
    } catch (cause) {
      error = String(cause);
      busy = false;
    }
  }

  async function refreshTotp() {
    if (!detail || detail.recordType !== 'totp') return;
    try {
      totp = await vaultApi.totpCode(detail.id);
    } catch {
      totp = null;
    }
  }

  onMount(() => {
    if (detail?.recordType === 'totp') {
      refreshTotp();
      totpTimer = setInterval(refreshTotp, 1000);
    }
  });

  onDestroy(() => {
    if (totpTimer) clearInterval(totpTimer);
    if (revealTimer) clearTimeout(revealTimer);
    password = '';
    totpSecret = '';
    notes = '';
  });
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-3 backdrop-blur-sm" role="dialog" aria-modal="true">
  <form
    on:submit|preventDefault={save}
    class="flex max-h-[94vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl"
  >
    <header class="flex items-center justify-between border-b border-border px-5 py-4">
      <div>
        <h3 class="text-lg font-semibold">{detail ? 'Edit vault item' : 'New vault item'}</h3>
        <p class="text-xs text-muted-foreground">Fields are encrypted together as one authenticated record.</p>
      </div>
      <Button variant="ghost" size="icon" on:click={onClose} aria-label="Close"><X size={19} /></Button>
    </header>

    <div class="min-h-0 flex-1 space-y-5 overflow-auto p-5">
      {#if error}
        <div class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
      {/if}

      <div class="grid grid-cols-3 gap-2 rounded-lg bg-muted p-1">
        <button
          type="button"
          class={`rounded-md px-3 py-2 text-sm ${recordType === 'login' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`}
          on:click={() => (recordType = 'login')}
        >Login</button>
        <button
          type="button"
          class={`rounded-md px-3 py-2 text-sm ${recordType === 'secure_note' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`}
          on:click={() => (recordType = 'secure_note')}
        >Secure note</button>
        <button
          type="button"
          class={`rounded-md px-3 py-2 text-sm ${recordType === 'totp' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`}
          on:click={() => (recordType = 'totp')}
        >TOTP</button>
      </div>

      <label class="block space-y-2">
        <span class="text-sm font-medium">Title</span>
        <Input bind:value={title} placeholder="Example account" required />
      </label>

      {#if recordType !== 'secure_note'}
        <label class="block space-y-2">
          <span class="text-sm font-medium">Username</span>
          <div class="flex gap-2">
            <Input bind:value={username} autocomplete="username" placeholder="name@example.com" />
            {#if detail}<Button variant="secondary" size="icon" on:click={() => copy('username')} aria-label="Copy username"><Clipboard size={17} /></Button>{/if}
          </div>
        </label>
      {/if}

      {#if recordType === 'login'}
        <label class="block space-y-2">
          <span class="text-sm font-medium">Password</span>
          <div class="flex gap-2">
            <Input
              type={revealPassword ? 'text' : 'password'}
              bind:value={password}
              autocomplete="new-password"
              placeholder="Stored password"
            />
            <Button variant="secondary" size="icon" on:click={togglePassword} aria-label="Toggle password visibility">
              {#if revealPassword}<EyeOff size={17} />{:else}<Eye size={17} />{/if}
            </Button>
            <Button variant="secondary" size="icon" on:click={generatePassword} aria-label="Generate password"><RefreshCw size={17} /></Button>
            {#if detail}<Button variant="secondary" size="icon" on:click={() => copy('password')} aria-label="Copy password"><Clipboard size={17} /></Button>{/if}
          </div>
        </label>

        <label class="block space-y-2">
          <span class="text-sm font-medium">Website origins</span>
          <Textarea bind:value={websites} rows={3} placeholder={'https://example.com\nhttps://accounts.example.com'} />
        </label>
      {/if}

      {#if recordType === 'totp'}
        {#if totp}
          <div class="rounded-xl border border-border bg-muted/50 p-5 text-center">
            <div class="font-mono text-4xl font-semibold tracking-[0.2em]">{totp.code}</div>
            <div class="mt-2 text-xs text-muted-foreground">Refreshes in {totp.remainingSeconds}s</div>
          </div>
        {/if}
        <label class="block space-y-2">
          <span class="text-sm font-medium">Base32 secret</span>
          <Input type="password" bind:value={totpSecret} autocomplete="off" placeholder="JBSWY3DPEHPK3PXP" />
        </label>
      {/if}

      <label class="block space-y-2">
        <span class="text-sm font-medium">Notes</span>
        <div class="flex items-start gap-2">
          <Textarea bind:value={notes} rows={6} placeholder="Encrypted notes" className="flex-1" />
          {#if detail}<Button variant="secondary" size="icon" on:click={() => copy('notes')} aria-label="Copy notes"><Clipboard size={17} /></Button>{/if}
        </div>
      </label>

      <label class="flex items-center gap-3 rounded-lg border border-border p-3">
        <input type="checkbox" bind:checked={favorite} class="h-4 w-4" />
        <span class="text-sm">Mark as favorite</span>
      </label>
    </div>

    <footer class="flex items-center justify-between gap-3 border-t border-border px-5 py-4">
      <div>
        {#if detail}
          <Button variant="destructive" size="sm" on:click={remove} disabled={busy}><Trash2 size={16} /> Delete</Button>
        {/if}
      </div>
      <div class="flex gap-2">
        <Button variant="secondary" on:click={onClose}>Cancel</Button>
        <Button type="submit" disabled={busy || !title.trim()}>
          {#if busy}<LoaderCircle size={16} class="animate-spin" />{:else}<Save size={16} />{/if}
          Save
        </Button>
      </div>
    </footer>
  </form>
</div>
