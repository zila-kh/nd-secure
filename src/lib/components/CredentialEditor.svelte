<script lang="ts">
  import { Clipboard, Eye, EyeOff, LoaderCircle, Plus, RefreshCw, Save, Trash2, X } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { CredentialDetail, CredentialField, CredentialInput, CredentialScope, CredentialType, TotpCode } from '../types';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import Textarea from './ui/Textarea.svelte';

  export let detail: CredentialDetail | null = null;
  export let onClose: () => void;
  export let onSaved: (saved: CredentialDetail) => void;
  export let onDeleted: (id: string) => void;

  const commonEnvironments = ['dev', 'test', 'uat', 'staging', 'prod'];

  let recordType: CredentialType = detail?.recordType ?? 'login';
  let scope: CredentialScope = detail?.scope ?? 'central';
  let project = detail?.project ?? '';
  let environment = detail?.environment ?? '';
  let folder = detail?.folder ?? '';
  let title = detail?.title ?? '';
  let username = detail?.username ?? '';
  let password = detail?.password ?? '';
  let secretValue = detail?.secretValue ?? '';
  let websites = detail?.websites?.join('\n') ?? '';
  let notes = detail?.notes ?? '';
  let totpSecret = detail?.totpSecret ?? '';
  let customFields: CredentialField[] = detail?.customFields?.map((field) => ({ ...field })) ?? [];
  let favorite = detail?.favorite ?? false;
  let revealPassword = false;
  let revealSecret = false;
  let revealHistory = false;
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
      scope,
      project: scope === 'project' ? project.trim() || undefined : undefined,
      environment: environment.trim() || undefined,
      folder: folder.trim() || undefined,
      username: username.trim() || undefined,
      password: password || undefined,
      secretValue: secretValue || undefined,
      websites: websites.split('\n').map((value) => value.trim()).filter(Boolean),
      notes: notes || undefined,
      totpSecret: totpSecret.trim() || undefined,
      customFields: customFields
        .map((field) => ({ name: field.name.trim(), value: field.value, hidden: field.hidden }))
        .filter((field) => field.name || field.value),
      favorite
    };
    try {
      onSaved(await vaultApi.saveCredential(input));
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

  async function copy(field: string) {
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

  function addCustomField() {
    if (customFields.length < 32) customFields = [...customFields, { name: '', value: '', hidden: false }];
  }

  function removeCustomField(index: number) {
    customFields = customFields.filter((_, current) => current !== index);
  }

  function updateCustomField(index: number, patch: Partial<CredentialField>) {
    customFields = customFields.map((field, current) => current === index ? { ...field, ...patch } : field);
  }

  async function refreshTotp() {
    if (!detail || detail.recordType !== 'totp') return;
    try { totp = await vaultApi.totpCode(detail.id); } catch { totp = null; }
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
    secretValue = '';
    totpSecret = '';
    notes = '';
    customFields = [];
  });
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-3 backdrop-blur-sm" role="dialog" aria-modal="true">
  <form on:submit|preventDefault={save} class="flex max-h-[94vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl">
    <header class="flex items-center justify-between border-b border-border px-5 py-4">
      <div><h3 class="text-lg font-semibold">{detail ? 'Edit credential' : 'New credential'}</h3><p class="text-xs text-muted-foreground">Sensitive metadata, custom fields, and password history stay inside authenticated encryption.</p></div>
      <Button variant="ghost" size="icon" on:click={onClose} aria-label="Close"><X size={19} /></Button>
    </header>

    <div class="min-h-0 flex-1 space-y-5 overflow-auto p-5">
      {#if error}<div class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>{/if}

      <div class="grid grid-cols-2 gap-2 rounded-lg bg-muted p-1 sm:grid-cols-4">
        <button type="button" class={`rounded-md px-3 py-2 text-sm ${recordType === 'login' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`} on:click={() => (recordType = 'login')}>Login</button>
        <button type="button" class={`rounded-md px-3 py-2 text-sm ${recordType === 'secret' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`} on:click={() => (recordType = 'secret')}>Secret key</button>
        <button type="button" class={`rounded-md px-3 py-2 text-sm ${recordType === 'secure_note' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`} on:click={() => (recordType = 'secure_note')}>Secure note</button>
        <button type="button" class={`rounded-md px-3 py-2 text-sm ${recordType === 'totp' ? 'bg-background text-foreground shadow' : 'text-muted-foreground'}`} on:click={() => (recordType = 'totp')}>TOTP</button>
      </div>

      <div class="space-y-3 rounded-xl border border-border p-4">
        <div class="grid grid-cols-2 gap-2">
          <button type="button" class={`rounded-md border px-3 py-2 text-sm ${scope === 'central' ? 'border-primary bg-primary/10' : 'border-border text-muted-foreground'}`} on:click={() => (scope = 'central')}>Central</button>
          <button type="button" class={`rounded-md border px-3 py-2 text-sm ${scope === 'project' ? 'border-primary bg-primary/10' : 'border-border text-muted-foreground'}`} on:click={() => (scope = 'project')}>Project</button>
        </div>
        {#if scope === 'project'}<label class="block space-y-2"><span class="text-sm font-medium">Project</span><Input bind:value={project} placeholder="Todo" required /></label>{/if}
        <label class="block space-y-2"><span class="text-sm font-medium">Environment</span><Input bind:value={environment} placeholder="prod" /><div class="flex flex-wrap gap-1.5">{#each commonEnvironments as name}<button type="button" class={`rounded border px-2 py-1 text-xs ${environment === name ? 'border-primary bg-primary/10' : 'border-border text-muted-foreground'}`} on:click={() => (environment = name)}>{name}</button>{/each}</div></label>
        <label class="block space-y-2"><span class="text-sm font-medium">Folder</span><Input bind:value={folder} placeholder="Infrastructure / Production" /></label>
      </div>

      <label class="block space-y-2"><span class="text-sm font-medium">Title</span><Input bind:value={title} placeholder={recordType === 'secret' ? 'DATABASE_URL' : 'Example account'} required /></label>

      {#if recordType !== 'secure_note' && recordType !== 'secret'}
        <label class="block space-y-2"><span class="text-sm font-medium">Username</span><div class="flex gap-2"><Input bind:value={username} autocomplete="username" placeholder="name@example.com" />{#if detail}<Button variant="secondary" size="icon" on:click={() => copy('username')} aria-label="Copy username"><Clipboard size={17} /></Button>{/if}</div></label>
      {/if}

      {#if recordType === 'login'}
        <label class="block space-y-2"><span class="text-sm font-medium">Password</span><div class="flex gap-2"><Input type={revealPassword ? 'text' : 'password'} bind:value={password} autocomplete="new-password" /><Button variant="secondary" size="icon" on:click={() => { revealPassword = !revealPassword; if (revealPassword) schedulePasswordHide(); }} aria-label="Toggle password visibility">{#if revealPassword}<EyeOff size={17} />{:else}<Eye size={17} />{/if}</Button><Button variant="secondary" size="icon" on:click={generatePassword} aria-label="Generate password"><RefreshCw size={17} /></Button>{#if detail}<Button variant="secondary" size="icon" on:click={() => copy('password')} aria-label="Copy password"><Clipboard size={17} /></Button>{/if}</div></label>
        <label class="block space-y-2"><span class="text-sm font-medium">Website origins</span><Textarea bind:value={websites} rows={3} placeholder={'https://example.com\nhttps://accounts.example.com'} /></label>
        {#if detail?.passwordHistory?.length}
          <div class="rounded-xl border border-border p-4"><div class="flex items-center justify-between"><div><div class="text-sm font-medium">Password history</div><p class="text-xs text-muted-foreground">Up to 10 previous passwords, encrypted with this record.</p></div><Button variant="secondary" size="sm" type="button" on:click={() => (revealHistory = !revealHistory)}>{revealHistory ? 'Hide' : 'Reveal'}</Button></div>{#if revealHistory}<div class="mt-3 space-y-2">{#each detail.passwordHistory as entry}<div class="flex items-center justify-between gap-3 rounded-md bg-muted p-2"><code class="min-w-0 flex-1 truncate text-xs">{entry.password}</code><time class="text-xs text-muted-foreground">{new Date(entry.changedAt * 1000).toLocaleString()}</time></div>{/each}</div>{/if}</div>
        {/if}
      {/if}

      {#if recordType === 'secret'}
        <label class="block space-y-2"><span class="text-sm font-medium">Secret value</span><div class="flex gap-2"><Input type={revealSecret ? 'text' : 'password'} bind:value={secretValue} autocomplete="off" required /><Button variant="secondary" size="icon" on:click={() => (revealSecret = !revealSecret)} aria-label="Toggle secret visibility">{#if revealSecret}<EyeOff size={17} />{:else}<Eye size={17} />{/if}</Button>{#if detail}<Button variant="secondary" size="icon" on:click={() => copy('secret')} aria-label="Copy secret"><Clipboard size={17} /></Button>{/if}</div></label>
      {/if}

      {#if recordType === 'totp'}
        {#if totp}<div class="rounded-xl border border-border bg-muted/50 p-5 text-center"><div class="font-mono text-4xl font-semibold tracking-[0.2em]">{totp.code}</div><div class="mt-2 text-xs text-muted-foreground">Refreshes in {totp.remainingSeconds}s</div></div>{/if}
        <label class="block space-y-2"><span class="text-sm font-medium">Base32 secret</span><Input type="password" bind:value={totpSecret} autocomplete="off" /></label>
      {/if}

      <div class="space-y-3 rounded-xl border border-border p-4">
        <div class="flex items-center justify-between"><div><div class="text-sm font-medium">Custom fields</div><p class="text-xs text-muted-foreground">Hidden values are excluded from search and remain encrypted at rest.</p></div><Button variant="secondary" size="sm" type="button" on:click={addCustomField} disabled={customFields.length >= 32}><Plus size={15} /> Add</Button></div>
        {#each customFields as field, index}
          <div class="grid gap-2 rounded-lg bg-muted/40 p-3 sm:grid-cols-[1fr_1fr_auto_auto]">
            <Input value={field.name} on:input={(event) => updateCustomField(index, { name: (event.currentTarget as HTMLInputElement).value })} placeholder="Field name" />
            <Input type={field.hidden ? 'password' : 'text'} value={field.value} on:input={(event) => updateCustomField(index, { value: (event.currentTarget as HTMLInputElement).value })} placeholder="Value" autocomplete="off" />
            <label class="flex items-center gap-2 text-xs"><input type="checkbox" checked={field.hidden} on:change={(event) => updateCustomField(index, { hidden: event.currentTarget.checked })} /> Hidden</label>
            <div class="flex gap-1">{#if detail}<Button variant="secondary" size="icon" type="button" on:click={() => copy(`custom:${index}`)} aria-label="Copy custom field"><Clipboard size={15} /></Button>{/if}<Button variant="ghost" size="icon" type="button" on:click={() => removeCustomField(index)} aria-label="Remove custom field"><X size={15} /></Button></div>
          </div>
        {/each}
      </div>

      <label class="block space-y-2"><span class="text-sm font-medium">Notes</span><div class="flex items-start gap-2"><Textarea bind:value={notes} rows={6} placeholder="Encrypted notes, owner, rotation policy, or usage instructions" className="flex-1" />{#if detail}<Button variant="secondary" size="icon" on:click={() => copy('notes')} aria-label="Copy notes"><Clipboard size={17} /></Button>{/if}</div></label>
      <label class="flex items-center gap-3 rounded-lg border border-border p-3"><input type="checkbox" bind:checked={favorite} class="h-4 w-4" /><span class="text-sm">Mark as favorite</span></label>
    </div>

    <footer class="flex items-center justify-between gap-3 border-t border-border px-5 py-4"><div>{#if detail}<Button variant="destructive" size="sm" on:click={remove} disabled={busy}><Trash2 size={16} /> Delete</Button>{/if}</div><div class="flex gap-2"><Button variant="secondary" on:click={onClose}>Cancel</Button><Button type="submit" disabled={busy || !title.trim() || (scope === 'project' && !project.trim()) || (recordType === 'secret' && !secretValue)}>{#if busy}<LoaderCircle size={16} class="animate-spin" />{:else}<Save size={16} />{/if} Save</Button></div></footer>
  </form>
</div>
