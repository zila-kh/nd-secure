<script lang="ts">
  import { confirm } from '@tauri-apps/plugin-dialog';
  import { LoaderCircle, Plus, RefreshCw, Search, ShieldCheck, Trash2 } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { CredentialDetail, CredentialSummary } from '../types';
  import { LatestRequest, mergeById } from '../workflow-state';
  import CredentialEditor from './CredentialEditor.svelte';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import VirtualCredentialList from './VirtualCredentialList.svelte';

  type ScopeFilter = 'all' | 'central' | 'project';
  type VaultMode = 'active' | 'trash';
  const pages = new LatestRequest();
  const details = new LatestRequest();
  const actions = new LatestRequest();
  let destroyed = false;
  let mode: VaultMode = 'active';
  let items: CredentialSummary[] = [];
  let cursor: string | null = null;
  let hasMore = true;
  let loading = false;
  let actionBusy = false;
  let listRevision = 0;
  let search = '';
  let appliedSearch = '';
  let scopeFilter: ScopeFilter = 'all';
  let projectFilter = '';
  let environmentFilter = '';
  let appliedProject: string | null = null;
  let appliedEnvironment: string | null = null;
  let error = '';
  let editorOpen = false;
  let editing: CredentialDetail | null = null;
  let editorKey = 0;
  let reauthPassword = '';
  let reauthReady = false;
  let reauthBusy = false;

  async function loadMore() {
    if (destroyed || loading || !hasMore) return;
    const current = pages.begin();
    loading = true;
    error = '';
    try {
      const page = mode === 'active'
        ? await vaultApi.credentialPage(cursor, 100, appliedSearch, appliedProject, appliedEnvironment)
        : await vaultApi.credentialTrashPage(cursor, 100);
      if (!current()) return;
      items = mergeById(items, page.items);
      cursor = page.nextCursor ?? null;
      hasMore = Boolean(cursor);
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) loading = false;
    }
  }

  async function refresh() {
    if (destroyed) return;
    pages.invalidate();
    loading = false;
    items = [];
    cursor = null;
    hasMore = true;
    listRevision += 1;
    await loadMore();
  }

  async function switchMode(next: VaultMode) {
    if (destroyed || mode === next || actionBusy) return;
    actions.invalidate();
    closeEditor();
    mode = next;
    reauthReady = false;
    reauthBusy = false;
    reauthPassword = '';
    await refresh();
  }

  async function applyFilters() {
    appliedSearch = search.trim();
    appliedProject = scopeFilter === 'central'
      ? '__central__'
      : scopeFilter === 'project'
        ? (projectFilter.trim() || '__project__')
        : (projectFilter.trim() || null);
    appliedEnvironment = environmentFilter.trim() || null;
    await refresh();
  }

  async function clearFilters() {
    search = '';
    appliedSearch = '';
    scopeFilter = 'all';
    projectFilter = '';
    environmentFilter = '';
    appliedProject = null;
    appliedEnvironment = null;
    await refresh();
  }

  function addNew() {
    if (destroyed || mode !== 'active') return;
    details.invalidate();
    editing = null;
    editorOpen = true;
    editorKey += 1;
  }

  async function openItem(item: CredentialSummary) {
    if (destroyed || mode !== 'active') return;
    const current = details.begin();
    try {
      const detail = await vaultApi.credentialDetail(item.id);
      if (!current()) return;
      editing = detail;
      editorOpen = true;
      editorKey += 1;
    } catch (cause) {
      if (current()) error = String(cause);
    }
  }

  function closeEditor() {
    details.invalidate();
    editorOpen = false;
    editing = null;
  }

  async function saved(_saved: CredentialDetail) {
    if (destroyed) return;
    closeEditor();
    await refresh();
  }

  async function deleted(_id: string) {
    if (destroyed) return;
    closeEditor();
    await refresh();
  }

  async function mutate(operation: () => Promise<unknown>, warning?: string) {
    if (destroyed || actionBusy || reauthBusy) return;
    const current = actions.begin();
    actionBusy = true;
    error = '';
    try {
      if (warning) {
        const approved = await confirm(warning, { title: 'Confirm credential action', kind: 'warning' });
        if (!current() || !approved) return;
      }
      await operation();
      if (current()) await refresh();
    } catch (cause) {
      if (current()) { reauthReady = false; error = String(cause); }
    } finally {
      if (current()) actionBusy = false;
    }
  }

  async function restore(item: CredentialSummary) {
    await mutate(() => vaultApi.restoreCredential(item.id));
  }

  async function confirmSensitiveActions() {
    if (destroyed || reauthBusy || actionBusy) return;
    const current = actions.begin();
    const password = reauthPassword;
    reauthPassword = '';
    reauthBusy = true;
    try {
      await vaultApi.reauthenticate(password);
      if (current()) { reauthReady = true; error = ''; }
    } catch (cause) {
      if (current()) { reauthReady = false; error = String(cause); }
    } finally {
      if (current()) reauthBusy = false;
    }
  }

  async function purge(item: CredentialSummary) {
    if (!reauthReady) { error = 'Confirm your master password before permanently deleting trash.'; return; }
    await mutate(() => vaultApi.purgeCredential(item.id),
      `Permanently delete "${item.title}"? This removes the encrypted record and cannot be undone.`);
  }

  async function emptyTrash() {
    if (!reauthReady) { error = 'Confirm your master password before emptying trash.'; return; }
    await mutate(() => vaultApi.emptyCredentialTrash(),
      'Permanently delete every credential currently in trash? This cannot be undone.');
    reauthReady = false;
  }

  onMount(() => { void loadMore(); });
  onDestroy(() => {
    destroyed = true;
    pages.dispose();
    details.dispose();
    actions.dispose();
    items = [];
    editing = null;
    reauthPassword = '';
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div><h2 class="text-2xl font-semibold tracking-tight">Credential Manager</h2><p class="text-sm text-muted-foreground">Encrypted logins, secrets, history, custom fields, folders, project scopes, TOTP, and recoverable trash.</p></div>
    <div class="flex flex-wrap gap-2">
      <div class="flex rounded-md border border-border p-1">
        <button disabled={actionBusy} class={`rounded px-3 py-1.5 text-sm ${mode === 'active' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'}`} on:click={() => switchMode('active')}>Vault</button>
        <button disabled={actionBusy} class={`rounded px-3 py-1.5 text-sm ${mode === 'trash' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'}`} on:click={() => switchMode('trash')}>Trash</button>
      </div>
      <Button variant="secondary" size="sm" on:click={refresh} disabled={loading || actionBusy}><RefreshCw size={16} class={loading ? 'animate-spin' : ''} /> Refresh</Button>
      {#if mode === 'active'}<Button size="sm" on:click={addNew}><Plus size={16} /> New credential</Button>{/if}
    </div>
  </header>

  {#if mode === 'active'}
    <form on:submit|preventDefault={applyFilters} class="space-y-3 rounded-xl border border-border bg-card p-3">
      <div class="flex gap-2"><div class="relative flex-1"><Search size={17} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" /><Input bind:value={search} placeholder="Search title, folder, project, environment, username, website, or visible custom fields" className="pl-9" /></div><Button variant="secondary" type="submit">Apply</Button></div>
      <div class="grid gap-2 sm:grid-cols-3">
        <label class="space-y-1.5"><span class="text-xs font-medium text-muted-foreground">Scope</span><select bind:value={scopeFilter} class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"><option value="all">All scopes</option><option value="central">Central</option><option value="project">Project</option></select></label>
        <label class="space-y-1.5"><span class="text-xs font-medium text-muted-foreground">Project</span><Input bind:value={projectFilter} placeholder="Todo" disabled={scopeFilter === 'central'} /></label>
        <label class="space-y-1.5"><span class="text-xs font-medium text-muted-foreground">Environment</span><Input bind:value={environmentFilter} placeholder="dev, test, uat, prod" /></label>
      </div>
      <div class="flex items-center justify-between gap-3"><p class="text-xs text-muted-foreground">Folder/custom-field metadata is encrypted with each record and is never stored as a plaintext SQLite index.</p><Button variant="ghost" size="sm" type="button" on:click={clearFilters}>Clear</Button></div>
    </form>
  {:else}
    <div class="space-y-3 rounded-xl border border-border bg-card p-4">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div><div class="font-medium">Encrypted trash</div><p class="text-xs text-muted-foreground">Deleting a credential moves it here. Restore requires no password re-entry; permanent deletion does.</p></div>
        <div class="flex flex-col gap-2 sm:flex-row">
          <Input type="password" bind:value={reauthPassword} autocomplete="current-password" placeholder="Master password" disabled={reauthBusy || actionBusy} />
          <Button variant="secondary" on:click={confirmSensitiveActions} disabled={reauthBusy || actionBusy || reauthPassword.length < 12}><ShieldCheck size={16} /> {reauthReady ? 'Confirmed' : 'Confirm sensitive actions'}</Button>
          <Button variant="destructive" on:click={emptyTrash} disabled={actionBusy || !reauthReady || items.length === 0}><Trash2 size={16} /> Empty trash</Button>
        </div>
      </div>
      <p class="text-xs text-muted-foreground">Confirmation is enforced in Rust and expires after about two minutes even if this screen still appears confirmed.</p>
    </div>
  {/if}

  {#if error}<div role="alert" class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>{/if}

  {#if mode === 'active'}
    <div class="min-h-0 flex-1">{#key listRevision}<VirtualCredentialList {items} onOpen={openItem} onNearEnd={loadMore} />{/key}</div>
  {:else}
    <div class="min-h-0 flex-1 overflow-auto rounded-xl border border-border">
      {#if items.length === 0 && !loading}<div class="p-8 text-center text-sm text-muted-foreground">Credential trash is empty.</div>{/if}
      <div class="divide-y divide-border">
        {#each items as item (item.id)}
          <div class="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div class="min-w-0"><div class="truncate font-medium">{item.title}</div>
              <div class="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground"><span>{item.recordType.replace('_', ' ')}</span>{#if item.folder}<span>Folder: {item.folder}</span>{/if}{#if item.project}<span>{item.project}{item.environment ? ` / ${item.environment}` : ''}</span>{/if}<span>Deleted {new Date(item.updatedAt * 1000).toLocaleString()}</span></div>
            </div>
            <div class="flex gap-2"><Button variant="secondary" size="sm" on:click={() => restore(item)} disabled={actionBusy}><RefreshCw size={15} /> Restore</Button><Button variant="destructive" size="sm" on:click={() => purge(item)} disabled={actionBusy || !reauthReady}><Trash2 size={15} /> Delete permanently</Button></div>
          </div>
        {/each}
      </div>
    </div>
  {/if}
  {#if loading}<div role="status" class="flex items-center justify-center gap-2 pb-2 text-sm text-muted-foreground"><LoaderCircle size={16} class="animate-spin" /> Loading encrypted credentials...</div>
  {:else if hasMore}<div class="text-center"><Button variant="secondary" size="sm" on:click={loadMore} disabled={actionBusy}>{error ? 'Retry loading' : 'Load more'}</Button></div>{/if}
</section>

{#if editorOpen}{#key editorKey}<CredentialEditor detail={editing} onClose={closeEditor} onSaved={saved} onDeleted={deleted} />{/key}{/if}
