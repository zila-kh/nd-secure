<script lang="ts">
  import { confirm } from '@tauri-apps/plugin-dialog';
  import { LoaderCircle, Plus, RefreshCw, Search, ShieldCheck, Trash2 } from 'lucide-svelte';
  import { onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { CredentialDetail, CredentialSummary } from '../types';
  import CredentialEditor from './CredentialEditor.svelte';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import VirtualCredentialList from './VirtualCredentialList.svelte';

  type ScopeFilter = 'all' | 'central' | 'project';
  type VaultMode = 'active' | 'trash';
  let mode: VaultMode = 'active';
  let items: CredentialSummary[] = [];
  let cursor: string | null = null;
  let hasMore = true;
  let loading = false;
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
    if (loading || !hasMore) return;
    loading = true;
    try {
      const page = mode === 'active'
        ? await vaultApi.credentialPage(cursor, 100, appliedSearch, appliedProject, appliedEnvironment)
        : await vaultApi.credentialTrashPage(cursor, 100);
      const known = new Set(items.map((item) => item.id));
      items = [...items, ...page.items.filter((item) => !known.has(item.id))];
      cursor = page.nextCursor ?? null;
      hasMore = Boolean(cursor);
      error = '';
    } catch (cause) {
      error = String(cause);
    } finally {
      loading = false;
    }
  }

  async function refresh() {
    items = [];
    cursor = null;
    hasMore = true;
    await loadMore();
  }

  async function switchMode(next: VaultMode) {
    mode = next;
    editorOpen = false;
    editing = null;
    reauthReady = false;
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
    editing = null;
    editorOpen = true;
    editorKey += 1;
  }

  async function openItem(item: CredentialSummary) {
    if (mode !== 'active') return;
    try {
      editing = await vaultApi.credentialDetail(item.id);
      editorOpen = true;
      editorKey += 1;
    } catch (cause) {
      error = String(cause);
    }
  }

  function closeEditor() {
    editorOpen = false;
    editing = null;
  }

  async function saved(_saved: CredentialDetail) {
    closeEditor();
    await refresh();
  }

  async function deleted(_id: string) {
    closeEditor();
    await refresh();
  }

  async function restore(item: CredentialSummary) {
    try {
      await vaultApi.restoreCredential(item.id);
      await refresh();
      error = '';
    } catch (cause) {
      error = String(cause);
    }
  }

  async function confirmSensitiveActions() {
    reauthBusy = true;
    try {
      await vaultApi.reauthenticate(reauthPassword);
      reauthPassword = '';
      reauthReady = true;
      error = '';
    } catch (cause) {
      reauthReady = false;
      error = String(cause);
    } finally {
      reauthBusy = false;
    }
  }

  async function purge(item: CredentialSummary) {
    if (!reauthReady) {
      error = 'Confirm your master password before permanently deleting trash.';
      return;
    }
    const approved = await confirm(
      `Permanently delete “${item.title}”? This removes the encrypted record and cannot be undone.`,
      { title: 'Permanently delete credential?', kind: 'warning' }
    );
    if (!approved) return;
    try {
      await vaultApi.purgeCredential(item.id);
      await refresh();
      error = '';
    } catch (cause) {
      reauthReady = false;
      error = String(cause);
    }
  }

  async function emptyTrash() {
    if (!reauthReady) {
      error = 'Confirm your master password before emptying trash.';
      return;
    }
    const approved = await confirm(
      'Permanently delete every credential currently in trash? This cannot be undone.',
      { title: 'Empty credential trash?', kind: 'warning' }
    );
    if (!approved) return;
    try {
      await vaultApi.emptyCredentialTrash();
      reauthReady = false;
      await refresh();
      error = '';
    } catch (cause) {
      reauthReady = false;
      error = String(cause);
    }
  }

  onMount(() => {
    void loadMore();
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h2 class="text-2xl font-semibold tracking-tight">Credential Manager</h2>
      <p class="text-sm text-muted-foreground">Encrypted logins, secrets, history, custom fields, folders, project scopes, TOTP, and recoverable trash.</p>
    </div>
    <div class="flex flex-wrap gap-2">
      <div class="flex rounded-md border border-border p-1">
        <button class={`rounded px-3 py-1.5 text-sm ${mode === 'active' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'}`} on:click={() => switchMode('active')}>Vault</button>
        <button class={`rounded px-3 py-1.5 text-sm ${mode === 'trash' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'}`} on:click={() => switchMode('trash')}>Trash</button>
      </div>
      <Button variant="secondary" size="sm" on:click={refresh} disabled={loading}><RefreshCw size={16} class={loading ? 'animate-spin' : ''} /> Refresh</Button>
      {#if mode === 'active'}<Button size="sm" on:click={addNew}><Plus size={16} /> New credential</Button>{/if}
    </div>
  </header>

  {#if mode === 'active'}
    <form on:submit|preventDefault={applyFilters} class="space-y-3 rounded-xl border border-border bg-card p-3">
      <div class="flex gap-2"><div class="relative flex-1"><Search size={17} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" /><Input bind:value={search} placeholder="Search title, folder, project, environment, username, website, or visible custom fields" className="pl-9" /></div><Button variant="secondary" type="submit">Apply</Button></div>
      <div class="grid gap-2 sm:grid-cols-3"><label class="space-y-1.5"><span class="text-xs font-medium text-muted-foreground">Scope</span><select bind:value={scopeFilter} class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"><option value="all">All scopes</option><option value="central">Central</option><option value="project">Project</option></select></label><label class="space-y-1.5"><span class="text-xs font-medium text-muted-foreground">Project</span><Input bind:value={projectFilter} placeholder="Todo" disabled={scopeFilter === 'central'} /></label><label class="space-y-1.5"><span class="text-xs font-medium text-muted-foreground">Environment</span><Input bind:value={environmentFilter} placeholder="dev, test, uat, prod…" /></label></div>
      <div class="flex items-center justify-between gap-3"><p class="text-xs text-muted-foreground">Folder/custom-field metadata is encrypted with each record and is never stored as a plaintext SQLite index.</p><Button variant="ghost" size="sm" type="button" on:click={clearFilters}>Clear</Button></div>
    </form>
  {:else}
    <div class="space-y-3 rounded-xl border border-border bg-card p-4">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div class="font-medium">Encrypted trash</div>
          <p class="text-xs text-muted-foreground">Deleting a credential now moves it here. Restore requires no password re-entry; permanent deletion does.</p>
        </div>
        <div class="flex flex-col gap-2 sm:flex-row">
          <Input type="password" bind:value={reauthPassword} autocomplete="current-password" placeholder="Master password" />
          <Button variant="secondary" on:click={confirmSensitiveActions} disabled={reauthBusy || reauthPassword.length < 12}><ShieldCheck size={16} /> {reauthReady ? 'Confirmed' : 'Confirm sensitive actions'}</Button>
          <Button variant="destructive" on:click={emptyTrash} disabled={!reauthReady || items.length === 0}><Trash2 size={16} /> Empty trash</Button>
        </div>
      </div>
      <p class="text-xs text-muted-foreground">Confirmation is enforced in Rust and expires after about two minutes even if this screen still appears confirmed.</p>
    </div>
  {/if}

  {#if error}<div class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>{/if}

  {#if mode === 'active'}
    <div class="min-h-0 flex-1"><VirtualCredentialList {items} onOpen={openItem} onNearEnd={loadMore} /></div>
  {:else}
    <div class="min-h-0 flex-1 overflow-auto rounded-xl border border-border">
      {#if items.length === 0 && !loading}
        <div class="p-8 text-center text-sm text-muted-foreground">Credential trash is empty.</div>
      {:else}
        <div class="divide-y divide-border">
          {#each items as item}
            <div class="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
              <div class="min-w-0">
                <div class="truncate font-medium">{item.title}</div>
                <div class="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <span>{item.recordType.replace('_', ' ')}</span>
                  {#if item.folder}<span>Folder: {item.folder}</span>{/if}
                  {#if item.project}<span>{item.project}{item.environment ? ` / ${item.environment}` : ''}</span>{/if}
                  <span>Deleted {new Date(item.updatedAt * 1000).toLocaleString()}</span>
                </div>
              </div>
              <div class="flex gap-2">
                <Button variant="secondary" size="sm" on:click={() => restore(item)}><RefreshCw size={15} /> Restore</Button>
                <Button variant="destructive" size="sm" on:click={() => purge(item)} disabled={!reauthReady}><Trash2 size={15} /> Delete permanently</Button>
              </div>
            </div>
          {/each}
          {#if hasMore}<div class="p-3 text-center"><Button variant="secondary" size="sm" on:click={loadMore} disabled={loading}>Load more</Button></div>{/if}
        </div>
      {/if}
    </div>
  {/if}

  {#if loading && items.length > 0}<div class="flex items-center justify-center gap-2 pb-2 text-sm text-muted-foreground"><LoaderCircle size={16} class="animate-spin" /> Loading encrypted credentials…</div>{/if}
</section>

{#if editorOpen}{#key editorKey}<CredentialEditor detail={editing} onClose={closeEditor} onSaved={saved} onDeleted={deleted} />{/key}{/if}
