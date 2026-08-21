<script lang="ts">
  import { LoaderCircle, Plus, RefreshCw, Search } from 'lucide-svelte';
  import { onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { CredentialDetail, CredentialSummary } from '../types';
  import CredentialEditor from './CredentialEditor.svelte';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import VirtualCredentialList from './VirtualCredentialList.svelte';

  type ScopeFilter = 'all' | 'central' | 'project';

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

  async function loadMore() {
    if (loading || !hasMore) return;
    loading = true;
    try {
      const page = await vaultApi.credentialPage(
        cursor,
        100,
        appliedSearch,
        appliedProject,
        appliedEnvironment
      );
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

  async function applyFilters() {
    appliedSearch = search.trim();
    if (scopeFilter === 'central') {
      appliedProject = '__central__';
    } else if (scopeFilter === 'project') {
      appliedProject = projectFilter.trim() || '__project__';
    } else {
      appliedProject = projectFilter.trim() || null;
    }
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

  onMount(() => {
    void loadMore();
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h2 class="text-2xl font-semibold tracking-tight">Credential Manager</h2>
      <p class="text-sm text-muted-foreground">Keep logins, API keys, tokens, connection strings, notes, and TOTP seeds encrypted by project and environment.</p>
    </div>
    <div class="flex gap-2">
      <Button variant="secondary" size="sm" on:click={refresh} disabled={loading}>
        <RefreshCw size={16} class={loading ? 'animate-spin' : ''} /> Refresh
      </Button>
      <Button size="sm" on:click={addNew}><Plus size={16} /> New credential</Button>
    </div>
  </header>

  <form on:submit|preventDefault={applyFilters} class="space-y-3 rounded-xl border border-border bg-card p-3">
    <div class="flex gap-2">
      <div class="relative flex-1">
        <Search size={17} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <Input bind:value={search} placeholder="Search title, username, project, environment, or website" className="pl-9" />
      </div>
      <Button variant="secondary" type="submit">Apply</Button>
    </div>

    <div class="grid gap-2 sm:grid-cols-3">
      <label class="space-y-1.5">
        <span class="text-xs font-medium text-muted-foreground">Scope</span>
        <select bind:value={scopeFilter} class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring">
          <option value="all">All scopes</option>
          <option value="central">Central</option>
          <option value="project">Project</option>
        </select>
      </label>
      <label class="space-y-1.5">
        <span class="text-xs font-medium text-muted-foreground">Project</span>
        <Input bind:value={projectFilter} placeholder="Todo" disabled={scopeFilter === 'central'} />
      </label>
      <label class="space-y-1.5">
        <span class="text-xs font-medium text-muted-foreground">Environment</span>
        <Input bind:value={environmentFilter} placeholder="dev, test, uat, prod…" />
      </label>
    </div>

    <div class="flex items-center justify-between gap-3">
      <p class="text-xs text-muted-foreground">Central secrets can be shared; project secrets stay grouped with an exact project/environment scope.</p>
      <Button variant="ghost" size="sm" type="button" on:click={clearFilters}>Clear</Button>
    </div>
  </form>

  {#if error}
    <div class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}

  <div class="min-h-0 flex-1">
    <VirtualCredentialList {items} onOpen={openItem} onNearEnd={loadMore} />
  </div>

  {#if loading && items.length > 0}
    <div class="flex items-center justify-center gap-2 pb-2 text-sm text-muted-foreground">
      <LoaderCircle size={16} class="animate-spin" /> Loading encrypted credentials…
    </div>
  {/if}
</section>

{#if editorOpen}
  {#key editorKey}
    <CredentialEditor detail={editing} onClose={closeEditor} onSaved={saved} onDeleted={deleted} />
  {/key}
{/if}
