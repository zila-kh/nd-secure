<script lang="ts">
  import { LoaderCircle, Plus, RefreshCw, Search } from 'lucide-svelte';
  import { onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { CredentialDetail, CredentialSummary } from '../types';
  import CredentialEditor from './CredentialEditor.svelte';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import VirtualCredentialList from './VirtualCredentialList.svelte';

  let items: CredentialSummary[] = [];
  let cursor: string | null = null;
  let hasMore = true;
  let loading = false;
  let search = '';
  let appliedSearch = '';
  let error = '';
  let editorOpen = false;
  let editing: CredentialDetail | null = null;
  let editorKey = 0;

  async function loadMore() {
    if (loading || !hasMore) return;
    loading = true;
    try {
      const page = await vaultApi.credentialPage(cursor, 100, appliedSearch);
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

  async function applySearch() {
    appliedSearch = search.trim();
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
      <h2 class="text-2xl font-semibold tracking-tight">Password Manager</h2>
      <p class="text-sm text-muted-foreground">Logins, secure notes, and TOTP seeds encrypted per record.</p>
    </div>
    <div class="flex gap-2">
      <Button variant="secondary" size="sm" on:click={refresh} disabled={loading}>
        <RefreshCw size={16} class={loading ? 'animate-spin' : ''} /> Refresh
      </Button>
      <Button size="sm" on:click={addNew}><Plus size={16} /> New item</Button>
    </div>
  </header>

  <form on:submit|preventDefault={applySearch} class="flex gap-2">
    <div class="relative flex-1">
      <Search size={17} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
      <Input bind:value={search} placeholder="Search decrypted titles, usernames, and websites" className="pl-9" />
    </div>
    <Button variant="secondary" type="submit">Search</Button>
  </form>

  {#if error}
    <div class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}

  <div class="min-h-0 flex-1">
    <VirtualCredentialList {items} onOpen={openItem} onNearEnd={loadMore} />
  </div>

  {#if loading && items.length > 0}
    <div class="flex items-center justify-center gap-2 pb-2 text-sm text-muted-foreground">
      <LoaderCircle size={16} class="animate-spin" /> Loading more encrypted records…
    </div>
  {/if}
</section>

{#if editorOpen}
  {#key editorKey}
    <CredentialEditor detail={editing} onClose={closeEditor} onSaved={saved} onDeleted={deleted} />
  {/key}
{/if}
