<script lang="ts">
  import { open } from '@tauri-apps/plugin-dialog';
  import { LoaderCircle, Plus, RefreshCw, Trash2, X } from 'lucide-svelte';
  import { onMount } from 'svelte';
  import { mediaUrl, vaultApi } from '../api';
  import type { GalleryItem } from '../types';
  import Button from './ui/Button.svelte';
  import VirtualGallery from './VirtualGallery.svelte';

  let items: GalleryItem[] = [];
  let cursor: string | null = null;
  let loading = false;
  let importing = false;
  let hasMore = true;
  let error = '';
  let selected: GalleryItem | null = null;

  async function refresh() {
    items = [];
    cursor = null;
    hasMore = true;
    await loadMore();
  }

  async function loadMore() {
    if (loading || !hasMore) return;
    loading = true;
    try {
      const page = await vaultApi.galleryPage(cursor, 120);
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

  async function importFiles() {
    const result = await open({
      multiple: true,
      directory: false,
      pickerMode: 'document',
      fileAccessMode: 'scoped',
      filters: [
        {
          name: 'Supported media',
          extensions: ['image/jpeg', 'image/png', 'video/mp4', 'video/webm', 'jpg', 'jpeg', 'png', 'mp4', 'webm']
        }
      ]
    });

    if (!result) return;
    const sources = Array.isArray(result) ? result : [result];
    if (sources.length === 0) return;

    importing = true;
    error = '';
    try {
      await vaultApi.importMedia(sources);
      await refresh();
    } catch (cause) {
      error = String(cause);
    } finally {
      importing = false;
    }
  }

  async function removeSelected() {
    if (!selected) return;
    try {
      await vaultApi.deleteMedia(selected.id);
      items = items.filter((item) => item.id !== selected?.id);
      selected = null;
    } catch (cause) {
      error = String(cause);
    }
  }

  function closeViewer() {
    selected = null;
  }

  onMount(() => {
    void loadMore();
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h2 class="text-2xl font-semibold tracking-tight">Gallery Vault</h2>
      <p class="text-sm text-muted-foreground">Chunk-encrypted media stored under opaque identifiers.</p>
    </div>
    <div class="flex gap-2">
      <Button variant="secondary" size="sm" on:click={refresh} disabled={loading}>
        <RefreshCw size={16} class={loading ? 'animate-spin' : ''} /> Refresh
      </Button>
      <Button size="sm" on:click={importFiles} disabled={importing}>
        {#if importing}<LoaderCircle size={16} class="animate-spin" />{:else}<Plus size={16} />{/if}
        Import media
      </Button>
    </div>
  </header>

  {#if error}
    <div class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}

  <div class="min-h-0 flex-1">
    <VirtualGallery {items} onOpen={(item) => (selected = item)} onNearEnd={loadMore} />
  </div>

  {#if loading && items.length > 0}
    <div class="flex items-center justify-center gap-2 pb-2 text-sm text-muted-foreground">
      <LoaderCircle size={16} class="animate-spin" /> Loading more encrypted items…
    </div>
  {/if}
</section>

{#if selected}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-3 backdrop-blur-sm" role="dialog" aria-modal="true">
    <div class="relative flex h-full max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl">
      <div class="flex items-center justify-between border-b border-border px-4 py-3">
        <div class="text-sm text-muted-foreground">
          {selected.mimeType} · {(selected.fileSizeBytes / 1024 / 1024).toFixed(2)} MB
        </div>
        <div class="flex gap-2">
          <Button variant="destructive" size="sm" on:click={removeSelected}><Trash2 size={16} /> Delete</Button>
          <Button variant="ghost" size="icon" on:click={closeViewer} aria-label="Close"><X size={19} /></Button>
        </div>
      </div>
      <div class="flex min-h-0 flex-1 items-center justify-center bg-black p-2">
        {#if selected.mimeType.startsWith('video/')}
          <video src={mediaUrl(selected.id)} controls autoplay class="max-h-full max-w-full"></video>
        {:else}
          <img src={mediaUrl(selected.id)} alt="Selected encrypted media" class="max-h-full max-w-full object-contain" />
        {/if}
      </div>
    </div>
  </div>
{/if}
