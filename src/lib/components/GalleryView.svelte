<script lang="ts">
  import { confirm, open } from '@tauri-apps/plugin-dialog';
  import { CheckCircle2, LoaderCircle, Plus, RefreshCw, Trash2, X } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
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
  let notice = '';
  let selected: GalleryItem | null = null;
  let galleryRevision = 0;
  let videoUrl = '';
  let videoToken = '';
  let videoLoading = false;

  async function refresh() {
    items = [];
    cursor = null;
    hasMore = true;
    galleryRevision += 1;
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
    notice = '';
    try {
      const importResult = await vaultApi.importMedia(sources);
      const successful = importResult.items.filter((item) => item.id);
      const failed = importResult.items.filter((item) => item.error);
      const warnings = importResult.items.filter((item) => item.warning);
      const removed = importResult.items.filter((item) => item.sourceRemoved).length;

      if (successful.length > 0) await refresh();

      const sourceSummary = importResult.sourceRemovalEnabled
        ? `${removed} verified original${removed === 1 ? '' : 's'} removed; all others were retained.`
        : 'Original source files were kept.';
      notice = `${successful.length} of ${sources.length} item${sources.length === 1 ? '' : 's'} imported. ${sourceSummary}`;

      const messages = [
        ...failed.map((item) => `File ${item.sourceIndex + 1}: ${item.error}`),
        ...warnings.map((item) => `File ${item.sourceIndex + 1}: ${item.warning}`)
      ];
      error = messages.slice(0, 5).join(' ');
      if (messages.length > 5) error += ` ${messages.length - 5} additional warning${messages.length - 5 === 1 ? '' : 's'} not shown.`;
    } catch (cause) {
      error = String(cause);
    } finally {
      importing = false;
    }
  }

  function revokeVideoStream() {
    const token = videoToken;
    videoToken = '';
    videoUrl = '';
    videoLoading = false;
    if (token) void vaultApi.closeMediaStream(token).catch(() => undefined);
  }

  async function openItem(item: GalleryItem) {
    revokeVideoStream();
    selected = item;
    error = '';

    if (!item.mimeType.startsWith('video/')) return;

    videoLoading = true;
    try {
      const stream = await vaultApi.openMediaStream(item.id);
      if (!selected || selected.id !== item.id) {
        void vaultApi.closeMediaStream(stream.token).catch(() => undefined);
        return;
      }
      videoToken = stream.token;
      videoUrl = stream.url;
    } catch (cause) {
      if (selected?.id === item.id) error = `Unable to open encrypted video: ${String(cause)}`;
    } finally {
      if (selected?.id === item.id) videoLoading = false;
    }
  }

  async function removeSelected() {
    if (!selected) return;
    const approved = await confirm(
      'Permanently delete this encrypted media item from ND Secure? This action cannot be undone.',
      { title: 'Delete encrypted media?', kind: 'warning' }
    );
    if (!approved || !selected) return;

    const selectedId = selected.id;
    revokeVideoStream();
    try {
      await vaultApi.deleteMedia(selectedId);
      items = items.filter((item) => item.id !== selectedId);
      selected = null;
      notice = 'Encrypted media item permanently deleted.';
      error = '';
    } catch (cause) {
      error = String(cause);
    }
  }

  function closeViewer() {
    revokeVideoStream();
    selected = null;
  }

  onMount(() => {
    void loadMore();
  });

  onDestroy(() => {
    revokeVideoStream();
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h2 class="text-2xl font-semibold tracking-tight">Gallery Vault</h2>
      <p class="text-sm text-muted-foreground">Encrypted originals with separately encrypted, pre-generated image thumbnails.</p>
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

  {#if notice}
    <div class="flex items-start gap-2 rounded-lg border border-primary/30 bg-primary/10 px-4 py-3 text-sm">
      <CheckCircle2 size={17} class="mt-0.5 shrink-0 text-primary" />
      <span>{notice}</span>
    </div>
  {/if}

  {#if error}
    <div class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}

  <div class="min-h-0 flex-1">
    {#key galleryRevision}
      <VirtualGallery {items} onOpen={openItem} onNearEnd={loadMore} />
    {/key}
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
          {#if videoLoading}
            <div class="flex items-center gap-2 text-sm text-white/70">
              <LoaderCircle size={18} class="animate-spin" /> Preparing encrypted video stream…
            </div>
          {:else if videoUrl}
            <video src={videoUrl} controls autoplay playsinline preload="metadata" class="max-h-full max-w-full"></video>
          {:else}
            <div class="text-sm text-white/70">Unable to load this encrypted video.</div>
          {/if}
        {:else}
          <img src={mediaUrl(selected.id)} alt="Selected encrypted media" class="max-h-full max-w-full object-contain" />
        {/if}
      </div>
    </div>
  </div>
{/if}
