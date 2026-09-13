<script lang="ts">
  import { confirm, open } from '@tauri-apps/plugin-dialog';
  import { CheckCircle2, LoaderCircle, Plus, RefreshCw, ShieldCheck, Trash2, X } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { mediaUrl, vaultApi } from '../api';
  import type { GalleryItem, GalleryTrashItem } from '../types';
  import {
    LatestRequest, mergeById, mediaPickerExtensions, normalizeMediaSelection, pendingMediaSelection
  } from '../workflow-state';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import VirtualGallery from './VirtualGallery.svelte';

  type GalleryMode = 'active' | 'trash';
  const pages = new LatestRequest();
  const viewer = new LatestRequest();
  const actions = new LatestRequest();
  const imports = new LatestRequest();
  let destroyed = false;
  let mode: GalleryMode = 'active';
  let items: GalleryItem[] = [];
  let trashItems: GalleryTrashItem[] = [];
  let cursor: string | null = null;
  let loading = false;
  let importing = false;
  let actionBusy = false;
  let hasMore = true;
  let error = '';
  let notice = '';
  let selected: GalleryItem | null = null;
  let galleryRevision = 0;
  let videoUrl = '';
  let videoToken = '';
  let videoLoading = false;
  let reauthPassword = '';
  let reauthReady = false;
  let reauthBusy = false;

  async function refresh() {
    if (destroyed) return;
    pages.invalidate();
    loading = false;
    items = [];
    trashItems = [];
    cursor = null;
    hasMore = true;
    galleryRevision += 1;
    await loadMore();
  }

  async function loadMore() {
    if (destroyed || loading || !hasMore) return;
    const current = pages.begin();
    const requestedMode = mode;
    const requestedCursor = cursor;
    loading = true;
    error = '';
    try {
      if (requestedMode === 'active') {
        const page = await vaultApi.galleryPage(requestedCursor, 120);
        if (!current()) return;
        items = mergeById(items, page.items);
        cursor = page.nextCursor ?? null;
      } else {
        const page = await vaultApi.galleryTrashPage(requestedCursor, 100);
        if (!current()) return;
        trashItems = mergeById(trashItems, page.items);
        cursor = page.nextCursor ?? null;
      }
      hasMore = Boolean(cursor);
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) loading = false;
    }
  }

  async function switchMode(next: GalleryMode) {
    if (destroyed || next === mode || actionBusy || importing) return;
    closeViewer();
    actions.invalidate();
    mode = next;
    reauthPassword = '';
    reauthReady = false;
    reauthBusy = false;
    notice = '';
    await refresh();
  }

  async function importFiles() {
    if (destroyed || importing) return;
    await pendingMediaSelection.choose(async () => normalizeMediaSelection(await open({
      multiple: true,
      directory: false,
      pickerMode: 'document',
      fileAccessMode: 'scoped',
      filters: [{ name: 'Supported media', extensions: mediaPickerExtensions(/Android/i.test(navigator.userAgent)) }]
    })));
    if (!destroyed && pendingMediaSelection.current.value) await importPending();
  }

  async function importPending() {
    const sources = pendingMediaSelection.current.value;
    if (destroyed || importing || !sources || !pendingMediaSelection.claim(sources)) return;
    const current = imports.begin();
    importing = true;
    error = '';
    notice = '';
    try {
      const status = await vaultApi.status();
      if (!current()) return;
      if (status.locked) {
        notice = 'Unlock the vault, then resume the selected import.';
        return;
      }
      const result = await vaultApi.importMedia([...sources]);
      // Consume a completed import even if a lock destroyed its originating screen.
      pendingMediaSelection.consume(sources);
      if (!current()) return;
      const successful = result.items.filter((item) => item.id);
      const removed = result.items.filter((item) => item.sourceRemoved).length;
      const messages = result.items.flatMap((item) => [
        ...(item.error ? [`File ${item.sourceIndex + 1}: ${item.error}`] : []),
        ...(item.warning ? [`File ${item.sourceIndex + 1}: ${item.warning}`] : [])
      ]);
      if (successful.length > 0) await refresh();
      if (!current()) return;
      const sourceSummary = result.sourceRemovalEnabled
        ? `${removed} verified originals removed; all others were retained.`
        : 'Original source files were kept.';
      notice = `${successful.length} of ${sources.length} items imported. ${sourceSummary}`;
      if (messages.length) {
        error = messages.slice(0, 5).join(' ');
        if (messages.length > 5) error += ` ${messages.length - 5} additional warnings not shown.`;
      }
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      pendingMediaSelection.release(sources);
      if (current()) importing = false;
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
    if (destroyed || mode !== 'active' || actionBusy) return;
    const current = viewer.begin();
    revokeVideoStream();
    selected = item;
    error = '';
    if (!item.mimeType.startsWith('video/')) return;
    videoLoading = true;
    try {
      const stream = await vaultApi.openMediaStream(item.id);
      if (!current()) {
        void vaultApi.closeMediaStream(stream.token).catch(() => undefined);
        return;
      }
      videoToken = stream.token;
      videoUrl = stream.url;
    } catch (cause) {
      if (current()) error = `Unable to open encrypted video: ${String(cause)}`;
    } finally {
      if (current()) videoLoading = false;
    }
  }

  async function mutate(operation: () => Promise<unknown>, message: string, warning?: string) {
    if (destroyed || actionBusy || reauthBusy) return;
    const current = actions.begin();
    actionBusy = true;
    error = '';
    try {
      if (warning) {
        const approved = await confirm(warning, { title: 'Confirm encrypted media action', kind: 'warning' });
        if (!current() || !approved) return;
      }
      await operation();
      if (!current()) return;
      closeViewer();
      await refresh();
      if (current()) notice = message;
    } catch (cause) {
      if (current()) {
        reauthReady = false;
        error = String(cause);
      }
    } finally {
      if (current()) actionBusy = false;
    }
  }

  async function removeSelected() {
    const id = selected?.id;
    if (!id) return;
    await mutate(() => vaultApi.deleteMedia(id), 'Encrypted media moved to Trash.',
      'Move this encrypted media item to Trash? It remains encrypted and can be restored later.');
  }

  async function restore(item: GalleryTrashItem) {
    await mutate(() => vaultApi.restoreMedia(item.id), 'Encrypted media restored to the Gallery Vault.');
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

  async function purge(item: GalleryTrashItem) {
    if (!reauthReady) { error = 'Confirm your master password before permanently deleting media.'; return; }
    await mutate(() => vaultApi.purgeMedia(item.id), 'Encrypted media permanently deleted.',
      'Permanently delete this encrypted media item from Trash? This cannot be undone.');
  }

  async function emptyTrash() {
    if (!reauthReady) { error = 'Confirm your master password before emptying media Trash.'; return; }
    await mutate(() => vaultApi.emptyMediaTrash(), 'Encrypted media Trash emptied.',
      'Permanently delete every encrypted media item currently in Trash? This cannot be undone.');
    reauthReady = false;
  }

  function closeViewer() {
    viewer.invalidate();
    revokeVideoStream();
    selected = null;
  }

  onMount(() => { void loadMore(); });
  onDestroy(() => {
    destroyed = true;
    pages.dispose();
    viewer.dispose();
    actions.dispose();
    imports.dispose();
    revokeVideoStream();
    selected = null;
    items = [];
    trashItems = [];
    reauthPassword = '';
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h2 class="text-2xl font-semibold tracking-tight">Gallery Vault</h2>
      <p class="text-sm text-muted-foreground">Encrypted originals with separately encrypted image thumbnails and recoverable Trash.</p>
    </div>
    <div class="flex flex-wrap gap-2">
      <div class="flex rounded-md border border-border p-1">
        <button disabled={actionBusy || importing} class={`rounded px-3 py-1.5 text-sm ${mode === 'active' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'}`} on:click={() => switchMode('active')}>Vault</button>
        <button disabled={actionBusy || importing} class={`rounded px-3 py-1.5 text-sm ${mode === 'trash' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'}`} on:click={() => switchMode('trash')}>Trash</button>
      </div>
      <Button variant="secondary" size="sm" on:click={refresh} disabled={loading || actionBusy}>
        <RefreshCw size={16} class={loading ? 'animate-spin' : ''} /> Refresh
      </Button>
      {#if mode === 'active'}
        <Button size="sm" on:click={importFiles} disabled={importing || $pendingMediaSelection.selecting || Boolean($pendingMediaSelection.value)}>
          {#if importing || $pendingMediaSelection.selecting}<LoaderCircle size={16} class="animate-spin" />{:else}<Plus size={16} />{/if} Import media
        </Button>
      {/if}
    </div>
  </header>

  {#if $pendingMediaSelection.value && !importing}
    <div class="space-y-2 rounded-lg border border-primary/30 bg-primary/10 p-3">
      <p class="text-sm">{$pendingMediaSelection.value.length} selected files {$pendingMediaSelection.processing ? 'are being imported' : 'are ready'}. A system picker may lock the vault; resume after unlocking.</p>
      <div class="flex gap-2"><Button size="sm" on:click={importPending} disabled={$pendingMediaSelection.processing}>Resume selected import</Button><Button variant="ghost" size="sm" on:click={() => pendingMediaSelection.clear()} disabled={$pendingMediaSelection.processing}>Discard selection</Button></div>
    </div>
  {/if}
  {#if notice}<div role="status" class="flex items-start gap-2 rounded-lg border border-primary/30 bg-primary/10 px-4 py-3 text-sm"><CheckCircle2 size={17} class="mt-0.5 shrink-0 text-primary" /><span>{notice}</span></div>{/if}
  {#if error || $pendingMediaSelection.error}<div role="alert" class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error || $pendingMediaSelection.error}</div>{/if}

  {#if mode === 'active'}
    <div class="min-h-0 flex-1">{#key galleryRevision}<VirtualGallery {items} onOpen={openItem} onNearEnd={loadMore} />{/key}</div>
  {:else}
    <div class="space-y-3 rounded-xl border border-border bg-card p-4">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div><div class="font-medium">Encrypted media Trash</div><p class="text-xs text-muted-foreground">Deleted media stays encrypted and recoverable. Permanent deletion requires recent master-password confirmation.</p></div>
        <div class="flex flex-col gap-2 sm:flex-row">
          <Input type="password" bind:value={reauthPassword} autocomplete="current-password" placeholder="Master password" disabled={reauthBusy || actionBusy} />
          <Button variant="secondary" on:click={confirmSensitiveActions} disabled={reauthBusy || actionBusy || reauthPassword.length < 12}><ShieldCheck size={16} /> {reauthReady ? 'Confirmed' : 'Confirm sensitive actions'}</Button>
          <Button variant="destructive" on:click={emptyTrash} disabled={actionBusy || !reauthReady || trashItems.length === 0}><Trash2 size={16} /> Empty Trash</Button>
        </div>
      </div>
      <p class="text-xs text-muted-foreground">Confirmation is enforced in Rust and expires automatically even if this screen still appears confirmed.</p>
    </div>
    <div class="min-h-0 flex-1 overflow-auto rounded-xl border border-border">
      {#if trashItems.length === 0 && !loading}<div class="p-8 text-center text-sm text-muted-foreground">Media Trash is empty.</div>{/if}
      <div class="divide-y divide-border">
        {#each trashItems as item (item.id)}
          <div class="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div class="min-w-0"><div class="font-medium">{item.mimeType.startsWith('video/') ? 'Encrypted video' : 'Encrypted image'}</div>
              <div class="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground"><span>{item.mimeType}</span><span>{(item.fileSizeBytes / 1024 / 1024).toFixed(2)} MB</span><span>Added {new Date(item.timestampAdded * 1000).toLocaleString()}</span><span>Deleted {new Date(item.deletedAt * 1000).toLocaleString()}</span></div>
            </div>
            <div class="flex gap-2"><Button variant="secondary" size="sm" on:click={() => restore(item)} disabled={actionBusy}><RefreshCw size={15} /> Restore</Button><Button variant="destructive" size="sm" on:click={() => purge(item)} disabled={actionBusy || !reauthReady}><Trash2 size={15} /> Delete permanently</Button></div>
          </div>
        {/each}
      </div>
    </div>
  {/if}
  {#if loading}<div role="status" class="flex items-center justify-center gap-2 pb-2 text-sm text-muted-foreground"><LoaderCircle size={16} class="animate-spin" /> Loading encrypted items...</div>
  {:else if hasMore}<div class="text-center"><Button variant="secondary" size="sm" on:click={loadMore} disabled={actionBusy}>{error ? 'Retry loading' : 'Load more'}</Button></div>{/if}
</section>

{#if selected}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-3 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Encrypted media viewer">
    <div class="relative flex h-full max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl">
      <div class="flex items-center justify-between border-b border-border px-4 py-3">
        <div class="text-sm text-muted-foreground">{selected.mimeType} - {(selected.fileSizeBytes / 1024 / 1024).toFixed(2)} MB</div>
        <div class="flex gap-2"><Button variant="destructive" size="sm" on:click={removeSelected} disabled={actionBusy}><Trash2 size={16} /> Move to Trash</Button><Button variant="ghost" size="icon" on:click={closeViewer} aria-label="Close"><X size={19} /></Button></div>
      </div>
      {#if error}<div role="alert" class="p-3 text-sm text-destructive">{error}</div>{/if}
      <div class="flex min-h-0 flex-1 items-center justify-center bg-black p-2">
        {#if selected.mimeType.startsWith('video/')}
          {#if videoLoading}<div class="flex items-center gap-2 text-sm text-white/70"><LoaderCircle size={18} class="animate-spin" /> Preparing encrypted video stream...</div>
          {:else if videoUrl}<video src={videoUrl} controls autoplay playsinline preload="metadata" class="max-h-full max-w-full"></video>
          {:else}<div class="text-sm text-white/70">Unable to load this encrypted video.</div>{/if}
        {:else}<img src={mediaUrl(selected.id)} alt="Selected encrypted media" class="max-h-full max-w-full object-contain" />{/if}
      </div>
    </div>
  </div>
{/if}
