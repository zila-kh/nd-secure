<script lang="ts">
  import { Film, ImageOff, LockKeyhole } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { thumbnailUrl } from '../api';
  import type { GalleryItem } from '../types';

  export let items: GalleryItem[] = [];
  export let onOpen: (item: GalleryItem) => void;
  export let onNearEnd: () => void;

  let viewport: HTMLDivElement;
  let width = 800;
  let height = 600;
  let scrollTop = 0;
  let failed = new Set<string>();
  let observer: ResizeObserver | undefined;
  let lastRequestedLength = -1;

  const gap = 12;
  const minCardWidth = 148;
  const rowHeight = 190;
  const overscanRows = 2;

  $: columns = Math.max(2, Math.floor((width + gap) / (minCardWidth + gap)));
  $: cardWidth = Math.max(120, (width - gap * (columns - 1)) / columns);
  $: rowCount = Math.ceil(items.length / columns);
  $: totalHeight = rowCount * rowHeight;
  $: startRow = Math.max(0, Math.floor(scrollTop / rowHeight) - overscanRows);
  $: endRow = Math.min(rowCount, Math.ceil((scrollTop + height) / rowHeight) + overscanRows);
  $: startIndex = startRow * columns;
  $: if (items.length < lastRequestedLength) lastRequestedLength = -1;
  $: visibleItems = items
    .slice(startIndex, Math.min(items.length, endRow * columns))
    .map((item, index) => ({ item, absoluteIndex: startIndex + index }));
  $: if (items.length > 0 && endRow >= rowCount - 2 && lastRequestedLength !== items.length) {
    lastRequestedLength = items.length;
    queueMicrotask(onNearEnd);
  }

  function measure() {
    if (!viewport) return;
    width = viewport.clientWidth;
    height = viewport.clientHeight;
  }

  function onScroll() {
    scrollTop = viewport.scrollTop;
  }

  function markFailed(id: string) {
    failed = new Set(failed).add(id);
  }

  function position(absoluteIndex: number) {
    const row = Math.floor(absoluteIndex / columns);
    const column = absoluteIndex % columns;
    return {
      top: row * rowHeight,
      left: column * (cardWidth + gap)
    };
  }

  onMount(() => {
    observer = new ResizeObserver(measure);
    observer.observe(viewport);
    measure();
  });

  onDestroy(() => observer?.disconnect());
</script>

<div
  class="relative h-full min-h-[420px] overflow-auto pr-1"
  bind:this={viewport}
  on:scroll={onScroll}
  aria-label="Encrypted gallery"
>
  <div class="relative" style={`height:${totalHeight}px`}>
    {#each visibleItems as entry (entry.item.id)}
      {@const pos = position(entry.absoluteIndex)}
      <button
        class="absolute overflow-hidden rounded-xl border border-border bg-card text-left shadow-sm transition-transform hover:scale-[1.015] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        style={`top:${pos.top}px;left:${pos.left}px;width:${cardWidth}px;height:${rowHeight - gap}px`}
        on:click={() => onOpen(entry.item)}
        aria-label={`Open ${entry.item.mimeType.startsWith('video/') ? 'video' : 'image'}`}
      >
        <div class="flex h-[138px] items-center justify-center overflow-hidden bg-muted">
          {#if entry.item.mimeType.startsWith('video/')}
            <div class="flex flex-col items-center gap-2 text-muted-foreground">
              <Film size={30} />
              <span class="text-xs">Encrypted video</span>
            </div>
          {:else if failed.has(entry.item.id)}
            <div class="flex flex-col items-center gap-2 text-muted-foreground">
              <ImageOff size={28} />
              <span class="text-xs">Preview unavailable</span>
            </div>
          {:else}
            <img
              src={thumbnailUrl(entry.item.id)}
              alt="Encrypted gallery thumbnail"
              loading="lazy"
              decoding="async"
              class="h-full w-full object-cover"
              on:error={() => markFailed(entry.item.id)}
            />
          {/if}
        </div>
        <div class="flex items-center justify-between px-3 py-2 text-xs text-muted-foreground">
          <span>{new Date(entry.item.timestampAdded * 1000).toLocaleDateString()}</span>
          <span>{(entry.item.fileSizeBytes / 1024 / 1024).toFixed(1)} MB</span>
        </div>
      </button>
    {/each}
  </div>

  {#if items.length === 0}
    <div class="absolute inset-0 flex flex-col items-center justify-center gap-3 text-center text-muted-foreground">
      <LockKeyhole size={38} />
      <div>
        <p class="font-medium text-foreground">Your gallery is empty</p>
        <p class="text-sm">Import JPEG, PNG, MP4, or WebM media.</p>
      </div>
    </div>
  {/if}
</div>
