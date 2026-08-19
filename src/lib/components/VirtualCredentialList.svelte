<script lang="ts">
  import { FileText, KeyRound, Star } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import type { CredentialSummary } from '../types';

  export let items: CredentialSummary[] = [];
  export let onOpen: (item: CredentialSummary) => void;
  export let onNearEnd: () => void;

  let viewport: HTMLDivElement;
  let height = 500;
  let scrollTop = 0;
  let observer: ResizeObserver | undefined;
  let lastRequestedLength = -1;

  const rowHeight = 72;
  const overscanRows = 5;

  $: rowCount = items.length;
  $: totalHeight = rowCount * rowHeight;
  $: startRow = Math.max(0, Math.floor(scrollTop / rowHeight) - overscanRows);
  $: endRow = Math.min(rowCount, Math.ceil((scrollTop + height) / rowHeight) + overscanRows);
  $: visibleItems = items.slice(startRow, endRow).map((item, index) => ({
    item,
    absoluteIndex: startRow + index
  }));
  $: if (items.length < lastRequestedLength) lastRequestedLength = -1;
  $: if (items.length > 0 && endRow >= rowCount - 10 && lastRequestedLength !== items.length) {
    lastRequestedLength = items.length;
    queueMicrotask(onNearEnd);
  }

  function measure() {
    if (viewport) height = viewport.clientHeight;
  }

  function onScroll() {
    scrollTop = viewport.scrollTop;
  }

  onMount(() => {
    observer = new ResizeObserver(measure);
    observer.observe(viewport);
    measure();
  });

  onDestroy(() => observer?.disconnect());
</script>

<div
  bind:this={viewport}
  on:scroll={onScroll}
  class="relative h-full min-h-[300px] overflow-auto rounded-xl border border-border bg-card"
  aria-label="Password vault items"
>
  <div class="relative" style={`height:${totalHeight}px`}>
    {#each visibleItems as entry (entry.item.id)}
      {@const Icon = entry.item.recordType === 'secure_note' ? FileText : KeyRound}
      <button
        class="absolute left-0 flex w-full items-center gap-3 border-b border-border px-4 text-left transition-colors hover:bg-accent focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
        style={`top:${entry.absoluteIndex * rowHeight}px;height:${rowHeight}px`}
        on:click={() => onOpen(entry.item)}
      >
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
          <svelte:component this={Icon} size={19} />
        </div>
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="truncate font-medium">{entry.item.title}</span>
            {#if entry.item.favorite}<Star size={14} class="shrink-0" fill="currentColor" />{/if}
          </div>
          <div class="truncate text-xs text-muted-foreground">
            {entry.item.username || entry.item.recordType.replace('_', ' ')}
          </div>
        </div>
        <time class="hidden text-xs text-muted-foreground sm:block">
          {new Date(entry.item.updatedAt * 1000).toLocaleDateString()}
        </time>
      </button>
    {/each}
  </div>

  {#if items.length === 0}
    <div class="absolute inset-0 flex flex-col items-center justify-center gap-3 text-center text-muted-foreground">
      <KeyRound size={38} />
      <div>
        <p class="font-medium text-foreground">No password items</p>
        <p class="text-sm">Create a login, secure note, or TOTP item.</p>
      </div>
    </div>
  {/if}
</div>
