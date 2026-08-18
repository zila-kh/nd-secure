<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  export let type: HTMLInputAttributes['type'] = 'text';
  export let value: string | number = '';
  export let placeholder = '';
  export let autocomplete: HTMLInputAttributes['autocomplete'] = 'off';
  export let disabled = false;
  export let required = false;
  export let minlength: number | undefined = undefined;
  export let className = '';
</script>

<input
  {type}
  bind:value
  {placeholder}
  {autocomplete}
  {disabled}
  {required}
  {minlength}
  class={`flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
  on:input
  on:change
  on:keydown
/>
