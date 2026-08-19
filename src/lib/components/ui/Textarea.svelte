<script lang="ts">
  export let value = '';
  export let placeholder = '';
  export let rows = 4;
  export let disabled = false;
  export let className = '';
</script>

<textarea
  bind:value
  {placeholder}
  {rows}
  {disabled}
  class={`flex w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
  on:input
  on:change
></textarea>
