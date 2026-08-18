<script lang="ts">
  export let className = '';
</script>

<div class={`rounded-xl border border-border bg-card text-card-foreground shadow-sm ${className}`}>
  <slot />
</div>
