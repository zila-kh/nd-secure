<script lang="ts">
  export let type: 'button' | 'submit' | 'reset' = 'button';
  export let variant: 'default' | 'secondary' | 'ghost' | 'destructive' = 'default';
  export let size: 'default' | 'sm' | 'icon' = 'default';
  export let disabled = false;
  export let className = '';

  const variants = {
    default: 'bg-primary text-primary-foreground hover:opacity-90',
    secondary: 'bg-secondary text-secondary-foreground hover:bg-accent',
    ghost: 'bg-transparent hover:bg-accent hover:text-accent-foreground',
    destructive: 'bg-destructive text-destructive-foreground hover:opacity-90'
  };

  const sizes = {
    default: 'h-10 px-4 py-2',
    sm: 'h-9 rounded-md px-3',
    icon: 'h-10 w-10'
  };
</script>

<button
  {...$$restProps}
  {type}
  {disabled}
  class={`inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 ${variants[variant]} ${sizes[size]} ${className}`}
  on:click
>
  <slot />
</button>
