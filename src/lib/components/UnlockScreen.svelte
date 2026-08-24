<script lang="ts">
  import { KeyRound, LoaderCircle, LockKeyhole, ShieldCheck } from 'lucide-svelte';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';

  export let initialized = false;
  export let recoveryConfigured = false;
  export let busy = false;
  export let error = '';
  export let onSubmit: (password: string) => Promise<void>;
  export let onRecover: (recoveryKey: string, newPassword: string) => Promise<void>;

  let password = '';
  let confirmPassword = '';
  let recoveryMode = false;
  let recoveryKey = '';
  let recoveryPassword = '';
  let recoveryConfirmPassword = '';

  async function submit() {
    if (!initialized && password !== confirmPassword) return;
    await onSubmit(password);
    password = '';
    confirmPassword = '';
  }

  async function recover() {
    if (!recoveryConfigured || recoveryPassword !== recoveryConfirmPassword) return;
    await onRecover(recoveryKey.trim(), recoveryPassword);
    recoveryKey = '';
    recoveryPassword = '';
    recoveryConfirmPassword = '';
  }

  function switchMode() {
    recoveryMode = !recoveryMode;
    password = '';
    confirmPassword = '';
    recoveryKey = '';
    recoveryPassword = '';
    recoveryConfirmPassword = '';
  }
</script>

<main class="safe-area flex min-h-screen items-center justify-center p-4">
  <section class="animate-fadeIn w-full max-w-md rounded-2xl border border-border bg-card/95 p-7 shadow-2xl backdrop-blur">
    <div class="mb-6 flex items-center gap-4">
      <div class="flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-primary-foreground">
        <ShieldCheck size={26} />
      </div>
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">ND Secure</h1>
        <p class="text-sm text-muted-foreground">Gallery vault and password manager</p>
      </div>
    </div>

    <div class="mb-5 rounded-lg border border-border bg-muted/50 p-4 text-sm text-muted-foreground">
      <div class="mb-1 flex items-center gap-2 font-medium text-foreground">
        {#if recoveryMode}<KeyRound size={16} />{:else}<LockKeyhole size={16} />{/if}
        {recoveryMode ? 'Recover your vault' : initialized ? 'Unlock your vault' : 'Create your vault'}
      </div>
      {#if recoveryMode}
        Your offline recovery key unwraps the same vault root key, then immediately re-wraps it under a new master password. The recovery key itself is never stored.
      {:else if initialized}
        Your master password derives a key-encryption key locally. The wrapped vault root key remains inside Rust while the vault is unlocked.
      {:else}
        Choose a strong master password. You can create a one-time-view offline recovery key later from Security Settings.
      {/if}
    </div>

    {#if recoveryMode}
      <form on:submit|preventDefault={recover} class="space-y-4">
        <label class="block space-y-2">
          <span class="text-sm font-medium">Recovery key</span>
          <Input
            type="password"
            bind:value={recoveryKey}
            autocomplete="off"
            placeholder="NDSECURE-R1-…"
            required
          />
        </label>
        <label class="block space-y-2">
          <span class="text-sm font-medium">New master password</span>
          <Input
            type="password"
            bind:value={recoveryPassword}
            autocomplete="new-password"
            placeholder="At least 12 characters"
            minlength={12}
            required
          />
        </label>
        <label class="block space-y-2">
          <span class="text-sm font-medium">Confirm new password</span>
          <Input
            type="password"
            bind:value={recoveryConfirmPassword}
            autocomplete="new-password"
            placeholder="Repeat new master password"
            minlength={12}
            required
          />
        </label>
        {#if recoveryConfirmPassword && recoveryPassword !== recoveryConfirmPassword}
          <p class="text-sm text-destructive">Passwords do not match.</p>
        {/if}
        {#if error}
          <p class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</p>
        {/if}
        <Button
          type="submit"
          className="w-full"
          disabled={busy || !recoveryKey.trim() || recoveryPassword.length < 12 || recoveryPassword !== recoveryConfirmPassword}
        >
          {#if busy}<LoaderCircle class="animate-spin" size={17} />{/if}
          Recover and set new password
        </Button>
        <Button variant="ghost" type="button" className="w-full" on:click={switchMode} disabled={busy}>
          Back to master password
        </Button>
      </form>
    {:else}
      <form on:submit|preventDefault={submit} class="space-y-4">
        <label class="block space-y-2">
          <span class="text-sm font-medium">Master password</span>
          <Input
            type="password"
            bind:value={password}
            autocomplete={initialized ? 'current-password' : 'new-password'}
            placeholder="At least 12 characters"
            minlength={12}
            required
          />
        </label>

        {#if !initialized}
          <label class="block space-y-2">
            <span class="text-sm font-medium">Confirm password</span>
            <Input
              type="password"
              bind:value={confirmPassword}
              autocomplete="new-password"
              placeholder="Repeat master password"
              minlength={12}
              required
            />
          </label>
          {#if confirmPassword && password !== confirmPassword}
            <p class="text-sm text-destructive">Passwords do not match.</p>
          {/if}
        {/if}

        {#if error}
          <p class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</p>
        {/if}

        <Button
          type="submit"
          className="w-full"
          disabled={busy || password.length < 12 || (!initialized && password !== confirmPassword)}
        >
          {#if busy}<LoaderCircle class="animate-spin" size={17} />{/if}
          {initialized ? 'Unlock' : 'Create encrypted vault'}
        </Button>
        {#if initialized && recoveryConfigured}
          <Button variant="ghost" type="button" className="w-full" on:click={switchMode} disabled={busy}>
            Use offline recovery key
          </Button>
        {/if}
      </form>
    {/if}
  </section>
</main>
