<script lang="ts">
  import { Images, KeyRound, LoaderCircle, Lock, Settings, ShieldCheck } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { vaultApi } from './lib/api';
  import GalleryView from './lib/components/GalleryView.svelte';
  import PasswordView from './lib/components/PasswordView.svelte';
  import SettingsView from './lib/components/SettingsView.svelte';
  import UnlockScreen from './lib/components/UnlockScreen.svelte';
  import Button from './lib/components/ui/Button.svelte';
  import type { SessionStatus, VaultView } from './lib/types';

  let status: SessionStatus = {
    initialized: false,
    locked: true,
    autoLockSeconds: 300,
    deleteSourceAfterImport: false,
    lockOnBlur: false,
    lockOnSuspend: true,
    clipboardTimeoutSeconds: 30,
    recoveryConfigured: false,
    recentlyReauthenticated: false
  };
  let view: VaultView = 'gallery';
  let loading = true;
  let busy = false;
  let error = '';
  let statusTimer: ReturnType<typeof setInterval> | undefined;

  const navigation = [
    { id: 'gallery' as const, label: 'Gallery', icon: Images },
    { id: 'passwords' as const, label: 'Passwords', icon: KeyRound },
    { id: 'settings' as const, label: 'Settings', icon: Settings }
  ];

  async function refreshStatus() {
    try {
      status = await vaultApi.status();
      error = '';
    } catch (cause) {
      error = String(cause);
    } finally {
      loading = false;
    }
  }

  async function submitPassword(password: string) {
    busy = true;
    error = '';
    try {
      status = status.initialized
        ? await vaultApi.unlock(password)
        : await vaultApi.initialize(password, status.autoLockSeconds);
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function recoverVault(recoveryKey: string, newPassword: string) {
    busy = true;
    error = '';
    try {
      status = await vaultApi.recover(recoveryKey, newPassword);
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function lock() {
    try {
      status = await vaultApi.lock();
      view = 'gallery';
    } catch (cause) {
      error = String(cause);
    }
  }

  function visibilityChanged() {
    if (
      document.visibilityState === 'hidden'
      && /Android/i.test(navigator.userAgent)
      && status.lockOnSuspend
      && !status.locked
    ) {
      void lock();
    }
  }

  onMount(() => {
    void refreshStatus();
    statusTimer = setInterval(refreshStatus, 5000);
    document.addEventListener('visibilitychange', visibilityChanged);
  });

  onDestroy(() => {
    if (statusTimer) clearInterval(statusTimer);
    document.removeEventListener('visibilitychange', visibilityChanged);
  });
</script>

{#if loading}
  <main class="flex min-h-screen items-center justify-center">
    <div class="flex items-center gap-3 text-muted-foreground"><LoaderCircle class="animate-spin" /> Loading encrypted vault…</div>
  </main>
{:else if status.locked}
  <UnlockScreen
    {busy}
    {error}
    initialized={status.initialized}
    recoveryConfigured={status.recoveryConfigured}
    onSubmit={submitPassword}
    onRecover={recoverVault}
  />
{:else}
  <div class="flex h-screen min-h-0 overflow-hidden">
    <aside class="hidden w-64 shrink-0 flex-col border-r border-border bg-card/90 p-4 backdrop-blur md:flex">
      <div class="mb-7 flex items-center gap-3 px-2 py-2">
        <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-primary-foreground">
          <ShieldCheck size={22} />
        </div>
        <div>
          <div class="font-semibold">ND Secure</div>
          <div class="text-xs text-muted-foreground">Local encrypted vault</div>
        </div>
      </div>

      <nav class="space-y-1">
        {#each navigation as item}
          <button
            class={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${view === item.id ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent hover:text-foreground'}`}
            on:click={() => (view = item.id)}
          >
            <svelte:component this={item.icon} size={18} />
            {item.label}
          </button>
        {/each}
      </nav>

      <div class="mt-auto">
        <Button variant="secondary" className="w-full" on:click={lock}><Lock size={17} /> Lock vault</Button>
      </div>
    </aside>

    <main class="safe-area min-w-0 flex-1 overflow-hidden pb-20 md:pb-4">
      {#if view === 'gallery'}
        <GalleryView />
      {:else if view === 'passwords'}
        <PasswordView />
      {:else}
        <SettingsView {status} onStatus={(next) => (status = next)} />
      {/if}
    </main>

    <nav class="fixed inset-x-0 bottom-0 z-40 flex items-center justify-around border-t border-border bg-card/95 px-2 pb-[env(safe-area-inset-bottom)] backdrop-blur md:hidden">
      {#each navigation as item}
        <button
          class={`flex min-w-[72px] flex-col items-center gap-1 px-3 py-2 text-xs ${view === item.id ? 'text-primary' : 'text-muted-foreground'}`}
          on:click={() => (view = item.id)}
        >
          <svelte:component this={item.icon} size={20} />
          {item.label}
        </button>
      {/each}
      <button class="flex min-w-[72px] flex-col items-center gap-1 px-3 py-2 text-xs text-muted-foreground" on:click={lock}>
        <Lock size={20} /> Lock
      </button>
    </nav>
  </div>
{/if}
