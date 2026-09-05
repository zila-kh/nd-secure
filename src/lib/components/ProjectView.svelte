<script lang="ts">
  import { open } from '@tauri-apps/plugin-dialog';
  import {
    AlertTriangle,
    CheckCircle2,
    FileCode2,
    FolderOpen,
    KeyRound,
    LoaderCircle,
    Play,
    RefreshCw,
    ShieldCheck,
    Trash2,
    XCircle
  } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type {
    ProjectEnvironmentStatus,
    ProjectInspection,
    ProjectRegistration
  } from '../types';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import Textarea from './ui/Textarea.svelte';

  let projects: ProjectRegistration[] = [];
  let selectedProjectId = '';
  let selectedEnvironment = '';
  let environmentStatus: ProjectEnvironmentStatus | null = null;
  let inspection: ProjectInspection | null = null;
  let registrationName = '';
  let registrationEnvironments = 'dev,test,uat,prod';
  let program = 'npm';
  let argumentsText = 'run\ndev';
  let reauthPassword = '';
  let loading = true;
  let busy = false;
  let statusBusy = false;
  let importingFile = '';
  let error = '';
  let notice = '';

  $: selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null;
  $: presentKeys = new Set(environmentStatus?.presentKeys ?? []);

  async function loadProjects(preferredId?: string) {
    try {
      projects = await vaultApi.projectList();
      const nextId = preferredId && projects.some((project) => project.id === preferredId)
        ? preferredId
        : selectedProjectId && projects.some((project) => project.id === selectedProjectId)
          ? selectedProjectId
          : projects[0]?.id ?? '';
      await chooseProject(nextId);
      error = '';
    } catch (cause) {
      error = String(cause);
    } finally {
      loading = false;
    }
  }

  async function chooseProject(id: string) {
    selectedProjectId = id;
    environmentStatus = null;
    const project = projects.find((item) => item.id === id);
    selectedEnvironment = project?.environments[0] ?? '';
    if (project && selectedEnvironment) {
      await refreshEnvironmentStatus();
    }
  }

  async function environmentChanged() {
    environmentStatus = null;
    await refreshEnvironmentStatus();
  }

  async function chooseProjectDirectory() {
    error = '';
    notice = '';
    const selected = await open({ directory: true, multiple: false, title: 'Register project with ND Secure' });
    if (!selected || Array.isArray(selected)) return;
    busy = true;
    try {
      inspection = await vaultApi.inspectProject(selected);
      registrationName = inspection.suggestedName;
    } catch (cause) {
      error = String(cause);
      inspection = null;
    } finally {
      busy = false;
    }
  }

  async function registerProject() {
    if (!inspection) return;
    const environments = registrationEnvironments
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    if (!registrationName.trim() || environments.length === 0) return;
    busy = true;
    error = '';
    notice = '';
    try {
      const registered = await vaultApi.registerProject(
        inspection.root,
        registrationName.trim(),
        environments
      );
      inspection = null;
      registrationName = '';
      registrationEnvironments = 'dev,test,uat,prod';
      notice = `Registered ${registered.name}. ND Secure wrote only safe metadata to the project.`;
      await loadProjects(registered.id);
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function refreshEnvironmentStatus() {
    if (!selectedProjectId || !selectedEnvironment || statusBusy) return;
    statusBusy = true;
    try {
      environmentStatus = await vaultApi.projectEnvironmentStatus(
        selectedProjectId,
        selectedEnvironment
      );
      error = '';
    } catch (cause) {
      error = String(cause);
    } finally {
      statusBusy = false;
    }
  }

  async function syncProject() {
    if (!selectedProjectId) return;
    busy = true;
    error = '';
    notice = '';
    try {
      const synced = await vaultApi.syncProject(selectedProjectId);
      notice = `Synced ${synced.requiredKeys.length} key names from .env.example.`;
      await loadProjects(synced.id);
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function importPlaintextEnv(fileName: string) {
    if (!selectedProjectId || !selectedEnvironment || importingFile) return;
    importingFile = fileName;
    error = '';
    notice = '';
    try {
      const result = await vaultApi.importProjectEnv(
        selectedProjectId,
        selectedEnvironment,
        fileName
      );
      const removal = result.sourceRemoved
        ? 'The plaintext source file was removed.'
        : 'The plaintext source file could not be removed; remove it manually now.';
      notice = `Encrypted ${result.importedKeys.length} new secrets in ND Secure. ${removal} Rotate imported credentials if the old file may have been exposed.`;
      await loadProjects(selectedProjectId);
    } catch (cause) {
      error = String(cause);
    } finally {
      importingFile = '';
    }
  }

  async function launchCommand() {
    if (!selectedProjectId || !selectedEnvironment || !program.trim() || !reauthPassword) return;
    busy = true;
    error = '';
    notice = '';
    const password = reauthPassword;
    reauthPassword = '';
    try {
      await vaultApi.reauthenticate(password);
      const args = argumentsText
        .split('\n')
        .map((value) => value.trim())
        .filter(Boolean);
      const result = await vaultApi.runProjectCommand(
        selectedProjectId,
        selectedEnvironment,
        program.trim(),
        args
      );
      notice = `Started PID ${result.pid} with ${result.injectedKeys.length} secrets injected only into its process environment.`;
    } catch (cause) {
      error = String(cause);
    } finally {
      reauthPassword = '';
      busy = false;
    }
  }

  async function removeProject() {
    if (!selectedProject || !confirm(`Deregister ${selectedProject.name} from ND Secure? Encrypted credentials are not deleted.`)) {
      return;
    }
    busy = true;
    error = '';
    notice = '';
    try {
      await vaultApi.deleteProject(selectedProject.id);
      notice = 'Project registration removed. Its encrypted credentials remain in the vault.';
      selectedProjectId = '';
      selectedEnvironment = '';
      environmentStatus = null;
      await loadProjects();
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void loadProjects();
  });

  onDestroy(() => {
    reauthPassword = '';
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4 overflow-auto">
  <header class="flex flex-wrap items-start justify-between gap-3">
    <div>
      <h2 class="text-2xl font-semibold tracking-tight">Secure Projects</h2>
      <p class="mt-1 max-w-3xl text-sm text-muted-foreground">
        Keep real environment values in ND Secure. Projects retain only safe key names in <code>.env.example</code>.
      </p>
    </div>
    <Button size="sm" on:click={chooseProjectDirectory} disabled={busy}>
      {#if busy}<LoaderCircle size={16} class="animate-spin" />{:else}<FolderOpen size={16} />{/if}
      Register project
    </Button>
  </header>

  <div class="rounded-xl border border-border bg-card p-4">
    <div class="flex gap-3">
      <ShieldCheck class="mt-0.5 shrink-0 text-primary" size={20} />
      <div class="space-y-1 text-sm">
        <p class="font-medium">No plaintext secret file is required.</p>
        <p class="text-muted-foreground">
          ND Secure adds ignore rules for <code>.env</code> files and stores project registration data encrypted.
          AI tools that only scan the repository can see variable names, not values. Runtime injection is still visible
          to processes with sufficient access under the same operating-system account.
        </p>
      </div>
    </div>
  </div>

  {#if error}
    <div class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
  {/if}
  {#if notice}
    <div class="rounded-lg border border-primary/30 bg-primary/10 px-4 py-3 text-sm">{notice}</div>
  {/if}

  {#if inspection}
    <div class="rounded-xl border border-primary/30 bg-card p-5 shadow-sm">
      <div class="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 class="font-semibold">Register this project</h3>
          <p class="mt-1 break-all text-xs text-muted-foreground">{inspection.root}</p>
        </div>
        <Button variant="ghost" size="sm" on:click={() => (inspection = null)}>Cancel</Button>
      </div>
      <div class="grid gap-4 md:grid-cols-2">
        <label class="space-y-2">
          <span class="text-sm font-medium">Project name</span>
          <Input bind:value={registrationName} placeholder="todo" />
        </label>
        <label class="space-y-2">
          <span class="text-sm font-medium">Environments</span>
          <Input bind:value={registrationEnvironments} placeholder="dev,test,uat,prod" />
          <span class="block text-xs text-muted-foreground">Comma-separated. Custom environment names are supported.</span>
        </label>
      </div>
      <div class="mt-4 grid gap-3 md:grid-cols-2">
        <div class="rounded-lg border border-border p-3 text-sm">
          <div class="font-medium">.env.example</div>
          <div class="mt-1 text-muted-foreground">
            {inspection.exampleExists ? `${inspection.requiredKeys.length} key names detected` : 'Not found yet; ND Secure can create it during migration'}
          </div>
        </div>
        <div class="rounded-lg border border-border p-3 text-sm">
          <div class="font-medium">Plaintext environment files</div>
          <div class="mt-1 text-muted-foreground">
            {inspection.plaintextEnvFiles.length > 0 ? inspection.plaintextEnvFiles.join(', ') : 'None detected'}
          </div>
        </div>
      </div>
      <div class="mt-4 flex justify-end">
        <Button on:click={registerProject} disabled={busy || !registrationName.trim()}>
          <ShieldCheck size={17} /> Register securely
        </Button>
      </div>
    </div>
  {/if}

  {#if loading}
    <div class="flex min-h-[240px] items-center justify-center gap-2 text-muted-foreground">
      <LoaderCircle size={18} class="animate-spin" /> Loading encrypted project registry…
    </div>
  {:else if projects.length === 0}
    <div class="flex min-h-[300px] flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border text-center">
      <FolderOpen size={40} class="text-muted-foreground" />
      <div>
        <p class="font-medium">No registered projects</p>
        <p class="mt-1 text-sm text-muted-foreground">Register a local project directory to replace plaintext .env files.</p>
      </div>
    </div>
  {:else}
    <div class="grid min-h-0 gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
      <aside class="rounded-xl border border-border bg-card p-3">
        <div class="mb-2 px-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Projects</div>
        <div class="space-y-1">
          {#each projects as project (project.id)}
            <button
              type="button"
              class={`w-full rounded-lg px-3 py-3 text-left transition-colors ${selectedProjectId === project.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'}`}
              on:click={() => chooseProject(project.id)}
            >
              <div class="truncate text-sm font-medium">{project.name}</div>
              <div class={`mt-1 truncate text-xs ${selectedProjectId === project.id ? 'text-primary-foreground/75' : 'text-muted-foreground'}`}>
                {project.environments.join(' · ')}
              </div>
            </button>
          {/each}
        </div>
      </aside>

      {#if selectedProject}
        <div class="min-w-0 space-y-4">
          <div class="rounded-xl border border-border bg-card p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div class="min-w-0">
                <h3 class="text-lg font-semibold">{selectedProject.name}</h3>
                <p class="mt-1 break-all text-xs text-muted-foreground">{selectedProject.root}</p>
                <p class="mt-2 text-xs text-muted-foreground">
                  Project ID <code>{selectedProject.id}</code> binds managed secrets so projects with the same name cannot share them accidentally.
                </p>
              </div>
              <div class="flex gap-2">
                <Button variant="secondary" size="sm" on:click={syncProject} disabled={busy}>
                  <RefreshCw size={15} /> Sync schema
                </Button>
                <Button variant="ghost" size="icon" on:click={removeProject} disabled={busy} aria-label="Deregister project">
                  <Trash2 size={17} />
                </Button>
              </div>
            </div>

            <div class="mt-5 flex flex-wrap items-end gap-3">
              <label class="min-w-[180px] space-y-2">
                <span class="text-sm font-medium">Environment</span>
                <select
                  bind:value={selectedEnvironment}
                  on:change={environmentChanged}
                  class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {#each selectedProject.environments as environment}
                    <option value={environment}>{environment}</option>
                  {/each}
                </select>
              </label>
              <Button variant="secondary" on:click={refreshEnvironmentStatus} disabled={statusBusy}>
                {#if statusBusy}<LoaderCircle size={16} class="animate-spin" />{:else}<RefreshCw size={16} />{/if}
                Check
              </Button>
            </div>
          </div>

          {#if environmentStatus}
            {#if environmentStatus.plaintextEnvFiles.length > 0}
              <div class="rounded-xl border border-amber-500/40 bg-amber-500/10 p-5">
                <div class="flex gap-3">
                  <AlertTriangle size={20} class="mt-0.5 shrink-0" />
                  <div class="min-w-0 flex-1">
                    <h3 class="font-semibold">Plaintext secrets detected</h3>
                    <p class="mt-1 text-sm text-muted-foreground">
                      Import a file into <strong>{selectedEnvironment}</strong>. ND Secure encrypts its values, updates only key names in .env.example, then removes the plaintext source when possible.
                    </p>
                    <div class="mt-4 flex flex-wrap gap-2">
                      {#each environmentStatus.plaintextEnvFiles as fileName}
                        <Button
                          variant="secondary"
                          size="sm"
                          on:click={() => importPlaintextEnv(fileName)}
                          disabled={Boolean(importingFile)}
                        >
                          {#if importingFile === fileName}<LoaderCircle size={15} class="animate-spin" />{:else}<KeyRound size={15} />{/if}
                          Encrypt + remove {fileName}
                        </Button>
                      {/each}
                    </div>
                    <p class="mt-3 text-xs text-muted-foreground">
                      Removing a file is not guaranteed secure erasure on SSDs or journaled file systems. Rotate migrated secrets if the plaintext file may already have been copied, indexed, backed up, or read by another tool.
                    </p>
                  </div>
                </div>
              </div>
            {/if}

            <div class="rounded-xl border border-border bg-card p-5">
              <div class="mb-4 flex items-center gap-2">
                <FileCode2 size={18} />
                <div>
                  <h3 class="font-semibold">Environment schema</h3>
                  <p class="text-xs text-muted-foreground">Names come from .env.example. Values never appear here.</p>
                </div>
              </div>
              {#if selectedProject.requiredKeys.length === 0}
                <div class="rounded-lg border border-dashed border-border p-5 text-sm text-muted-foreground">
                  No keys are registered. Add key names to .env.example and sync, or migrate an existing plaintext .env file.
                </div>
              {:else}
                <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {#each selectedProject.requiredKeys as key}
                    <div class="flex items-center justify-between gap-2 rounded-lg border border-border px-3 py-2.5">
                      <code class="min-w-0 truncate text-xs">{key}</code>
                      {#if presentKeys.has(key)}
                        <span class="flex shrink-0 items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                          <CheckCircle2 size={14} /> Present
                        </span>
                      {:else}
                        <span class="flex shrink-0 items-center gap-1 text-xs text-destructive">
                          <XCircle size={14} /> Missing
                        </span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
            </div>

            <div class="rounded-xl border border-border bg-card p-5">
              <div class="mb-4 flex items-center gap-2">
                <Play size={18} />
                <div>
                  <h3 class="font-semibold">Run with protected environment</h3>
                  <p class="text-xs text-muted-foreground">Desktop compatibility mode. ND Secure creates no .env file and invokes the executable directly, without a shell.</p>
                </div>
              </div>
              <div class="grid gap-4 md:grid-cols-2">
                <label class="space-y-2">
                  <span class="text-sm font-medium">Executable</span>
                  <Input bind:value={program} placeholder="npm" autocomplete="off" />
                </label>
                <label class="space-y-2">
                  <span class="text-sm font-medium">Master password confirmation</span>
                  <Input type="password" bind:value={reauthPassword} placeholder="Required before secret injection" autocomplete="current-password" />
                </label>
              </div>
              <label class="mt-4 block space-y-2">
                <span class="text-sm font-medium">Arguments — one argument per line</span>
                <Textarea bind:value={argumentsText} rows={4} placeholder={'run\ndev'} />
              </label>
              <div class="mt-4 flex flex-wrap items-center justify-between gap-3">
                <p class="max-w-2xl text-xs text-muted-foreground">
                  The child receives only an allowlisted baseline environment plus this project's exact environment secrets. No central or other-project secret is inherited.
                </p>
                <Button
                  on:click={launchCommand}
                  disabled={busy || !program.trim() || !reauthPassword || (environmentStatus?.missingKeys.length ?? 0) > 0}
                >
                  {#if busy}<LoaderCircle size={16} class="animate-spin" />{:else}<Play size={16} />{/if}
                  Reauthenticate & run
                </Button>
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</section>
