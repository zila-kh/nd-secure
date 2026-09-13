<script lang="ts">
  import { confirm, open } from '@tauri-apps/plugin-dialog';
  import { AlertTriangle, CheckCircle2, FileCode2, FolderOpen, KeyRound, LoaderCircle, Play, RefreshCw, ShieldCheck, Trash2, XCircle } from 'lucide-svelte';
  import { onDestroy, onMount } from 'svelte';
  import { vaultApi } from '../api';
  import type { ProjectEnvironmentStatus, ProjectInspection, ProjectRegistration } from '../types';
  import { LatestRequest, pendingProjectSelection, snapshotProjectCommand } from '../workflow-state';
  import Button from './ui/Button.svelte';
  import Input from './ui/Input.svelte';
  import Textarea from './ui/Textarea.svelte';

  const projectLoads = new LatestRequest();
  const environmentLoads = new LatestRequest();
  const actions = new LatestRequest();
  const isAndroid = typeof navigator !== 'undefined' && /Android/i.test(navigator.userAgent);
  let destroyed = false;
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

  async function loadProjects(preferredId = selectedProjectId, preferredEnvironment = selectedEnvironment) {
    if (destroyed || isAndroid) return;
    const current = projectLoads.begin();
    loading = true;
    error = '';
    try {
      const next = await vaultApi.projectList();
      if (!current()) return;
      projects = next;
      const nextId = next.some((project) => project.id === preferredId) ? preferredId : next[0]?.id ?? '';
      await selectProject(nextId, preferredEnvironment);
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) loading = false;
    }
  }

  async function selectProject(id: string, preferredEnvironment = '') {
    if (destroyed) return;
    environmentLoads.invalidate();
    environmentStatus = null;
    statusBusy = false;
    selectedProjectId = id;
    const project = projects.find((item) => item.id === id);
    selectedEnvironment = project?.environments.includes(preferredEnvironment)
      ? preferredEnvironment : project?.environments[0] ?? '';
    await refreshEnvironmentStatus();
  }

  async function chooseProject(id: string) {
    if (destroyed || busy || importingFile) return;
    // A manual choice takes precedence over an older project-list refresh.
    projectLoads.invalidate();
    loading = false;
    await selectProject(id);
  }

  async function environmentChanged() {
    environmentStatus = null;
    await refreshEnvironmentStatus();
  }

  async function refreshEnvironmentStatus() {
    if (destroyed || !selectedProjectId || !selectedEnvironment) return;
    // Do not drop a new environment selection just because an old check is pending.
    const current = environmentLoads.begin();
    const id = selectedProjectId;
    const environment = selectedEnvironment;
    statusBusy = true;
    environmentStatus = null;
    error = '';
    try {
      const next = await vaultApi.projectEnvironmentStatus(id, environment);
      if (current()) environmentStatus = next;
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) statusBusy = false;
    }
  }

  async function chooseProjectDirectory() {
    if (destroyed || isAndroid || busy || importingFile) return;
    await pendingProjectSelection.choose(async () => {
      const selected = await open({ directory: true, multiple: false, title: 'Register project with ND Secure' });
      return typeof selected === 'string' ? selected : null;
    });
    if (!destroyed && pendingProjectSelection.current.value) await inspectSelectedDirectory();
  }

  async function inspectSelectedDirectory() {
    const root = pendingProjectSelection.current.value;
    if (destroyed || isAndroid || busy || importingFile || !root || pendingProjectSelection.current.processing) return;
    const current = actions.begin();
    busy = true;
    error = '';
    notice = '';
    try {
      const status = await vaultApi.status();
      if (!current()) return;
      if (status.locked) { notice = 'Unlock the vault, then resume the selected project.'; return; }
      const next = await vaultApi.inspectProject(root);
      if (!current()) return;
      inspection = next;
      registrationName = next.suggestedName;
    } catch (cause) {
      if (current()) { error = String(cause); inspection = null; }
    } finally {
      if (current()) busy = false;
    }
  }

  function cancelInspection() {
    if (busy) return;
    inspection = null;
    registrationName = '';
    pendingProjectSelection.clear();
  }

  async function registerProject() {
    if (destroyed || busy || importingFile || !inspection) return;
    const root = inspection.root;
    const selection = pendingProjectSelection.current.value;
    const environments = registrationEnvironments.split(',').map((value) => value.trim()).filter(Boolean);
    const name = registrationName.trim();
    if (!name || environments.length === 0) { error = 'Enter a project name and at least one environment.'; return; }
    if (selection !== null && !pendingProjectSelection.claim(selection)) return;
    const current = actions.begin();
    busy = true;
    error = '';
    notice = '';
    try {
      const registered = await vaultApi.registerProject(root, name, environments);
      if (selection !== null) pendingProjectSelection.consume(selection);
      if (!current()) return;
      inspection = null;
      registrationName = '';
      registrationEnvironments = 'dev,test,uat,prod';
      notice = `Registered ${registered.name}. ND Secure wrote only safe metadata to the project.`;
      await loadProjects(registered.id);
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (selection !== null) pendingProjectSelection.release(selection);
      if (current()) busy = false;
    }
  }

  async function syncProject() {
    if (destroyed || busy || importingFile || !selectedProjectId) return;
    const current = actions.begin();
    const id = selectedProjectId;
    const environment = selectedEnvironment;
    busy = true;
    error = '';
    notice = '';
    try {
      const synced = await vaultApi.syncProject(id);
      if (!current()) return;
      notice = `Synced ${synced.requiredKeys.length} key names from .env.example.`;
      await loadProjects(id, environment);
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) busy = false;
    }
  }

  async function importPlaintextEnv(fileName: string) {
    if (destroyed || busy || importingFile || !selectedProjectId || !selectedEnvironment) return;
    const current = actions.begin();
    const id = selectedProjectId;
    const environment = selectedEnvironment;
    importingFile = fileName;
    error = '';
    notice = '';
    try {
      const result = await vaultApi.importProjectEnv(id, environment, fileName);
      if (!current()) return;
      const removal = result.sourceRemoved
        ? 'The plaintext source file was removed.'
        : 'The plaintext source file could not be removed; remove it manually now.';
      notice = `Encrypted ${result.importedKeys.length} new secrets in ND Secure. ${removal} Rotate imported credentials if the old file may have been exposed.`;
      await loadProjects(id, environment);
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) importingFile = '';
    }
  }

  async function launchCommand() {
    if (destroyed || busy || importingFile || !selectedProjectId || !selectedEnvironment || !program.trim() || !reauthPassword) return;
    const current = actions.begin();
    const command = snapshotProjectCommand({ id: selectedProjectId, environment: selectedEnvironment, program, argumentsText });
    const password = reauthPassword;
    reauthPassword = '';
    busy = true;
    error = '';
    notice = '';
    try {
      await vaultApi.reauthenticate(password);
      if (!current()) return;
      const result = await vaultApi.runProjectCommand(command.id, command.environment, command.program, [...command.args]);
      if (current()) notice = `Started PID ${result.pid} with ${result.injectedKeys.length} secrets injected only into its process environment.`;
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) { reauthPassword = ''; busy = false; }
    }
  }

  async function removeProject() {
    const project = projects.find((item) => item.id === selectedProjectId);
    if (destroyed || busy || importingFile || !project) return;
    const current = actions.begin();
    busy = true;
    error = '';
    notice = '';
    try {
      const approved = await confirm(`Deregister ${project.name} from ND Secure? Encrypted credentials are not deleted.`,
        { title: 'Deregister project?', kind: 'warning' });
      if (!current() || !approved) return;
      await vaultApi.deleteProject(project.id);
      if (!current()) return;
      notice = 'Project registration removed. Its encrypted credentials remain in the vault.';
      await loadProjects('', '');
    } catch (cause) {
      if (current()) error = String(cause);
    } finally {
      if (current()) busy = false;
    }
  }

  onMount(() => {
    if (isAndroid) loading = false;
    else void loadProjects();
  });
  onDestroy(() => {
    destroyed = true;
    projectLoads.dispose();
    environmentLoads.dispose();
    actions.dispose();
    reauthPassword = '';
    projects = [];
    environmentStatus = null;
    inspection = null;
  });
</script>

<section class="animate-fadeIn flex h-full min-h-0 flex-col gap-4 overflow-auto">
  <header class="flex flex-wrap items-start justify-between gap-3">
    <div><h2 class="text-2xl font-semibold tracking-tight">Secure Projects</h2><p class="mt-1 max-w-3xl text-sm text-muted-foreground">Keep real environment values in ND Secure. Projects retain only safe key names in <code>.env.example</code>.</p></div>
    <Button size="sm" on:click={chooseProjectDirectory} disabled={isAndroid || busy || Boolean(importingFile) || $pendingProjectSelection.selecting || Boolean($pendingProjectSelection.value)}>
      {#if busy || $pendingProjectSelection.selecting}<LoaderCircle size={16} class="animate-spin" />{:else}<FolderOpen size={16} />{/if} Register project
    </Button>
  </header>
  {#if isAndroid}
    <div role="status" class="rounded-xl border border-border bg-card p-4 text-sm">Local project folders and process launching are desktop-only. Use ND Secure on Windows or macOS for this workflow. Encrypted credentials and media remain available on Android.</div>
  {/if}
  <div class="rounded-xl border border-border bg-card p-4"><div class="flex gap-3"><ShieldCheck class="mt-0.5 shrink-0 text-primary" size={20} /><div class="space-y-1 text-sm"><p class="font-medium">No plaintext secret file is required.</p><p class="text-muted-foreground">ND Secure adds ignore rules for <code>.env</code> files and stores project registration data encrypted. AI tools that only scan the repository can see variable names, not values. Runtime injection is still visible to processes with sufficient access under the same operating-system account.</p></div></div></div>
  {#if $pendingProjectSelection.value && !inspection && !busy}
    <div class="space-y-2 rounded-lg border border-primary/30 bg-primary/10 p-3"><p class="text-sm">A selected project is ready for inspection. Resume after unlocking if the system picker locked the vault.</p><div class="flex gap-2"><Button size="sm" on:click={inspectSelectedDirectory} disabled={$pendingProjectSelection.processing}>Resume selected project</Button><Button size="sm" variant="ghost" on:click={cancelInspection} disabled={$pendingProjectSelection.processing}>Discard selection</Button></div></div>
  {/if}
  {#if error || $pendingProjectSelection.error}<div role="alert" class="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error || $pendingProjectSelection.error}</div>{/if}
  {#if notice}<div role="status" class="rounded-lg border border-primary/30 bg-primary/10 px-4 py-3 text-sm">{notice}</div>{/if}

  {#if inspection}
    <div class="rounded-xl border border-primary/30 bg-card p-5 shadow-sm">
      <div class="mb-4 flex items-start justify-between gap-3"><div><h3 class="font-semibold">Register this project</h3><p class="mt-1 break-all text-xs text-muted-foreground">{inspection.root}</p></div><Button variant="ghost" size="sm" on:click={cancelInspection} disabled={busy}>Cancel</Button></div>
      <div class="grid gap-4 md:grid-cols-2">
        <label class="space-y-2"><span class="text-sm font-medium">Project name</span><Input bind:value={registrationName} placeholder="todo" disabled={busy} /></label>
        <label class="space-y-2"><span class="text-sm font-medium">Environments</span><Input bind:value={registrationEnvironments} placeholder="dev,test,uat,prod" disabled={busy} /><span class="block text-xs text-muted-foreground">Comma-separated. Custom environment names are supported.</span></label>
      </div>
      <div class="mt-4 grid gap-3 md:grid-cols-2">
        <div class="rounded-lg border border-border p-3 text-sm"><div class="font-medium">.env.example</div><div class="mt-1 text-muted-foreground">{inspection.exampleExists ? `${inspection.requiredKeys.length} key names detected` : 'Not found yet; ND Secure can create it during migration'}</div></div>
        <div class="rounded-lg border border-border p-3 text-sm"><div class="font-medium">Plaintext environment files</div><div class="mt-1 text-muted-foreground">{inspection.plaintextEnvFiles.length > 0 ? inspection.plaintextEnvFiles.join(', ') : 'None detected'}</div></div>
      </div>
      <div class="mt-4 flex justify-end"><Button on:click={registerProject} disabled={busy || !registrationName.trim()}><ShieldCheck size={17} /> Register securely</Button></div>
    </div>
  {/if}

  {#if loading}<div class="flex min-h-[240px] items-center justify-center gap-2 text-muted-foreground"><LoaderCircle size={18} class="animate-spin" /> Loading encrypted project registry...</div>
  {:else if projects.length === 0 && !isAndroid}
    <div class="flex min-h-[300px] flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border text-center"><FolderOpen size={40} class="text-muted-foreground" /><div><p class="font-medium">No registered projects</p><p class="mt-1 text-sm text-muted-foreground">Register a local project directory to replace plaintext .env files.</p></div><Button variant="secondary" size="sm" on:click={() => loadProjects()} disabled={busy}>Refresh projects</Button></div>
  {:else if projects.length > 0}
    <div class="grid min-h-0 gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
      <aside class="rounded-xl border border-border bg-card p-3"><div class="mb-2 px-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Projects</div><div class="space-y-1">
        {#each projects as project (project.id)}<button type="button" disabled={busy || Boolean(importingFile)} class={`w-full rounded-lg px-3 py-3 text-left transition-colors ${selectedProjectId === project.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'}`} on:click={() => chooseProject(project.id)}><div class="truncate text-sm font-medium">{project.name}</div><div class={`mt-1 truncate text-xs ${selectedProjectId === project.id ? 'text-primary-foreground/75' : 'text-muted-foreground'}`}>{project.environments.join(' / ')}</div></button>{/each}
      </div></aside>
      {#if selectedProject}
        <div class="min-w-0 space-y-4">
          <div class="rounded-xl border border-border bg-card p-5">
            <div class="flex flex-wrap items-start justify-between gap-3"><div class="min-w-0"><h3 class="text-lg font-semibold">{selectedProject.name}</h3><p class="mt-1 break-all text-xs text-muted-foreground">{selectedProject.root}</p><p class="mt-2 text-xs text-muted-foreground">Project ID <code>{selectedProject.id}</code> binds managed secrets so projects with the same name cannot share them accidentally.</p></div><div class="flex gap-2"><Button variant="secondary" size="sm" on:click={syncProject} disabled={busy || Boolean(importingFile)}><RefreshCw size={15} /> Sync schema</Button><Button variant="ghost" size="icon" on:click={removeProject} disabled={busy || Boolean(importingFile)} aria-label="Deregister project"><Trash2 size={17} /></Button></div></div>
            <div class="mt-5 flex flex-wrap items-end gap-3"><label class="min-w-[180px] space-y-2"><span class="text-sm font-medium">Environment</span><select bind:value={selectedEnvironment} on:change={environmentChanged} disabled={busy || Boolean(importingFile)} class="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">{#each selectedProject.environments as environment}<option value={environment}>{environment}</option>{/each}</select></label><Button variant="secondary" on:click={refreshEnvironmentStatus} disabled={statusBusy || busy || Boolean(importingFile)}>{#if statusBusy}<LoaderCircle size={16} class="animate-spin" />{:else}<RefreshCw size={16} />{/if} Check</Button></div>
          </div>
          {#if environmentStatus}
            {#if environmentStatus.plaintextEnvFiles.length > 0}
              <div class="rounded-xl border border-amber-500/40 bg-amber-500/10 p-5"><div class="flex gap-3"><AlertTriangle size={20} class="mt-0.5 shrink-0" /><div class="min-w-0 flex-1"><h3 class="font-semibold">Plaintext secrets detected</h3><p class="mt-1 text-sm text-muted-foreground">Import a file into <strong>{selectedEnvironment}</strong>. ND Secure encrypts its values, updates only key names in .env.example, then removes the plaintext source when possible.</p><div class="mt-4 flex flex-wrap gap-2">{#each environmentStatus.plaintextEnvFiles as fileName}<Button variant="secondary" size="sm" on:click={() => importPlaintextEnv(fileName)} disabled={busy || Boolean(importingFile)}>{#if importingFile === fileName}<LoaderCircle size={15} class="animate-spin" />{:else}<KeyRound size={15} />{/if} Encrypt + remove {fileName}</Button>{/each}</div><p class="mt-3 text-xs text-muted-foreground">Removing a file is not guaranteed secure erasure on SSDs or journaled file systems. Rotate migrated secrets if the plaintext file may already have been copied, indexed, backed up, or read by another tool.</p></div></div></div>
            {/if}
            <div class="rounded-xl border border-border bg-card p-5"><div class="mb-4 flex items-center gap-2"><FileCode2 size={18} /><div><h3 class="font-semibold">Environment schema</h3><p class="text-xs text-muted-foreground">Names come from .env.example. Values never appear here.</p></div></div>
              {#if selectedProject.requiredKeys.length === 0}<div class="rounded-lg border border-dashed border-border p-5 text-sm text-muted-foreground">No keys are registered. Add key names to .env.example and sync, or migrate an existing plaintext .env file.</div>
              {:else}<div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{#each selectedProject.requiredKeys as key}<div class="flex items-center justify-between gap-2 rounded-lg border border-border px-3 py-2.5"><code class="min-w-0 truncate text-xs">{key}</code>{#if presentKeys.has(key)}<span class="flex shrink-0 items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400"><CheckCircle2 size={14} /> Present</span>{:else}<span class="flex shrink-0 items-center gap-1 text-xs text-destructive"><XCircle size={14} /> Missing</span>{/if}</div>{/each}</div>{/if}
            </div>
            <div class="rounded-xl border border-border bg-card p-5"><div class="mb-4 flex items-center gap-2"><Play size={18} /><div><h3 class="font-semibold">Run with protected environment</h3><p class="text-xs text-muted-foreground">Desktop compatibility mode. ND Secure creates no .env file and invokes the executable directly, without a shell.</p></div></div>
              <div class="grid gap-4 md:grid-cols-2"><label class="space-y-2"><span class="text-sm font-medium">Executable</span><Input bind:value={program} placeholder="npm" autocomplete="off" disabled={busy || Boolean(importingFile)} /></label><label class="space-y-2"><span class="text-sm font-medium">Master password confirmation</span><Input type="password" bind:value={reauthPassword} placeholder="Required before secret injection" autocomplete="current-password" disabled={busy || Boolean(importingFile)} /></label></div>
              <label class="mt-4 block space-y-2"><span class="text-sm font-medium">Arguments - one argument per line</span><Textarea bind:value={argumentsText} rows={4} placeholder={'run\ndev'} disabled={busy || Boolean(importingFile)} /></label>
              <div class="mt-4 flex flex-wrap items-center justify-between gap-3"><p class="max-w-2xl text-xs text-muted-foreground">The child receives only an allowlisted baseline environment plus this project's exact environment secrets. No central or other-project secret is inherited.</p><Button on:click={launchCommand} disabled={busy || Boolean(importingFile) || statusBusy || !program.trim() || !reauthPassword || (environmentStatus?.missingKeys.length ?? 0) > 0}>{#if busy}<LoaderCircle size={16} class="animate-spin" />{:else}<Play size={16} />{/if} Reauthenticate &amp; run</Button></div>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</section>
