/** UI lifecycle guards only. Authorization remains enforced by Rust. */
export class LatestRequest {
  private generation = 0;
  private disposed = false;

  begin(): () => boolean {
    const generation = ++this.generation;
    return () => !this.disposed && generation === this.generation;
  }

  invalidate(): void { this.generation += 1; }
  dispose(): void { this.disposed = true; this.invalidate(); }
}

export function mergeById<T extends { id: string }>(existing: T[], incoming: T[]): T[] {
  const result = [...existing];
  const known = new Set(existing.map((item) => item.id));
  for (const item of incoming) {
    if (!known.has(item.id)) {
      known.add(item.id);
      result.push(item);
    }
  }
  return result;
}

/** Android uses MIME types; desktop file dialogs use extensions without dots. */
export function mediaPickerExtensions(android: boolean): string[] {
  return android
    ? ['image/jpeg', 'image/png', 'video/mp4', 'video/webm']
    : ['jpg', 'jpeg', 'png', 'mp4', 'webm'];
}

export function normalizeMediaSelection(result: string | string[] | null): readonly string[] | null {
  if (result === null) return null;
  const sources = [...new Set(Array.isArray(result) ? result : [result])];
  if (sources.length === 0) return null;
  if (sources.length > 100) throw new Error('Select at most 100 media files per import.');
  if (sources.some((source) => source.length === 0 || source.length > 16 * 1024)) {
    throw new Error('A selected media source identifier is invalid.');
  }
  return Object.freeze(sources);
}

export interface ProjectCommandDraft {
  id: string;
  environment: string;
  program: string;
  argumentsText: string;
}

/** Capture the exact target BEFORE awaiting password confirmation. No shell parsing. */
export function snapshotProjectCommand(draft: ProjectCommandDraft) {
  return Object.freeze({
    id: draft.id,
    environment: draft.environment,
    program: draft.program.trim(),
    args: Object.freeze(draft.argumentsText.split(/\r?\n/).filter((line) => line.length > 0))
  });
}

export interface SelectionState<T> {
  readonly value: T | null;
  readonly selecting: boolean;
  readonly processing: boolean;
  readonly error: string;
}

/**
 * A native dialog can outlive the protected screen that opened it. Keep ONLY its
 * selection in process memory for explicit resumption after unlock. Never persist
 * source identifiers, passwords, or decrypted data. Implements Svelte's store contract.
 */
export class SelectionMailbox<T> {
  private state: SelectionState<T> = Object.freeze({ value: null, selecting: false, processing: false, error: '' });
  private subscribers = new Set<(state: SelectionState<T>) => void>();

  get current(): SelectionState<T> { return this.state; }

  subscribe(callback: (state: SelectionState<T>) => void): () => void {
    this.subscribers.add(callback);
    callback(this.state);
    return () => { this.subscribers.delete(callback); };
  }

  private publish(patch: Partial<SelectionState<T>>): void {
    this.state = Object.freeze({ ...this.state, ...patch });
    for (const callback of this.subscribers) callback(this.state);
  }

  async choose(picker: () => Promise<T | null>): Promise<void> {
    if (this.state.selecting || this.state.value !== null) return;
    this.publish({ selecting: true, error: '' });
    try {
      this.publish({ value: await picker() });
    } catch (cause) {
      this.publish({ error: String(cause) });
    } finally {
      this.publish({ selecting: false });
    }
  }

  claim(expected: T): boolean {
    if (this.state.selecting || this.state.processing || this.state.value !== expected) return false;
    this.publish({ processing: true });
    return true;
  }

  release(expected: T): void {
    if (this.state.value === expected) this.publish({ processing: false });
  }

  consume(expected: T): void {
    if (this.state.value === expected) this.publish({ value: null, processing: false, error: '' });
  }

  clear(): void {
    if (!this.state.selecting && !this.state.processing) this.publish({ value: null, error: '' });
  }
}

export const pendingMediaSelection = new SelectionMailbox<readonly string[]>();
export const pendingProjectSelection = new SelectionMailbox<string>();
