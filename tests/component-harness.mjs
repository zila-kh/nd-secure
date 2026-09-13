import { readFileSync } from 'node:fs';
import ts from 'typescript';
import * as workflow from '../src/lib/workflow-state.ts';

export function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

/** Execute the actual component's controller code, not a duplicate implementation.
 * This intentionally does NOT simulate Svelte rendering or native Tauri behavior.
 * Only test boundaries (IPC, dialogs, lifecycle hooks) are replaced by test doubles.
 */
export function controller(name, overrides = {}) {
  const file = readFileSync(new URL(`../src/lib/components/${name}.svelte`, import.meta.url), 'utf8');
  const source = file.match(/<script lang="ts">([\s\S]*?)<\/script>/)?.[1];
  if (!source) throw new Error(`Missing TypeScript script in ${name}`);
  const ast = ts.createSourceFile(`${name}.ts`, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const statements = ast.statements.filter((node) => !ts.isImportDeclaration(node) && !ts.isLabeledStatement(node));
  const functions = statements.filter(ts.isFunctionDeclaration).map((node) => node.name.text);
  const variables = statements.filter(ts.isVariableStatement).flatMap((node) => node.declarationList.declarations)
    .filter((node) => ts.isIdentifier(node.name)).map((node) => node.name.text);
  const clean = ts.createPrinter().printFile(ts.factory.updateSourceFile(ast, statements));
  const javascript = ts.transpileModule(clean, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;
  const mounts = [], destroys = [];
  const bindings = {
    ...workflow,
    pendingMediaSelection: new workflow.SelectionMailbox(),
    pendingProjectSelection: new workflow.SelectionMailbox(),
    onMount: (fn) => mounts.push(fn), onDestroy: (fn) => destroys.push(fn),
    navigator: { userAgent: 'Test desktop' },
    confirm: async () => true, open: async () => null,
    vaultApi: new Proxy({}, { get: (_, key) => () => { throw new Error(`Unexpected IPC: ${String(key)}`); } }),
    ...overrides
  };
  const result = new Function(...Object.keys(bindings), `${javascript}\nreturn {
    ${functions.join(',')},
    state() { return { ${variables.join(',')} }; },
    set(patch) { ${variables.map((key) => `if(Object.hasOwn(patch, '${key}')) ${key} = patch.${key};`).join('\n')} }
  };`)(...Object.values(bindings));
  return { ...result, mount: () => mounts.forEach((fn) => fn()), destroy: () => destroys.forEach((fn) => fn()), bindings };
}
