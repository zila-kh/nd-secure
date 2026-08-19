import { appendFileSync } from 'node:fs';

const names = process.argv.slice(2);
if (names.length === 0) {
  throw new Error('At least one secret environment variable name is required');
}

const present = names.filter((name) => (process.env[name] ?? '').trim().length > 0);
if (present.length !== 0 && present.length !== names.length) {
  const missing = names.filter((name) => !present.includes(name));
  throw new Error(`Configure the complete secret group or remove it. Missing: ${missing.join(', ')}`);
}

const outputPath = process.env.GITHUB_OUTPUT;
if (!outputPath) {
  throw new Error('GITHUB_OUTPUT is not set');
}
const enabled = present.length === names.length;
appendFileSync(outputPath, `enabled=${enabled}\n`);
console.log(enabled ? 'Signing configuration is complete.' : 'Signing configuration is absent; platform artifacts will be omitted.');
