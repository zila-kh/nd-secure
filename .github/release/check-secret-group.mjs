import { appendFileSync } from 'node:fs';

const names = process.argv.slice(2);
if (names.length === 0) {
  throw new Error('At least one secret environment variable name is required');
}

const outputPath = process.env.GITHUB_OUTPUT;
if (!outputPath) {
  throw new Error('GITHUB_OUTPUT is not set');
}

const present = names.filter((name) => (process.env[name] ?? '').trim().length > 0);
if (present.length === 0) {
  appendFileSync(outputPath, 'enabled=false\n');
  console.log('Optional signing configuration is absent; this platform artifact will be omitted.');
  process.exit(0);
}

if (present.length !== names.length) {
  const missing = names.filter((name) => !present.includes(name));
  throw new Error(`Optional signing configuration is incomplete. Missing secrets: ${missing.join(', ')}`);
}

appendFileSync(outputPath, 'enabled=true\n');
console.log('Production signing configuration is complete.');
