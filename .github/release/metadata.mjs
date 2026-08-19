import { appendFileSync, readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';

const config = JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8'));
const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(config.version ?? '');
if (!match) {
  throw new Error(`Expected a numeric SemVer in src-tauri/tauri.conf.json, got: ${config.version}`);
}

const runNumber = Number(process.env.GITHUB_RUN_NUMBER);
if (!Number.isSafeInteger(runNumber) || runNumber < 1) {
  throw new Error(`Invalid GITHUB_RUN_NUMBER: ${process.env.GITHUB_RUN_NUMBER}`);
}

const [, major, minor, patchText] = match;
const patch = Number(patchText) + runNumber;
const version = `${major}.${minor}.${patch}`;
const tag = `v${version}`;
const androidVersionCode = 1_000_000 + runNumber;
if (androidVersionCode > 2_100_000_000) {
  throw new Error(`Android versionCode exceeds the supported range: ${androidVersionCode}`);
}

const tagRef = `refs/tags/${tag}`;
const tagCheck = spawnSync('git', ['show-ref', '--verify', '--quiet', tagRef]);
if (tagCheck.status === 0) {
  const existingSha = execFileSync('git', ['rev-list', '-n', '1', tag], { encoding: 'utf8' }).trim();
  if (existingSha !== process.env.GITHUB_SHA) {
    throw new Error(`Refusing to reuse ${tag}; it already points to ${existingSha}`);
  }
} else if (tagCheck.status !== 1) {
  throw new Error(`Unable to inspect ${tagRef}`);
}

const releaseConfigJson = JSON.stringify({
  version,
  bundle: { android: { versionCode: androidVersionCode } },
});

const outputPath = process.env.GITHUB_OUTPUT;
if (!outputPath) {
  throw new Error('GITHUB_OUTPUT is not set');
}
appendFileSync(
  outputPath,
  [
    `version=${version}`,
    `tag=${tag}`,
    `android_version_code=${androidVersionCode}`,
    `release_config_json=${releaseConfigJson}`,
    '',
  ].join('\n'),
);
