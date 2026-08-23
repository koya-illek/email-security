#!/usr/bin/env node
// Release entry point: pins the deployed source revision into the Worker so
// /api/health, the API directory, and every stored report carry truthful
// provenance instead of a stale placeholder from wrangler.toml.
//
// Usage:
//   npm run deploy                 # real deployment
//   npm run deploy -- --dry-run    # same injection, no deployment
import { execFileSync, spawnSync } from 'node:child_process';

function resolveRevision() {
  let revision;
  try {
    revision = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch (error) {
    throw new Error(`Cannot identify the release commit: ${error.message}`);
  }

  const dirty = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0;
  if (dirty) {
    throw new Error('Refusing to deploy a dirty worktree. Commit the release or use npm run check for an uncommitted dry run.');
  }
  return revision;
}

let revision;
try {
  revision = resolveRevision();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
const passthrough = process.argv.slice(2);
console.log(`Deploying source revision ${revision}${passthrough.length ? ` (${passthrough.join(' ')})` : ''}`);

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const result = spawnSync(npx, ['--no-install', 'wrangler', 'deploy', '--var', `SOURCE_REVISION:${revision}`, ...passthrough], {
  stdio: 'inherit'
});
process.exit(result.status ?? 1);
