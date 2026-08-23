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
  try {
    const revision = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0;
    return dirty ? `${revision}-dirty` : revision;
  } catch {
    // Outside git (or git unavailable), an unpinned marker beats a plausible lie.
    return 'unpinned';
  }
}

const revision = resolveRevision();
const passthrough = process.argv.slice(2);
console.log(`Deploying source revision ${revision}${passthrough.length ? ` (${passthrough.join(' ')})` : ''}`);

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const result = spawnSync(npx, ['--no-install', 'wrangler', 'deploy', '--var', `SOURCE_REVISION:${revision}`, ...passthrough], {
  stdio: 'inherit'
});
process.exit(result.status ?? 1);
