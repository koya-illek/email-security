'use strict';

const { spawnSync } = require('node:child_process');
const { defineConfig, devices } = require('@playwright/test');

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;

// A hard-coded port collides with any other local dev server or this
// project's own leftover workerd; reserve a free ephemeral port instead,
// matching the guard test/conformance.mjs already uses.
//
// Playwright evaluates this file more than once (main process and workers),
// so the first evaluation sticks the resolved port into the environment and
// later evaluations reuse it instead of racing onto a different port. The
// probe inherits FORCE_COLOR=1 under Playwright, which colourises even
// numeric console.log output, so parsing keeps digits only.
function resolvePort() {
  const sticky = Number(process.env.EMAIL_CHECKER_PW_PORT);
  if (Number.isInteger(sticky) && sticky > 0) return sticky;
  const script =
    "require('net').createServer().listen(0,'127.0.0.1',function(){" +
    "const p=this.address().port;this.close(function(){console.log(p)})})";
  const result = spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' }
  });
  const port = Number(String(result.stdout || '').replace(/[^0-9]/g, ''));
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error(`Could not reserve a free Playwright port: ${result.stderr || 'empty probe output'}`);
  }
  process.env.EMAIL_CHECKER_PW_PORT = String(port);
  return port;
}

const port = resolvePort();
const baseURL = `http://127.0.0.1:${port}`;

module.exports = defineConfig({
  testDir: './test/browser',
  fullyParallel: true,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL,
    trace: 'retain-on-failure',
    launchOptions: executablePath ? { executablePath } : undefined
  },
  webServer: {
    command: `npx wrangler dev --local --host 127.0.0.1 --port ${port}`,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 30_000
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-chromium', use: { ...devices['iPhone 13'], browserName: 'chromium' } }
  ]
});
