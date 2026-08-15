'use strict';

const { defineConfig, devices } = require('@playwright/test');
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;

module.exports = defineConfig({
  testDir: './test/browser',
  fullyParallel: true,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:8799',
    trace: 'retain-on-failure',
    launchOptions: executablePath ? { executablePath } : undefined
  },
  webServer: {
    command: 'npx wrangler dev --local --host 127.0.0.1 --port 8799',
    url: 'http://127.0.0.1:8799',
    reuseExistingServer: false,
    timeout: 30_000
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-chromium', use: { ...devices['iPhone 13'], browserName: 'chromium' } }
  ]
});
