// Browser tests for the embedded pages, against the fixture server in server.js.
//
// The unit tests under internal/server/static/app render modules to strings in
// jsdom, which cannot prove that a chart draws, that a details element collapses,
// or that a select changes the URL. These do, in a real Chromium, against the
// same HTML and modules the Go binary embeds.
import { defineConfig, devices } from '@playwright/test';

const port = 4173;

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.js/,
  timeout: 20_000,
  fullyParallel: true,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  outputDir: '../../test-results',
  use: {
    baseURL: `http://localhost:${port}`,
    ...devices['Desktop Chrome'],
    colorScheme: 'dark',
  },
  webServer: {
    command: 'node test/ui/server.js',
    cwd: '../..',
    port,
    reuseExistingServer: !process.env.CI,
    env: { PORT: String(port) },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
