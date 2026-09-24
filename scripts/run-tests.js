'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const testDir = path.resolve(__dirname, '..', 'tests');
if (!fs.existsSync(testDir)) process.exit(0);
const files = fs.readdirSync(testDir)
  .filter((name) => name.endsWith('.test.js'))
  .sort()
  .map((name) => path.join(testDir, name));
if (!files.length) process.exit(0);
const result = spawnSync(process.execPath, ['--test', '--test-reporter=spec', ...files], {
  stdio: 'inherit',
  timeout: 120_000,
  killSignal: 'SIGKILL',
  windowsHide: true,
});
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
