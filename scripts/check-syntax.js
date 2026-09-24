'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const roots = [path.join(root, 'src'), path.join(root, 'scripts'), path.join(root, 'tests')];
const files = [];

function collect(entry) {
  if (!fs.existsSync(entry)) return;
  const stat = fs.statSync(entry);
  if (stat.isDirectory()) {
    for (const name of fs.readdirSync(entry)) collect(path.join(entry, name));
    return;
  }
  if (entry.endsWith('.js') || entry.endsWith('.cjs')) files.push(entry);
}

for (const entry of roots) collect(entry);
let failed = false;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failed = true;
    process.stderr.write(`\n${path.relative(root, file)}\n${result.stderr || result.stdout}\n`);
  }
}
if (failed) process.exit(1);
process.stdout.write(`Syntax OK: ${files.length} JavaScript files\n`);
