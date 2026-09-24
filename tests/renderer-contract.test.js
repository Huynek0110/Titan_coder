'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const app = fs.readFileSync(path.join(root, 'src', 'renderer', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'src', 'renderer', 'index.html'), 'utf8');
const preload = fs.readFileSync(path.join(root, 'src', 'main', 'preload.js'), 'utf8');

test('renderer uses the interaction IPC contract instead of starting a second run', () => {
  assert.match(app, /respondInteraction/);
  assert.match(app, /type:\s*'ask-user'/);
  assert.match(app, /type:\s*'approval-request'/);
  assert.match(preload, /respondInteraction/);
});

test('renderer keeps model output out of unsafe HTML/network sinks', () => {
  assert.doesNotMatch(app, /\.innerHTML\s*=/);
  assert.doesNotMatch(app, /\bfetch\s*\(/);
  assert.doesNotMatch(app, /\beval\s*\(/);
  assert.match(app, /createTextNode/);
  assert.match(app, /isSafeHttpUrl/);
  assert.match(html, /Content-Security-Policy/);
  assert.doesNotMatch(html, /<script>\s*var savedTheme/);
});

test('onboarding and settings expose the expected local controls', () => {
  for (const id of ['onboarding-test-btn', 'onboarding-start-btn', 'onboarding-install-btn', 'settings-mcp-json', 'settings-model-preset', 'settings-context-length', 'settings-max-tokens', 'settings-load-model', 'settings-allow-fallback-tools', 'ask-user-modal', 'approval-modal']) {
    assert.match(html, new RegExp(`id=["']${id}["']`));
    assert.match(app, new RegExp(`['"]${id}['"]`));
  }
});
