'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  APP_NAME,
  APP_VERSION,
  DEFAULT_SETTINGS,
  MODEL_PRESETS,
  sanitizeSettings,
  updateSettings,
} = require('../src/main/core/defaults');
const Logger = require('../src/main/core/logger');
const SettingsStore = require('../src/main/core/settings-store');
const SessionStore = require('../src/main/core/session-store');

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codepilot-local-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('defaults and settings sanitization are stable', () => {
  assert.equal(APP_NAME, 'CodePilot Local');
  assert.equal(APP_VERSION, '0.1.0');
  assert.equal(DEFAULT_SETTINGS.lmBaseUrl, 'http://127.0.0.1:1234/v1');
  assert.equal(DEFAULT_SETTINGS.temperature, 0.2);
  assert.equal(DEFAULT_SETTINGS.webProvider, 'duckduckgo');
  assert.equal(DEFAULT_SETTINGS.searchProvider, 'duckduckgo');
  assert.equal(DEFAULT_SETTINGS.modelPreset, 'qwen3-4b-1050ti');
  assert.equal(DEFAULT_SETTINGS.contextLength, 4096);
  assert.equal(DEFAULT_SETTINGS.maxTokens, 1024);
  assert.equal(DEFAULT_SETTINGS.maxSubagents, 1);
  assert.equal(DEFAULT_SETTINGS.flashAttention, true);
  assert.ok(DEFAULT_SETTINGS.modelPreset);
  assert.ok(MODEL_PRESETS.includes('qwen38-4b-distilled-ma7ee7'));
  assert.ok(MODEL_PRESETS.includes('qwen3-4b-thinking-2507'));

  const clean = sanitizeSettings({
    temperature: 99,
    topP: 0.4,
    maxTokens: 128,
    fileRoot: 'relative/path',
    unknown: 'drop me',
    mcpServers: [],
  });
  assert.equal(clean.temperature, DEFAULT_SETTINGS.temperature);
  assert.equal(clean.topP, 0.4);
  assert.equal(clean.maxTokens, 128);
  assert.equal(clean.fileRoot, '');
  assert.deepEqual(clean.mcpServers, {});
  assert.equal('unknown' in clean, false);

  const updated = updateSettings(DEFAULT_SETTINGS, { model: 'local', fileRoot: '' });
  assert.equal(updated.model, 'local');
  assert.doesNotThrow(() => updateSettings(DEFAULT_SETTINGS, { lmBaseUrl: 'http://127.0.0.1:1234/v1' }));
  assert.equal(DEFAULT_SETTINGS.model, '');

  const tuned = updateSettings(DEFAULT_SETTINGS, {
    modelPreset: 'qwen3-4b-1050ti', contextLength: 4096, maxTokens: 1024, flashAttention: false,
  });
  assert.equal(tuned.modelPreset, 'qwen3-4b-1050ti');
  assert.equal(tuned.contextLength, 4096);
  assert.equal(tuned.maxTokens, 1024);
  assert.equal(tuned.flashAttention, false);
  assert.throws(() => updateSettings(DEFAULT_SETTINGS, { modelPreset: 'unknown' }), /modelPreset/);
});

test('settings encrypt and redact a brave API key with safeStorage', async (t) => {
  const dir = tempDir(t);
  const calls = [];
  const safeStorage = {
    isEncryptionAvailable: () => true,
    encryptString(value) {
      calls.push(['encrypt', value]);
      return Buffer.from(`encrypted:${value}`, 'utf8');
    },
    decryptString(value) {
      calls.push(['decrypt', value.toString('utf8')]);
      const text = value.toString('utf8');
      if (!text.startsWith('encrypted:')) throw new Error('bad ciphertext');
      return text.slice('encrypted:'.length);
    },
  };
  const store = new SettingsStore({ dir, safeStorage });
  await store.init();
  const secret = 'brave-secret-value';
  const publicSettings = await store.setEncryptedSecret(secret);
  assert.equal(publicSettings.braveApiKeyPresent, true);
  assert.equal('braveApiKey' in publicSettings, false);
  assert.equal(store.getInternal().braveApiKey, secret);

  const raw = fs.readFileSync(path.join(dir, 'settings.json'), 'utf8');
  assert.equal(raw.includes(secret), false);
  assert.match(raw, /braveApiKeyEncrypted/);
  assert.equal(calls.some(([kind, value]) => kind === 'encrypt' && value === secret), true);

  const reloaded = new SettingsStore({ dir, safeStorage });
  await reloaded.load();
  assert.equal(reloaded.get().braveApiKeyPresent, true);
  assert.equal(reloaded.getInternal().braveApiKey, secret);
  assert.equal('braveApiKey' in reloaded.get(), false);

  await reloaded.clear();
  assert.equal(reloaded.get().braveApiKeyPresent, false);
});

test('settings preserve redacted MCP secrets when the form is saved', async (t) => {
  const store = new SettingsStore({ dir: tempDir(t) });
  await store.init();
  const mcp = { remote: { url: 'https://mcp.example.test/mcp', headers: { Authorization: 'Bearer super-secret' } } };
  await store.update({ mcpServers: mcp });
  const publicSettings = store.get();
  assert.equal(publicSettings.mcpServers.remote.headers.Authorization, '[REDACTED]');
  await store.update({ mcpServers: publicSettings.mcpServers, model: 'still-local' });
  assert.equal(store.getInternal().mcpServers.remote.headers.Authorization, 'Bearer super-secret');
  assert.equal(store.getInternal().model, 'still-local');
});

test('settings persist updates atomically and recover from corruption', async (t) => {
  const dir = tempDir(t);
  const store = new SettingsStore({ dir });
  await store.init();
  await store.update({ model: 'persisted-model', topP: 0.25 });
  assert.equal(fs.existsSync(path.join(dir, 'settings.json')), true);
  assert.deepEqual(fs.readdirSync(dir).filter((name) => name.endsWith('.tmp')), []);

  const reloaded = new SettingsStore({ dir });
  await reloaded.init();
  assert.equal(reloaded.get().model, 'persisted-model');
  assert.equal(reloaded.get().topP, 0.25);

  fs.writeFileSync(path.join(dir, 'settings.json'), '{ definitely not json');
  await reloaded.load();
  assert.equal(reloaded.get().model, DEFAULT_SETTINGS.model);
  assert.equal(reloaded.get().temperature, DEFAULT_SETTINGS.temperature);
});

test('logger bounds and redacts daily output', async (t) => {
  const dir = tempDir(t);
  const output = [];
  const logger = new Logger({
    logDir: dir,
    maxBytes: 512,
    maxFiles: 2,
    console: false,
  });
  logger.info('Authorization: Bearer top-secret-token', { apiKey: 'api-secret', password: 'pw' });
  for (let i = 0; i < 20; i += 1) logger.warn(`bounded-${i}`);
  await logger.flush();
  const recent = logger.getRecentFile();
  assert.ok(recent);
  const text = fs.readFileSync(recent, 'utf8');
  assert.equal(logger.recent(), text);
  assert.equal(text.includes('top-secret-token'), false);
  assert.equal(text.includes('api-secret'), false);
  assert.equal(text.includes('pw'), false);
  assert.ok(fs.statSync(recent).size <= 512);
  await logger.stop();
});

test('session store caps sessions, trims messages, and serializes concurrent appends', async (t) => {
  const dir = tempDir(t);
  const store = new SessionStore({ dir });
  await store.init();
  const workspace = path.join(dir, 'workspace');
  const session = await store.createSession({ workspace, mode: 'chat', title: 'Original' });
  assert.match(session.id, /^[0-9a-f-]{36}$/i);

  await Promise.all(Array.from({ length: 25 }, (_, i) =>
    store.appendMessage(session.id, { role: i % 2 ? 'assistant' : 'user', content: `message-${i}` })));
  let loaded = await store.getSession(session.id);
  assert.equal(loaded.messages.length, 25);
  assert.equal(loaded.messages.at(-1).content, 'message-24');

  await store.updateTitle(session.id, 'Renamed');
  loaded = await store.getSession(session.id);
  assert.equal(loaded.title, 'Renamed');

  for (let i = 0; i < 510; i += 1) {
    await store.appendMessage(session.id, { role: 'user', content: `trim-${i}` });
  }
  loaded = await store.getSession(session.id);
  assert.equal(loaded.messages.length, 500);
  assert.equal(loaded.messages.at(-1).content, 'trim-509');

  const first = await store.createSession({ workspace: '', mode: 'chat', title: 'first' });
  assert.equal(first.workspace, '');
  for (let i = 0; i < 100; i += 1) {
    await store.createSession({ workspace, mode: 'chat', title: `session-${i}` });
  }
  const summaries = await store.listSessions();
  assert.equal(summaries.length, 100);
  assert.equal(summaries.some((item) => item.id === first.id), false);
});

test('default token budget leaves room for the agent prompt and tool schemas', () => {
  const WorkspaceTools = require('../src/main/tools/workspace-tools').WorkspaceTools;
  const SystemTools = require('../src/main/tools/system-tools').SystemTools;
  const WebTools = require('../src/main/tools/web-tools').WebTools;
  const { systemPrompt } = require('../src/main/core/agent-runner');

  const root = process.cwd();
  const sources = [
    new WorkspaceTools({ root }),
    new SystemTools({ root, logDir: root }),
    new WebTools({ searchProvider: 'duckduckgo' }),
  ];
  const tools = sources.flatMap((source) => source.definitions('agent')).map((definition) => ({
    type: 'function',
    function: {
      name: definition.name,
      description: definition.description || '',
      parameters: definition.parameters || definition.schema || {},
    },
  }));
  const promptChars = systemPrompt({
    mode: 'agent',
    workspace: root,
    settings: DEFAULT_SETTINGS,
    hasWorkspace: true,
  }).length + JSON.stringify(tools).length;

  // Measured against LM Studio: the real agent turn is about 3.2 characters
  // per token, so three is a safe over-estimate.  Anything larger than a
  // 2048 context makes LM Studio reject every request before it starts.
  const promptTokens = Math.ceil(promptChars / 3);
  const room = DEFAULT_SETTINGS.contextLength - DEFAULT_SETTINGS.maxTokens;
  assert.ok(tools.length >= 20, 'expected the agent tool surface to stay complete');
  assert.ok(
    room - promptTokens > 1000,
    `context budget too small: ${room} tokens available, prompt uses ~${promptTokens}`
  );
});

test('session runs and tool data are bounded and corrupt files recover', async (t) => {  const dir = tempDir(t);
  const store = new SessionStore({ dir });
  await store.init();
  const session = await store.createSession({ workspace: '', mode: 'agent', title: 'runs' });
  const run = await store.updateRun(session.id, { name: 'run-1', status: 'running' });
  assert.equal(run.status, 'running');
  await store.updateRun(session.id, run.id, { status: 'complete', data: 'x'.repeat(200_000) });
  const runs = await store.listRuns(session.id);
  assert.equal(runs[0].status, 'complete');
  assert.ok(JSON.stringify(runs[0]).length < 200_000);
  const tool = await store.updateToolRun(session.id, { name: 'tool-1', output: 'y'.repeat(200_000) });
  assert.ok(Buffer.byteLength(JSON.stringify(tool), 'utf8') < 200_000);

  fs.writeFileSync(path.join(dir, 'sessions.json'), 'not json at all');
  const recovered = new SessionStore({ dir });
  await recovered.load();
  assert.deepEqual(await recovered.listSessions(), []);
  const created = await recovered.createSession({ workspace: '', mode: 'chat' });
  assert.ok(created.id);
});
