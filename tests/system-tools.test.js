'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const {
  SystemTools,
  TOOL_NAMES,
  OUTPUT_CAP,
  redactSecrets,
} = require('../src/main/tools/system-tools');

function tempWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'system-tools-test-'));
}

function fakeChild(pid = 4242) {
  const child = new EventEmitter();
  child.pid = pid;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.killCalls = [];
  child.kill = (signal) => {
    child.killCalls.push(signal || null);
    queueMicrotask(() => child.emit('close', null, signal || 'SIGTERM'));
    return true;
  };
  return child;
}

function closeWithOutput(child, stdout = '', stderr = '', code = 0) {
  queueMicrotask(() => {
    if (stdout) child.stdout.emit('data', Buffer.from(stdout));
    if (stderr) child.stderr.emit('data', Buffer.from(stderr));
    child.emit('close', code, null);
  });
}

test('exports all focused tools and makes plan definitions read-only/no-shell', () => {
  const root = tempWorkspace();
  try {
    const tools = new SystemTools({ root, logDir: path.join(root, 'logs') });
    const definitions = tools.definitions();
    assert.equal(definitions.length, TOOL_NAMES.length);
    assert.deepEqual(
      definitions.map((definition) => definition.function.name).sort(),
      [...TOOL_NAMES].sort(),
    );
    for (const definition of definitions) {
      assert.equal(definition.function.parameters.additionalProperties, false);
    }
    const plan = tools.definitions('plan');
    assert.ok(plan.length < definitions.length);
    assert.ok(plan.every((definition) => definition.metadata.shell === false));
    assert.ok(plan.every((definition) => definition.metadata.mutating === false));
    assert.ok(!plan.some((definition) => ['run_command', 'start_process', 'run_test', 'run_lint', 'run_format', 'stop_process'].includes(definition.function.name)));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('redacts common secret forms without pretending to be exhaustive', () => {
  const value = 'Authorization: Bearer abc.def password="very secret" API_KEY=topsecret OPENAI_API_KEY=envsecret https://x.test/?token=querysecret';
  const redacted = redactSecrets(value);
  assert.doesNotMatch(redacted, /abc\.def|very secret|topsecret|envsecret|querysecret/);
  assert.match(redacted, /\[REDACTED\]/);
  assert.doesNotMatch(redactSecrets('{"OPENAI_API_KEY":"json-secret"}'), /json-secret/);
  assert.doesNotMatch(redactSecrets('{"Authorization":"Bearer json-token"}'), /json-token/);
});

test('run_command uses the workspace shell, streams redacted output, and caps output', async () => {
  const root = tempWorkspace();
  const calls = [];
  const events = [];
  try {
    const child = fakeChild();
    const spawn = (command, options) => {
      calls.push({ command, options });
      closeWithOutput(child, 'ok API_KEY=secret123\n', 'Authorization: Bearer tok123\n');
      return child;
    };
    const tools = new SystemTools({ root, logDir: path.join(root, 'logs'), platform: 'linux' }, { spawn });
    const result = await tools.execute(
      'run_command',
      { command: 'printf hello', timeoutMs: 1000 },
      { onOutput: (event) => events.push(event) },
    );
    assert.equal(result.ok, true);
    assert.equal(result.data.exitCode, 0);
    assert.equal(result.data.stdout, 'ok API_KEY=[REDACTED]\n');
    assert.match(result.data.stderr, /Bearer \[REDACTED\]/);
    assert.equal(calls[0].options.cwd, path.resolve(root));
    assert.equal(calls[0].options.shell, true);
    assert.equal(calls[0].options.windowsHide, true);
    assert.equal('env' in result.data, false);
    assert.ok(events.some((chunk) => chunk.includes('[REDACTED]')));

    const splitChild = fakeChild(4299);
    const splitTools = new SystemTools({ root, logDir: path.join(root, 'split-logs'), platform: 'linux' }, {
      spawn: () => {
        queueMicrotask(() => {
          splitChild.stdout.emit('data', 'OPENAI_API_KEY=');
          splitChild.stdout.emit('data', 'split-secret\n');
          splitChild.emit('close', 0, null);
        });
        return splitChild;
      },
    });
    const split = await splitTools.execute('run_command', { command: 'split-output' });
    assert.equal(split.ok, true);
    assert.doesNotMatch(split.data.stdout, /split-secret/);
    assert.match(split.data.stdout, /OPENAI_API_KEY=\[REDACTED\]/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('run_command aborts through the child process and caps very large output', async () => {
  const root = tempWorkspace();
  const children = [];
  try {
    const spawn = () => {
      const child = fakeChild(4300 + children.length);
      children.push(child);
      return child;
    };
    const tools = new SystemTools({ root, logDir: path.join(root, 'logs'), platform: 'linux' }, { spawn });
    const controller = new AbortController();
    const aborted = tools.execute('run_command', { command: 'long-running' }, { signal: controller.signal });
    controller.abort();
    const abortedResult = await aborted;
    assert.equal(abortedResult.ok, false);
    assert.match(abortedResult.error, /abort/i);
    assert.equal(children[0].killCalls[0], 'SIGKILL');

    const largeChild = fakeChild(4400);
    const largeTools = new SystemTools({ root, logDir: path.join(root, 'large-logs'), platform: 'linux' }, {
      spawn: () => {
        closeWithOutput(largeChild, 'x'.repeat(OUTPUT_CAP + 1000));
        return largeChild;
      },
    });
    const large = await largeTools.execute('run_command', { command: 'large-output' });
    assert.equal(large.ok, true);
    assert.equal(large.data.truncated, true);
    assert.equal(large.data.stdout.length, OUTPUT_CAP);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('persistent processes have bounded logs, can be read, and are stopped', async () => {
  const root = tempWorkspace();
  const children = [];
  try {
    const spawn = () => {
      const child = fakeChild(5000 + children.length);
      children.push(child);
      return child;
    };
    const tools = new SystemTools({ root, logDir: path.join(root, 'logs'), platform: 'linux' }, { spawn });
    const started = await tools.execute('start_process', { command: 'server', name: 'dev' });
    assert.equal(started.ok, true);
    const id = started.data.id;
    assert.match(id, /^proc_[0-9a-f-]{36}$/);
    const child = children[0];
    child.stdout.emit('data', 'hello\n');
    const read = await tools.execute('read_process', { id });
    assert.equal(read.ok, true);
    assert.match(read.data.process.stdout, /hello/);
    assert.ok(read.data.process.logPath.startsWith(path.join(root, 'logs') + path.sep));
    const listed = await tools.execute('list_processes', {});
    assert.equal(listed.data.count, 1);
    const stopped = await tools.execute('stop_process', { id });
    assert.equal(stopped.ok, true);
    assert.equal(stopped.data.process.status, 'exited');
    assert.equal(children[0].killCalls.length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('git tools use execFile without a shell and scope paths after --', async () => {
  const root = tempWorkspace();
  const calls = [];
  try {
    const execFile = (file, args, options, callback) => {
      calls.push({ file, args, options });
      callback(null, ' M src/example.js\n', '');
    };
    const tools = new SystemTools({ root, logDir: path.join(root, 'logs'), platform: 'linux' }, { execFile });
    const status = await tools.execute('git_status', { path: 'src' });
    assert.equal(status.ok, true);
    assert.equal(calls[0].file, 'git');
    assert.equal(calls[0].options.shell, false);
    assert.ok(calls[0].args.includes('--'));
    assert.equal(calls[0].args[calls[0].args.length - 1], 'src');
    const escaped = await tools.execute('git_status', { path: path.join(root, '..', 'outside') });
    assert.equal(escaped.ok, false);
    assert.match(escaped.error, /workspace/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('project task detection does not execute and run_test delegates to run_command', async () => {
  const root = tempWorkspace();
  const commands = [];
  try {
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      scripts: { test: 'node --test', lint: 'eslint .', build: 'tsc' },
    }));
    const spawn = (command) => {
      commands.push(command);
      const child = fakeChild();
      closeWithOutput(child, 'passed');
      return child;
    };
    const tools = new SystemTools({ root, logDir: path.join(root, 'logs'), platform: 'linux' }, { spawn });
    const detected = await tools.execute('list_project_tasks', {});
    assert.equal(detected.ok, true);
    assert.ok(detected.data.tasks.some((task) => task.kind === 'test' && task.command === 'npm test'));
    assert.deepEqual(commands, []);
    const run = await tools.execute('run_test', { target: 'tests/unit.test.js' });
    assert.equal(run.ok, true);
    assert.equal(commands.length, 1);
    assert.match(commands[0], /^npm test -- /);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('project memory is bounded, fixed-path, and supports recall/forget', async () => {
  const root = tempWorkspace();
  const logDir = path.join(root, 'logs');
  try {
    const tools = new SystemTools({ root, logDir, platform: 'linux' });
    const remembered = await tools.execute('project_memory', { action: 'remember', key: 'project', value: 'remembered' });
    assert.equal(remembered.ok, true);
    const recalled = await tools.execute('project_memory', { action: 'recall', key: 'project' });
    assert.equal(recalled.data.value, 'remembered');
    const forgotten = await tools.execute('project_memory', { action: 'forget', key: 'project' });
    assert.equal(forgotten.data.removed, true);
    const missing = await tools.execute('project_memory', { action: 'recall', key: 'project' });
    assert.equal(missing.data.value, null);
    assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(path.join(logDir, 'memory.json'), 'utf8'))), []);
    const tooLong = await tools.execute('project_memory', { action: 'remember', key: 'x', value: 'x'.repeat(4001) });
    assert.equal(tooLong.ok, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('open_path is workspace-scoped and system_info excludes environment dumps', async () => {
  const root = tempWorkspace();
  try {
    const opened = [];
    const tools = new SystemTools(
      { root, logDir: path.join(root, 'logs'), platform: 'linux', openPath: (value) => opened.push(value) },
    );
    fs.writeFileSync(path.join(root, 'file.txt'), 'hello');
    const result = await tools.execute('open_path', { path: 'file.txt' });
    assert.equal(result.ok, true);
    assert.equal(result.data.opened, true);
    assert.equal(opened.length, 1);
    assert.match(result.data.suggestion, /xdg-open/);
    const outside = await tools.execute('open_path', { path: path.join(root, '..', 'file.txt') });
    assert.equal(outside.ok, false);
    const info = await tools.execute('system_info', {});
    assert.equal(info.data.workspace, path.resolve(root));
    assert.equal('env' in info.data, false);
    assert.equal('username' in info.data, false);
    assert.equal('home' in info.data, false);
    const time = await tools.execute('current_time', {});
    assert.match(time.data.iso, /^\d{4}-\d{2}-\d{2}T/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
