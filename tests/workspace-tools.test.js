'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { WorkspaceTools } = require('../src/main/tools/workspace-tools');

async function makeTempDirectory(prefix) {
  return fsp.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function expectOk(tools, name, args) {
  const result = await tools.execute(name, args);
  assert.equal(result.ok, true, result.error || result.summary);
  return result;
}

test('WorkspaceTools path containment handles traversal and outside absolute paths', async (t) => {
  const root = await makeTempDirectory('workspace-root-');
  const outside = await makeTempDirectory('workspace-outside-');
  t.after(async () => {
    await fsp.rm(root, { recursive: true, force: true });
    await fsp.rm(outside, { recursive: true, force: true });
  });

  const tools = new WorkspaceTools({ root });
  assert.equal(tools.getRoot(), fs.realpathSync(root));
  assert.throws(() => tools.resolveWorkspacePath('..'), /escapes the workspace root/i);
  assert.throws(() => tools.resolveWorkspacePath(outside), /escapes the workspace root/i);
  assert.equal(tools.resolveWorkspacePath(path.join(root, 'new', 'file.txt')), path.join(fs.realpathSync(root), 'new', 'file.txt'));

  const planNames = tools.definitions('plan').map((definition) => definition.function.name);
  assert.equal(planNames.includes('write_file'), false);
  assert.equal(planNames.includes('delete_path'), false);
  for (const definition of tools.definitions('plan')) {
    assert.equal(definition.function.parameters.type, 'object');
    assert.equal(definition.function.parameters.additionalProperties, false);
    assert.ok(Array.isArray(definition.function.parameters.required));
  }
});

test('write_file, read_file, and edit_file round-trip UTF-8 content', async (t) => {
  const root = await makeTempDirectory('workspace-edit-');
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const tools = new WorkspaceTools({ root });

  const written = await expectOk(tools, 'write_file', {
    path: 'nested/hello.txt',
    content: 'alpha\nbeta\ngamma\n',
  });
  assert.equal(written.data.created, true);
  assert.equal(written.data.bytesWritten, Buffer.byteLength('alpha\nbeta\ngamma\n'));

  const read = await expectOk(tools, 'read_file', { path: 'nested/hello.txt' });
  assert.equal(read.data.content, 'alpha\nbeta\ngamma');
  assert.equal(read.data.lineCount, 3);

  const edited = await expectOk(tools, 'edit_file', {
    path: 'nested/hello.txt',
    oldText: 'beta',
    newText: 'BETA',
  });
  assert.equal(edited.data.replacements, 1);
  assert.equal(await fsp.readFile(path.join(root, 'nested', 'hello.txt'), 'utf8'), 'alpha\nBETA\ngamma\n');

  const duplicateFailure = await tools.execute('edit_file', {
    path: 'nested/hello.txt',
    oldText: 'a',
    newText: 'x',
  });
  assert.equal(duplicateFailure.ok, false);

  const replaceAll = await expectOk(tools, 'edit_file', {
    path: 'nested/hello.txt',
    oldText: 'a',
    newText: 'A',
    replaceAll: true,
  });
  assert.equal(replaceAll.data.replacements, 4);
});

test('apply_patch applies standard context-based unified diff hunks', async (t) => {
  const root = await makeTempDirectory('workspace-patch-');
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const tools = new WorkspaceTools({ root });
  await expectOk(tools, 'write_file', { path: 'sample.txt', content: 'alpha\nbeta\ngamma\n' });

  const patch = [
    '--- a/sample.txt',
    '+++ b/sample.txt',
    '@@ -1,3 +1,4 @@',
    ' alpha',
    '-beta',
    '+beta updated',
    '+inserted',
    ' gamma',
    '',
  ].join('\n');
  const result = await expectOk(tools, 'apply_patch', { path: 'sample.txt', patch });
  assert.equal(result.data.hunksApplied, 1);
  assert.equal(result.data.changed, true);
  assert.equal(
    await fsp.readFile(path.join(root, 'sample.txt'), 'utf8'),
    'alpha\nbeta updated\ninserted\ngamma\n',
  );

  const bad = await tools.execute('apply_patch', {
    path: 'sample.txt',
    patch: '@@ -1,1 +1,1 @@\n-not-present\n+wrong\n',
  });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /context did not match/i);
});

test('list_directory and search_text are bounded, skip ignored trees, and redact secrets', async (t) => {
  const root = await makeTempDirectory('workspace-search-');
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const tools = new WorkspaceTools({ root });

  await fsp.mkdir(path.join(root, 'src'), { recursive: true });
  await fsp.mkdir(path.join(root, 'node_modules', 'dependency'), { recursive: true });
  await fsp.writeFile(
    path.join(root, 'src', 'app.js'),
    'const password = "very-secret-value";\nconsole.log("findable needle");\n',
  );
  await fsp.writeFile(path.join(root, 'node_modules', 'dependency', 'index.js'), 'findable needle\n');
  await fsp.writeFile(path.join(root, '.hidden.js'), 'findable needle\n');

  const listed = await expectOk(tools, 'list_directory', {});
  assert.deepEqual(listed.data.entries.map((entry) => entry.name), ['src']);
  assert.equal(listed.data.entries.some((entry) => entry.name === 'node_modules'), false);
  assert.equal(listed.data.entries.some((entry) => entry.name === '.hidden.js'), false);

  const listedHidden = await expectOk(tools, 'list_directory', { includeHidden: true });
  assert.equal(listedHidden.data.entries.some((entry) => entry.name === '.hidden.js'), true);
  assert.equal(listedHidden.data.entries.some((entry) => entry.name === 'node_modules'), false);

  const found = await expectOk(tools, 'find_files', { pattern: '*.js' });
  assert.deepEqual(
    found.data.files.map((file) => file.path).sort(),
    ['.hidden.js', 'src/app.js'],
  );
  assert.equal(found.data.files.some((file) => file.path.includes('node_modules')), false);

  const searched = await expectOk(tools, 'search_text', { query: 'needle', include: '**/*.js' });
  assert.deepEqual(
    searched.data.matches.map((match) => match.path).sort(),
    ['.hidden.js', 'src/app.js'],
  );
  assert.equal(searched.data.matches.some((match) => match.path.includes('node_modules')), false);
  const sourceMatch = searched.data.matches.find((match) => match.path === 'src/app.js');
  assert.equal(sourceMatch.line, 2);

  const secretSearch = await expectOk(tools, 'search_text', { query: 'very-secret-value' });
  assert.equal(secretSearch.data.matches.length, 1);
  assert.doesNotMatch(JSON.stringify(secretSearch.data), /very-secret-value/);
  assert.match(secretSearch.data.matches[0].text, /\[REDACTED\]/);
});

test('symlink escapes are rejected when symbolic links are supported', async (t) => {
  const root = await makeTempDirectory('workspace-link-root-');
  const outside = await makeTempDirectory('workspace-link-outside-');
  t.after(async () => {
    await fsp.rm(root, { recursive: true, force: true });
    await fsp.rm(outside, { recursive: true, force: true });
  });
  await fsp.writeFile(path.join(outside, 'secret.txt'), 'outside');

  const link = path.join(root, 'escape');
  try {
    await fsp.symlink(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) {
      t.skip(`symbolic links are unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  const tools = new WorkspaceTools({ root });
  assert.throws(() => tools.resolveWorkspacePath('escape/secret.txt'), /outside the workspace root/i);
  const result = await tools.execute('read_file', { path: 'escape/secret.txt' });
  assert.equal(result.ok, false);
  assert.match(result.error, /outside the workspace root/i);
});

test('context tools, move, create, delete, and trash return compact workspace data', async (t) => {
  const root = await makeTempDirectory('workspace-context-');
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const trashed = [];
  const tools = new WorkspaceTools({
    root,
    trashItem: async (target) => trashed.push(target),
  });

  await expectOk(tools, 'write_file', {
    path: 'package.json',
    content: '{"name":"fixture"}\n',
  });
  await expectOk(tools, 'write_file', {
    path: 'src/lib.js',
    content: 'export function answer() {\n  return 42;\n}\n',
  });
  await fsp.writeFile(path.join(root, 'binary.dat'), Buffer.from([0, 1, 2, 3, 0]));

  const many = await expectOk(tools, 'read_many_files', { paths: ['package.json', 'src/lib.js'] });
  assert.equal(many.data.files.length, 2);
  assert.equal(many.data.files.every((file) => file.ok), true);

  const info = await expectOk(tools, 'get_file_info', { path: 'package.json' });
  assert.equal(info.data.type, 'file');
  assert.equal(info.data.extension, 'json');

  const binaryRead = await tools.execute('read_file', { path: 'binary.dat' });
  assert.equal(binaryRead.ok, false);
  assert.match(binaryRead.error, /binary/i);

  await expectOk(tools, 'create_directory', { path: 'assets/nested' });
  const moved = await expectOk(tools, 'move_file', { from: 'src/lib.js', to: 'assets/moved.js' });
  assert.equal(moved.data.type, 'file');
  assert.equal(await fsp.readFile(path.join(root, 'assets', 'moved.js'), 'utf8'), 'export function answer() {\n  return 42;\n}\n');

  const symbols = await expectOk(tools, 'find_symbols', { query: 'answer' });
  assert.equal(symbols.data.symbols.length, 1);
  assert.equal(symbols.data.symbols[0].name, 'answer');

  const overview = await expectOk(tools, 'project_overview', { maxFiles: 100 });
  assert.ok(overview.data.fileCount >= 3);
  assert.equal(overview.data.manifests.includes('package.json'), true);
  assert.ok(overview.data.languages.some((language) => language.extension === 'js'));

  const map = await expectOk(tools, 'project_map', { path: 'assets', depth: 2, maxEntries: 20 });
  assert.equal(map.data.entries.some((entry) => entry.path === 'assets/moved.js'), true);

  await expectOk(tools, 'delete_path', { path: 'assets', recursive: true });
  await expectOk(tools, 'delete_path', { path: 'binary.dat' });
  assert.deepEqual(trashed, [
    fs.realpathSync(path.join(root, 'assets')),
    fs.realpathSync(path.join(root, 'binary.dat')),
  ]);

  const definitionNames = tools.definitions('agent').map((definition) => definition.function.name);
  assert.equal(definitionNames.length, 15);
  assert.equal(new Set(definitionNames).size, 15);
});

test('delete_path refuses to delete the workspace root', async (t) => {
  const root = await makeTempDirectory('workspace-delete-');
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  await fsp.writeFile(path.join(root, 'keep.txt'), 'keep');
  const tools = new WorkspaceTools({ root });

  const result = await tools.execute('delete_path', { path: '.', recursive: true });
  assert.equal(result.ok, false);
  assert.match(result.error, /workspace root/i);
  assert.equal(await fsp.readFile(path.join(root, 'keep.txt'), 'utf8'), 'keep');
});
