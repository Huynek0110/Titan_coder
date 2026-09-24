'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');

const {
  McpManager,
  parseSse,
  redact,
} = require('../src/main/core/mcp-manager');

function fakeHttpResponse(body, { status = 200, headers = {} } = {}) {
  return {
    status,
    headers,
    async text() { return body; },
  };
}

function makeFakeStdio(tools = [{ name: 'echo', description: 'Echo text', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false } }]) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.requests = [];
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      for (const line of String(chunk).split(/\r?\n/).filter(Boolean)) {
        const message = JSON.parse(line);
        child.requests.push(message);
        if (message.method === 'initialize') {
          child.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'fake', version: '1' } } })}\n`);
        } else if (message.method === 'tools/list') {
          child.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { tools } })}\n`);
        } else if (message.method === 'tools/call') {
          child.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { content: [
            { type: 'text', text: `echo:${message.params.arguments.text}` },
            { type: 'image', data: 'base64-secret-should-not-pass', mimeType: 'image/png' },
            { type: 'resource', resource: { text: 'resource text' } },
          ] } })}\n`);
        }
        // notifications/initialized intentionally has no response.
      }
      callback();
    },
  });
  child.kill = () => {
    child.killed = true;
    setImmediate(() => {
      child.emit('exit', 0, null);
      child.emit('close', 0, null);
    });
  };
  return child;
}

test('SSE parser handles comments, CRLF, multiline data, and event boundaries', () => {
  const events = parseSse(': keepalive\r\nevent: message\r\ndata: {"a":\r\ndata: 1}\r\nid: 7\r\n\r\n');
  assert.deepEqual(events, [{ event: 'message', data: '{"a":\n1}', id: '7' }]);
});

test('MCP redaction removes secrets from nested values and URLs', () => {
  const value = redact({ headers: { Authorization: 'Bearer abcdefghijklmnop', cookie: 'sid=secret' }, text: 'https://x.test/?access_token=secret-value' });
  assert.equal(value.headers.Authorization, '[REDACTED]');
  assert.equal(value.headers.cookie, '[REDACTED]');
  assert.doesNotMatch(JSON.stringify(value), /abcdefghijklmnop|secret-value|sid=secret/);
});

test('stdio MCP lifecycle exposes safe unique names and shuts down the child', async () => {
  const first = makeFakeStdio();
  const second = makeFakeStdio([{ name: 'odd/name', description: 'Odd', inputSchema: { type: 'string' } }]);
  const children = [first, second];
  const manager = new McpManager({
    spawnImpl: () => children.shift(),
    requestTimeout: 2_000,
  });
  manager.addConfig('a.b', { command: 'fake', args: ['one'] });
  manager.addConfig('a_b', { command: 'fake', args: ['two'] });

  const started = await manager.start();
  assert.equal(started.running, true);
  assert.equal(manager.status().servers['a.b'].status, 'running');
  const definitions = manager.definitions();
  assert.equal(definitions.length, 2);
  assert.equal(new Set(definitions.map((definition) => definition.function.name)).size, 2);
  assert.match(definitions[0].function.name, /^mcp__a_b__/);
  for (const definition of definitions) {
    assert.equal(definition.function.parameters.type, 'object');
    assert.equal(definition.function.parameters.additionalProperties, false);
  }

  const echoDefinition = definitions.find((definition) => definition.function.name.endsWith('__echo'));
  assert.ok(echoDefinition);
  const result = await manager.execute(echoDefinition.function.name, { text: 'hello' });
  assert.equal(result.ok, true);
  assert.match(result.data.text, /echo:hello/);
  assert.match(result.data.text, /resource text/);
  assert.doesNotMatch(JSON.stringify(result.data), /base64-secret-should-not-pass/);
  assert.ok(result.data.content.some((item) => item.summary === '[non-text content omitted]'));

  assert.equal(first.requests[0].method, 'initialize');
  assert.equal(first.requests[0].params.protocolVersion, '2025-06-18');
  assert.ok(first.requests.some((request) => request.method === 'notifications/initialized' && request.id === undefined));
  assert.ok(first.requests.some((request) => request.method === 'tools/list'));
  assert.ok(first.requests.some((request) => request.method === 'tools/call'));

  await manager.stop();
  assert.equal(manager.status().running, false);
  assert.equal(manager.definitions().length, 0);
  assert.equal(manager.status().servers['a.b'].status, 'stopped');
  // The first child is the one assigned to a.b; both were killed by stop().
  assert.equal(manager.status().servers['a.b'].running, false);
});

test('streamable HTTP lifecycle handles JSON, 202 notifications, sessions, and SSE responses', async () => {
  const requests = [];
  let callCount = 0;
  const fetchImpl = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, options, body });
    callCount += 1;
    if (body.method === 'initialize') {
      return fakeHttpResponse(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2025-06-18' } }), { headers: { 'content-type': 'application/json', 'mcp-session-id': 'session-1' } });
    }
    if (body.method === 'notifications/initialized') return fakeHttpResponse('', { status: 202 });
    if (body.method === 'tools/list') {
      return fakeHttpResponse(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { tools: [{ name: 'sseTool', inputSchema: { type: 'object', properties: {} } }] } })}\n\n`, { headers: { 'content-type': 'text/event-stream' } });
    }
    return fakeHttpResponse(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: 'ok' }] } }), { headers: { 'content-type': 'application/json' } });
  };
  const manager = new McpManager({ fetchImpl, requestTimeout: 2_000 });
  manager.addConfig('http', { type: 'http', url: 'https://mcp.example.test/mcp', headers: { 'X-Client': 'test' } });
  await manager.start();
  assert.equal(manager.status().servers.http.status, 'running');
  assert.equal(manager.definitions()[0].function.name, 'mcp__http__sseTool');
  assert.ok(requests.every((request) => request.options.headers['MCP-Protocol-Version'] === '2025-06-18'));
  assert.ok(requests[1].options.headers['Mcp-Session-Id'] === 'session-1');
  const called = await manager.execute('mcp__http__sseTool', {});
  assert.equal(called.ok, true);
  assert.match(called.data.text, /ok/);
  assert.equal(callCount, 4);
  await manager.stop();
});
