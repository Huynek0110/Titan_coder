'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { cleanBaseUrl, parseSseBlock, mergeToolCallFragments } = require('../src/main/core/lmstudio');
const { ToolBroker, parseArguments, compactResult, classifyIntent } = require('../src/main/core/tool-broker');
const { AgentRunner, compactMessages, leakedToolProtocol, stripControlProtocol } = require('../src/main/core/agent-runner');
const { InteractionManager } = require('../src/main/core/interaction-manager');
const { parseFallbackToolCall } = require('../src/main/core/fallback-tool-parser');

test('normalizes LM Studio base URL', () => {
  assert.equal(cleanBaseUrl('localhost:1234'), 'http://localhost:1234/v1');
  assert.equal(cleanBaseUrl('http://127.0.0.1:1234/v1/chat/completions'), 'http://127.0.0.1:1234/v1');
});

test('parses OpenAI SSE payloads', () => {
  assert.deepEqual(parseSseBlock('data: {"choices":[]}'), { choices: [] });
  assert.deepEqual(parseSseBlock('data: [DONE]'), { done: true });
  assert.equal(parseSseBlock('event: ping'), null);
});

test('merges streamed tool call fragments', () => {
  const calls = new Map();
  mergeToolCallFragments(calls, [{ index: 0, id: 'c1', function: { name: 'read_', arguments: '{"path":' } }]);
  mergeToolCallFragments(calls, [{ index: 0, function: { name: 'file', arguments: '"a.js"}' } }]);
  assert.deepEqual(calls.get(0), { id: 'c1', type: 'function', function: { name: 'read_file', arguments: '{"path":"a.js"}' } });
});

test('rejects malformed/non-object tool arguments', () => {
  assert.deepEqual(parseArguments('{"path":"a.js"}'), { path: 'a.js' });
  assert.match(parseArguments('[1,2]').error, /object/);
  assert.match(parseArguments('{bad').error, /JSON/);
});

test('compacts oversized tool results', () => {
  const result = compactResult({ ok: true, summary: 'ok', data: { text: 'x'.repeat(40_000) } });
  assert.equal(result.truncated, true);
  assert.ok(JSON.stringify(result).length < 24_500);
});

test('detects and strips leaked control protocol without executing it', () => {
  const leaked = '<tool_call>{"name":"write_file","arguments":{}}</tool_call>';
  assert.equal(leakedToolProtocol(leaked), true);
  assert.equal(leakedToolProtocol('```json\n{"name":"write_file","arguments":{}}\n```'), true);
  assert.equal(stripControlProtocol(leaked), '{"name":"write_file","arguments":{}}');
});

test('recovers only an exact single Qwen <call> tool wrapper', () => {
  const definitions = [{ function: { name: 'get_current_time' } }];
  const recovered = parseFallbackToolCall('<call>\n{"name":"get_current_time","arguments":{}}\n</call>', definitions);
  assert.equal(recovered.function.name, 'get_current_time');
  assert.deepEqual(JSON.parse(recovered.function.arguments), {});
  assert.equal(parseFallbackToolCall('<call>{"name":"danger","arguments":{}}</call>', definitions), null);
  assert.equal(parseFallbackToolCall('<call>{"tool":"get_current_time","arguments":{}}</call>', definitions), null);
  assert.equal(parseFallbackToolCall('<call>{"name":"get_current_time","arguments":[]}</call>', definitions), null);
  assert.equal(parseFallbackToolCall('<call>bad json</call>', definitions), null);
  assert.equal(parseFallbackToolCall(`<call>${JSON.stringify({ name: 'get_current_time', arguments: { value: 'x'.repeat(20_000) } })}</call>`, definitions), null);
});

test('classifies a debugging request', () => {
  assert.equal(classifyIntent('hãy debug lỗi trong code', 'agent'), 'fix');
});

test('agent asks user and then finishes naturally', async () => {
  const calls = [
    { content: '', toolCalls: [{ id: 'call_1', type: 'function', function: { name: 'ask_user', arguments: '{"question":"Bạn muốn TypeScript hay JavaScript?"}' } }], finishReason: 'tool_calls' },
    { content: 'Mình sẽ dùng TypeScript như bạn đã chọn.', toolCalls: [], finishReason: 'stop' },
  ];
  const lmClient = { chatStream: async () => calls.shift() };
  const broker = { selectDefinitions: () => [], execute: async () => ({ ok: true }) };
  const interactions = new InteractionManager();
  interactions.ask = async () => 'TypeScript';
  const runner = new AgentRunner({
    lmClient,
    broker,
    getSettings: async () => ({ contextChars: 10_000, maxSubagents: 0, maxSteps: 4 }),
    interactionProvider: async (payload) => payload.type === 'ask-user' ? interactions.ask(payload) : false,
  });
  const result = await runner.run({
    session: { workspace: '', messages: [] },
    text: 'Tạo project cho tôi',
    mode: 'agent',
  });
  assert.equal(result.text, 'Mình sẽ dùng TypeScript như bạn đã chọn.');
});

test('interactions do not expose AbortSignal to renderer', async () => {
  const manager = new InteractionManager({ askTimeoutMs: 1000 });
  const controller = new AbortController();
  let event;
  manager.on('request', (value) => { event = value; });
  const promise = manager.ask({ question: 'Tiếp tục?', signal: controller.signal }, controller.signal);
  assert.equal('signal' in event, false);
  manager.respond(event.id, { type: 'ask-user', answer: 'Có' });
  assert.equal(await promise, 'Có');
});

function testToolSource(names = ['read_file', 'write_file'], onExecute = () => {}) {
  const definitions = names.map((name) => ({
    type: 'function',
    function: {
      name,
      parameters: {
        type: 'object',
        properties: name === 'write_file' ? { path: { type: 'string' } } : { path: { type: 'string' } },
        required: ['path'],
        additionalProperties: false,
      },
    },
  }));
  return {
    definitions() { return definitions; },
    async execute(name, args, context) { return onExecute(name, args, context); },
  };
}

test('plan mode rejects a native mutation even when the model asks for one', async () => {
  const calls = [];
  const broker = new ToolBroker({ sources: [testToolSource(['read_file', 'write_file'], (name) => calls.push(name))] });
  const responses = [
    { content: '', toolCalls: [{ id: 'bad-write', type: 'function', function: { name: 'write_file', arguments: '{"path":"x"}' } }] },
    { content: 'Đã phân tích, không thay đổi file.', toolCalls: [] },
  ];
  const runner = new AgentRunner({
    lmClient: { chatStream: async () => responses.shift() },
    broker,
    getSettings: async () => ({ contextChars: 10_000, maxSteps: 3, maxSubagents: 0, approvalMode: 'automatic' }),
  });
  const result = await runner.run({ session: { workspace: 'C:\\workspace', messages: [] }, text: 'fix error in project', mode: 'plan' });
  assert.equal(result.text, 'Đã phân tích, không thay đổi file.');
  assert.deepEqual(calls, []);
});

test('subagents cannot execute a hidden mutation tool', async () => {
  const calls = [];
  const broker = new ToolBroker({ sources: [testToolSource(['read_file', 'write_file'], (name) => calls.push(name))] });
  const responses = [
    { content: '', toolCalls: [{ id: 'hidden-write', type: 'function', function: { name: 'write_file', arguments: '{"path":"x"}' } }] },
    { content: 'Báo cáo read-only.', toolCalls: [] },
  ];
  const runner = new AgentRunner({
    lmClient: { chatStream: async () => responses.shift() },
    broker,
    getSettings: async () => ({ contextChars: 10_000, maxSteps: 3, maxSubagents: 3, approvalMode: 'automatic' }),
  });
  const result = await runner.run({
    session: { workspace: 'C:\\workspace', messages: [] },
    text: 'inspect the project',
    mode: 'plan',
    subagent: { id: 'sub-test', role: 'explorer', task: 'inspect' },
  });
  assert.equal(result.text, 'Báo cáo read-only.');
  assert.deepEqual(calls, []);
});

test('schema compilation failures are fail-closed and use definitions(mode)', async () => {
  const modes = [];
  const calls = [];
  const source = testToolSource(['read_file', 'bad_tool'], (name) => calls.push(name));
  const originalDefinitions = source.definitions;
  source.definitions = function definitions(mode) {
    modes.push(mode);
    return mode === 'agent' ? [...originalDefinitions(), { type: 'function', function: { name: 'bad_schema', parameters: { type: 'not-a-type' } } }] : originalDefinitions();
  };
  const broker = new ToolBroker({ sources: [source] });
  const result = await broker.execute('bad_schema', {}, { allowedNames: ['bad_schema'], allowMutation: false, allowMcp: false });
  assert.equal(result.ok, false);
  assert.equal(calls.length, 0);
  assert.deepEqual(modes, ['agent']);
});

test('core tools enforce their AJV schemas, roles, task count, and reason', async () => {
  const runner = new AgentRunner({
    lmClient: {},
    broker: { execute: async () => ({ ok: true }) },
    getSettings: async () => ({ approvalMode: 'automatic' }),
  });
  const common = { runId: 'r', signal: undefined, mode: 'agent', budget: { subagents: 0, maxSubagents: 3 }, hasWorkspace: false, workspace: '', allowedNames: ['ask_user', 'update_plan', 'spawn_subagents'], allowMutation: true, allowMcp: false };
  const badQuestion = await runner.executeTool({ ...common, call: { id: '1', function: { name: 'ask_user', arguments: '{"question":"Q","unexpected":true}' } } });
  const badPlan = await runner.executeTool({ ...common, call: { id: '2', function: { name: 'update_plan', arguments: '{"summary":"x","steps":[{"title":"t","status":"unknown"}]}' } } });
  const badRole = await runner.executeTool({ ...common, call: { id: '3', function: { name: 'spawn_subagents', arguments: '{"reason":"why","tasks":[{"role":"writer","task":"do"}]}' } } });
  const noReason = await runner.executeTool({ ...common, call: { id: '4', function: { name: 'spawn_subagents', arguments: '{"tasks":[{"role":"explorer","task":"do"}]}' } } });
  const tooMany = await runner.executeTool({ ...common, call: { id: '5', function: { name: 'spawn_subagents', arguments: JSON.stringify({ reason: 'why', tasks: Array.from({ length: 4 }, () => ({ role: 'explorer', task: 'do' })) }) } } });
  for (const value of [badQuestion, badPlan, badRole, noReason, tooMany]) assert.equal(value.ok, false);
});

test('buildConversation removes the just-persisted current user message by content', () => {
  const runner = new AgentRunner({ lmClient: {}, broker: {}, getSettings: async () => ({}) });
  const conversation = runner.buildConversation({
    session: { messages: [{ id: 'old', role: 'user', content: 'same text' }, { id: 'current', role: 'user', content: 'current text' }] },
    text: 'current text',
    attachments: [],
    mode: 'agent',
    workspace: '',
    settings: { contextChars: 10_000 },
    hasWorkspace: false,
  });
  assert.equal(conversation.filter((message) => message.role === 'user' && message.content === 'current text').length, 1);
});

test('malformed protocol is buffered, classified, and never emitted to the renderer', async () => {
  const events = [];
  const responses = [
    { content: '<call>{"name":"read_file","arguments":', toolCalls: [] },
    { content: 'Câu trả lời an toàn.', toolCalls: [] },
  ];
  let generationIndex = 0;
  const runner = new AgentRunner({
    lmClient: { chatStream: async ({ onDelta }) => { if (generationIndex++ === 0) onDelta?.('<call>raw-secret'); return responses.shift(); } },
    broker: { selectDefinitions: () => [], execute: async () => { throw new Error('must not execute'); } },
    getSettings: async () => ({ contextChars: 10_000, maxSteps: 3, maxSubagents: 0 }),
    onEvent: (event) => events.push(event),
  });
  const result = await runner.run({ session: { messages: [] }, text: 'hello', mode: 'agent' });
  assert.equal(result.text, 'Câu trả lời an toàn.');
  assert.equal(events.some((event) => event.classification === 'discarded'), true);
  assert.doesNotMatch(JSON.stringify(events), /<call>|raw-secret|arguments/);
});

test('automatic fallback does not execute mutating tools', async () => {
  const calls = [];
  const broker = new ToolBroker({ sources: [testToolSource(['write_file'], (name) => calls.push(name))] });
  const responses = [
    { content: '```json\n{"name":"write_file","arguments":{"path":"x"}}\n```', toolCalls: [] },
    { content: 'Fallback mutation was rejected.', toolCalls: [] },
  ];
  const runner = new AgentRunner({
    lmClient: { chatStream: async () => responses.shift() },
    broker,
    getSettings: async () => ({ contextChars: 10_000, maxSteps: 3, maxSubagents: 0, approvalMode: 'automatic' }),
  });
  const result = await runner.run({ session: { workspace: 'C:\\workspace', messages: [] }, text: 'implement a change', mode: 'agent' });
  assert.equal(result.text, 'Fallback mutation was rejected.');
  assert.deepEqual(calls, []);
});

test('fallback mutation requires explicit approval in ask mode', async () => {
  let calls = 0;
  let approvals = 0;
  const source = testToolSource(['write_file'], () => { calls += 1; });
  const rejected = new ToolBroker({
    sources: [source],
    interactionProvider: async () => { approvals += 1; return false; },
  });
  const context = { allowedNames: ['write_file'], allowMutation: true, allowMcp: false, approvalMode: 'ask', fallback: true };
  const denied = await rejected.execute('write_file', { path: 'x' }, context);
  assert.equal(denied.ok, false);
  assert.equal(calls, 0);
  assert.equal(approvals, 1);

  const approved = new ToolBroker({
    sources: [source],
    interactionProvider: async () => true,
  });
  const result = await approved.execute('write_file', { path: 'x' }, context);
  assert.equal(result.ok, true);
  assert.equal(calls, 1);
});

test('AbortError from a tool source is rethrown', async () => {
  const abort = new Error('cancelled');
  abort.name = 'AbortError';
  const broker = new ToolBroker({ sources: [testToolSource(['read_file'], () => { throw abort; })] });
  await assert.rejects(
    broker.execute('read_file', { path: 'x' }, { allowedNames: ['read_file'], allowMutation: false, allowMcp: false }),
    (error) => error.name === 'AbortError',
  );
});

test('context compaction bounds the latest input and keeps assistant-tool groups coherent', () => {
  const messages = [
    { role: 'system', content: 'system' },
    { role: 'assistant', tool_calls: [{ id: 'call-1', type: 'function', function: { name: 'read_file', arguments: JSON.stringify({ path: 'a'.repeat(100_000) }) } }] },
    { role: 'tool', tool_call_id: 'call-1', content: 'result '.repeat(50_000) },
    { role: 'user', content: 'current '.repeat(50_000) },
  ];
  const compacted = compactMessages(messages, 6_000, { maxOutputChars: 1_000, toolReserveChars: 1_000 });
  assert.ok(JSON.stringify(compacted).length <= 6_000);
  const current = compacted.findLast?.((message) => message.role === 'user') || compacted.filter((message) => message.role === 'user').at(-1);
  assert.ok(current);
  assert.ok(current.content.length < 100_000);
  const assistantIndex = compacted.findIndex((message) => message.role === 'assistant' && message.tool_calls?.length);
  if (assistantIndex >= 0) assert.equal(compacted[assistantIndex + 1]?.role, 'tool');
});

test('oversized attachments are bounded in the current user turn', () => {
  const runner = new AgentRunner({ lmClient: {}, broker: {}, getSettings: async () => ({}) });
  const conversation = runner.buildConversation({
    session: { messages: [] },
    text: 'inspect',
    attachments: [{ name: 'huge.txt', content: 'x'.repeat(100_000) }],
    mode: 'agent',
    workspace: '',
    settings: { contextChars: 3_000, maxTokens: 256 },
    hasWorkspace: false,
  });
  const user = conversation.filter((message) => message.role === 'user').at(-1);
  assert.ok(user.content.length < 100_000);
  assert.match(user.content, /đã cắt bớt|truncated/i);
});
