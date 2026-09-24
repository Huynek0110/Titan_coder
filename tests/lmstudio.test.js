'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { LMStudioClient, isLoopbackHost, parseSseBlock } = require('../src/main/core/lmstudio');

function sseResponse(events, { keepOpen = false } = {}) {
  const encoder = new TextEncoder();
  let index = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (index < events.length) {
        controller.enqueue(encoder.encode(events[index++]));
        return;
      }
      if (!keepOpen) controller.close();
    },
  });
  return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

test('recognizes local LM Studio hosts and rejects remote by default', async () => {
  assert.equal(isLoopbackHost('localhost'), true);
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('[::1]'), true);
  assert.equal(isLoopbackHost('example.com'), false);
  const client = new LMStudioClient({ getSettings: async () => ({ lmBaseUrl: 'https://example.com/v1' }) });
  await assert.rejects(() => client.settings(), /không cục bộ/i);
});

test('SSE parser recognizes DONE and ignores comment-only events', () => {
  assert.deepEqual(parseSseBlock(': keep-alive'), null);
  assert.deepEqual(parseSseBlock('data: [DONE]'), { done: true });
});

test('status reads the native model list only once', async () => {
  let calls = 0;
  const client = new LMStudioClient({
    getSettings: async () => ({ lmBaseUrl: 'http://127.0.0.1:1234/v1', model: '' }),
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({ models: [{ type: 'llm', key: 'qwen2.5-coder-14b-instruct', display_name: 'Qwen', loaded_instances: [] }] }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const status = await client.getStatus();
  assert.equal(status.online, true);
  assert.equal(status.selectedModel, 'qwen2.5-coder-14b-instruct');
  assert.equal(calls, 1);
});

test('chat stream stops on DONE and returns tool fragments', async () => {
  const client = new LMStudioClient({
    getSettings: async () => ({
      lmBaseUrl: 'http://127.0.0.1:1234/v1',
      model: 'qwen-test',
      temperature: 0,
      topP: 1,
      maxTokens: 100,
      modelTimeoutMs: 30_000,
    }),
    fetchImpl: async () => sseResponse([
      'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n',
      'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"read_file","arguments":"{\\"path\\":\\"a.js\\"}"}}]}}]}\n\n',
      'data: [DONE]\n\n',
    ], { keepOpen: true }),
  });
  const result = await client.chatStream({ messages: [{ role: 'user', content: 'hi' }], tools: [] });
  assert.equal(result.content, 'hello');
  assert.equal(result.toolCalls[0].function.name, 'read_file');
});

test('chat stream fails closed on a malformed SSE event', async () => {
  const client = new LMStudioClient({
    getSettings: async () => ({
      lmBaseUrl: 'http://127.0.0.1:1234/v1', model: 'qwen-test', maxTokens: 32, modelTimeoutMs: 30_000,
    }),
    fetchImpl: async () => sseResponse(['data: {bad}\n\n', 'data: [DONE]\n\n']),
  });
  await assert.rejects(() => client.chatStream({ messages: [{ role: 'user', content: 'hi' }], tools: [] }), /SSE event không hợp lệ/);
});
