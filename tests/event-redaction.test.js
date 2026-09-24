'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { safeEventText, eventResult } = require('../src/main/core/tool-broker');

test('tool activity events redact and bound arguments', () => {
  const text = safeEventText({
    command: 'curl.exe -H "Authorization: Bearer abcdefghijklmnop" https://example.com/?api_key=secretvalue',
    content: 'x'.repeat(5000),
  });
  assert.match(text, /\[REDACTED\]/);
  assert.doesNotMatch(text, /abcdefghijklmnop|secretvalue/);
  assert.ok(text.length <= 1600);
});

test('tool result events omit full result data', () => {
  const event = eventResult({ ok: true, summary: 'done', data: { secret: 'do-not-send' } });
  assert.equal(Object.prototype.hasOwnProperty.call(event, 'data'), false);
  assert.equal(event.summary, 'done');
});
