'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { ToolBroker } = require('../src/main/core/tool-broker');

test('internal tool metadata is not sent to the model', () => {
  const source = {
    definitions: () => [{
      type: 'function',
      function: { name: 'write_file', description: 'write', parameters: { type: 'object', properties: {}, additionalProperties: false } },
      metadata: { readOnly: false, mutating: true, internal: true },
    }],
    execute: async () => ({ ok: true, summary: 'ok' }),
  };
  const broker = new ToolBroker({ sources: [source] });
  const selected = broker.selectDefinitions('write a file', 'agent');
  assert.equal(selected[0].metadata, undefined);
  assert.equal(selected[0].function.name, 'write_file');
});
