'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { InteractionManager } = require('../src/main/core/interaction-manager');

test('approval responses fail closed and require matching type', async () => {
  const manager = new InteractionManager({ approvalTimeoutMs: 1000 });
  let event;
  manager.on('request', (value) => { event = value; });
  const pending = manager.approve({ tool: 'write_file', arguments: { path: 'x' } });
  assert.equal(event.type, 'approval-request');
  assert.equal(manager.respond(event.id, { type: 'ask-user', answer: 'oops' }), false);
  assert.equal(manager.respond(event.id, { type: 'approval-request' }), true);
  assert.equal(await pending, false);

  const approvedManager = new InteractionManager({ approvalTimeoutMs: 1000 });
  let approvedEvent;
  approvedManager.on('request', (value) => { approvedEvent = value; });
  const approved = approvedManager.approve({ tool: 'write_file' });
  assert.equal(approvedManager.respond(approvedEvent.id, { type: 'approval-request', approved: true }), true);
  assert.equal(await approved, true);
});

test('ask responses cannot approve a pending question', async () => {
  const manager = new InteractionManager({ askTimeoutMs: 1000 });
  let event;
  manager.on('request', (value) => { event = value; });
  const pending = manager.ask({ question: 'tiếp?' });
  assert.equal(manager.respond(event.id, { type: 'approval-request', approved: true }), false);
  assert.equal(manager.respond(event.id, { type: 'ask-user', answer: 'tiếp' }), true);
  assert.equal(await pending, 'tiếp');
});
