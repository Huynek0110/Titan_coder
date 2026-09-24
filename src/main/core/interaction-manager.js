'use strict';

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

class InteractionManager extends EventEmitter {
  constructor({ askTimeoutMs = 15 * 60_000, approvalTimeoutMs = 5 * 60_000 } = {}) {
    super();
    this.askTimeoutMs = askTimeoutMs;
    this.approvalTimeoutMs = approvalTimeoutMs;
    this.pending = new Map();
  }

  async ask(payload, signal) {
    const answer = await this.request({ type: 'ask-user', ...payload }, signal, this.askTimeoutMs);
    return answer?.answer ?? '';
  }

  async approve(payload, signal) {
    const result = await this.request({ ...payload, type: 'approval-request' }, signal, this.approvalTimeoutMs);
    return result?.approved === true;
  }

  request(payload, signal, timeoutMs) {
    if (signal?.aborted) return Promise.reject(abortError());
    const id = `interaction_${crypto.randomUUID()}`;
    return new Promise((resolve, reject) => {
      let timer;
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        this.pending.delete(id);
      };
      const onAbort = () => {
        cleanup();
        reject(abortError());
      };
      timer = setTimeout(() => {
        cleanup();
        reject(new Error('Người dùng không phản hồi trong thời gian cho phép.'));
      }, timeoutMs);
      const { signal: _privateSignal, ...publicPayload } = payload;
      const expectedType = payload.type === 'ask-user' ? 'ask-user' : 'approval-request';
      signal?.addEventListener('abort', onAbort, { once: true });
      this.pending.set(id, {
        expectedType,
        resolve: (value) => {
          cleanup();
          resolve(value);
        },
        reject: (error) => {
          cleanup();
          reject(error);
        },
      });
      this.emit('request', { ...publicPayload, id, type: expectedType, createdAt: Date.now() });
    });
  }

  respond(id, value) {
    const pending = this.pending.get(id);
    if (!pending) return false;
    if (value?.type !== pending.expectedType) return false;
    if (pending.expectedType === 'ask-user') {
      pending.resolve({ answer: String(value.answer || '').slice(0, 10_000) });
    } else {
      pending.resolve({ approved: value.approved === true });
    }
    return true;
  }

  cancelAll(reason = 'Application closed') {
    for (const [id, pending] of this.pending) {
      pending.reject(new Error(reason));
      this.pending.delete(id);
    }
  }
}

function abortError() {
  const error = new Error('Tương tác đã bị hủy.');
  error.name = 'AbortError';
  return error;
}

module.exports = { InteractionManager };
