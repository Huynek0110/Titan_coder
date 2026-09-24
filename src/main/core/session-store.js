'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { SAFE_LIMITS } = require('./defaults');

const SESSION_FILE = 'sessions.json';
const SESSION_SCHEMA_VERSION = 1;
const MAX_SESSIONS = SAFE_LIMITS.maxSessions;
const MAX_MESSAGES = SAFE_LIMITS.maxMessagesPerSession;
const MAX_TOOL_DATA_BYTES = SAFE_LIMITS.maxToolDataBytes;
// This file is a bounded convenience snapshot for the UI.  The application's
// in-memory transcript is the source of truth; temp-file rename protects the
// snapshot from partial writes but is not a transaction log or a crash-proof
// multi-step commit protocol.
const DEFAULT_SESSION_MODE = 'chat';
const DEFAULT_SESSION_TITLE = 'Cuộc trò chuyện mới';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function uuid() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `${crypto.randomBytes(16).toString('hex')}-${crypto.randomBytes(8).toString('hex')}`;
}

function now() {
  return new Date().toISOString();
}

function clone(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function cloneSession(value) {
  return decorateSession(clone(value));
}

function textValue(value, fallback = '', maxLength = 4_096) {
  if (typeof value !== 'string') return fallback;
  return value.trim().slice(0, maxLength);
}

function timestamp(value, fallback = now()) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const time = new Date(value);
    return Number.isNaN(time.getTime()) ? fallback : time.toISOString();
  }
  if (typeof value !== 'string') return fallback;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : fallback;
}

function messageTimestamp(value, fallback = now()) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) return value;
  return fallback;
}

function workspaceValue(value) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') {
    const error = new TypeError('workspace must be an absolute path or an empty string');
    error.code = 'INVALID_WORKSPACE';
    throw error;
  }
  const text = value.trim();
  if (!text) return '';
  if (text.length > 4_096 || !path.isAbsolute(text)) {
    const error = new TypeError('workspace must be an absolute path or an empty string');
    error.code = 'INVALID_WORKSPACE';
    throw error;
  }
  return path.normalize(text);
}

function safeDirectory(requested) {
  const candidate = typeof requested === 'string' && requested.trim()
    ? path.resolve(requested)
    : path.join(os.tmpdir(), 'CodePilotLocal', 'sessions');
  try {
    fs.mkdirSync(candidate, { recursive: true });
    fs.accessSync(candidate, fs.constants.R_OK | fs.constants.W_OK);
    return { dir: candidate, fallback: false };
  } catch {
    const fallback = path.join(os.tmpdir(), 'CodePilotLocal', 'sessions');
    try {
      fs.mkdirSync(fallback, { recursive: true });
      return { dir: fallback, fallback: true };
    } catch {
      const emergency = path.join(os.tmpdir(), `CodePilotLocal-sessions-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
      try { fs.mkdirSync(emergency, { recursive: true }); } catch { /* best effort */ }
      return { dir: emergency, fallback: true };
    }
  }
}

function tempName(filePath) {
  return `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
}

async function atomicWriteJson(filePath, value) {
  const temporary = tempName(filePath);
  try {
    const text = `${JSON.stringify(value, null, 2)}\n`;
    await fsp.mkdir(path.dirname(filePath), { recursive: true });
    await fsp.writeFile(temporary, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await fsp.rename(temporary, filePath);
    try { await fsp.chmod(filePath, 0o600); } catch { /* platform dependent */ }
  } catch (error) {
    try { await fsp.unlink(temporary); } catch { /* best effort */ }
    throw error;
  }
}

function utf8Prefix(value, maxBytes) {
  const buffer = Buffer.from(String(value), 'utf8');
  if (buffer.length <= maxBytes) return buffer.toString('utf8');
  let end = maxBytes;
  while (end > 0 && (buffer[end] & 0xc0) === 0x80) end -= 1;
  if (end > 0 && (buffer[end] & 0x80) !== 0) end -= 1;
  return buffer.subarray(0, end).toString('utf8');
}

function cloneBounded(value, depth = 0, seen = new WeakSet()) {
  if (depth > 14) return null;
  if (value === null || value === undefined) return value ?? null;
  const type = typeof value;
  if (type === 'string') return value.length > 1_000_000 ? utf8Prefix(value, 1_000_000) : value;
  if (type === 'number') return Number.isFinite(value) ? value : null;
  if (type === 'boolean') return value;
  if (type === 'bigint') return value.toString();
  if (type !== 'object') return null;

  if (seen.has(value)) return null;
  seen.add(value);
  try {
    if (Buffer.isBuffer(value)) return utf8Prefix(value.toString('utf8'), MAX_TOOL_DATA_BYTES);
    if (value instanceof Date) return value.toISOString();
    if (Array.isArray(value)) {
      return value.slice(0, 500).map((item) => cloneBounded(item, depth + 1, seen));
    }
    const result = {};
    for (const [key, item] of Object.entries(value).slice(0, 500)) {
      if (key === '__proto__' || key === 'prototype' || key === 'constructor') continue;
      result[key] = cloneBounded(item, depth + 1, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

/** Bound a tool result/data value before it is persisted or returned. */
function capToolData(value) {
  const bounded = cloneBounded(value);
  let serialized;
  try { serialized = JSON.stringify(bounded); } catch { return { truncated: true, value: '[unserializable tool data]' }; }
  if (serialized === undefined) return null;
  const bytes = Buffer.byteLength(serialized, 'utf8');
  if (bytes <= MAX_TOOL_DATA_BYTES) return bounded;
  if (typeof bounded === 'string') return utf8Prefix(bounded, MAX_TOOL_DATA_BYTES);
  // Keep a valid JSON document and make the loss of the original shape
  // explicit to consumers.  Escaping a JSON string can expand it, so reduce
  // the payload until the complete wrapper is within the byte cap.
  let payload = utf8Prefix(serialized, Math.max(0, MAX_TOOL_DATA_BYTES - 160));
  let wrapper = { truncated: true, originalBytes: bytes, value: payload };
  while (Buffer.byteLength(JSON.stringify(wrapper), 'utf8') > MAX_TOOL_DATA_BYTES && payload.length > 0) {
    payload = payload.slice(0, Math.max(0, Math.floor(payload.length * 0.75)));
    wrapper = { truncated: true, originalBytes: bytes, value: payload };
  }
  return wrapper;
}

function trimMessages(messages) {
  if (!Array.isArray(messages) || messages.length <= MAX_MESSAGES) return messages;
  const currentIndex = messages.findIndex((message) => message?.current === true);
  if (currentIndex >= 0 && currentIndex < messages.length - MAX_MESSAGES) {
    const current = messages[currentIndex];
    const withoutCurrent = messages.filter((_, index) => index !== currentIndex);
    return withoutCurrent.slice(-(MAX_MESSAGES - 1)).concat(current);
  }
  return messages.slice(-MAX_MESSAGES);
}

function normalizeMessage(value) {
  const source = typeof value === 'string' ? { role: 'assistant', content: value } : (isObject(value) ? value : {});
  const role = textValue(source.role, 'assistant', 64) || 'assistant';
  const content = typeof source.content === 'string'
    ? source.content
    : (source.content === undefined ? '' : source.content);
  const message = { ...source };
  message.id = textValue(source.id, uuid(), 200) || uuid();
  message.role = role;
  message.content = role.toLowerCase() === 'tool' ? capToolData(content) : cloneBounded(content);
  const created = messageTimestamp(source.createdAt ?? source.timestamp);
  message.createdAt = created;
  message.updatedAt = messageTimestamp(source.updatedAt, created);
  delete message.sessionId;
  return message;
}

function normalizeRun(value, kind = 'run') {
  const source = isObject(value) ? value : {};
  const id = textValue(source.id || source.runId || source.toolRunId, uuid(), 200) || uuid();
  const result = { ...source };
  result.id = id;
  if (kind === 'run') {
    result.runId = id;
  } else {
    result.toolRunId = id;
  }
  result.status = textValue(source.status, 'running', 64) || 'running';
  result.startedAt = timestamp(source.startedAt || source.createdAt);
  result.updatedAt = timestamp(source.updatedAt, result.startedAt);

  // Tool payloads can be arbitrarily large.  Cap every common payload field,
  // not just `data`, so an update cannot bypass the bound with `result` or
  // `toolData`.
  for (const field of ['data', 'result', 'output', 'error', 'toolData', 'input', 'arguments', 'response', 'stdout', 'stderr']) {
    if (source[field] !== undefined) result[field] = capToolData(source[field]);
    else delete result[field];
  }
  if (source.data === undefined && source.result !== undefined) result.data = capToolData(source.result);
  return result;
}

function decorateSession(session) {
  if (!session || typeof session !== 'object') return session;
  if (!Object.prototype.hasOwnProperty.call(session, 'sessionId')) {
    Object.defineProperty(session, 'sessionId', {
      configurable: true,
      enumerable: false,
      get() { return this.id; },
      set(value) { this.id = value; },
    });
  }
  return session;
}

function normalizeSession(value) {
  const source = isObject(value) ? value : {};
  const id = textValue(source.id || source.sessionId, uuid(), 200) || uuid();
  const created = timestamp(source.createdAt || source.created);
  let workspace = '';
  try {
    workspace = workspaceValue(source.workspace === undefined ? '' : source.workspace);
  } catch {
    // A malformed persisted workspace should not discard an otherwise valid
    // transcript; an explicit createSession call still rejects it below.
  }
  const session = {
    id,
    workspace,
    mode: textValue(source.mode, DEFAULT_SESSION_MODE, 64) || DEFAULT_SESSION_MODE,
    title: textValue(source.title, DEFAULT_SESSION_TITLE, 300),
    createdAt: created,
    updatedAt: timestamp(source.updatedAt, created),
    messages: [],
    runs: [],
    toolRuns: [],
  };

  const messages = Array.isArray(source.messages) ? source.messages : [];
  session.messages = trimMessages(messages.map(normalizeMessage));
  const runs = Array.isArray(source.runs) ? source.runs : [];
  session.runs = runs.slice(-MAX_MESSAGES).map((run) => normalizeRun(run, 'run'));
  const toolRuns = Array.isArray(source.toolRuns)
    ? source.toolRuns
    : (Array.isArray(source.toolCalls) ? source.toolCalls : []);
  session.toolRuns = toolRuns.slice(-MAX_MESSAGES).map((run) => normalizeRun(run, 'tool'));
  return decorateSession(session);
}

function summarize(session) {
  const messages = Array.isArray(session.messages) ? session.messages : [];
  const runs = Array.isArray(session.runs) ? session.runs : [];
  const toolRuns = Array.isArray(session.toolRuns) ? session.toolRuns : [];
  return decorateSession({
    id: session.id,
    workspace: session.workspace,
    mode: session.mode,
    title: session.title,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    messageCount: messages.length,
    runCount: runs.length,
    toolRunCount: toolRuns.length,
  });
}

class SessionStore {
  constructor(options = {}) {
    const { dir, logger } = isObject(options) ? options : {};
    const selected = safeDirectory(dir);
    this.dir = selected.dir;
    this.usedFallbackDir = selected.fallback;
    this.filePath = path.join(this.dir, SESSION_FILE);
    this.schemaVersion = SESSION_SCHEMA_VERSION;
    this.logger = logger;
    this._data = { version: SESSION_SCHEMA_VERSION, schemaVersion: SESSION_SCHEMA_VERSION, sessions: [] };
    this._loaded = false;
    this._queue = Promise.resolve();
  }

  _enqueue(operation) {
    const run = this._queue.then(operation, operation);
    this._queue = run.catch(() => undefined);
    return run;
  }

  _log(level, ...args) {
    try {
      if (this.logger && typeof this.logger[level] === 'function') this.logger[level](...args);
    } catch {
      // A logger failure must never affect transcript persistence.
    }
  }

  _emptyData() {
    return { version: SESSION_SCHEMA_VERSION, schemaVersion: SESSION_SCHEMA_VERSION, sessions: [] };
  }

  _readDataFromDisk() {
    let text;
    try {
      text = fs.readFileSync(this.filePath, 'utf8');
    } catch (error) {
      if (!error || error.code !== 'ENOENT') this._log('warn', 'Unable to read session store; using an empty store');
      return { data: this._emptyData(), shouldPersist: true };
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      this._log('warn', 'Corrupt session store; starting with an empty store');
      return { data: this._emptyData(), shouldPersist: true };
    }

    const version = isObject(parsed) ? (parsed.version ?? parsed.schemaVersion) : undefined;
    if (version !== undefined && version !== SESSION_SCHEMA_VERSION) {
      this._log('warn', 'Unsupported session store version; starting with an empty store');
      return { data: this._emptyData(), shouldPersist: true };
    }

    let sessions;
    if (Array.isArray(parsed)) sessions = parsed;
    else if (isObject(parsed) && Array.isArray(parsed.sessions)) sessions = parsed.sessions;
    else if (isObject(parsed) && isObject(parsed.session) && !Array.isArray(parsed.session)) sessions = [parsed.session];
    else return { data: this._emptyData(), shouldPersist: true };

    const normalized = [];
    const ids = new Set();
    for (const candidate of sessions) {
      try {
        const session = normalizeSession(candidate);
        if (ids.has(session.id)) continue;
        ids.add(session.id);
        normalized.push(session);
      } catch {
        // Ignore one malformed session and retain the rest.
      }
    }
    this._trimSessions(normalized);
    for (const session of normalized) {
      session.messages = session.messages.slice(-MAX_MESSAGES);
      session.runs = session.runs.slice(-MAX_MESSAGES);
      session.toolRuns = session.toolRuns.slice(-MAX_MESSAGES);
    }
    return {
      data: { version: SESSION_SCHEMA_VERSION, schemaVersion: SESSION_SCHEMA_VERSION, sessions: normalized },
      shouldPersist: false,
    };
  }

  async _loadUnlocked() {
    const result = this._readDataFromDisk();
    this._data = result.data;
    this._loaded = true;
    if (result.shouldPersist) {
      try { await this._writeDataUnlocked(); } catch { this._log('warn', 'Unable to persist recovered session store'); }
    }
    return this;
  }

  async init() {
    return this._enqueue(() => this._loadUnlocked());
  }

  async load() {
    return this._enqueue(() => this._loadUnlocked());
  }

  async _writeDataUnlocked() {
    const document = {
      version: SESSION_SCHEMA_VERSION,
      schemaVersion: SESSION_SCHEMA_VERSION,
      sessions: this._data.sessions,
    };
    await atomicWriteJson(this.filePath, document);
  }

  async save() {
    return this._enqueue(async () => {
      await this._writeDataUnlocked();
      return this;
    });
  }

  async flush() {
    await this._queue;
    return this;
  }

  _findIndex(id) {
    if (typeof id !== 'string' || !id) return -1;
    return this._data.sessions.findIndex((session) => session.id === id || session.sessionId === id);
  }

  _requireSession(id) {
    const index = this._findIndex(id);
    if (index < 0) {
      const error = new Error(`Session not found: ${id}`);
      error.code = 'SESSION_NOT_FOUND';
      throw error;
    }
    return { index, session: this._data.sessions[index] };
  }

  _touch(session) {
    session.updatedAt = now();
  }

  _trimSessions(sessions = this._data.sessions) {
    if (sessions.length <= MAX_SESSIONS) return;
    // Array order is creation order.  Timestamp sorting keeps an explicitly
    // touched session alive, while stable sorting handles equal timestamps.
    const ordered = sessions.map((session, index) => ({ session, index }));
    ordered.sort((a, b) => {
      const at = Date.parse(a.session.updatedAt || a.session.createdAt || '') || 0;
      const bt = Date.parse(b.session.updatedAt || b.session.createdAt || '') || 0;
      return at === bt ? a.index - b.index : at - bt;
    });
    const keep = ordered.slice(-MAX_SESSIONS).sort((a, b) => a.index - b.index).map((item) => item.session);
    sessions.splice(0, sessions.length, ...keep);
  }

  async listSessions() {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      return this._data.sessions
        .slice()
        .sort((a, b) => {
          const at = Date.parse(a.updatedAt || a.createdAt || '') || 0;
          const bt = Date.parse(b.updatedAt || b.createdAt || '') || 0;
          return bt - at;
        })
        .map(summarize);
    });
  }

  async getSession(id) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const index = this._findIndex(id);
      return index < 0 ? null : cloneSession(this._data.sessions[index]);
    });
  }

  async get(id) {
    return this.getSession(id);
  }

  async list() {
    return this.listSessions();
  }

  async createSession(options = {}) {
    const { workspace = '', mode = DEFAULT_SESSION_MODE, title = DEFAULT_SESSION_TITLE } = isObject(options) ? options : {};
    const normalizedWorkspace = workspaceValue(workspace);
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const timestampValue = now();
      const session = normalizeSession({
        id: uuid(),
        workspace: normalizedWorkspace,
        mode,
        title,
        createdAt: timestampValue,
        updatedAt: timestampValue,
        messages: [],
        runs: [],
        toolRuns: [],
      });
      this._data.sessions.push(session);
      this._trimSessions();
      await this._writeDataUnlocked();
      return cloneSession(session);
    });
  }

  async appendMessage(sessionOrId, messageOrRole, content, extra) {
    let id = sessionOrId;
    let message;
    if (isObject(sessionOrId) && (sessionOrId.sessionId || sessionOrId.id)) {
      const options = sessionOrId;
      id = options.sessionId || options.id;
      message = options.message || options;
    } else if (typeof messageOrRole === 'string' && arguments.length >= 3) {
      message = { role: messageOrRole, content, ...(isObject(extra) ? extra : {}) };
    } else {
      message = messageOrRole;
    }

    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const { session } = this._requireSession(id);
      const normalized = normalizeMessage(message);
      session.messages.push(normalized);
      // The newly appended message is always the current/last message.  Old
      // messages are removed first when the per-session cap is exceeded.
      session.messages = trimMessages(session.messages);
      this._touch(session);
      await this._writeDataUnlocked();
      return cloneSession(session);
    });
  }

  async updateTitle(id, title) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const { session } = this._requireSession(id);
      if (typeof title !== 'string') throw new TypeError('title must be a string');
      session.title = title.trim().slice(0, 300);
      this._touch(session);
      await this._writeDataUnlocked();
      return cloneSession(session);
    });
  }

  _entityArguments(entityOrId, patch, kind) {
    let id = entityOrId;
    let update = patch;
    if (isObject(entityOrId)) {
      update = entityOrId;
      id = entityOrId.id || entityOrId.runId || entityOrId.toolRunId;
      if (!id && kind === 'run') id = entityOrId.runId;
      if (!id && kind === 'tool') id = entityOrId.toolRunId;
    }
    if (update === undefined || update === null) update = {};
    if (typeof update === 'string' || Buffer.isBuffer(update) || update instanceof Uint8Array) {
      update = { data: update };
    } else if (Array.isArray(update)) {
      update = { data: update };
    }
    if (typeof update !== 'object' || update === null || Array.isArray(update)) {
      throw new TypeError('run update must be an object');
    }
    return { id: id ? String(id) : null, update: { ...update } };
  }

  _updateEntity(id, entityOrId, patch, kind) {
    const collection = kind === 'run' ? 'runs' : 'toolRuns';
    const args = this._entityArguments(entityOrId, patch, kind);
    const entityId = args.id || uuid();
    const sessionIndex = this._findSessionIndex(id);
    if (sessionIndex < 0) {
      const error = new Error(`Session not found: ${id}`);
      error.code = 'SESSION_NOT_FOUND';
      throw error;
    }
    const session = this._data.sessions[sessionIndex];
    const existingIndex = session[collection]
      .findIndex((item) => item.id === entityId || item.runId === entityId || item.toolRunId === entityId);
    let normalized;
    if (existingIndex >= 0) {
      const merged = { ...session[collection][existingIndex], ...args.update, id: entityId };
      delete merged.__proto__;
      session[collection][existingIndex] = normalizeRun(merged, kind === 'run' ? 'run' : 'tool');
      normalized = session[collection][existingIndex];
    } else {
      // A patch with a concrete id is allowed to create a run (useful when a
      // caller persists an id assigned by an external runner).  A missing id
      // also gets a fresh UUID rather than being silently dropped.
      normalized = normalizeRun({ ...args.update, id: entityId }, kind === 'run' ? 'run' : 'tool');
      session[collection].push(normalized);
      if (session[collection].length > MAX_MESSAGES) session[collection].splice(0, session[collection].length - MAX_MESSAGES);
    }
    this._touch(session);
    return normalized;
  }

  _findSessionIndex(id) {
    return this._findIndex(id);
  }

  async updateRun(sessionId, runIdOrPatch, patch) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const run = this._updateEntity(sessionId, runIdOrPatch, patch, 'run');
      await this._writeDataUnlocked();
      return clone(run);
    });
  }

  async updateToolRun(sessionId, toolRunIdOrPatch, patch) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const run = this._updateEntity(sessionId, toolRunIdOrPatch, patch, 'tool');
      await this._writeDataUnlocked();
      return clone(run);
    });
  }

  async listRuns(sessionId) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const index = this._findIndex(sessionId);
      if (index < 0) return [];
      return clone(this._data.sessions[index].runs);
    });
  }

  async listToolRuns(sessionId) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const index = this._findIndex(sessionId);
      if (index < 0) return [];
      return clone(this._data.sessions[index].toolRuns);
    });
  }

  async delete(id) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const index = this._findIndex(id);
      if (index < 0) return false;
      this._data.sessions.splice(index, 1);
      await this._writeDataUnlocked();
      return true;
    });
  }

  async deleteSession(id) {
    return this.delete(id);
  }
}

SessionStore.SESSION_FILE = SESSION_FILE;
SessionStore.SESSION_SCHEMA_VERSION = SESSION_SCHEMA_VERSION;
SessionStore.MAX_SESSIONS = MAX_SESSIONS;
SessionStore.MAX_MESSAGES = MAX_MESSAGES;
SessionStore.MAX_TOOL_DATA_BYTES = MAX_TOOL_DATA_BYTES;
SessionStore.DEFAULT_SESSION_MODE = DEFAULT_SESSION_MODE;
SessionStore.DEFAULT_SESSION_TITLE = DEFAULT_SESSION_TITLE;
SessionStore.atomicWriteJson = atomicWriteJson;
SessionStore.capToolData = capToolData;
module.exports = SessionStore;
module.exports.SessionStore = SessionStore;
module.exports.default = SessionStore;
module.exports.SESSION_FILE = SESSION_FILE;
module.exports.SESSION_SCHEMA_VERSION = SESSION_SCHEMA_VERSION;
module.exports.MAX_SESSIONS = MAX_SESSIONS;
module.exports.MAX_MESSAGES = MAX_MESSAGES;
module.exports.MAX_TOOL_DATA_BYTES = MAX_TOOL_DATA_BYTES;
module.exports.DEFAULT_SESSION_MODE = DEFAULT_SESSION_MODE;
module.exports.DEFAULT_SESSION_TITLE = DEFAULT_SESSION_TITLE;
module.exports.capToolData = capToolData;
