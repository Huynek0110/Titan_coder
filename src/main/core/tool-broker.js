'use strict';

const Ajv = require('ajv');

const MAX_ARGUMENT_CHARS = 32_000;
const MAX_RESULT_CHARS = 24_000;

// This is deliberately a conservative fallback catalogue.  Definitions may
// provide more precise metadata (the system tools do), but the names keep the
// broker safe for older/third-party sources which do not publish metadata.
const MUTATING_TOOLS = new Set([
  'write_file', 'edit_file', 'apply_patch', 'create_directory', 'move_file', 'delete_path',
  'run_command', 'start_process', 'stop_process', 'run_test', 'run_lint', 'run_format',
  'open_path', 'project_memory', 'http_request',
]);

const CORE_CONTROL_TOOLS = new Set(['ask_user', 'update_plan', 'spawn_subagents']);
const KNOWN_READ_ONLY_TOOLS = new Set([
  'list_directory', 'find_files', 'read_file', 'read_many_files', 'search_text', 'get_file_info',
  'project_overview', 'find_symbols', 'project_map', 'git_status', 'git_diff', 'git_log',
  'git_blame', 'list_project_tasks', 'read_process', 'list_processes', 'system_info', 'current_time',
  'web_search', 'web_fetch',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringify(value) {
  try {
    const result = JSON.stringify(value);
    return typeof result === 'string' ? result : '';
  } catch {
    return '';
  }
}

function metadataFor(definition) {
  const metadata = definition?.metadata;
  if (isObject(metadata)) return metadata;
  const functionMetadata = definition?.function?.metadata;
  return isObject(functionMetadata) ? functionMetadata : {};
}

function isMcpTool(name, definition = null) {
  const metadata = metadataFor(definition);
  return metadata.mcp === true || /^mcp__/i.test(String(name || ''));
}

/**
 * Return whether a tool can change the workspace, process state, or external
 * state.  Unknown tools are treated as mutating; a source can explicitly mark
 * a tool read-only, but silence is not an authorization.
 */
function isMutatingTool(name, definition = null) {
  const metadata = metadataFor(definition);
  const toolName = String(name || '');
  if (CORE_CONTROL_TOOLS.has(toolName)) return false;
  if (MUTATING_TOOLS.has(toolName)) return true;
  if (metadata.mutating === true) return true;
  if (metadata.readOnly === true) return false;
  if (metadata.readOnly === false) return true;
  return !KNOWN_READ_ONLY_TOOLS.has(toolName);
}

function isReadOnlyTool(name, definition = null) {
  if (isMcpTool(name, definition)) return false;
  if (isMutatingTool(name, definition)) return false;
  const metadata = metadataFor(definition);
  if (metadata.readOnly === true) return true;
  if (metadata.readOnly === false || metadata.mutating === true) return false;
  return !isMcpTool(name, definition);
}

function toolRisk(name, definition = null) {
  const mcp = isMcpTool(name, definition);
  const mutating = isMutatingTool(name, definition);
  return { mcp, mutating, readOnly: !mcp && !mutating && isReadOnlyTool(name, definition) };
}

function parseArguments(raw) {
  if (raw == null || raw === '') return {};
  if (typeof raw === 'object') {
    if (Array.isArray(raw)) return { error: 'Tool arguments phải là object JSON, không phải array.' };
    let serialized;
    try { serialized = JSON.stringify(raw); } catch (error) {
      return { error: `Tool arguments không serialize được: ${error.message}` };
    }
    if (typeof serialized !== 'string') return { error: 'Tool arguments không serialize được.' };
    if (serialized.length > MAX_ARGUMENT_CHARS) {
      return { error: `Tool arguments vượt quá ${MAX_ARGUMENT_CHARS} ký tự.` };
    }
    try {
      return JSON.parse(serialized);
    } catch (error) {
      return { error: `Tool arguments không serialize được: ${error.message}` };
    }
  }
  if (typeof raw !== 'string') return { error: 'Tool arguments phải là object JSON.' };
  const text = raw.trim();
  if (text.length > MAX_ARGUMENT_CHARS) return { error: `Tool arguments vượt quá ${MAX_ARGUMENT_CHARS} ký tự.` };
  if (!text) return {};
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    return { error: `JSON arguments không hợp lệ: ${error.message}` };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { error: 'Tool arguments phải là JSON object, không phải array hoặc scalar.' };
  }
  // Pretty-printed object arguments can be short as input but large after
  // serialization.  Apply the same cap to both representations.
  const serialized = stringify(value);
  if (!serialized) return { error: 'Tool arguments không serialize được.' };
  if (serialized.length > MAX_ARGUMENT_CHARS) {
    return { error: `Tool arguments vượt quá ${MAX_ARGUMENT_CHARS} ký tự.` };
  }
  return value;
}

function compactResult(result) {
  const value = isObject(result)
    ? result
    : { ok: true, summary: String(result ?? ''), data: result };
  const envelope = {
    ok: Boolean(value.ok),
    summary: String(value.summary || (value.ok === false ? 'Tool failed' : 'Tool completed')).slice(0, 800),
  };
  if (value.error !== undefined && value.error !== null) envelope.error = String(value.error).slice(0, 2000);
  if (Object.prototype.hasOwnProperty.call(value, 'data')) envelope.data = value.data;
  if (value.truncated !== undefined) envelope.truncated = Boolean(value.truncated);
  if (value.exitCode !== undefined) envelope.exitCode = value.exitCode;
  if (value.timedOut !== undefined) envelope.timedOut = Boolean(value.timedOut);

  let serialized = stringify(envelope);
  if (serialized && serialized.length <= MAX_RESULT_CHARS) return envelope;

  // Keep a valid JSON envelope below the hard limit.  A data preview is safer
  // than returning a half-serialized object to the model or renderer.
  let previewLimit = Math.max(256, Math.floor(MAX_RESULT_CHARS * 0.72));
  let compact;
  for (;;) {
    compact = {
      ok: envelope.ok,
      summary: envelope.summary,
      ...(envelope.error === undefined ? {} : { error: envelope.error }),
      truncated: true,
      dataPreview: serialized.slice(0, previewLimit),
    };
    const compactSerialized = stringify(compact);
    if (compactSerialized.length <= MAX_RESULT_CHARS) return compact;
    if (previewLimit <= 128) break;
    previewLimit = Math.floor(previewLimit * 0.7);
  }
  return {
    ok: envelope.ok,
    summary: envelope.summary.slice(0, 400),
    truncated: true,
    dataPreview: '',
  };
}

function editDistance(a, b) {
  const rows = Array.from({ length: a.length + 1 }, (_, index) => [index]);
  for (let column = 0; column <= b.length; column += 1) rows[0][column] = column;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return rows[a.length][b.length];
}

function nearestNames(name, candidates, limit = 3) {
  const needle = String(name || '');
  return candidates
    .map((candidate) => ({ candidate, distance: editDistance(needle.toLowerCase(), String(candidate).toLowerCase()) }))
    .sort((a, b) => a.distance - b.distance)
    .slice(0, limit)
    .map(({ candidate }) => candidate);
}

function classifyIntent(text, mode) {
  const value = String(text || '').toLowerCase();
  if (mode === 'chat' && !/project|repo|code|file|folder|bug|test|lỗi|mã|thư mục|tệp|repo|compile|build|install|git/.test(value)) {
    return 'conversation';
  }
  if (/plan|roadmap|architecture|thiết kế|kế hoạch|lộ trình|so sánh|review source/.test(value)) return 'plan';
  if (/test|kiểm thử|coverage|pass|fail|build|lint|format|compile/.test(value)) return 'test';
  if (/search|internet|web|documentation|docs|tài liệu|latest|newest|hiện tại|tin tức|github/.test(value)) return 'web';
  if (/fix|debug|error|bug|lỗi|sửa|diagnos|stack trace|crash/.test(value)) return 'fix';
  if (/implement|create|add|build|write|refactor|rename|migrate|viết|thêm|tạo|sửa|refactor|chuyển/.test(value)) return 'edit';
  return 'explain';
}

const INTENT_TOOLS = {
  conversation: ['system_info', 'current_time', 'web_search', 'web_fetch', 'project_memory'],
  web: ['web_search', 'web_fetch', 'http_request', 'current_time', 'project_memory'],
  explain: ['project_overview', 'project_map', 'list_directory', 'find_files', 'search_text', 'read_file', 'find_symbols', 'read_many_files'],
  plan: ['project_overview', 'project_map', 'find_files', 'search_text', 'read_file', 'read_many_files', 'find_symbols', 'git_status', 'git_diff', 'list_project_tasks'],
  test: ['project_overview', 'list_project_tasks', 'read_file', 'search_text', 'run_test', 'run_lint', 'git_diff', 'git_status'],
  fix: ['project_overview', 'search_text', 'read_file', 'edit_file', 'apply_patch', 'run_test'],
  edit: ['project_overview', 'search_text', 'read_file', 'edit_file', 'write_file', 'run_test'],
};

function isMcpSource(source) {
  return Boolean(source && (
    source.isMcp === true
    || source.kind === 'mcp'
    || source.type === 'mcp'
    || /McpManager/i.test(source.constructor?.name || '')
  ));
}

function safeEventText(value, maximum = 1600) {
  let text = stringify(value);
  if (!text) text = String(value ?? '');
  text = text
    .replace(/(bearer\s+)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/((?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=]\s*)[^,}\s]+/gi, '$1[REDACTED]')
    .replace(/([?&](?:token|api[_-]?key|key|secret|password)=)[^&#\s]+/gi, '$1[REDACTED]');
  return text.length > maximum ? `${text.slice(0, maximum - 1)}…` : text;
}

function safeEventArguments(value, depth = 0, seen = new WeakSet()) {
  if (depth > 3) return '[arguments nested too deeply]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return safeEventText(value, 800);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value !== 'object') return safeEventText(String(value), 800);
  if (seen.has(value)) return '[circular arguments]';
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.slice(0, 30).map((item) => safeEventArguments(item, depth + 1, seen));
    const output = {};
    for (const [key, item] of Object.entries(value).slice(0, 40)) {
      if (['authorization', 'cookie', 'set-cookie', 'password', 'passwd', 'secret', 'token', 'apikey', 'api_key', 'access_token', 'refresh_token', 'client_secret', 'private_key'].includes(key.toLowerCase())) {
        output[key] = '[REDACTED]';
      } else {
        output[key] = safeEventArguments(item, depth + 1, seen);
      }
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

function eventResult(envelope) {
  const result = {
    ok: Boolean(envelope?.ok),
    summary: String(envelope?.summary || '').slice(0, 800),
  };
  if (envelope?.error) result.error = String(envelope.error).slice(0, 1200);
  if (envelope?.truncated !== undefined) result.truncated = Boolean(envelope.truncated);
  if (envelope?.exitCode !== undefined) result.exitCode = envelope.exitCode;
  if (envelope?.timedOut !== undefined) result.timedOut = Boolean(envelope.timedOut);
  return result;
}

function approvalRequired(mode) {
  return ['ask', 'manual', 'always'].includes(String(mode || '').toLowerCase());
}

function modelDefinition(definition) {
  if (!definition || !Object.prototype.hasOwnProperty.call(definition, 'metadata')) return definition;
  const { metadata: _internalMetadata, ...publicDefinition } = definition;
  return publicDefinition;
}

function abortError(message = 'Tool execution was aborted.') {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

class ToolBroker {
  constructor({ sources = [], onEvent = () => {}, interactionProvider = null } = {}) {
    this.sources = Array.isArray(sources) ? sources.filter(Boolean) : [];
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.interactionProvider = typeof interactionProvider === 'function' ? interactionProvider : null;
    this.entries = new Map();
    this.validators = new Map();
    this.refresh();
  }

  setSources(sources) {
    this.sources = Array.isArray(sources) ? sources.filter(Boolean) : [];
    this.refresh();
  }

  _notice(event) {
    try { this.onEvent(event); } catch { /* event delivery must not make the broker executable */ }
  }

  _definitions(source, mode, register = false) {
    try {
      const value = source?.definitions?.(mode);
      const definitions = Array.isArray(value) ? value : [];
      if (register) {
        for (const definition of definitions) this._registerDefinition(source, definition, mode);
      }
      return definitions;
    } catch (error) {
      this._notice({ type: 'notice', level: 'error', message: `Không tải được danh sách tool: ${error.message}` });
      return [];
    }
  }

  _registerDefinition(source, definition, mode = 'agent') {
    const fn = definition?.function;
    if (!fn || typeof fn.name !== 'string' || !fn.name.trim()) return;
    const name = fn.name.trim();
    const modeValue = String(mode || 'agent').toLowerCase();
    const selectedMode = ['chat', 'plan', 'agent'].includes(modeValue) ? modeValue : 'agent';
    const existing = this.entries.get(name);
    const priorRecord = existing?.validatorsByMode?.get(selectedMode);
    if (priorRecord && !priorRecord.schemaError) return;
    const entry = existing || {
      name,
      validatorsByMode: new Map(),
      defaultMode: selectedMode,
      source,
      definition,
      mode: selectedMode,
      validator: null,
      schemaError: null,
    };
    const record = { source, definition, mode: selectedMode, validator: null, schemaError: null };
    try {
      const schema = fn.parameters === undefined
        ? { type: 'object', properties: {}, additionalProperties: false }
        : fn.parameters;
      const ajv = new Ajv({ allErrors: true, strict: false, allowUnionTypes: true });
      record.validator = ajv.compile(schema);
    } catch (error) {
      // Keep a tombstone so execute() can fail closed and callers can explain
      // why the tool is unavailable.  A schema compiler error must never turn
      // into an unvalidated source call.
      record.schemaError = error;
      this._notice({ type: 'notice', level: 'error', message: `Schema tool ${name} không hợp lệ: ${error.message}` });
    }
    entry.validatorsByMode.set(selectedMode, record);
    if (!existing || selectedMode === 'agent' || entry.defaultMode === selectedMode) {
      entry.source = source;
      entry.definition = definition;
      entry.mode = selectedMode;
      entry.validator = record.validator;
      entry.schemaError = record.schemaError;
      entry.defaultMode = selectedMode;
      if (record.validator) this.validators.set(name, record.validator);
      else this.validators.delete(name);
    }
    this.entries.set(name, entry);
  }

  _recordForMode(entry, mode = 'agent') {
    if (!entry) return null;
    const modeValue = String(mode || 'agent').toLowerCase();
    const selectedMode = ['chat', 'plan', 'agent'].includes(modeValue) ? modeValue : 'agent';
    return entry.validatorsByMode?.get(selectedMode)
      || (entry.mode === selectedMode ? entry : null)
      || entry;
  }

  refresh(mode = 'agent') {
    const modeValue = String(mode || 'agent').toLowerCase();
    const selectedMode = ['chat', 'plan', 'agent'].includes(modeValue) ? modeValue : 'agent';
    this.entries.clear();
    this.validators.clear();
    for (const source of this.sources) {
      for (const definition of this._definitions(source, selectedMode)) {
        this._registerDefinition(source, definition, selectedMode);
      }
    }
  }

  _hasValidEntry(name, definition = null, mode = 'agent') {
    const entry = this.entries.get(name);
    if (!entry) return false;
    const record = this._recordForMode(entry, mode);
    return Boolean(record && !record.schemaError && typeof record.validator === 'function');
  }

  _usableDefinitions(definitions, mode = 'agent') {
    return definitions.filter((definition) => {
      const name = definition?.function?.name;
      if (!name) return false;
      const entry = this.entries.get(name);
      if (!entry) return false;
      const record = this._recordForMode(entry, mode);
      return Boolean(record && !record.schemaError && typeof record.validator === 'function');
    });
  }

  allDefinitions(mode = 'agent') {
    const modeValue = String(mode || 'agent').toLowerCase();
    const selectedMode = ['chat', 'plan', 'agent'].includes(modeValue) ? modeValue : 'agent';
    const definitions = [];
    const seen = new Set();
    for (const source of this.sources) {
      for (const definition of this._usableDefinitions(this._definitions(source, selectedMode, true), selectedMode)) {
        const name = definition?.function?.name;
        if (!name || seen.has(name)) continue;
        if (selectedMode !== 'agent' && (isMutatingTool(name, definition) || isMcpTool(name, definition))) continue;
        seen.add(name);
        definitions.push(modelDefinition(definition));
      }
    }
    return definitions;
  }

  selectDefinitions(text, mode = 'agent', options = {}) {
    const modeValue = String(mode || 'agent').toLowerCase();
    const selectedMode = ['chat', 'plan', 'agent'].includes(modeValue) ? modeValue : 'agent';
    const intent = classifyIntent(text, selectedMode);
    const preferred = [...(INTENT_TOOLS[intent] || INTENT_TOOLS.explain)];
    if (selectedMode === 'plan' || options.subagent) {
      // Do not append blocked tools while iterating the same array.  The old
      // implementation accidentally retained run_test/edit tools in plan mode.
      for (let index = preferred.length - 1; index >= 0; index -= 1) {
        if (isMutatingTool(preferred[index]) || isMcpTool(preferred[index])) preferred.splice(index, 1);
      }
    }
    if (options.subagent) {
      preferred.push(
        'project_overview', 'project_map', 'list_directory', 'find_files', 'search_text', 'read_file',
        'read_many_files', 'find_symbols', 'git_status', 'git_diff', 'git_log', 'list_project_tasks',
        'web_search', 'web_fetch',
      );
    }
    const maxTools = Math.max(4, Math.min(Number(options.maxTools || (selectedMode === 'chat' ? 5 : 9)), 14));
    const definitionsBySource = new Map();
    const definitionsFor = (source) => {
      if (!definitionsBySource.has(source)) {
        definitionsBySource.set(source, this._usableDefinitions(this._definitions(source, selectedMode, true), selectedMode));
      }
      return definitionsBySource.get(source);
    };
    const byName = new Map();
    for (const source of this.sources) {
      for (const definition of definitionsFor(source)) {
        const fn = definition?.function;
        if (fn?.name && !byName.has(fn.name)) byName.set(fn.name, definition);
      }
    }
    const selected = [];
    const seen = new Set();
    const add = (definition) => {
      const name = definition?.function?.name;
      if (!name || seen.has(name) || !this._hasValidEntry(name, definition, selectedMode)) return;
      if (selectedMode !== 'agent' && (isMutatingTool(name, definition) || isMcpTool(name, definition))) return;
      if (options.subagent && (isMutatingTool(name, definition) || isMcpTool(name, definition))) return;
      if (selected.length >= maxTools + (options.includeMcp ? 3 : 0)) return;
      selected.push(modelDefinition(definition));
      seen.add(name);
    };
    for (const name of preferred) add(byName.get(name));
    if (options.includeMcp && selectedMode !== 'plan' && !options.subagent) {
      for (const source of this.sources.filter(isMcpSource)) {
        for (const definition of definitionsFor(source)) add(definition);
      }
    }
    return selected.slice(0, maxTools + (options.includeMcp ? 3 : 0));
  }

  getEntry(name) {
    return this.entries.get(String(name || ''));
  }

  requiresApproval(name, mode, definition = this.getEntry(name)?.definition || null) {
    if (!approvalRequired(mode)) return false;
    return isMutatingTool(name, definition) || isMcpTool(name, definition);
  }

  _capabilityAllowed(name, entry, context) {
    const allowedNames = context.allowedNames;
    if (allowedNames !== undefined && allowedNames !== null) {
      const permitted = allowedNames instanceof Set
        ? allowedNames.has(String(name))
        : (Array.isArray(allowedNames) && allowedNames.includes(String(name)));
      if (!permitted) {
        return { ok: false, error: `Tool “${name}” không nằm trong allowlist của lượt này.` };
      }
    }
    const risk = toolRisk(name, entry.definition);
    const mode = String(context.mode || 'agent').toLowerCase();
    if (risk.mutating && (mode !== 'agent' || context.subagentId)) {
      return { ok: false, error: `Mutation bị chặn: ${name} chỉ được chạy trong Agent mode.` };
    }
    if (context.fallback === true && (risk.mutating || risk.mcp)
      && context.allowFallbackTools !== true
      && !approvalRequired(context.approvalMode)) {
      return { ok: false, error: 'Fallback tool cần allowFallbackTools=true hoặc approval mode ask.' };
    }
    // Mutation authority is explicit. A read-only call can use the broker
    // without extra ceremony; a mutating name needs allowMutation=true (or
    // the separately-approved ask-mode fallback path).
    const approvalMode = String(context.approvalMode || 'automatic').toLowerCase();
    const allowMutation = context.allowMutation === true
      || (context.fallback === true && approvalRequired(approvalMode) && context.allowMutation !== false);
    if (risk.mutating && !allowMutation) {
      return { ok: false, error: `Mutation bị chặn: ${name} không được phép trong ngữ cảnh này.` };
    }
    const allowMcp = context.allowMcp === true;
    const planMode = String(context.mode || '').toLowerCase() === 'plan' || Boolean(context.subagentId);
    if (risk.mcp && (!allowMcp || planMode)) {
      return { ok: false, error: `MCP bị chặn: ${name} không được phép trong ngữ cảnh này.` };
    }
    if (planMode && risk.mutating) {
      return { ok: false, error: `Plan mode không được thay đổi trạng thái bằng ${name}.` };
    }
    return { ok: true };
  }

  async execute(name, rawArguments, context = {}) {
    const safeContext = isObject(context) ? context : {};
    const emit = (event) => this._notice({
      ...event,
      runId: safeContext.runId,
      subagentId: safeContext.subagentId,
      parentId: safeContext.eventParentId || null,
    });
    if (safeContext.signal?.aborted) throw abortError();
    const parsed = parseArguments(rawArguments);
    if (parsed.error) return compactResult({ ok: false, summary: 'Tool arguments không hợp lệ', error: parsed.error });
    const entry = this.getEntry(name);
    if (!entry) {
      const suggestions = nearestNames(name, [...this.entries.keys()]);
      return compactResult({ ok: false, summary: `Không có tool “${name}”`, error: `Tool không tồn tại. Các tool gần giống: ${suggestions.join(', ') || 'không có'}.` });
    }
    const modeValue = String(safeContext.mode || '').toLowerCase();
    const requestedMode = ['chat', 'plan', 'agent'].includes(modeValue) ? modeValue : 'agent';
    const record = this._recordForMode(entry, requestedMode);
    if (!record || record.schemaError || typeof record.validator !== 'function') {
      return compactResult({ ok: false, summary: `Tool ${name} không thể chạy`, error: 'Schema tool không hợp lệ; tool đã bị khóa.' });
    }
    const capability = this._capabilityAllowed(name, record, safeContext);
    if (!capability.ok) return compactResult({ ok: false, summary: `Tool ${name} bị chặn`, error: capability.error });

    const validate = record.validator;
    if (!validate(parsed)) {
      const errors = (validate.errors || []).slice(0, 8).map((error) => `${error.instancePath || '/'} ${error.message}`).join('; ');
      return compactResult({ ok: false, summary: `Tham số của ${name} không đúng`, error: errors || 'Schema validation failed.' });
    }

    const needsApproval = this.requiresApproval(name, safeContext.approvalMode, record.definition);
    if (needsApproval) {
      if (!this.interactionProvider) {
        return compactResult({ ok: false, summary: `Tool ${name} cần xác nhận`, error: 'Không có interaction provider để xác nhận tool.' });
      }
      let approved;
      try {
        approved = await this.interactionProvider({
          type: 'approval',
          tool: name,
          arguments: safeEventArguments(parsed),
          argumentsTruncated: stringify(parsed).length > 8_000,
          fallback: safeContext.fallback === true,
          signal: safeContext.signal,
        });
      } catch (error) {
        if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') throw error;
        if (safeContext.signal?.aborted) throw abortError();
        throw error;
      }
      const isApproved = approved === true || (approved && typeof approved === 'object' && approved.approved === true);
      if (!isApproved) return compactResult({ ok: false, summary: `Người dùng từ chối tool ${name}`, error: 'Tool was not approved.' });
    }

    const startedAt = Date.now();
    const argumentsTruncated = stringify(parsed).length > 8_000;
    emit({ type: 'tool-start', callId: safeContext.callId, name, arguments: safeEventArguments(parsed), argumentsTruncated, startedAt });
    try {
      const result = await record.source.execute(name, parsed, {
        ...safeContext,
        callId: safeContext.callId,
        mode: requestedMode,
        fallback: safeContext.fallback === true,
        onOutput: (chunk) => {
          try { emit({ type: 'tool-output', callId: safeContext.callId, name, chunk: safeEventText(String(chunk).slice(-4000), 4000) }); } catch { /* output is advisory */ }
        },
      });
      if (result?.name === 'AbortError' || result?.code === 'ABORT_ERR') {
        const error = result instanceof Error ? result : abortError();
        throw error;
      }
      const normalized = compactResult(result);
      emit({ type: 'tool-result', callId: safeContext.callId, name, ...eventResult(normalized), durationMs: Date.now() - startedAt });
      return normalized;
    } catch (error) {
      if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') throw error;
      if (safeContext.signal?.aborted) throw abortError();
      const normalized = compactResult({ ok: false, summary: `Tool ${name} gặp lỗi`, error: error?.message || String(error) });
      emit({ type: 'tool-result', callId: safeContext.callId, name, ...eventResult(normalized), durationMs: Date.now() - startedAt });
      return normalized;
    }
  }
}

module.exports = {
  ToolBroker,
  parseArguments,
  compactResult,
  classifyIntent,
  nearestNames,
  isMcpTool,
  isMutatingTool,
  isReadOnlyTool,
  toolRisk,
  abortError,
  MUTATING_TOOLS,
  MAX_ARGUMENT_CHARS,
  MAX_RESULT_CHARS,
  safeEventText,
  eventResult,
  modelDefinition,
  approvalRequired,
  safeEventArguments,
};
