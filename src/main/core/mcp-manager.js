'use strict';

/**
 * MCP client lifecycle and tool bridge.
 *
 * This module intentionally uses only Node built-ins.  It supports the MCP
 * stdio transport and the streamable HTTP transport; the older HTTP+SSE
 * transport is rejected rather than accidentally treating its endpoint event
 * as a JSON-RPC response.
 */

const { EventEmitter } = require('node:events');
const { spawn: nodeSpawn } = require('node:child_process');
const { TextDecoder } = require('node:util');
const { createHash } = require('node:crypto');
const dns = require('node:dns');
const net = require('node:net');
const { isPrivateAddress } = require('../tools/web-tools');

const MCP_PROTOCOL_VERSION = '2025-06-18';
const CLIENT_NAME = 'CoderLocally';
const CLIENT_VERSION = '1.0.0';
const DEFAULT_REQUEST_TIMEOUT = 20_000;
const MAX_RESPONSE_BYTES = 2_000_000;
const MAX_LINE_BYTES = 1_000_000;
const STDERR_RING_CHARS = 16_384;
const MAX_TOOL_DESCRIPTION = 2_000;
const MAX_SCHEMA_BYTES = 32_768;
const MAX_SCHEMA_DEPTH = 8;
const MAX_SCHEMA_PROPERTIES = 128;
const MAX_EXPOSED_NAME = 64;
const MAX_INTERNAL_TOOL_NAME = 128;
const DEFAULT_STARTUP_TIMEOUT = 60_000;
const MAX_CONFIG_URL_CHARS = 8_192;
const MAX_COMMAND_CHARS = 4_096;
const MAX_ARGS = 256;
const MAX_ARG_CHARS = 16_384;
const MAX_CWD_CHARS = 4_096;
const MAX_HEADER_ENTRIES = 100;
const MAX_HEADER_VALUE_CHARS = 16_384;
const MAX_ENV_ENTRIES = 200;
const MAX_ENV_VALUE_CHARS = 16_384;
const MAX_CONFIG_TEXT_BYTES = 256_000;

const HTTP_HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'content-length',
  'expect',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const BLOCKED_MCP_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'metadata.azure.com',
  'instance-data',
  'instance-data.ec2.internal',
]);

const STDIO_ENV_PASSTHROUGH = new Set([
  'path',
  'systemroot',
  'windir',
  'comspec',
  'pathext',
  'temp',
  'tmp',
  'tmpdir',
  'home',
  'user',
  'logname',
  'shell',
  'lang',
  'lc_all',
  'lc_ctype',
  'systemdrive',
]);

const SENSITIVE_KEY_RE = /(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|token|secret|password|passwd|credential|private[-_]?key|client[-_]?secret|(?:[A-Za-z0-9]+[-_])*api[-_]?key|(?:^|[-_])key(?:$|[-_])|(?<![A-Za-z])key(?![A-Za-z]))/i;
const SENSITIVE_QUERY_RE = /([?&](?:access[-_]?token|refresh[-_]?token|id[-_]?token|token|api[-_]?key|apikey|key|secret|password|passwd|auth|authorization|signature|sig)=)[^&#\s]*/gi;
const SENSITIVE_ASSIGNMENT_RE = /(?<![A-Za-z])((?:["']?)(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|token|secret|password|passwd|credential|private[-_]?key|client[-_]?secret|(?:[A-Za-z0-9]+[-_])*api[-_]?key|(?:^|[-_])key(?:$|[-_])|key)(?:["']?)\s*[:=]\s*)(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^\s,;\]}\[]+))/gi;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clampInteger(value, fallback, minimum, maximum) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}

function normalizedHostname(value) {
  return String(value || '').trim().replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

function isBlockedMcpHostname(value) {
  const hostname = normalizedHostname(value);
  return BLOCKED_MCP_HOSTNAMES.has(hostname)
    || hostname.endsWith('.localhost')
    || hostname.endsWith('.localhost.localdomain');
}

function isBlockedMcpAddress(value) {
  const kind = net.isIP(normalizedHostname(value));
  return kind === 0 || isPrivateAddress(value);
}

function lookupAllAddresses(lookup, hostname, context = {}, timeout = DEFAULT_REQUEST_TIMEOUT) {
  if (context && context.signal && context.signal.aborted) return Promise.reject(new Error('Request cancelled'));
  const host = normalizedHostname(hostname);
  const direct = net.isIP(host);
  if (direct) return Promise.resolve([{ address: host, family: direct }]);
  if (typeof lookup !== 'function') return Promise.reject(new Error('DNS resolver is unavailable'));

  const lookupPromise = new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    let returned;
    try {
      returned = lookup(host, { all: true, verbatim: true }, (error, addresses) => {
        if (error) finish(error);
        else finish(null, addresses);
      });
    } catch (error) {
      finish(error);
      return;
    }
    if (returned && typeof returned.then === 'function') {
      returned.then((value) => finish(null, value), (error) => finish(error));
    } else if (returned !== undefined) {
      finish(null, returned);
    }
  });

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const signal = context && context.signal;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal && typeof signal.removeEventListener === 'function') signal.removeEventListener('abort', onAbort);
      if (error) reject(error);
      else resolve(value);
    };
    const onAbort = () => finish(new Error('Request cancelled'));
    if (signal) {
      if (signal.aborted) {
        finish(new Error('Request cancelled'));
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    timer = setTimeout(() => finish(new Error('DNS lookup timed out')), Math.max(1, Number(timeout) || DEFAULT_REQUEST_TIMEOUT));
    lookupPromise.then((value) => finish(null, value), (error) => finish(error));
  }).then((result) => {
    const values = typeof result === 'string'
      ? [result]
      : Array.isArray(result)
        ? result
        : result && typeof result === 'object' && result.address
          ? [result]
          : [];
    const addresses = values
      .map((item) => typeof item === 'string' ? { address: item, family: net.isIP(item) } : item)
      .filter((item) => item && typeof item.address === 'string' && net.isIP(item.address))
      .map((item) => ({ address: item.address, family: Number(item.family) || net.isIP(item.address) }));
    if (!addresses.length) throw new Error('DNS returned no usable address');
    return addresses;
  });
}

function buildStdioEnv(configured = {}, inherited = process.env) {
  const output = {};
  const keys = new Set();
  const addInherited = (name, value) => {
    const normalized = String(name).toLowerCase();
    if (!STDIO_ENV_PASSTHROUGH.has(normalized) || keys.has(normalized) || typeof value !== 'string') return;
    output[name] = value;
    keys.add(normalized);
  };

  // Do not copy arbitrary process.env values (API keys, cloud credentials,
  // proxy passwords, and so on) into an untrusted MCP process.
  for (const [name, value] of Object.entries(inherited || {})) addInherited(name, value);
  for (const [name, value] of Object.entries(configured || {})) {
    const normalized = String(name).toLowerCase();
    for (const existing of Object.keys(output)) {
      if (existing.toLowerCase() === normalized) delete output[existing];
    }
    output[name] = value;
    keys.add(normalized);
  }
  return output;
}

function configTextSize(config) {
  try { return Buffer.byteLength(JSON.stringify(config), 'utf8'); } catch { return Number.MAX_SAFE_INTEGER; }
}

function redactString(value) {
  let text = String(value ?? '');
  text = text.replace(/(\b(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key)\s*:\s*)[^\r\n]*/gi, '$1[REDACTED]');
  text = text.replace(SENSITIVE_ASSIGNMENT_RE, (whole, prefix, doubleQuoted, singleQuoted, bare) => {
    const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
    return `${prefix}${quote}[REDACTED]${quote}`;
  });
  text = text.replace(SENSITIVE_QUERY_RE, '$1[REDACTED]');
  text = text.replace(/(\bBearer\s+)[^\s,;]+/gi, '$1[REDACTED]');
  text = text.replace(/(\bBasic\s+)[^\s,;]+/gi, '$1[REDACTED]');
  text = text.replace(/(https?:\/\/)[^\/\s:@]+:[^\/@\s]+@/gi, '$1[REDACTED@');
  text = text.replace(/\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/g, '[REDACTED]');
  text = text.replace(/\b(?:sk|pk|rk)-[a-zA-Z0-9_-]{12,}\b/g, '[REDACTED]');
  text = text.replace(/\b(?:gh[pousr]|github_pat)_[a-zA-Z0-9_]{12,}\b/g, '[REDACTED]');
  text = text.replace(/\bxox[baprs]-[a-zA-Z0-9-]{12,}\b/g, '[REDACTED]');
  return text;
}

function redact(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (Buffer.isBuffer(value)) return redactString(value.toString('utf8'));
  if (typeof value === 'string') return redactString(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return value;
  if (typeof value === 'function') return '[Function]';
  if (value instanceof Error) return redactString(value.message || String(value));
  if (typeof value !== 'object') return redactString(String(value));
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redact(item, seen));
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    Object.defineProperty(output, key, {
      value: SENSITIVE_KEY_RE.test(key) ? '[REDACTED]' : redact(item, seen),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return output;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function scrubConfiguredValue(text, secret) {
  if (typeof secret !== 'string' || !secret) return text;
  const candidates = [secret];
  try {
    const encoded = encodeURIComponent(secret);
    if (encoded && encoded !== secret) candidates.push(encoded);
  } catch { /* malformed surrogate pair; raw value is still scrubbed */ }
  let output = String(text);
  for (const candidate of candidates) {
    if (candidate.length >= 3) {
      output = output.split(candidate).join('[REDACTED]');
    } else {
      const expression = new RegExp(`(^|[^A-Za-z0-9])${escapeRegExp(candidate)}(?=$|[^A-Za-z0-9])`, 'g');
      output = output.replace(expression, '$1[REDACTED]');
    }
  }
  return output;
}

function safeMessage(error) {
  if (error && (error.name === 'AbortError' || error.code === 'ABORT_ERR')) return 'Request cancelled';
  if (error && error.code === 'ETIMEDOUT') return 'Request timed out';
  const message = error && error.message ? error.message : String(error || 'Request failed');
  return redactString(message).replace(/[\r\n]+/g, ' ').slice(0, 2_000);
}

function getHeader(headers, name) {
  if (!headers) return undefined;
  const wanted = String(name).toLowerCase();
  if (typeof headers.get === 'function') {
    try { return headers.get(name) || undefined; } catch { return undefined; }
  }
  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === wanted) return Array.isArray(value) ? value.join(', ') : String(value);
  }
  return undefined;
}

function headersToObject(headers) {
  const result = Object.create(null);
  if (!headers) return result;
  if (typeof headers.forEach === 'function') {
    try {
      headers.forEach((value, key) => { result[String(key).toLowerCase()] = String(value); });
      return result;
    } catch { /* object fallback */ }
  }
  for (const [key, value] of Object.entries(headers)) result[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  return result;
}

function parseSse(input) {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input ?? '');
  const normalized = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const events = [];
  let eventName = 'message';
  let id;
  let data = [];
  let hasField = false;

  const dispatch = () => {
    if (hasField) events.push({ event: eventName || 'message', data: data.join('\n'), ...(id === undefined ? {} : { id }) });
    eventName = 'message';
    id = undefined;
    data = [];
    hasField = false;
  };

  for (const line of normalized.split('\n')) {
    if (line === '') {
      dispatch();
      continue;
    }
    if (line.startsWith(':')) continue;
    const separator = line.indexOf(':');
    const field = separator < 0 ? line : line.slice(0, separator);
    let value = separator < 0 ? '' : line.slice(separator + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') {
      eventName = value || 'message';
      hasField = true;
    } else if (field === 'data') {
      data.push(value);
      hasField = true;
    } else if (field === 'id') {
      id = value;
      hasField = true;
    }
    // `retry` and unknown fields are intentionally ignored.
  }
  if (hasField) dispatch();
  return events;
}

const parseSSE = parseSse;

function parseSseJson(input) {
  const messages = [];
  for (const event of parseSse(input)) {
    if (!event.data || event.data === '[DONE]') continue;
    try {
      const value = JSON.parse(event.data);
      if (Array.isArray(value)) messages.push(...value);
      else messages.push(value);
    } catch {
      // A non-JSON SSE event is handled as a transport error by the caller.
    }
  }
  return messages;
}

function safeSegment(value, fallback = 'server', maximum = 32) {
  let text = String(value ?? '').normalize('NFKC');
  text = text.replace(/[^A-Za-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '');
  if (!text) text = fallback;
  if (text.length > maximum) {
    const digest = createHash('sha256').update(text).digest('hex').slice(0, 8);
    text = `${text.slice(0, Math.max(1, maximum - 9))}-${digest}`;
  }
  return text;
}

function truncateDescription(value) {
  if (value === null || value === undefined) return '';
  return redactString(String(value)).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, MAX_TOOL_DESCRIPTION);
}

function normalizeSchemaNode(input, depth = 0) {
  if (!isObject(input) || depth > MAX_SCHEMA_DEPTH) return { type: 'string' };
  const output = {};
  if (typeof input.type === 'string') output.type = input.type.slice(0, 40);
  else if (Array.isArray(input.type)) {
    const first = input.type.find((item) => item !== 'null');
    if (typeof first === 'string') output.type = first.slice(0, 40);
  }
  if (typeof input.description === 'string') output.description = truncateDescription(input.description);
  if (input.enum && Array.isArray(input.enum)) output.enum = input.enum.slice(0, 50).map((item) => (typeof item === 'string' ? redactString(item).slice(0, 500) : (typeof item === 'number' || typeof item === 'boolean' || item === null ? item : String(item).slice(0, 500))));
  if (typeof input.const === 'string' || typeof input.const === 'number' || typeof input.const === 'boolean' || input.const === null) output.const = typeof input.const === 'string' ? redactString(input.const).slice(0, 500) : input.const;
  if (typeof input.default === 'string' || typeof input.default === 'number' || typeof input.default === 'boolean' || input.default === null) output.default = typeof input.default === 'string' ? redactString(input.default).slice(0, 500) : input.default;
  for (const scalar of ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'pattern', 'format']) {
    if (typeof input[scalar] === 'string') output[scalar] = redactString(input[scalar]).slice(0, 500);
    else if (typeof input[scalar] === 'number') output[scalar] = input[scalar];
  }
  if (input.items !== undefined) output.items = normalizeSchemaNode(input.items, depth + 1);
  if (isObject(input.properties)) {
    output.type = output.type || 'object';
    output.properties = {};
    let count = 0;
    for (const [name, schema] of Object.entries(input.properties)) {
      if (++count > MAX_SCHEMA_PROPERTIES) break;
      const propertyName = String(name).slice(0, 200);
      Object.defineProperty(output.properties, propertyName, {
        value: normalizeSchemaNode(schema, depth + 1),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    output.additionalProperties = false;
  }
  if (Array.isArray(input.required)) {
    output.required = input.required.filter((item) => typeof item === 'string').map((item) => item.slice(0, 200)).slice(0, MAX_SCHEMA_PROPERTIES);
  }
  if (Array.isArray(input.oneOf)) output.oneOf = input.oneOf.slice(0, 20).map((item) => normalizeSchemaNode(item, depth + 1));
  if (Array.isArray(input.anyOf)) output.anyOf = input.anyOf.slice(0, 20).map((item) => normalizeSchemaNode(item, depth + 1));
  if (Array.isArray(input.allOf)) output.allOf = input.allOf.slice(0, 20).map((item) => normalizeSchemaNode(item, depth + 1));
  return output;
}

function normalizeInputSchema(input) {
  const source = isObject(input) ? input : {};
  const output = {
    type: 'object',
    properties: {},
    additionalProperties: false,
  };
  if (typeof source.description === 'string') output.description = truncateDescription(source.description);
  if (isObject(source.properties)) {
    let count = 0;
    for (const [name, schema] of Object.entries(source.properties)) {
      if (++count > MAX_SCHEMA_PROPERTIES) break;
      const propertyName = String(name).slice(0, 200);
      Object.defineProperty(output.properties, propertyName, {
        value: normalizeSchemaNode(schema, 1),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
  }
  if (Array.isArray(source.required)) output.required = source.required.filter((item) => typeof item === 'string').map((item) => item.slice(0, 200)).slice(0, MAX_SCHEMA_PROPERTIES);
  // Other root-level constraints are safe and useful to the model.
  for (const key of ['minProperties', 'maxProperties']) if (typeof source[key] === 'number') output[key] = source[key];
  let encoded;
  try { encoded = JSON.stringify(output); } catch { encoded = ''; }
  if (encoded.length > MAX_SCHEMA_BYTES) {
    return {
      type: 'object',
      properties: {},
      additionalProperties: false,
      description: 'Input schema omitted because it exceeded the size limit.',
    };
  }
  return output;
}

function validateHeaders(headers) {
  if (headers === undefined) return {};
  if (!isObject(headers)) throw new TypeError('HTTP headers must be an object');
  const output = {};
  const names = new Set();
  let count = 0;
  for (const [name, value] of Object.entries(headers)) {
    const normalizedName = String(name).toLowerCase();
    if (++count > MAX_HEADER_ENTRIES || name.length > 256 || ['__proto__', 'prototype', 'constructor'].includes(name) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n]/.test(name)) throw new TypeError('HTTP headers contain an invalid name');
    if (HTTP_HOP_BY_HOP_HEADERS.has(normalizedName)) throw new TypeError(`HTTP header ${name} is not allowed`);
    if (names.has(normalizedName)) throw new TypeError('HTTP headers contain a duplicate name');
    names.add(normalizedName);
    if (typeof value !== 'string' || value.length > MAX_HEADER_VALUE_CHARS || /[\r\n]/.test(value)) throw new TypeError('HTTP headers contain an invalid value');
    output[name] = value;
  }
  return output;
}

function validateEnv(env) {
  if (env === undefined) return {};
  if (!isObject(env)) throw new TypeError('stdio env must be an object');
  const output = {};
  const names = new Set();
  let count = 0;
  for (const [name, value] of Object.entries(env)) {
    const normalizedName = String(name).toLowerCase();
    if (++count > MAX_ENV_ENTRIES || name.length > 256 || ['__proto__', 'prototype', 'constructor'].includes(name) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || typeof value !== 'string') throw new TypeError('stdio env contains an invalid entry');
    if (names.has(normalizedName)) throw new TypeError('stdio env contains a duplicate name');
    names.add(normalizedName);
    if (/[\r\n]/.test(value) || value.length > MAX_ENV_VALUE_CHARS) throw new TypeError('stdio env contains an invalid value');
    output[name] = value;
  }
  return output;
}

function normalizeConfig(config, options = {}) {
  if (!isObject(config)) throw new TypeError('MCP config must be an object');
  if (configTextSize(config) > MAX_CONFIG_TEXT_BYTES) throw new TypeError('MCP config is too large');
  const hasOwn = (key) => Object.prototype.hasOwnProperty.call(config, key);
  const declared = String((hasOwn('type') ? config.type : undefined) || (hasOwn('transport') ? config.transport : undefined) || '').toLowerCase();
  if (declared.length > 64) throw new TypeError('MCP transport is invalid');
  const command = hasOwn('command') ? config.command : undefined;
  const urlValue = hasOwn('url') ? config.url : undefined;
  const isStdio = declared === 'stdio' || (!declared && typeof command === 'string');
  const isHttp = declared === 'http' || declared === 'streamable-http' || declared === 'streamable_http' || declared === 'streamablehttp' || (!declared && typeof urlValue === 'string');
  if (declared === 'sse' || declared === 'http+sse' || declared === 'http-sse') {
    throw new TypeError('Legacy HTTP+SSE transport is not supported; configure streamable HTTP');
  }
  const hasAllowPrivateNetwork = Object.prototype.hasOwnProperty.call(config, 'allowPrivateNetwork');
  if (hasAllowPrivateNetwork && typeof config.allowPrivateNetwork !== 'boolean') {
    throw new TypeError('MCP allowPrivateNetwork must be a boolean');
  }
  if (isStdio && typeof command === 'string' && command.trim()) {
    if (command.length > MAX_COMMAND_CHARS || /[\r\n\0]/.test(command)) throw new TypeError('stdio command is invalid');
    const args = hasOwn('args') ? config.args : undefined;
    const cwd = hasOwn('cwd') ? config.cwd : undefined;
    const env = hasOwn('env') ? config.env : undefined;
    if (args !== undefined && (!Array.isArray(args) || args.length > MAX_ARGS || args.some((item) => typeof item !== 'string' || item.length > MAX_ARG_CHARS || /[\r\n\0]/.test(item)))) throw new TypeError('stdio args must be a bounded array of strings');
    if (cwd !== undefined && (typeof cwd !== 'string' || cwd.length > MAX_CWD_CHARS || /[\r\n\0]/.test(cwd))) throw new TypeError('stdio cwd is invalid');
    if (hasAllowPrivateNetwork && config.allowPrivateNetwork === true) throw new TypeError('allowPrivateNetwork is only valid for HTTP MCP servers');
    return {
      kind: 'stdio',
      command,
      args: args ? args.slice() : [],
      env: validateEnv(env),
      ...(cwd ? { cwd } : {}),
    };
  }
  if (isHttp && typeof urlValue === 'string') {
    if (!urlValue.trim() || urlValue.length > MAX_CONFIG_URL_CHARS) throw new TypeError('MCP HTTP URL is invalid');
    let url;
    try { url = new URL(urlValue); } catch { throw new TypeError('MCP HTTP URL is invalid'); }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new TypeError('MCP HTTP URL must use http or https');
    if (url.username || url.password) throw new TypeError('MCP HTTP URL credentials are not allowed');
    if (url.toString().length > MAX_CONFIG_URL_CHARS) throw new TypeError('MCP HTTP URL is too long');
    // This is deliberately an explicit boolean opt-in; hostnames are never
    // treated as trusted merely because they look local or are renderer-supplied.
    const allowPrivateNetwork = (hasAllowPrivateNetwork && config.allowPrivateNetwork === true) || options.allowPrivateNetwork === true;
    const hostname = normalizedHostname(url.hostname);
    if (!allowPrivateNetwork && (isBlockedMcpHostname(hostname) || (net.isIP(hostname) && isPrivateAddress(hostname)))) {
      throw new TypeError('MCP private-network access requires allowPrivateNetwork:true');
    }
    return {
      kind: 'http',
      url: url.toString(),
      headers: validateHeaders(hasOwn('headers') ? config.headers : undefined),
      allowPrivateNetwork,
    };
  }
  throw new TypeError('MCP config must define stdio command or streamable HTTP url');
}

async function readResponseBody(response, limit) {
  if (!response) return { buffer: Buffer.alloc(0), text: '', truncated: false };
  const body = response.body;
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    let truncated = false;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        const chunk = Buffer.isBuffer(part.value) ? part.value : Buffer.from(part.value);
        if (total < limit) {
          const room = limit - total;
          if (chunk.length > room) {
            if (room > 0) chunks.push(chunk.subarray(0, room));
            total = limit;
            truncated = true;
            await reader.cancel();
            break;
          }
          chunks.push(chunk);
          total += chunk.length;
        } else {
          truncated = true;
          await reader.cancel();
          break;
        }
      }
    } finally {
      try { reader.releaseLock(); } catch { /* already released */ }
    }
    const buffer = Buffer.concat(chunks);
    return { buffer, text: buffer.toString('utf8'), truncated };
  }
  if (body && typeof body[Symbol.asyncIterator] === 'function') {
    const chunks = [];
    let total = 0;
    let truncated = false;
    for await (const part of body) {
      const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
      if (total < limit) {
        const room = limit - total;
        if (chunk.length > room) {
          if (room > 0) chunks.push(chunk.subarray(0, room));
          total = limit;
          truncated = true;
          break;
        }
        chunks.push(chunk);
        total += chunk.length;
      } else {
        truncated = true;
        break;
      }
    }
    const buffer = Buffer.concat(chunks);
    return { buffer, text: buffer.toString('utf8'), truncated };
  }
  if (typeof response.text === 'function') {
    const value = await response.text();
    const buffer = Buffer.from(String(value));
    return { buffer: buffer.subarray(0, limit), text: buffer.subarray(0, limit).toString('utf8'), truncated: buffer.length > limit };
  }
  if (typeof response.json === 'function') {
    const value = await response.json();
    const buffer = Buffer.from(JSON.stringify(value));
    return { buffer: buffer.subarray(0, limit), text: buffer.subarray(0, limit).toString('utf8'), truncated: buffer.length > limit };
  }
  if (typeof response.arrayBuffer === 'function') {
    const buffer = Buffer.from(await response.arrayBuffer());
    return { buffer: buffer.subarray(0, limit), text: buffer.subarray(0, limit).toString('utf8'), truncated: buffer.length > limit };
  }
  const value = body === undefined || body === null ? '' : String(body);
  const buffer = Buffer.from(value);
  return { buffer: buffer.subarray(0, limit), text: buffer.subarray(0, limit).toString('utf8'), truncated: buffer.length > limit };
}

class McpManager extends EventEmitter {
  constructor(options = {}) {
    super();
    const opts = isObject(options) ? options : {};
    this.requestTimeout = clampInteger(opts.requestTimeout, DEFAULT_REQUEST_TIMEOUT, 1, 300_000);
    this.startupTimeout = clampInteger(opts.startupTimeout, Math.min(DEFAULT_STARTUP_TIMEOUT, Math.max(10, this.requestTimeout * 3)), 10, 600_000);
    this.fetchImpl = opts.fetchImpl || opts.fetch || null;
    this.lookup = opts.lookup || opts.dnsLookup || opts.resolve || dns.promises.lookup.bind(dns.promises);
    this.allowPrivateNetwork = opts.allowPrivateNetwork === true;
    this.spawnImpl = opts.spawnImpl || opts.spawn || nodeSpawn;
    this.maxResponseBytes = clampInteger(opts.maxResponseBytes, MAX_RESPONSE_BYTES, 1, 20_000_000);
    this.maxToolResultChars = clampInteger(opts.maxToolResultChars, 100_000, 1, 2_000_000);
    this.configs = new Map();
    this.servers = new Map();
    this.serverSegments = new Map();
    this.serverGenerations = new Map();
    this.toolIndex = new Map();
    this.lifecycleTail = Promise.resolve();
    this.lifecycleEpoch = 0;
    this.started = false;
    this.protocolVersion = MCP_PROTOCOL_VERSION;
    this.clientInfo = { name: CLIENT_NAME, version: CLIENT_VERSION };
  }

  status() {
    const servers = {};
    let anyStarting = false;
    let anyError = false;
    let anyStopped = false;
    for (const [name, server] of this.servers) {
      const item = {
        status: server.status,
        running: server.status === 'running',
        toolCount: server.tools.length,
        initialized: Boolean(server.initialized),
        stderrBytes: Buffer.byteLength(server.stderrRing || ''),
      };
      if (server.error) item.error = this._scrubConfiguredSecrets(redactString(server.error)).slice(0, 1_000);
      const displayName = this._scrubConfiguredSecrets(redactString(name)).slice(0, 160) || 'server';
      servers[displayName] = item;
      if (server.status === 'starting') anyStarting = true;
      if (server.status === 'error') anyError = true;
      if (server.status === 'stopped') anyStopped = true;
    }
    for (const name of this.configs.keys()) {
      const displayName = this._scrubConfiguredSecrets(redactString(name)).slice(0, 160) || 'server';
      if (servers[displayName]) continue;
      servers[displayName] = { status: 'stopped', running: false, toolCount: 0, initialized: false, stderrBytes: 0 };
      anyStopped = true;
    }
    const state = anyError ? 'error' : anyStarting ? 'starting' : (this.started && !anyStopped ? 'running' : this.started ? 'degraded' : 'stopped');
    return { status: state, running: this.started, started: this.started, servers };
  }

  _enqueueLifecycle(task) {
    const operation = this.lifecycleTail.then(() => task(), () => task());
    // Lifecycle operations are intentionally serialized.  Always attach a
    // handler to the queued promise so a fire-and-forget addConfig/reload
    // cannot create an unhandled rejection in the main process.
    const safeOperation = operation.catch((error) => {
      this._emitError(error);
    });
    this.lifecycleTail = safeOperation;
    return safeOperation;
  }

  addConfig(name, config) {
    if (typeof name !== 'string' || !name.trim() || name.length > 128 || /[\u0000-\u001f\u007f]/.test(name) || ['__proto__', 'prototype', 'constructor'].includes(name.trim())) throw new TypeError('MCP server name is invalid');
    const normalized = normalizeConfig(config, { allowPrivateNetwork: this.allowPrivateNetwork });
    const cleanName = name.trim();
    const previous = this.servers.get(cleanName);
    this.configs.set(cleanName, normalized);
    if (previous && previous.config !== normalized) {
      // Interrupt an in-flight initialization immediately.  The serialized
      // lifecycle task below still performs the actual replacement, while the
      // early stop prevents a broken old server from delaying the new one.
      void this._stopServer(previous).catch(() => {});
    }
    if (!this.serverSegments.has(cleanName)) this._allocateServerSegment(cleanName);
    this._enqueueLifecycle(async () => {
      const current = this.servers.get(cleanName);
      if (current && current.config === normalized && (current.status === 'starting' || current.status === 'running')) return;
      if (current) await this._stopServer(current);
      if (this.configs.get(cleanName) !== normalized) return;
      if (this.started) await this._connectServer(cleanName, normalized);
    });
    this._emitStatus();
    return cleanName;
  }

  removeConfig(name) {
    if (typeof name !== 'string') return false;
    const cleanName = name.trim();
    const existed = this.configs.has(cleanName) || this.servers.has(cleanName);
    const server = this.servers.get(cleanName);
    this.configs.delete(cleanName);
    this.servers.delete(cleanName);
    this.serverSegments.delete(cleanName);
    if (server) void this._stopServer(server).catch(() => {});
    this._removeToolsForServer(cleanName);
    this._enqueueLifecycle(() => this._stopServer(server));
    this._emitStatus();
    return existed;
  }

  definitions() {
    return [...this.toolIndex.values()].map((record) => record.definition);
  }

  async start() {
    const epoch = this.lifecycleEpoch;
    await this._enqueueLifecycle(async () => {
      if (this.started || this.lifecycleEpoch !== epoch) return;
      this.started = true;
      this._emitStatus();
      const entries = [...this.configs.entries()];
      await Promise.all(entries.map(async ([name, config]) => {
        if (this.lifecycleEpoch !== epoch || !this.started || this.configs.get(name) !== config) return;
        try {
          await this._connectServer(name, config);
        } catch (error) {
          this._emitError(error, name);
        }
      }));
    });
    return this.status();
  }

  async stop() {
    // Flip the state and interrupt active requests before joining the queue so
    // a stuck initialization cannot postpone a reload or shutdown.
    this.lifecycleEpoch += 1;
    this.started = false;
    for (const server of [...this.servers.values()]) void this._stopServer(server).catch(() => {});
    await this._enqueueLifecycle(async () => {
      this.started = false;
      this._emitStatus();
      const servers = [...this.servers.values()];
      await Promise.all(servers.map((server) => this._stopServer(server)));
      this.toolIndex.clear();
      this._emitStatus();
    });
    return this.status();
  }

  async execute(exposedName, args, context = {}) {
    const safeContext = isObject(context) ? context : {};
    try {
      if (safeContext.signal && safeContext.signal.aborted) return this._failure('MCP request cancelled', 'Request cancelled');
      if (typeof exposedName !== 'string' || !exposedName) return this._failure('Unknown MCP tool', 'Unknown MCP tool');
      const record = this.toolIndex.get(exposedName);
      if (!record) return this._failure('Unknown MCP tool', `Unknown MCP tool: ${redactString(exposedName.slice(0, 200))}`);
      const server = this.servers.get(record.serverName);
      if (!server || server.status !== 'running' || (record.serverGeneration !== undefined && record.serverGeneration !== server.generation)) return this._failure('MCP server unavailable', 'MCP server is not running');
      if (args !== undefined && !isObject(args)) return this._failure('Invalid MCP tool arguments', 'Tool arguments must be an object');
      const result = await this._request(server, 'tools/call', { name: record.toolName, arguments: args || {} }, safeContext);
      if (this.servers.get(record.serverName) !== server || this.configs.get(record.serverName) !== server.config || server.status !== 'running') return this._failure('MCP server unavailable', 'MCP server is not running');
      return this._toolResult(record, result, server);
    } catch (error) {
      return this._failure('MCP tool request failed', safeMessage(error));
    }
  }

  _failure(summary, error) {
    return { ok: false, summary: this._scrubConfiguredSecrets(redactString(summary)).slice(0, 500), data: null, error: this._scrubConfiguredSecrets(redactString(String(error || 'Request failed'))).slice(0, 2_000) };
  }

  _scrubConfiguredSecrets(value) {
    let text = String(value ?? '');
    for (const config of this.configs.values()) {
      const values = [
        config.url,
        ...Object.values(config.headers || {}),
        ...Object.values(config.env || {}),
      ];
      for (const secret of values) text = scrubConfiguredValue(text, secret);
    }
    return text;
  }

  _scrubServerSecrets(server, value) {
    let text = String(value ?? '');
    if (!server) return this._scrubConfiguredSecrets(text);
    const values = [
      server?.config?.url,
      ...Object.values(server?.config?.headers || {}),
      ...Object.values(server?.config?.env || {}),
    ];
    for (const secret of values) text = scrubConfiguredValue(text, secret);
    return text;
  }

  _allocateServerSegment(name) {
    const used = new Set(this.serverSegments.values());
    const base = safeSegment(name, 'server', 32);
    let segment = base;
    let suffix = 2;
    while (used.has(segment)) {
      segment = `${base.slice(0, Math.max(1, 32 - String(suffix).length - 1))}-${suffix}`;
      suffix += 1;
    }
    this.serverSegments.set(name, segment);
  }

  _newServer(name, config) {
    const generation = (this.serverGenerations.get(name) || 0) + 1;
    this.serverGenerations.set(name, generation);
    return {
      name,
      config,
      kind: config.kind,
      generation,
      retired: false,
      status: 'stopped',
      error: '',
      child: null,
      stdoutBuffer: '',
      stderrRing: '',
      pending: new Map(),
      controllers: new Set(),
      nextId: 1,
      sessionId: null,
      initialized: false,
      tools: [],
      stopPromise: null,
    };
  }

  _isCurrentServer(server) {
    return Boolean(server
      && !server.retired
      && server.status !== 'stopping'
      && this.servers.get(server.name) === server
      && this.configs.get(server.name) === server.config);
  }

  _emitStatus(change = null) {
    const current = this.status();
    this.emit('status', current);
    this.emit('statusChange', change ? { ...current, ...change, overallStatus: current.status } : current);
  }

  _setServerStatus(server, status, error = '') {
    server.status = status;
    server.error = error ? this._scrubServerSecrets(server, safeMessage(error)).slice(0, 1_000) : '';
    if (this.servers.get(server.name) !== server || this.configs.get(server.name) !== server.config) return;
    this._emitStatus({
      server: this._scrubConfiguredSecrets(redactString(server.name)).slice(0, 160),
      status,
      ...(server.error ? { error: server.error } : {}),
    });
  }

  _emitError(error, serverName = '', sourceServer = null) {
    const server = sourceServer || this.servers.get(serverName) || [...this.servers.values()].find((item) => item.name === serverName);
    if (sourceServer && (this.servers.get(sourceServer.name) !== sourceServer || this.configs.get(sourceServer.name) !== sourceServer.config)) return;
    const message = server ? this._scrubServerSecrets(server, safeMessage(error)) : this._scrubConfiguredSecrets(safeMessage(error));
    // EventEmitter treats an unhandled `error` event as an exception.  Do not
    // turn an expected MCP/server failure into an application crash.
    if (this.listenerCount('error') > 0) this.emit('error', new Error(message));
    this.emit('mcpError', { server: this._scrubConfiguredSecrets(redactString(serverName)).slice(0, 160), error: message });
  }

  async _connectServer(name, config) {
    if (this.configs.get(name) !== config) return;
    const old = this.servers.get(name);
    if (old && (old.status === 'starting' || old.status === 'running') && old.config === config) return;
    if (old && old.status !== 'stopped') await this._stopServer(old);
    if (this.configs.get(name) !== config) return;

    const server = this._newServer(name, config);
    this.servers.set(name, server);
    this._setServerStatus(server, 'starting');
    const startupController = new AbortController();
    let startupTimedOut = false;
    server.controllers.add(startupController);
    const startupTimer = setTimeout(() => {
      startupTimedOut = true;
      startupController.abort();
    }, this.startupTimeout);
    const startupContext = { signal: startupController.signal };
    try {
      if (config.kind === 'stdio') {
        this._startStdio(server);
        if (!server.child) throw new Error('stdio process could not be started');
      } else if (/\/sse\/?$/i.test(new URL(config.url).pathname)) {
        throw new Error('Legacy HTTP+SSE transport is not supported; use streamable HTTP POST');
      }

      const initialize = await this._request(server, 'initialize', {
        protocolVersion: this.protocolVersion,
        capabilities: {},
        clientInfo: this.clientInfo,
      }, startupContext);
      if (!this._isCurrentServer(server)) return;
      if (initialize !== undefined && (!isObject(initialize) || (initialize.protocolVersion && initialize.protocolVersion !== this.protocolVersion))) {
        throw new Error('MCP server returned an invalid initialize response');
      }
      server.initialized = true;
      await this._notify(server, 'notifications/initialized', {}, startupContext);
      if (!this._isCurrentServer(server)) return;
      const listed = await this._request(server, 'tools/list', {}, startupContext);
      if (!this._isCurrentServer(server)) return;
      const rawTools = Array.isArray(listed) ? listed : listed && Array.isArray(listed.tools) ? listed.tools : null;
      if (!rawTools) throw new Error('MCP server returned an invalid tools/list response');
      const tools = this._normalizeTools(rawTools, name, server);
      if (!this._isCurrentServer(server)) return;
      this._replaceToolsForServer(name, tools, server);
      server.tools = tools;
      this._setServerStatus(server, 'running');
    } catch (error) {
      if (!this._isCurrentServer(server)) return;
      const failure = startupTimedOut ? new Error('MCP startup timed out') : error;
      this._emitError(failure, name, server);
      this._removeToolsForServer(name, server.generation);
      this._killChild(server);
      this._rejectPending(server, failure);
      server.initialized = false;
      this._setServerStatus(server, 'error', failure);
    } finally {
      clearTimeout(startupTimer);
      server.controllers.delete(startupController);
    }
  }

  _startStdio(server) {
    const env = buildStdioEnv(server.config.env || {});
    const child = this.spawnImpl(server.config.command, (server.config.args || []).slice(), {
      ...(server.config.cwd ? { cwd: server.config.cwd } : {}),
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    if (!child) throw new Error('stdio process could not be started');
    server.child = child;
    if (child.stdout && typeof child.stdout.on === 'function') {
      child.stdout.on('data', (chunk) => this._consumeStdout(server, chunk));
      child.stdout.on('error', (error) => {
        if (this._isCurrentServer(server)) this._emitError(error, server.name, server);
      });
    }
    if (child.stderr && typeof child.stderr.on === 'function') {
      child.stderr.on('data', (chunk) => {
        if (!this._isCurrentServer(server)) return;
        const text = this._scrubServerSecrets(server, redactString(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk))).slice(-STDERR_RING_CHARS);
        server.stderrRing = `${server.stderrRing}${text}`.slice(-STDERR_RING_CHARS);
      });
      child.stderr.on('error', (error) => {
        if (this._isCurrentServer(server)) this._emitError(error, server.name, server);
      });
    }
    if (typeof child.on === 'function') {
      child.on('error', (error) => {
        if (!this._isCurrentServer(server)) return;
        this._emitError(error, server.name, server);
        this._rejectPending(server, error);
        this._removeToolsForServer(server.name, server.generation);
        this._setServerStatus(server, 'error', error);
      });
      let exited = false;
      const onChildClosed = (code) => {
        if (exited) return;
        exited = true;
        if (!this._isCurrentServer(server) || !this.started) return;
        const error = new Error(`MCP stdio process exited (${code === null || code === undefined ? 'unknown' : code})`);
        this._emitError(error, server.name, server);
        this._rejectPending(server, error);
        this._removeToolsForServer(server.name, server.generation);
        this._setServerStatus(server, 'error', error);
      };
      child.on('exit', onChildClosed);
      child.on('close', onChildClosed);
    }
  }

  _consumeStdout(server, chunk) {
    if (!this._isCurrentServer(server)) return;
    const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
    server.stdoutBuffer += text;
    if (Buffer.byteLength(server.stdoutBuffer) > MAX_LINE_BYTES * 2) {
      server.stdoutBuffer = '';
      const error = new Error('MCP stdout line exceeded the size limit');
      this._emitError(error, server.name, server);
      return;
    }
    let newline;
    while ((newline = server.stdoutBuffer.indexOf('\n')) >= 0) {
      let line = server.stdoutBuffer.slice(0, newline).replace(/\r$/, '').replace(/^\uFEFF/, '');
      server.stdoutBuffer = server.stdoutBuffer.slice(newline + 1);
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
        this._emitError(new Error('MCP stdout line exceeded the size limit'), server.name, server);
        continue;
      }
      if (!line.trim()) continue;
      let message;
      try { message = JSON.parse(line); } catch {
        this._emitError(new Error('MCP stdout contained invalid JSON'), server.name, server);
        continue;
      }
      this._handleProtocolMessage(server, message);
    }
  }

  _handleProtocolMessage(server, message) {
    if (!this._isCurrentServer(server)) return;
    if (!isObject(message) || message.jsonrpc !== '2.0') {
      this._emitError(new Error('MCP server sent an invalid JSON-RPC message'), server.name, server);
      return;
    }
    if (message.id === undefined || message.id === null) return; // notification
    const key = String(message.id);
    const pending = server.pending.get(key);
    if (!pending) return;
    server.pending.delete(key);
    if (message.error) {
      const error = new Error(`MCP ${pending.method} failed: ${message.error.message || 'server error'}`);
      error.code = message.error.code;
      pending.reject(error);
    } else {
      pending.resolve(message.result);
    }
  }

  _request(server, method, params, context = {}, options = {}) {
    const notification = options.notification === true;
    const payload = { jsonrpc: '2.0', method, params: params === undefined ? {} : params };
    if (!notification) payload.id = server.nextId++;
    let serialized;
    try { serialized = JSON.stringify(payload); } catch { return Promise.reject(new Error('MCP request is not serializable')); }
    if (Buffer.byteLength(serialized) > this.maxResponseBytes) return Promise.reject(new Error('MCP request is too large'));
    if (server.kind === 'http') return this._requestHttp(server, payload, context, notification);
    return this._requestStdio(server, payload, method, context, notification);
  }

  _requestStdio(server, payload, method, context, notification) {
    if (!server.child || !server.child.stdin || typeof server.child.stdin.write !== 'function') return Promise.reject(new Error('MCP stdio process is unavailable'));
    const externalSignal = context && context.signal;
    if (externalSignal && externalSignal.aborted) return Promise.reject(new Error('Request cancelled'));
    let serializedNotification;
    if (notification) {
      try { serializedNotification = `${JSON.stringify(payload)}\n`; server.child.stdin.write(serializedNotification); return Promise.resolve(); } catch (error) { return Promise.reject(error); }
    }
    const id = payload.id;
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer;
      const pending = {
        method,
        resolve: (value) => finish(null, value),
        reject: (error) => finish(error),
      };
      const onAbort = () => {
        server.pending.delete(String(id));
        finish(new Error('Request cancelled'));
      };
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (externalSignal && typeof externalSignal.removeEventListener === 'function') externalSignal.removeEventListener('abort', onAbort);
        if (error) reject(error);
        else resolve(value);
      };
      server.pending.set(String(id), pending);
      if (externalSignal && typeof externalSignal.addEventListener === 'function') externalSignal.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(() => {
        server.pending.delete(String(id));
        finish(new Error('MCP request timed out'));
      }, this.requestTimeout);
      try { server.child.stdin.write(`${JSON.stringify(payload)}\n`); } catch (error) { server.pending.delete(String(id)); finish(error); }
    });
  }

  async _requestHttp(server, payload, context, notification) {
    const result = await this._httpExchange(server, payload, context);
    if (notification) {
      if (result.accepted || result.status >= 200 && result.status < 300) return;
      throw new Error(`MCP HTTP request failed (${result.status})`);
    }
    const messages = result.messages || [];
    const response = messages.find((message) => isObject(message) && message.jsonrpc === '2.0'
      && (message.id === payload.id || String(message.id) === String(payload.id))
      && (message.result !== undefined || message.error));
    if (!response) {
      if (result.accepted) throw new Error('MCP HTTP server accepted the request without a JSON-RPC response');
      throw new Error('MCP HTTP server returned no JSON-RPC response');
    }
    if (response.error) {
      const error = new Error(`MCP ${payload.method} failed: ${response.error.message || 'server error'}`);
      error.code = response.error.code;
      throw error;
    }
    return response.result;
  }

  async _validateHttpTarget(server, context = {}) {
    let url;
    try { url = new URL(server.config.url); } catch { throw new Error('MCP HTTP URL is invalid'); }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new TypeError('MCP HTTP URL must use http or https');
    if (url.username || url.password) throw new TypeError('MCP HTTP URL credentials are not allowed');
    const allowPrivateNetwork = server.config.allowPrivateNetwork === true || this.allowPrivateNetwork === true;
    const hostname = normalizedHostname(url.hostname);
    if (!allowPrivateNetwork && isBlockedMcpHostname(hostname)) throw new Error('MCP private-network access requires allowPrivateNetwork:true');
    const addresses = await lookupAllAddresses(this.lookup, hostname, context, this.requestTimeout);
    if (!allowPrivateNetwork && addresses.some((item) => isBlockedMcpAddress(item.address))) {
      throw new Error('MCP HTTP target resolves to a private or reserved address');
    }
    return { url: url.toString(), addresses, origin: url.origin };
  }

  async _httpExchange(server, payload, context) {
    const target = await this._validateHttpTarget(server, context);
    const fetchImpl = this.fetchImpl || (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null);
    if (typeof fetchImpl !== 'function') throw new Error('HTTP fetch is unavailable');
    const controller = new AbortController();
    server.controllers.add(controller);
    const externalSignal = context && context.signal;
    let timedOut = false;
    const onAbort = () => controller.abort();
    if (externalSignal) {
      if (externalSignal.aborted) controller.abort();
      else externalSignal.addEventListener('abort', onAbort, { once: true });
    }
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, this.requestTimeout);
    const configuredHeaders = validateHeaders(server.config.headers);
    const headers = {
      ...configuredHeaders,
      Accept: 'application/json, text/event-stream',
      'Content-Type': 'application/json',
      'MCP-Protocol-Version': this.protocolVersion,
      'User-Agent': `${CLIENT_NAME}/${CLIENT_VERSION}`,
    };
    if (server.sessionId) headers['Mcp-Session-Id'] = server.sessionId;
    try {
      if (controller.signal.aborted) throw new Error('Request cancelled');
      const exchangePromise = Promise.resolve().then(async () => {
        const response = await fetchImpl(target.url, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
          signal: controller.signal,
          redirect: 'error',
        });
        if (response && response.redirected) throw new Error('MCP HTTP redirects are not allowed');
        if (response && response.url) {
          let responseUrl;
          try { responseUrl = new URL(response.url, target.url); } catch { throw new Error('MCP HTTP response URL is invalid'); }
          if (responseUrl.origin !== target.origin) throw new Error('MCP HTTP redirects are not allowed');
        }
        const body = await readResponseBody(response, this.maxResponseBytes);
        return { response, body };
      });
      const exchange = await new Promise((resolve, reject) => {
        let settled = false;
        const onExchangeAbort = () => finish(new Error('Request cancelled'));
        const finish = (error, value) => {
          if (settled) return;
          settled = true;
          try { controller.signal.removeEventListener('abort', onExchangeAbort); } catch { /* native AbortSignal */ }
          if (error) reject(error);
          else resolve(value);
        };
        controller.signal.addEventListener('abort', onExchangeAbort, { once: true });
        if (controller.signal.aborted) finish(new Error('Request cancelled'));
        exchangePromise.then((value) => finish(null, value), (error) => finish(error));
      });
      const { response, body } = exchange;
      const responseHeaders = headersToObject(response && response.headers);
      const newSession = getHeader(responseHeaders, 'mcp-session-id');
      if (newSession) server.sessionId = String(newSession).slice(0, 512);
      const status = Number(response && response.status) || 0;
      if (status === 202 && !body.text.trim()) return { accepted: true, status, messages: [] };
      if (status < 200 || status >= 300) {
        if (status === 405 || status === 501) throw new Error('Legacy HTTP+SSE transport is not supported; use streamable HTTP POST');
        throw new Error(`MCP HTTP request failed (${status})`);
      }
      const contentType = getHeader(responseHeaders, 'content-type') || '';
      const messages = this._parseHttpMessages(body.text, contentType);
      return { accepted: false, status, messages, truncated: body.truncated };
    } catch (error) {
      if (timedOut) throw new Error('MCP request timed out');
      if (controller.signal.aborted || (externalSignal && externalSignal.aborted)) throw new Error('Request cancelled');
      throw error;
    } finally {
      clearTimeout(timer);
      server.controllers.delete(controller);
      if (externalSignal && typeof externalSignal.removeEventListener === 'function') externalSignal.removeEventListener('abort', onAbort);
    }
  }

  _parseHttpMessages(text, contentType) {
    const value = String(text || '');
    const type = String(contentType || '').toLowerCase();
    if (type.includes('text/event-stream')) {
      const events = parseSse(value);
      if (events.some((event) => event.event === 'endpoint' || /^\s*(?:https?:\/\/[^\s]*\/messages|\/messages(?:\?|$))/i.test(event.data))) {
        throw new Error('Legacy HTTP+SSE transport is not supported; use streamable HTTP POST');
      }
      const messages = [];
      for (const event of events) {
        if (!event.data || event.data === '[DONE]') continue;
        try {
          const parsed = JSON.parse(event.data);
          if (Array.isArray(parsed)) messages.push(...parsed);
          else messages.push(parsed);
        } catch {
          throw new Error('MCP HTTP SSE event contained invalid JSON');
        }
      }
      return messages;
    }
    if (!value.trim()) return [];
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      // A few servers omit content-type; accept a JSON body in that case.
      if (type && !type.includes('json')) throw new Error('MCP HTTP response was not JSON or SSE');
      throw new Error('MCP HTTP response contained invalid JSON');
    }
  }

  _notify(server, method, params, context = {}) {
    return this._request(server, method, params, context, { notification: true });
  }

  _normalizeTools(rawTools, serverName, server = null) {
    const tools = [];
    for (const item of rawTools.slice(0, MAX_SCHEMA_PROPERTIES * 4)) {
      if (!isObject(item) || typeof item.name !== 'string') continue;
      const toolName = item.name.trim();
      if (!toolName || toolName.length > MAX_INTERNAL_TOOL_NAME || /[\u0000-\u001f\u007f]/.test(toolName)) continue;
      const parameters = normalizeInputSchema(item.inputSchema);
      const record = {
        serverName,
        toolName,
        exposedName: '',
        definition: {
          type: 'function',
          function: {
            name: '',
            description: truncateDescription(item.description || `MCP tool ${toolName}`),
            parameters,
          },
        },
      };
      tools.push(server ? this._scrubServerValue(server, record) : record);
    }
    return tools;
  }

  _replaceToolsForServer(serverName, tools, expectedServer = null) {
    if (expectedServer && !this._isCurrentServer(expectedServer)) return;
    this._removeToolsForServer(serverName, expectedServer ? null : undefined);
    const serverSegment = this.serverSegments.get(serverName) || safeSegment(serverName);
    for (const record of tools) {
      const toolSegment = safeSegment(record.toolName, 'tool', 32);
      let base = `mcp__${serverSegment}__${toolSegment}`;
      if (base.length > MAX_EXPOSED_NAME) base = base.slice(0, MAX_EXPOSED_NAME);
      let exposed = base;
      let suffix = 2;
      while (this.toolIndex.has(exposed) || !/^mcp__[A-Za-z0-9_-]+__[A-Za-z0-9_-]+$/.test(exposed)) {
        const ending = `-${suffix}`;
        exposed = `${base.slice(0, Math.max(1, MAX_EXPOSED_NAME - ending.length))}${ending}`;
        suffix += 1;
        if (suffix > 1000) break;
      }
      record.serverGeneration = expectedServer?.generation ?? record.serverGeneration;
      record.exposedName = exposed;
      record.definition.function.name = exposed;
      this.toolIndex.set(exposed, record);
    }
  }

  _removeToolsForServer(serverName, generation = null) {
    for (const [exposed, record] of this.toolIndex) {
      if (record.serverName === serverName && (generation === null || record.serverGeneration === generation)) this.toolIndex.delete(exposed);
    }
  }

  _toolResult(record, result, server) {
    const bounded = this._boundToolResult(result, server);
    const exposedName = this._scrubServerSecrets(server, redactString(record.exposedName)).slice(0, MAX_EXPOSED_NAME);
    if (bounded.isError) {
      return {
        ok: false,
        summary: `MCP tool ${exposedName} returned an error`,
        data: bounded,
        error: bounded.text ? this._scrubServerSecrets(server, redactString(bounded.text)).slice(0, 2_000) : 'MCP tool reported an error',
      };
    }
    return {
      ok: true,
      summary: `MCP tool ${exposedName} completed`,
      data: bounded,
    };
  }

  _scrubServerValue(server, value, seen = new WeakSet()) {
    if (typeof value === 'string') return this._scrubServerSecrets(server, redactString(value));
    if (Array.isArray(value)) {
      if (seen.has(value)) return '[Circular]';
      seen.add(value);
      return value.map((item) => this._scrubServerValue(server, item, seen));
    }
    if (isObject(value)) {
      if (seen.has(value)) return '[Circular]';
      seen.add(value);
      const output = {};
      for (const [key, item] of Object.entries(value)) output[key] = this._scrubServerValue(server, item, seen);
      return output;
    }
    return value;
  }

  _boundToolResult(result, server = null) {
    const output = { text: '', content: [], isError: false, truncated: false };
    if (!isObject(result)) {
      output.content.push({ type: 'text', text: 'MCP tool returned no structured result.' });
      output.text = output.content[0].text;
      return output;
    }
    output.isError = result.isError === true;
    const chunks = [];
    let total = 0;
    let contentTotal = 0;
    const addText = (value) => {
      if (typeof value !== 'string') return;
      const clean = this._scrubServerSecrets(server, redactString(value));
      const room = this.maxToolResultChars - total;
      if (room <= 0) {
        output.truncated = true;
        return;
      }
      if (clean.length > room) {
        chunks.push(clean.slice(0, room));
        total = this.maxToolResultChars;
        output.truncated = true;
      } else {
        chunks.push(clean);
        total += clean.length;
      }
    };
    if (Array.isArray(result.content)) {
      for (const item of result.content.slice(0, 256)) {
        if (!isObject(item)) {
          output.content.push({ type: 'unknown', summary: '[non-text content omitted]' });
          continue;
        }
        if (item.type === 'text') {
          const value = typeof item.text === 'string' ? item.text : '';
          const clean = this._scrubServerSecrets(server, redactString(value));
          addText(clean);
          const room = Math.max(0, this.maxToolResultChars - contentTotal);
          const shown = clean.slice(0, room);
          contentTotal += shown.length;
          if (shown.length < clean.length) output.truncated = true;
          output.content.push({ type: 'text', text: shown });
        } else if (item.type === 'resource' && isObject(item.resource) && typeof item.resource.text === 'string') {
          const clean = this._scrubServerSecrets(server, redactString(item.resource.text));
          addText(clean);
          const room = Math.max(0, this.maxToolResultChars - contentTotal);
          const shown = clean.slice(0, room);
          contentTotal += shown.length;
          if (shown.length < clean.length) output.truncated = true;
          output.content.push({ type: 'resource', text: shown });
        } else {
          const type = typeof item.type === 'string' ? item.type.slice(0, 80) : 'unknown';
          output.content.push({ type, summary: '[non-text content omitted]' });
        }
      }
    } else {
      output.content.push({ type: 'structured', summary: '[structured content omitted]' });
    }
    if (result.structuredContent !== undefined) output.content.push({ type: 'structuredContent', summary: '[structured content omitted]' });
    output.text = chunks.join('\n').slice(0, this.maxToolResultChars);
    if (total > this.maxToolResultChars) output.truncated = true;
    output.content = this._scrubServerValue(server, redact(output.content.slice(0, 256)));
    output.text = this._scrubServerSecrets(server, redactString(output.text));
    return output;
  }

  _killChild(server) {
    if (!server.child || typeof server.child.kill !== 'function') return;
    try { server.child.kill(); } catch { /* best effort during cleanup */ }
  }

  _rejectPending(server, error) {
    for (const pending of server.pending.values()) pending.reject(error);
    server.pending.clear();
  }

  async _stopServer(server) {
    if (!server) return;
    if (server.stopPromise) return server.stopPromise;
    server.stopPromise = (async () => {
      server.retired = true;
      server.status = 'stopping';
      for (const controller of server.controllers) {
        try { controller.abort(); } catch { /* best effort during shutdown */ }
      }
      server.controllers.clear();
      this._rejectPending(server, new Error('MCP server stopped'));
      server.initialized = false;
      server.sessionId = null;
      server.stdoutBuffer = '';
      server.tools = [];
      this._removeToolsForServer(server.name, server.generation);
      const child = server.child;
      // Give a well-behaved child a chance to observe kill, but never make
      // stop() depend on a process that has already disappeared.
      if (child && typeof child.once === 'function') {
        try {
          await new Promise((resolve) => {
            let done = false;
            let timer;
            const finish = () => {
              if (done) return;
              done = true;
              clearTimeout(timer);
              resolve();
            };
            child.once('close', finish);
            child.once('exit', finish);
            timer = setTimeout(finish, Math.min(100, this.requestTimeout));
            this._killChild(server);
          });
        } catch {
          // Cleanup must remain best effort even for a nonconforming child.
          this._killChild(server);
        }
      } else {
        this._killChild(server);
      }
      server.child = null;
      if (this.servers.get(server.name) === server) {
        server.retired = false;
        this._setServerStatus(server, 'stopped');
      }
    })();
    return server.stopPromise;
  }
}

module.exports = {
  McpManager,
  MCP_PROTOCOL_VERSION,
  CLIENT_NAME,
  CLIENT_VERSION,
  parseSse,
  parseSSE,
  parseSseEvents: parseSse,
  parseSseJson,
  redact,
  redactSecrets: redact,
  redactString,
  normalizeInputSchema,
  safeSegment,
};
