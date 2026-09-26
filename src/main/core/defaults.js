'use strict';

/**
 * Application-wide defaults and settings validation.
 *
 * This module deliberately has no Electron (or other UI) dependencies.  It
 * is used by the settings store as well as by code which needs to display or
 * seed settings, so keeping the defaults here makes the validation rules
 * consistent for both paths.
 */

const path = require('node:path');

const APP_NAME = 'CodePilot Local';
const APP_VERSION = '0.1.0';
const APP_INFO = Object.freeze({ name: APP_NAME, version: APP_VERSION });
const SETTINGS_VERSION = 1;

/**
 * These are deliberately conservative limits.  They are not user settings;
 * they are guard rails used while reading settings supplied by a file or by
 * an untrusted renderer process.
 */
const SAFE_LIMITS = Object.freeze({
  temperature: Object.freeze({ min: 0, max: 2 }),
  topP: Object.freeze({ min: 0, max: 1 }),
  maxTokens: Object.freeze({ min: 1, max: 1_000_000 }),
  contextLength: Object.freeze({ min: 512, max: 32_768 }),
  contextChars: Object.freeze({ min: 1_000, max: 2_000_000 }),
  maxSteps: Object.freeze({ min: 1, max: 100 }),
  maxSubagents: Object.freeze({ min: 0, max: 20 }),
  maxConcurrentSubagents: Object.freeze({ min: 1, max: 20 }),
  maxSubagentSteps: Object.freeze({ min: 1, max: 100 }),
  modelChars: 512,
  urlChars: 2_048,
  pathChars: 4_096,
  secretChars: 16_384,
  mcpServers: 128,
  mcpJsonDepth: 12,
  mcpJsonItems: 2_000,
  maxLogBytes: 5 * 1024 * 1024,
  maxLogFiles: 14,
  maxSessions: 100,
  maxMessagesPerSession: 500,
  maxToolDataBytes: 64 * 1024,
});

// Keep the public settings shape small and stable.  In particular, secrets
// are represented by braveApiKey here, but SettingsStore removes that field
// from its public representation and replaces it with a presence flag.
const DEFAULT_SETTINGS = {
  lmBaseUrl: 'http://127.0.0.1:1234/v1',
  model: '',
  modelPreset: 'qwen3-4b-1050ti',
  temperature: 0.2,
  topP: 0.9,
  // LM Studio rejects a request when prompt tokens + max_tokens exceed the
  // context the model was loaded with.  The agent prompt alone (system prompt
  // plus every tool schema) is roughly 1600 tokens, so a 2048 context leaves
  // no room at all.  4096 context with 1024 output tokens fits a full turn on
  // a 4 GB card, and the history budget stays small enough to leave headroom
  // for tool results.
  maxTokens: 1024,
  contextLength: 4096,
  contextChars: 4500,
  maxSteps: 8,
  maxSubagents: 1,
  maxConcurrentSubagents: 1,
  maxSubagentSteps: 6,
  flashAttention: true,
  approvalMode: 'automatic',
  allowFallbackTools: false,
  fileRoot: '',
  webProvider: 'duckduckgo',
  braveApiKey: '',
  mcpServers: Object.freeze({}),
};

// `searchProvider` is the name used by the web tool layer.  Keep it as a
// non-enumerable compatibility alias so the persisted/default shape remains
// the small, documented `webProvider` shape while existing callers can use
// either spelling.
Object.defineProperty(DEFAULT_SETTINGS, 'searchProvider', {
  configurable: false,
  enumerable: false,
  get() { return this.webProvider; },
  set(value) { this.webProvider = value; },
});
Object.defineProperty(DEFAULT_SETTINGS, 'appName', { value: APP_NAME, enumerable: false });
Object.defineProperty(DEFAULT_SETTINGS, 'appVersion', { value: APP_VERSION, enumerable: false });
Object.defineProperty(DEFAULT_SETTINGS, 'workspace', {
  configurable: false,
  enumerable: false,
  get() { return this.fileRoot; },
  set(value) { this.fileRoot = value; },
});
Object.defineProperty(DEFAULT_SETTINGS, 'limits', { value: SAFE_LIMITS, enumerable: false });
Object.freeze(DEFAULT_SETTINGS);
const DEFAULT_CONFIG = Object.freeze({ app: APP_INFO, settings: DEFAULT_SETTINGS });

const APPROVAL_MODES = new Set(['automatic', 'manual', 'ask', 'always', 'never']);
const MODEL_PRESETS = new Set(['qwen3-4b-1050ti', 'qwen3-4b-thinking-2507', 'qwen25-coder-3b', 'qwen25-coder-14b', 'qwen38-4b-distilled-ma7ee7', 'custom']);
const WEB_PROVIDERS = new Set(['duckduckgo', 'brave']);
const KNOWN_KEYS = new Set([
  'lmBaseUrl',
  'model',
  'modelPreset',
  'temperature',
  'topP',
  'maxTokens',
  'contextLength',
  'contextChars',
  'maxSteps',
  'maxSubagents',
  'maxConcurrentSubagents',
  'maxSubagentSteps',
  'flashAttention',
  'approvalMode',
  'allowFallbackTools',
  'fileRoot',
  'webProvider',
  'searchProvider',
  'braveApiKey',
  'mcpServers',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function cloneMcpValue(value, depth = 0, state = new WeakSet()) {
  if (depth > SAFE_LIMITS.mcpJsonDepth) return null;

  if (value === null) return null;
  if (typeof value === 'string') return value.slice(0, SAFE_LIMITS.secretChars);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'undefined' || typeof value === 'function' || typeof value === 'symbol') return null;

  if (state.has(value)) return null;
  state.add(value);
  try {
    if (Array.isArray(value)) {
      const result = [];
      const count = Math.min(value.length, SAFE_LIMITS.mcpJsonItems);
      for (let i = 0; i < count; i += 1) {
        result.push(cloneMcpValue(value[i], depth + 1, state));
      }
      return result;
    }

    if (!isPlainObject(value)) return null;
    const result = {};
    const entries = Object.entries(value).slice(0, SAFE_LIMITS.mcpJsonItems);
    for (const [key, item] of entries) {
      // Never allow a persisted object to modify Object.prototype.
      if (key === '__proto__' || key === 'prototype' || key === 'constructor') continue;
      result[key] = cloneMcpValue(item, depth + 1, state);
    }
    return result;
  } finally {
    state.delete(value);
  }
}

function normalizeMcpServers(value) {
  if (!isPlainObject(value)) return {};
  const result = {};
  const entries = Object.entries(value).slice(0, SAFE_LIMITS.mcpServers);
  for (const [name, config] of entries) {
    if (!name || name === '__proto__' || name === 'prototype' || name === 'constructor') continue;
    result[name] = cloneMcpValue(config);
  }
  return result;
}

function normalizeUrl(value, fallback) {
  if (typeof value !== 'string') return fallback;
  const text = value.trim();
  if (!text || text.length > SAFE_LIMITS.urlChars) return fallback;
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return fallback;
    // Credentials in a URL are almost always an accidental secret leak.
    if (parsed.username || parsed.password) return fallback;
    return parsed.toString();
  } catch {
    return fallback;
  }
}

function normalizeString(value, fallback, maxLength) {
  if (typeof value !== 'string') return fallback;
  return value.trim().slice(0, maxLength);
}

function normalizeInteger(value, fallback, range) {
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) return fallback;
  if (value < range.min || value > range.max) return fallback;
  return value;
}

function normalizeNumber(value, fallback, range) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  if (value < range.min || value > range.max) return fallback;
  return value;
}

function normalizePath(value, fallback = '') {
  if (typeof value !== 'string') return fallback;
  const text = value.trim();
  if (!text) return '';
  if (text.length > SAFE_LIMITS.pathChars || !path.isAbsolute(text)) return fallback;
  return path.normalize(text);
}

function normalizeEnum(value, allowed, fallback) {
  if (typeof value !== 'string') return fallback;
  const text = value.trim().toLowerCase();
  return allowed.has(text) ? text : fallback;
}

function decorateSettingsAliases(settings) {
  if (!settings || typeof settings !== 'object') return settings;
  if (!Object.prototype.hasOwnProperty.call(settings, 'searchProvider')) {
    Object.defineProperty(settings, 'searchProvider', {
      configurable: true,
      enumerable: false,
      get() { return this.webProvider; },
      set(value) { this.webProvider = value; },
    });
  }
  if (!Object.prototype.hasOwnProperty.call(settings, 'workspace')) {
    Object.defineProperty(settings, 'workspace', {
      configurable: true,
      enumerable: false,
      get() { return this.fileRoot; },
      set(value) { this.fileRoot = value; },
    });
  }
  if (!Object.prototype.hasOwnProperty.call(settings, 'limits')) {
    Object.defineProperty(settings, 'limits', { configurable: true, enumerable: false, value: SAFE_LIMITS });
  }
  return settings;
}

function defaultsCopy() {
  return decorateSettingsAliases({
    ...DEFAULT_SETTINGS,
    mcpServers: {},
  });
}

/**
 * Convert an arbitrary settings-like value into a safe, complete settings
 * object.  Invalid values fall back to their defaults; this function is
 * intended for loading files and for sanitizing renderer-provided data.
 */
function sanitizeSettings(value) {
  const result = defaultsCopy();
  if (!isPlainObject(value)) return result;

  // Accept the persisted envelope as a convenience, while never retaining
  // envelope-only fields in the returned settings.
  const source = isPlainObject(value.settings) ? value.settings : value;

  if (Object.prototype.hasOwnProperty.call(source, 'web') && isPlainObject(source.web)) {
    if (!Object.prototype.hasOwnProperty.call(source, 'webProvider')) {
      result.webProvider = normalizeEnum(source.web.provider, WEB_PROVIDERS, result.webProvider);
    }
    if (!Object.prototype.hasOwnProperty.call(source, 'braveApiKey')) {
      result.braveApiKey = normalizeString(source.web.braveApiKey, result.braveApiKey, SAFE_LIMITS.secretChars);
    }
  }

  // `workspace` was used by an early UI prototype.  It is an input alias
  // for fileRoot, not a second persisted setting.
  if (!Object.prototype.hasOwnProperty.call(source, 'fileRoot') &&
      Object.prototype.hasOwnProperty.call(source, 'workspace')) {
    result.fileRoot = normalizePath(source.workspace, result.fileRoot);
  }

  for (const key of KNOWN_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    const candidate = source[key];
    switch (key) {
      case 'lmBaseUrl':
        result[key] = normalizeUrl(candidate, result[key]);
        break;
      case 'model':
        result[key] = normalizeString(candidate, result[key], SAFE_LIMITS.modelChars);
        break;
      case 'modelPreset':
        result[key] = normalizeEnum(candidate, MODEL_PRESETS, result[key]);
        break;
      case 'temperature':
        result[key] = normalizeNumber(candidate, result[key], SAFE_LIMITS.temperature);
        break;
      case 'topP':
        result[key] = normalizeNumber(candidate, result[key], SAFE_LIMITS.topP);
        break;
      case 'maxTokens':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.maxTokens);
        break;
      case 'contextLength':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.contextLength);
        break;
      case 'contextChars':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.contextChars);
        break;
      case 'maxSteps':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.maxSteps);
        break;
      case 'maxSubagents':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.maxSubagents);
        break;
      case 'maxConcurrentSubagents':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.maxConcurrentSubagents);
        break;
      case 'maxSubagentSteps':
        result[key] = normalizeInteger(candidate, result[key], SAFE_LIMITS.maxSubagentSteps);
        break;
      case 'flashAttention':
        result[key] = typeof candidate === 'boolean' ? candidate : result[key];
        break;
      case 'approvalMode':
        result[key] = normalizeEnum(candidate, APPROVAL_MODES, result[key]);
        break;
      case 'allowFallbackTools':
        result[key] = typeof candidate === 'boolean' ? candidate : result[key];
        break;
      case 'fileRoot':
        result[key] = normalizePath(candidate, result[key]);
        break;
      case 'webProvider':
        result[key] = normalizeEnum(candidate, WEB_PROVIDERS, result.webProvider);
        break;
      case 'searchProvider':
        result.webProvider = normalizeEnum(candidate, WEB_PROVIDERS, result.webProvider);
        break;
      case 'braveApiKey':
        result[key] = normalizeString(candidate, result.braveApiKey, SAFE_LIMITS.secretChars);
        break;
      case 'mcpServers':
        result[key] = normalizeMcpServers(candidate);
        break;
      default:
        break;
    }
  }

  return decorateSettingsAliases(result);
}

function invalid(message) {
  const error = new TypeError(`Invalid settings: ${message}`);
  error.code = 'INVALID_SETTINGS';
  return error;
}

function assertUrl(value) {
  if (typeof value !== 'string' || value.length > SAFE_LIMITS.urlChars) throw invalid('lmBaseUrl must be a URL string');
  const text = value.trim();
  let parsed;
  try {
    parsed = new URL(text);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('protocol');
    if (parsed.username || parsed.password) throw new Error('credentials');
  } catch {
    throw invalid('lmBaseUrl must be an absolute http(s) URL');
  }
  return parsed.toString();
}

function assertString(value, name, maxLength, { allowEmpty = true } = {}) {
  if (typeof value !== 'string') throw invalid(`${name} must be a string`);
  if (value.length > maxLength) throw invalid(`${name} is too long`);
  if (!allowEmpty && value.trim() === '') throw invalid(`${name} must not be empty`);
  return value.trim().slice(0, maxLength);
}

function assertNumber(value, name, range, integer = false) {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw invalid(`${name} must be a finite number`);
  if (integer && !Number.isInteger(value)) throw invalid(`${name} must be an integer`);
  if (value < range.min || value > range.max) throw invalid(`${name} must be between ${range.min} and ${range.max}`);
  return value;
}

/**
 * Validate a partial update.  Unknown keys are intentionally ignored: this
 * prevents a renderer from smuggling arbitrary properties into the persisted
 * settings object.  Known keys are strict so an update cannot silently turn a
 * typo or an unsafe value into a surprising setting.
 */
function validateSettingsPatch(patch, current = DEFAULT_SETTINGS) {
  if (!isPlainObject(patch)) throw invalid('patch must be an object');
  const result = {};

  for (const [rawKey, candidate] of Object.entries(patch)) {
    const key = rawKey === 'workspace'
      ? 'fileRoot'
      : (rawKey === 'searchProvider' ? 'webProvider' : rawKey);
    if (rawKey === 'web' && isPlainObject(candidate)) {
      if (Object.prototype.hasOwnProperty.call(candidate, 'provider')) {
        result.webProvider = assertString(candidate.provider, 'web.provider', 64, { allowEmpty: false }).toLowerCase();
        if (!WEB_PROVIDERS.has(result.webProvider)) throw invalid('web.provider is not supported');
      }
      if (Object.prototype.hasOwnProperty.call(candidate, 'braveApiKey')) {
        result.braveApiKey = assertString(candidate.braveApiKey, 'web.braveApiKey', SAFE_LIMITS.secretChars);
      }
      continue;
    }
    if (!KNOWN_KEYS.has(key)) continue;

    switch (key) {
      case 'lmBaseUrl':
        result[key] = assertUrl(candidate);
        break;
      case 'model':
        result[key] = assertString(candidate, key, SAFE_LIMITS.modelChars);
        break;
      case 'modelPreset': {
        const preset = assertString(candidate, key, 64, { allowEmpty: false }).toLowerCase();
        if (!MODEL_PRESETS.has(preset)) throw invalid('modelPreset is not supported');
        result[key] = preset;
        break;
      }
      case 'temperature':
        result[key] = assertNumber(candidate, key, SAFE_LIMITS.temperature);
        break;
      case 'topP':
        result[key] = assertNumber(candidate, key, SAFE_LIMITS.topP);
        break;
      case 'maxTokens':
      case 'contextLength':
      case 'contextChars':
      case 'maxSteps':
      case 'maxSubagents':
      case 'maxConcurrentSubagents':
      case 'maxSubagentSteps':
        result[key] = assertNumber(candidate, key, SAFE_LIMITS[key], true);
        break;
      case 'flashAttention':
        if (typeof candidate !== 'boolean') throw invalid('flashAttention must be a boolean');
        result[key] = candidate;
        break;
      case 'approvalMode': {
        const mode = assertString(candidate, key, 64, { allowEmpty: false }).toLowerCase();
        if (!APPROVAL_MODES.has(mode)) throw invalid('approvalMode is not supported');
        result[key] = mode;
        break;
      }
      case 'allowFallbackTools':
        if (typeof candidate !== 'boolean') throw invalid('allowFallbackTools must be a boolean');
        result[key] = candidate;
        break;
      case 'fileRoot': {
        if (typeof candidate !== 'string') throw invalid('fileRoot must be a string');
        const text = candidate.trim();
        if (!text) {
          result[key] = '';
        } else {
          if (text.length > SAFE_LIMITS.pathChars || !path.isAbsolute(text)) throw invalid('fileRoot must be absolute or empty');
          result[key] = path.normalize(text);
        }
        break;
      }
      case 'webProvider': {
        const provider = assertString(candidate, key, 64, { allowEmpty: false }).toLowerCase();
        if (!WEB_PROVIDERS.has(provider)) throw invalid('webProvider is not supported');
        result[key] = provider;
        break;
      }
      case 'braveApiKey':
        result[key] = assertString(candidate, key, SAFE_LIMITS.secretChars);
        break;
      case 'mcpServers': {
        if (!isPlainObject(candidate)) throw invalid('mcpServers must be an object');
        const normalized = normalizeMcpServers(candidate);
        if (Object.keys(normalized).length > SAFE_LIMITS.mcpServers) throw invalid('too many MCP servers');
        result[key] = normalized;
        break;
      }
      default:
        break;
    }
  }

  return result;
}

/** Return a new validated settings object, leaving `current` untouched. */
function updateSettings(current, patch) {
  if (arguments.length === 1) {
    patch = current;
    current = DEFAULT_SETTINGS;
  }
  const validated = validateSettingsPatch(patch, current);
  return sanitizeSettings({ ...sanitizeSettings(current), ...validated });
}

function getDefaultSettings() {
  return defaultsCopy();
}

module.exports = {
  APP_NAME,
  APP_VERSION,
  VERSION: APP_VERSION,
  APP_INFO,
  DEFAULT_APP: APP_INFO,
  DEFAULT_CONFIG,
  DEFAULT_SETTINGS,
  DEFAULTS: DEFAULT_SETTINGS,
  SETTINGS_VERSION,
  SETTINGS_SCHEMA_VERSION: SETTINGS_VERSION,
  SAFE_LIMITS,
  LIMITS: SAFE_LIMITS,
  MAX_LOG_BYTES: SAFE_LIMITS.maxLogBytes,
  MAX_SESSIONS: SAFE_LIMITS.maxSessions,
  MAX_MESSAGES_PER_SESSION: SAFE_LIMITS.maxMessagesPerSession,
  MAX_TOOL_DATA_BYTES: SAFE_LIMITS.maxToolDataBytes,
  APPROVAL_MODES: Object.freeze([...APPROVAL_MODES]),
  MODEL_PRESETS: Object.freeze([...MODEL_PRESETS]),
  WEB_PROVIDERS: Object.freeze([...WEB_PROVIDERS]),
  KNOWN_KEYS: Object.freeze([...KNOWN_KEYS]),
  isPlainObject,
  normalizeMcpServers,
  decorateSettingsAliases,
  sanitizeSettings,
  validateSettingsPatch,
  updateSettings,
  getDefaultSettings,
};
