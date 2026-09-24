'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const IGNORED_DIRECTORY_NAMES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  '.venv',
  'venv',
  '__pycache__',
]);

const MAX_LIST_ENTRIES = 500;
const MAX_RESULTS = 200;
const DEFAULT_READ_BYTES = 256 * 1024;
const MAX_READ_BYTES = 1024 * 1024;
const DEFAULT_MANY_FILES_BYTES = 1024 * 1024;
const MAX_MANY_FILES_BYTES = 2 * 1024 * 1024;
const MAX_WRITE_BYTES = 10 * 1024 * 1024;
const SEARCH_FILE_BYTES = 512 * 1024;
const SEARCH_TOTAL_BYTES = 20 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES_SCANNED = 10_000;
const MAX_PATTERN_LENGTH = 512;
const MAX_REGEX_PATTERN_LENGTH = 512;
const MAX_GLOB_INPUT_LENGTH = 4096;
const MAX_GLOB_CACHE_ENTRIES = 128;
const MAX_REGEX_QUANTIFIERS = 64;
const MAX_REGEX_GROUPS = 128;
const MAX_REGEX_REPETITION = 1_000;
const MAX_SECRET_POLICY_SCAN_CHARS = MAX_READ_BYTES;
const SENSITIVE_REDACTION = '[REDACTED]';
const SENSITIVE_FILE_ERROR = 'Sensitive file access is blocked by workspace policy.';
const SENSITIVE_CONFIG_EXTENSIONS = new Set([
  '.json', '.json5', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg', '.properties', '.config',
]);
const SENSITIVE_DIRECTORY_NAMES = new Set([
  '.env', '.secrets', '.secret', 'secrets', 'secret', '.credentials', 'credentials',
]);
const PRIVATE_KEY_HEADER_RE = /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----/i;
const SENSITIVE_CONFIG_VALUE_RE = /["']?(?:authorization|cookie|set[_-]?cookie|password|passwd|pwd|secret|secrets?|credentials?|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']?[^"',}\]\s]+/i;
const SENSITIVE_CONFIG_KEY_PART_RE = /(?:^|[_-])(?:password|passwd|pwd|secret|secrets?|credentials?|token|api[_-]?key|apikey|access[_-]?key|refresh[_-]?token|id[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)(?:$|[_-])/i;
const SENSITIVE_CONFIG_FILE_RE = /^(?:secret|secrets|credential|credentials)(?:[._-](?:txt|json5?|ya?ml|toml|ini|conf|cfg|properties|config|bak|backup|old|enc|encrypted))?$/i;

const READ_ONLY_TOOLS = new Set([
  'list_directory',
  'find_files',
  'read_file',
  'read_many_files',
  'search_text',
  'get_file_info',
  'project_overview',
  'find_symbols',
  'project_map',
]);

const CHAT_TOOLS = new Set([
  ...READ_ONLY_TOOLS,
  'write_file',
  'edit_file',
  'apply_patch',
  'create_directory',
]);

function errorMessage(error) {
  try {
    if (error && typeof error.message === 'string' && error.message) return error.message;
    return String(error);
  } catch {
    return 'Unknown error';
  }
}

function isAbortError(error) {
  return Boolean(error && (error.name === 'AbortError' || error.code === 'ABORT_ERR'));
}

function createAbortError() {
  const error = new Error('Workspace operation was cancelled.');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function throwIfAborted(signal) {
  if (signal && signal.aborted === true) throw createAbortError();
}

function getSignal(context) {
  return context && context.signal ? context.signal : null;
}

function allowsSecretRead(context) {
  return Boolean(
    context &&
    Object.prototype.hasOwnProperty.call(context, 'allowSecretRead') &&
    context.allowSecretRead === true,
  );
}

function markSensitiveFileSkipped(state) {
  if (!state) return;
  state.sensitiveFilesSkipped = (state.sensitiveFilesSkipped || 0) + 1;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function isSamePath(left, right) {
  const relative = path.relative(left, right);
  return relative === '' && !path.isAbsolute(relative);
}

function toPortablePath(value) {
  return value.split(path.sep).join('/');
}

function displayPath(root, target) {
  const relative = path.relative(root, target);
  return toPortablePath(relative || '.');
}

function isIgnoredLocation(root, target) {
  const relative = path.relative(root, target);
  if (!relative) return false;
  return relative
    .split(path.sep)
    .some((part) => IGNORED_DIRECTORY_NAMES.has(part.toLowerCase()));
}

function isSensitiveFile(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) return false;
  const parts = filePath.split(/[\\/]+/).filter(Boolean).map((part) => part.toLowerCase());
  const name = parts[parts.length - 1] || '';
  const parentParts = parts.slice(0, -1);
  const extension = path.extname(name).toLowerCase();

  if (name === '.env' || name.startsWith('.env.') || name.endsWith('.env') || name === '.envrc') return true;
  if (name === '.npmrc' || name === '.pypirc' || name === '.netrc' || name === '.pgpass' || name === '.git-credentials') return true;
  if (SENSITIVE_DIRECTORY_NAMES.has(name)) return true;
  if (parentParts.some((part) => SENSITIVE_DIRECTORY_NAMES.has(part))) return true;
  if (/(?:^|[._-])id_(?:rsa|dsa|ecdsa|ed25519)(?:[._-]|$)/.test(name)) return true;
  if (/(?:^|[._-])private[_-]?key(?:[._-]|$)/.test(name)) return true;
  if (SENSITIVE_CONFIG_FILE_RE.test(name)) return true;
  if (/\.(?:secret|secrets|credential|credentials)$/.test(name)) return true;
  if (name.startsWith('credentials.') || name.startsWith('secrets.')) return true;
  if (/\.(?:pem|key|p12|pfx|pkcs8|pkcs12|sec1|jks|jceks|keystore|keytab|ppk|kdbx)$/.test(name)) return true;

  // Do not block every config file: ordinary project configuration is useful
  // to coding agents.  Config files with an explicit secret marker are treated
  // as sensitive, and content is checked separately after a bounded read.
  if (
    SENSITIVE_CONFIG_EXTENSIONS.has(extension) &&
    /(?:secret|credential|password|passwd|token|api[_-]?key|private[_-]?key)/i.test(name)
  ) return true;

  return false;
}

function isConfigKeyCharacter(character) {
  return Boolean(character) && /[A-Za-z0-9_.\- "' ]/.test(character);
}

function hasSensitiveConfigKey(text, signal) {
  throwIfAborted(signal);
  if (!/(?:password|passwd|pwd|secret|credentials?|token|key)/i.test(text)) return false;
  let assignments = 0;
  const limit = Math.min(text.length, MAX_SECRET_POLICY_SCAN_CHARS);
  for (let index = 0; index < limit; index += 1) {
    if ((index & 1023) === 0) throwIfAborted(signal);
    if (text[index] !== ':' && text[index] !== '=') continue;
    assignments += 1;
    if (assignments > 4096) break;
    const lowerBound = Math.max(0, index - 256);
    let start = index;
    while (start > lowerBound && isConfigKeyCharacter(text[start - 1])) start -= 1;
    const key = text.slice(start, index).trim().replace(/^["']|["']$/g, '');
    if (!key || key.length > 256) continue;
    const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
    if (SENSITIVE_CONFIG_KEY_PART_RE.test(normalized)) return true;
  }
  return false;
}

function isSensitiveContent(filePath, text, signal) {
  throwIfAborted(signal);
  if (typeof text !== 'string' || text.length === 0) return false;
  if (PRIVATE_KEY_HEADER_RE.test(text)) return true;
  if (!isSensitiveFile(filePath)) {
    const name = path.basename(filePath).toLowerCase();
    const extension = path.extname(name).toLowerCase();
    const configLike = SENSITIVE_CONFIG_EXTENSIONS.has(extension) ||
      /(?:^|[._-])(?:config|settings)(?:[._-]|$)/.test(name);
    if (!configLike) return false;
  }
  const sensitive = hasSensitiveConfigKey(text, signal) || SENSITIVE_CONFIG_VALUE_RE.test(text);
  throwIfAborted(signal);
  return sensitive;
}

function sensitiveReadResult(root, target) {
  const relative = displayPath(root, target);
  return {
    ok: false,
    summary: `Blocked sensitive file ${relative}`,
    data: {
      path: relative,
      blocked: true,
      redacted: true,
      content: SENSITIVE_REDACTION,
    },
    error: `${SENSITIVE_FILE_ERROR} (${relative})`,
  };
}

function isLikelyBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  if (sample.length === 0) return false;
  if (sample.includes(0)) return true;

  let suspicious = 0;
  for (const byte of sample) {
    if (
      (byte < 9) ||
      byte === 11 ||
      byte === 12 ||
      (byte >= 14 && byte <= 31) ||
      byte === 127
    ) {
      suspicious += 1;
    }
  }
  return suspicious / sample.length > 0.25;
}

function decodeUtf8(buffer) {
  const text = buffer.toString('utf8');
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function splitTextLines(text, signal) {
  throwIfAborted(signal);
  if (text.length === 0) return [];
  const lines = text.split(/\r\n|\n|\r/);
  if (lines[lines.length - 1] === '') lines.pop();
  throwIfAborted(signal);
  return lines;
}

function splitLineRecords(text, signal) {
  const records = [];
  let offset = 0;

  while (offset < text.length) {
    throwIfAborted(signal);
    const newline = text.indexOf('\n', offset);
    if (newline === -1) {
      records.push({ text: text.slice(offset), ending: '' });
      break;
    }

    const hasCarriageReturn = newline > offset && text[newline - 1] === '\r';
    records.push({
      text: text.slice(offset, hasCarriageReturn ? newline - 1 : newline),
      ending: hasCarriageReturn ? '\r\n' : '\n',
    });
    offset = newline + 1;
  }

  return records;
}

function joinLineRecords(records) {
  return records.map((record) => `${record.text}${record.ending}`).join('');
}

function hasGlobSyntax(value) {
  return /[*?[\]]/.test(value);
}

function looksUnsafeGlob(glob) {
  if (typeof glob !== 'string' || glob.length > MAX_PATTERN_LENGTH) return true;
  let wildcardCount = 0;
  for (const character of glob) {
    if (character === '*' || character === '?') wildcardCount += 1;
  }
  if (wildcardCount > 64) return true;
  if ((glob.match(/\*{3,}/g) || []).some((run) => run.length > 8)) return true;
  if (/\[[^\]]{80,}\]/.test(glob)) return true;

  // A long chain of adjacent wildcard atoms creates an equivalent ambiguous
  // regular expression.  A small number of wildcards (including **/*.js)
  // remains fully supported.
  const adjacentWildcards = /(?:\*{1,2}|\?)[^/]{0,16}(?:\*{1,2}|\?)(?:[^/]{0,16}(?:\*{1,2}|\?)){3,}/;
  return adjacentWildcards.test(glob);
}

const GLOB_REGEXP_CACHE = new Map();

function globToRegExp(glob) {
  if (typeof glob !== 'string' || glob.length === 0) {
    throw new TypeError('Glob pattern must be a non-empty string.');
  }
  if (glob.length > MAX_PATTERN_LENGTH) {
    throw new RangeError(`Glob pattern must be at most ${MAX_PATTERN_LENGTH} characters.`);
  }
  if (looksUnsafeGlob(glob)) {
    throw new Error('The glob pattern appears unsafe or computationally expensive.');
  }
  const cached = GLOB_REGEXP_CACHE.get(glob);
  if (cached) return cached;

  const normalized = glob.replace(/\\/g, '/');
  let source = '^';

  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index];
    if (character === '*') {
      if (normalized[index + 1] === '*') {
        index += 1;
        if (normalized[index + 1] === '/') {
          index += 1;
          source += '(?:.*/)?';
        } else {
          source += '.*';
        }
      } else {
        source += '[^/]*';
      }
      continue;
    }
    if (character === '?') {
      source += '[^/]';
      continue;
    }
    if (character === '[') {
      let closing = index + 1;
      let escaped = false;
      while (closing < normalized.length) {
        if (!escaped && normalized[closing] === ']') break;
        escaped = !escaped && normalized[closing] === '\\';
        if (normalized[closing] !== '\\') escaped = false;
        closing += 1;
      }
      if (closing < normalized.length) {
        let content = normalized.slice(index + 1, closing);
        if (content.startsWith('!')) content = `^${content.slice(1)}`;
        if (content.length === 0 || content.length > 80 || /[\r\n]/.test(content)) {
          throw new Error('The glob character class is invalid or too large.');
        }
        try {
          // Compile the class once here so malformed user input fails before
          // the walk begins rather than for every filesystem entry.
          new RegExp(`[${content}]`, 'i');
        } catch {
          throw new Error('The glob character class is invalid.');
        }
        source += `[${content}]`;
        index = closing;
        continue;
      }
    }
    source += character.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  }

  source += '$';
  let expression;
  try {
    expression = new RegExp(source, 'i');
  } catch {
    throw new Error('The glob pattern is invalid.');
  }
  if (GLOB_REGEXP_CACHE.size >= MAX_GLOB_CACHE_ENTRIES) {
    const first = GLOB_REGEXP_CACHE.keys().next().value;
    GLOB_REGEXP_CACHE.delete(first);
  }
  GLOB_REGEXP_CACHE.set(glob, expression);
  return expression;
}

function matchesGlob(relativePath, basename, pattern) {
  if (
    typeof relativePath !== 'string' ||
    typeof basename !== 'string' ||
    relativePath.length > MAX_GLOB_INPUT_LENGTH ||
    basename.length > MAX_GLOB_INPUT_LENGTH
  ) return false;
  const expression = globToRegExp(pattern);
  if (pattern.includes('/') || pattern.includes('\\')) {
    return expression.test(relativePath);
  }
  return expression.test(basename) || expression.test(relativePath);
}

function clampInteger(value, fallback, minimum, maximum) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value)) throw new TypeError('Value must be an integer.');
  return Math.min(maximum, Math.max(minimum, value));
}

function optionalString(args, name, options = {}) {
  const value = args[name];
  if (value === undefined && options.fallback !== undefined) return options.fallback;
  if (value === undefined) {
    if (options.required || options.allowEmpty === false) {
      throw new TypeError(`${name} is required and must be a string.`);
    }
    return undefined;
  }
  if (typeof value !== 'string') throw new TypeError(`${name} must be a string.`);
  if (options.allowEmpty === false && value.length === 0) {
    throw new TypeError(`${name} must not be empty.`);
  }
  if (options.maxLength && value.length > options.maxLength) {
    throw new RangeError(`${name} must be at most ${options.maxLength} characters.`);
  }
  return value;
}

function optionalBoolean(args, name, fallback = false) {
  const value = args[name];
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new TypeError(`${name} must be a boolean.`);
  return value;
}

function redactSensitive(text) {
  let redacted = text;
  const secretName = '(?:password|passwd|pwd|proxy[_-]?authorization|authorization|set[_-]?cookie|cookie|x[_-]?api[_-]?key|api[\\s_-]*key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token(?:Value)?|(?:aws[_-]?)?secrets?(?:[_-]?(?:access[_-]?key|key|value))?|access[\\s_-]*key|private[_-]?key|client[_-]?secret|signing[\\s_-]*key|encryption[\\s_-]*key|credential(?:s)?)';

  redacted = redacted.replace(
    /((?<![A-Za-z0-9_$])(?:["']?)(?:password|passwd|pwd|proxy[_-]?authorization|authorization|set[_-]?cookie|cookie|x[_-]?api[_-]?key|api[\s_-]*key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token(?:Value)?|(?:aws[_-]?)?secrets?(?:[_-]?(?:access[_-]?key|key|value))?|access[\s_-]*key|private[_-]?key|client[_-]?secret|signing[\s_-]*key|encryption[\s_-]*key|credential(?:s)?)(?:["']?)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\]]+)/gi,
    '$1[REDACTED]',
  );
  redacted = redacted.replace(
    new RegExp(`((?<![A-Za-z0-9_$])(?:["']?)${secretName}(?:["']?)\\s*[:=]\\s*)(?!["'])[^\\r\\n]*`, 'gi'),
    '$1[REDACTED]',
  );
  redacted = redacted.replace(
    new RegExp(`([?&](?:${secretName})=)[^&#\\s]+`, 'gi'),
    '$1[REDACTED]',
  );
  redacted = redacted.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]');
  redacted = redacted.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b/g, '[REDACTED]');
  redacted = redacted.replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED]');
  redacted = redacted.replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,})\b/g, '[REDACTED]');
  redacted = redacted.replace(
    /([a-z][a-z0-9+.-]*:\/\/)([^\s/:@]+):([^\s/@]+)@/gi,
    '$1[REDACTED]@',
  );
  redacted = redacted.replace(
    /-----BEGIN(?: [^-]*)? PRIVATE KEY-----[\s\S]*/gi,
    '-----BEGIN PRIVATE KEY----- [REDACTED]',
  );

  return redacted;
}

function compactText(value, maximum = 500) {
  const redacted = redactSensitive(value.replace(/\s+/g, ' ').trim());
  return redacted.length > maximum ? `${redacted.slice(0, maximum - 1)}…` : redacted;
}

function lineStartIndexes(text, signal) {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if ((index & 1023) === 0) throwIfAborted(signal);
    if (text[index] === '\n') starts.push(index + 1);
  }
  throwIfAborted(signal);
  return starts;
}

function lineNumberForOffset(starts, offset, signal) {
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    throwIfAborted(signal);
    const middle = (low + high) >> 1;
    if (starts[middle] <= offset) low = middle + 1;
    else high = middle - 1;
  }
  return high + 1;
}

function hasAmbiguousRepeatedAlternation(pattern) {
  const splitAlternatives = (content) => {
    const branches = [];
    let start = 0;
    let depth = 0;
    let escaped = false;
    let inClass = false;
    for (let index = 0; index < content.length; index += 1) {
      const character = content[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\') {
        escaped = true;
        continue;
      }
      if (inClass) {
        if (character === ']') inClass = false;
        continue;
      }
      if (character === '[') {
        inClass = true;
        continue;
      }
      if (character === '(') depth += 1;
      else if (character === ')') depth = Math.max(0, depth - 1);
      else if (character === '|' && depth === 0) {
        branches.push(content.slice(start, index));
        start = index + 1;
      }
    }
    branches.push(content.slice(start));
    return branches;
  };

  for (let start = 0; start < pattern.length; start += 1) {
    if (pattern[start] !== '(') continue;
    let depth = 0;
    let escaped = false;
    let inClass = false;
    let close = -1;
    for (let index = start; index < pattern.length; index += 1) {
      const character = pattern[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\') {
        escaped = true;
        continue;
      }
      if (inClass) {
        if (character === ']') inClass = false;
        continue;
      }
      if (character === '[') {
        inClass = true;
        continue;
      }
      if (character === '(') depth += 1;
      else if (character === ')') {
        depth -= 1;
        if (depth === 0) {
          close = index;
          break;
        }
      }
    }
    if (close === -1) continue;
    let quantifierIndex = close + 1;
    while (/\s/.test(pattern[quantifierIndex] || '')) quantifierIndex += 1;
    const quantifier = pattern[quantifierIndex];
    const repeated = quantifier === '*' || quantifier === '+' || quantifier === '?' ||
      (quantifier === '{' && /^\{\d+(?:,\d*)?\}/.test(pattern.slice(quantifierIndex)));
    if (!repeated) continue;
    const branches = splitAlternatives(pattern.slice(start + 1, close));
    for (let leftIndex = 0; leftIndex < branches.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < branches.length; rightIndex += 1) {
        const left = branches[leftIndex].replace(/^\?[:=!]/, '');
        const right = branches[rightIndex].replace(/^\?[:=!]/, '');
        if (!left || !right) return true;
        if (
          left === '.' || right === '.' ||
          /\\[wWsSdD]/.test(left) || /\\[wWsSdD]/.test(right)
        ) return true;
        if (left.startsWith(right) || right.startsWith(left)) return true;
      }
    }
  }
  return false;
}

function hasRepeatedSimpleQuantifier(pattern) {
  for (let index = 0; index < pattern.length - 1; index += 1) {
    const atom = pattern[index];
    if (!/[A-Za-z0-9]/.test(atom)) continue;
    const quantifier = pattern[index + 1];
    if (quantifier !== '*' && quantifier !== '+') continue;
    const limit = Math.min(pattern.length - 1, index + 10);
    for (let cursor = index + 2; cursor < limit; cursor += 1) {
      if (pattern[cursor] === atom && pattern[cursor + 1] === quantifier) return true;
    }
  }
  return false;
}

function looksUnsafeRegex(pattern) {
  if (typeof pattern !== 'string' || pattern.length > MAX_REGEX_PATTERN_LENGTH) return true;
  if (/\\[1-9]/.test(pattern)) return true;
  if (/(?:\.\*|\.\+)[^\r\n]{0,32}(?:\.\*|\.\+)/.test(pattern)) return true;
  if (hasRepeatedSimpleQuantifier(pattern)) return true;
  if (hasAmbiguousRepeatedAlternation(pattern)) return true;

  const groups = [];
  let lastGroup = null;
  let previousWasQuantifier = false;
  let quantifierCount = 0;
  let inClass = false;

  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];

    if (character === '\\') {
      if (index + 1 < pattern.length) index += 1;
      previousWasQuantifier = false;
      continue;
    }
    if (inClass) {
      if (character === ']') inClass = false;
      continue;
    }
    if (character === '[') {
      inClass = true;
      previousWasQuantifier = false;
      continue;
    }

    // Group modifiers such as (?:, (?=), and (?! are prefixes, not lazy
    // quantifiers.  Skip them so the structural checks below remain useful.
    if (character === '?' && pattern[index - 1] === '(') {
      let cursor = index + 1;
      if (pattern[cursor] === '<' && pattern[cursor + 1] !== '=' && pattern[cursor + 1] !== '!') {
        const namedEnd = pattern.indexOf('>', cursor + 1);
        if (namedEnd !== -1) cursor = namedEnd;
      } else if ([':', '=', '!'].includes(pattern[cursor])) {
        cursor += 1;
      }
      index = cursor;
      previousWasQuantifier = false;
      continue;
    }

    if (character === '(') {
      if (groups.length >= MAX_REGEX_GROUPS) return true;
      groups.push({ hasQuantifier: false });
      lastGroup = null;
      previousWasQuantifier = false;
      continue;
    }
    if (character === ')') {
      const group = groups.pop();
      if (group) {
        if (group.hasQuantifier) {
          const parent = groups[groups.length - 1];
          if (parent) parent.hasQuantifier = true;
        }
        lastGroup = group;
      }
      previousWasQuantifier = false;
      continue;
    }
    if (character === '|') {
      previousWasQuantifier = false;
      continue;
    }

    let quantifierEnd = -1;
    let repetition = 0;
    if (character === '*' || character === '+' || character === '?') {
      // A second ?/* after a quantifier is a lazy/possessive-style modifier;
      // it is not a second repetition in the patterns accepted by JavaScript.
      if (previousWasQuantifier) {
        previousWasQuantifier = character === '?' || character === '*' || character === '+';
        continue;
      }
      quantifierEnd = index + 1;
    } else if (character === '{') {
      const match = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(index));
      if (!match) {
        previousWasQuantifier = false;
        continue;
      }
      quantifierEnd = index + match[0].length;
      repetition = Number(match[2] === '' || match[2] === undefined ? match[1] : match[2]);
    }

    if (quantifierEnd !== -1) {
      quantifierCount += 1;
      if (quantifierCount > MAX_REGEX_QUANTIFIERS || repetition > MAX_REGEX_REPETITION) return true;
      if (character === '*' || character === '+' || character === '?' || character === '{') {
        const previousCharacter = pattern[index - 1];
        if (previousCharacter === ')') {
          if (lastGroup && (lastGroup.hasQuantifier)) return true;
        } else if (previousWasQuantifier) {
          return true;
        }
      }
      const currentGroup = groups[groups.length - 1];
      if (currentGroup) currentGroup.hasQuantifier = true;
      previousWasQuantifier = true;
      index = quantifierEnd - 1;
      continue;
    }

    previousWasQuantifier = false;
  }

  return false;
}

function parseHunkHeader(line) {
  const standard = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$/.exec(line);
  if (standard) {
    return {
      oldStart: Number(standard[1]),
      oldCount: standard[2] === undefined ? 1 : Number(standard[2]),
      newStart: Number(standard[3]),
      newCount: standard[4] === undefined ? 1 : Number(standard[4]),
    };
  }

  if (/^@@(?: .*)?$/.test(line)) {
    return { oldStart: null, oldCount: null, newStart: null, newCount: null };
  }
  return null;
}

function isPatchPreamble(line) {
  return (
    line === '*** Begin Patch' ||
    line === '*** End Patch' ||
    line.startsWith('*** Update File: ') ||
    line.startsWith('diff --git ') ||
    line.startsWith('index ') ||
    line.startsWith('--- ') ||
    line.startsWith('+++ ') ||
    line.startsWith('new file mode ') ||
    line.startsWith('deleted file mode ') ||
    line.startsWith('old mode ') ||
    line.startsWith('new mode ') ||
    line.startsWith('similarity index ') ||
    line.startsWith('rename from ') ||
    line.startsWith('rename to ')
  );
}

function normalizePatchHeaderPath(value, stripDiffPrefix = true) {
  let filePath = value.trim();
  if (filePath.startsWith('"')) {
    try {
      filePath = JSON.parse(filePath);
    } catch {
      filePath = filePath.slice(1, -1);
    }
  }
  const tab = filePath.indexOf('\t');
  if (tab !== -1) filePath = filePath.slice(0, tab);
  filePath = filePath.replace(/\\/g, '/');
  if (stripDiffPrefix && (filePath.startsWith('a/') || filePath.startsWith('b/'))) filePath = filePath.slice(2);
  filePath = path.posix.normalize(filePath);
  return process.platform === 'win32' ? filePath.toLowerCase() : filePath;
}

function parseUnifiedDiff(patch, expectedPath, signal) {
  if (typeof patch !== 'string') throw new TypeError('patch must be a string.');
  if (patch.length === 0) throw new Error('Patch is empty.');
  if (Buffer.byteLength(patch, 'utf8') > 2 * 1024 * 1024) {
    throw new RangeError('Patch is too large (maximum 2 MiB).');
  }

  const physicalLines = patch.split(/\r\n|\n|\r/);
  if (physicalLines[physicalLines.length - 1] === '') physicalLines.pop();

  const hunks = [];
  let current = null;
  let sawHeader = false;
  let oldFileHeader = null;
  let newFileHeader = null;

  const finishHunk = () => {
    if (!current) return;
    throwIfAborted(signal);
    if (current.lines.length === 0) throw new Error(`Hunk ${hunks.length + 1} is empty.`);

    const oldCount = current.lines.filter((line) => line.kind !== '+').length;
    const newCount = current.lines.filter((line) => line.kind !== '-').length;
    throwIfAborted(signal);
    if (current.header.oldCount !== null && oldCount !== current.header.oldCount) {
      throw new Error(
        `Hunk ${hunks.length + 1} declares ${current.header.oldCount} old lines but contains ${oldCount}.`,
      );
    }
    if (current.header.newCount !== null && newCount !== current.header.newCount) {
      throw new Error(
        `Hunk ${hunks.length + 1} declares ${current.header.newCount} new lines but contains ${newCount}.`,
      );
    }
    for (let index = 0; index < current.lines.length; index += 1) {
      throwIfAborted(signal);
      if (current.lines[index].noNewline && index !== current.lines.length - 1) {
        throw new Error(`Hunk ${hunks.length + 1} has an invalid no-newline marker.`);
      }
    }

    current.header.oldCount = oldCount;
    current.header.newCount = newCount;
    hunks.push(current);
    current = null;
  };

  for (let lineIndex = 0; lineIndex < physicalLines.length; lineIndex += 1) {
    throwIfAborted(signal);
    const line = physicalLines[lineIndex];
    const header = parseHunkHeader(line);
    if (header) {
      finishHunk();
      sawHeader = true;
      current = { header, lines: [] };
      continue;
    }

    if (!current) {
      if (line.startsWith('--- ')) oldFileHeader = line.slice(4);
      if (line.startsWith('+++ ')) newFileHeader = line.slice(4);
      if (isPatchPreamble(line) || line.length === 0) continue;
      throw new Error(`Unexpected patch content before the first hunk: ${line.slice(0, 80)}`);
    }

    if (/^\s*\\ No newline at end of file\s*$/.test(line)) {
      if (current.lines.length === 0) {
        throw new Error(`Hunk ${hunks.length + 1} has a misplaced no-newline marker.`);
      }
      current.lines[current.lines.length - 1].noNewline = true;
      continue;
    }

    if (line === '*** End Patch') {
      finishHunk();
      current = null;
      break;
    }

    const marker = line[0];
    if (marker !== ' ' && marker !== '-' && marker !== '+') {
      throw new Error(
        `Malformed patch line ${lineIndex + 1}; context, removal, and addition lines need a prefix.`,
      );
    }

    current.lines.push({
      kind: marker,
      text: line.slice(1),
      noNewline: false,
    });
  }

  finishHunk();
  if (!sawHeader || hunks.length === 0) {
    throw new Error('Patch must contain at least one unified diff hunk.');
  }

  if (oldFileHeader || newFileHeader) {
    const oldHeader = oldFileHeader ? normalizePatchHeaderPath(oldFileHeader) : null;
    const newHeader = newFileHeader ? normalizePatchHeaderPath(newFileHeader) : null;
    if (oldHeader === '/dev/null') throw new Error('Creating files with apply_patch is not supported; use write_file.');
    if (newHeader === '/dev/null') throw new Error('Deleting files with apply_patch is not supported; use delete_path.');
    if (oldHeader && newHeader && oldHeader !== newHeader) {
      throw new Error('Patch headers refer to different files; apply_patch only supports one file.');
    }
    const selectedHeader = newHeader || oldHeader;
    const expectedHeader = normalizePatchHeaderPath(expectedPath, false);
    if (selectedHeader && selectedHeader !== expectedHeader) {
      throw new Error(`Patch header does not match target path ${expectedHeader}.`);
    }
  }

  return hunks;
}

function hunkRecordsMatch(records, expected, signal) {
  if (records.length !== expected.length) return false;
  for (let index = 0; index < expected.length; index += 1) {
    throwIfAborted(signal);
    const line = expected[index];
    const record = records[index];
    if (record.text !== line.text) return false;
    if (line.noNewline && record.ending !== '') return false;
  }
  return true;
}

function applyParsedHunks(content, hunks, signal) {
  let records = splitLineRecords(content, signal);
  let cursor = 0;
  let relocatedHunks = 0;
  const preferredEnding = records.find((record) => record.ending)?.ending ||
    (content.includes('\r\n') ? '\r\n' : os.EOL);

  for (let hunkIndex = 0; hunkIndex < hunks.length; hunkIndex += 1) {
    throwIfAborted(signal);
    const hunk = hunks[hunkIndex];
    const oldLines = hunk.lines.filter((line) => line.kind !== '+');
    throwIfAborted(signal);
    let matchIndex;

    if (oldLines.length === 0) {
      matchIndex = hunk.header.oldStart === null
        ? cursor
        : Math.min(records.length, hunk.header.oldStart);
      if (matchIndex < cursor) matchIndex = cursor;
      if (hunk.header.oldStart !== null && hunk.header.oldStart > records.length + 1) {
        throw new Error(`Hunk ${hunkIndex + 1} inserts beyond the end of the file.`);
      }
    } else {
      if (hunk.header.oldStart !== null && hunk.header.oldStart < 1) {
        throw new Error(`Hunk ${hunkIndex + 1} has an invalid old line number.`);
      }

      const expected = hunk.header.oldStart === null ? cursor : hunk.header.oldStart - 1;
      matchIndex = -1;
      const first = Math.max(cursor, expected);
      for (let candidate = first; candidate <= records.length - oldLines.length; candidate += 1) {
        throwIfAborted(signal);
        if (hunkRecordsMatch(records.slice(candidate, candidate + oldLines.length), oldLines, signal)) {
          matchIndex = candidate;
          break;
        }
      }
      if (matchIndex === -1) {
        for (let candidate = cursor; candidate <= records.length - oldLines.length; candidate += 1) {
          throwIfAborted(signal);
          if (hunkRecordsMatch(records.slice(candidate, candidate + oldLines.length), oldLines, signal)) {
            matchIndex = candidate;
            break;
          }
        }
      }
      if (matchIndex === -1) {
        throw new Error(`Hunk ${hunkIndex + 1} context did not match the file after line ${cursor + 1}.`);
      }
      if (hunk.header.oldStart !== null && matchIndex !== hunk.header.oldStart - 1) {
        relocatedHunks += 1;
      }
    }

    const replacement = [];
    let oldOffset = 0;
    for (const line of hunk.lines) {
      throwIfAborted(signal);
      if (line.kind === '+') {
        let ending = line.noNewline ? '' : preferredEnding;
        if (
          !line.noNewline &&
          records.length > 0 &&
          records[records.length - 1].ending === '' &&
          (matchIndex + oldOffset === records.length || matchIndex === records.length)
        ) {
          ending = '';
        }
        replacement.push({ text: line.text, ending });
      } else {
        const source = records[matchIndex + oldOffset];
        oldOffset += 1;
        if (line.kind === ' ') replacement.push({ ...source });
      }
    }

    records = [
      ...records.slice(0, matchIndex),
      ...replacement,
      ...records.slice(matchIndex + oldLines.length),
    ];
    cursor = matchIndex + replacement.length;
  }

  return { content: joinLineRecords(records), relocatedHunks };
}

function extractSymbols(text, extension, signal) {
  const symbols = [];
  const seen = new Set();

  const add = (name, kind, lineNumber, signature) => {
    const key = `${lineNumber}:${kind}:${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    symbols.push({
      name,
      kind,
      line: lineNumber,
      signature: compactText(signature, 300),
    });
  };

  const extend = (line, lineNumber) => {
    let match;
    if ((match = /^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/.exec(line))) {
      add(match[1], 'class', lineNumber, line);
    }
    if ((match = /^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)/.exec(line))) {
      add(match[1], 'interface', lineNumber, line);
    }
    if ((match = /^\s*(?:export\s+)?(?:const\s+)?enum\s+([A-Za-z_$][\w$]*)/.exec(line))) {
      add(match[1], 'enum', lineNumber, line);
    }
    if ((match = /^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*=/.exec(line))) {
      add(match[1], 'type', lineNumber, line);
    }
    if ((match = /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/.exec(line))) {
      add(match[1], 'function', lineNumber, line);
    }
    if ((match = /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/.exec(line))) {
      add(match[1], 'function', lineNumber, line);
    }
    if ((match = /^\s*(?:(?:public|private|protected|static|readonly|abstract|override|async|get|set)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>{}()]*>)?\s*\([^;]*\)\s*(?::[^=;{]+)?\s*\{/.exec(line))) {
      if (!['if', 'for', 'while', 'switch', 'catch', 'function'].includes(match[1])) {
        add(match[1], 'method', lineNumber, line);
      }
    }
  };

  if (['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'].includes(extension)) {
    let inBlockComment = false;
    const lines = splitTextLines(text, signal);
    for (let index = 0; index < lines.length; index += 1) {
      throwIfAborted(signal);
      const line = lines[index];
      const trimmed = line.trim();
      if (inBlockComment) {
        if (trimmed.includes('*/')) inBlockComment = false;
        continue;
      }
      if (trimmed.startsWith('/*')) {
        if (!trimmed.includes('*/')) inBlockComment = true;
        continue;
      }
      if (!trimmed.startsWith('//')) extend(line, index + 1);
    }
  } else if (extension === '.py') {
    splitTextLines(text, signal).forEach((line, index) => {
      throwIfAborted(signal);
      if (/^\s*class\s+[A-Za-z_][\w]*\s*(?:\([^)]*\))?\s*:/.test(line)) {
        const name = /\bclass\s+([A-Za-z_][\w]*)/.exec(line)[1];
        add(name, 'class', index + 1, line);
      } else if (/^\s*(?:async\s+)?def\s+[A-Za-z_][\w]*\s*\(/.test(line)) {
        const name = /\bdef\s+([A-Za-z_][\w]*)/.exec(line)[1];
        add(name, 'function', index + 1, line);
      }
    });
  } else if (extension === '.go') {
    splitTextLines(text, signal).forEach((line, index) => {
      throwIfAborted(signal);
      let match = /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)\s*\(/.exec(line);
      if (match) add(match[1], 'function', index + 1, line);
      if (!(match = /^\s*type\s+([A-Za-z_][\w]*)\s+(?:struct|interface)\b/.exec(line))) {
        match = /^\s*type\s+([A-Za-z_][\w]*)\b/.exec(line);
        if (match) add(match[1], 'type', index + 1, line);
      }
    });
  } else if (extension === '.rs') {
    splitTextLines(text, signal).forEach((line, index) => {
      throwIfAborted(signal);
      let match = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][\w]*)/.exec(line);
      if (match) add(match[1], 'function', index + 1, line);
      if (!(match = /^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum|trait)\s+([A-Za-z_][\w]*)/.exec(line))) {
        if ((match = /^\s*impl(?:<[^>]+>)?\s+([A-Za-z_][\w]*)/.exec(line))) {
          add(match[1], 'implementation', index + 1, line);
        }
      } else {
        add(match[2], match[1], index + 1, line);
      }
    });
  } else if (['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.cs', '.java', '.kt', '.kts', '.php'].includes(extension)) {
    splitTextLines(text, signal).forEach((line, index) => {
      throwIfAborted(signal);
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;
      let match = /^(?:public\s+|private\s+|protected\s+|internal\s+|static\s+|final\s+|abstract\s+|sealed\s+|data\s+)*(class|struct|interface|enum|namespace)\s+([A-Za-z_][\w]*)/.exec(trimmed);
      if (match) {
        add(match[2], match[1], index + 1, line);
        return;
      }
      if ((match = /^(?:[A-Za-z_][\w:<>[\],*&\s]*\s+)?([A-Za-z_][\w]*)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?[;{]$/.exec(trimmed))) {
        if (!['if', 'for', 'while', 'switch', 'catch'].includes(match[1])) {
          add(match[1], 'function', index + 1, line);
        }
      }
    });
  }

  return symbols;
}

function toolDefinition(name, description, properties, required = []) {
  return {
    type: 'function',
    function: {
      name,
      description,
      parameters: {
        type: 'object',
        properties,
        required,
        additionalProperties: false,
      },
    },
  };
}

const TOOL_DEFINITIONS = Object.freeze({
  list_directory: toolDefinition(
    'list_directory',
    'List up to 500 entries in a workspace directory. Hidden and generated/dependency directories are omitted by default.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute directory path.' },
      includeHidden: { type: 'boolean', description: 'Include dotfiles. Defaults to false.' },
    },
    [],
  ),
  find_files: toolDefinition(
    'find_files',
    'Find workspace files by glob pattern and/or case-insensitive name query without reading their contents.',
    {
      pattern: { type: 'string', maxLength: 512, description: 'Glob such as **/*.ts or *.test.js.' },
      query: { type: 'string', maxLength: 512, description: 'Case-insensitive file-name substring or glob.' },
      maxResults: { type: 'integer', minimum: 1, maximum: 200, description: 'Maximum matches (default 100).' },
    },
    [],
  ),
  read_file: toolDefinition(
    'read_file',
    'Read a UTF-8 text file with replacement decoding, optional line range, binary detection, and a hard byte cap.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute file path.' },
      startLine: { type: 'integer', minimum: 1, description: 'First 1-based line to return (default 1).' },
      endLine: { type: 'integer', minimum: 1, description: 'Last 1-based line to return.' },
      maxBytes: { type: 'integer', minimum: 1, maximum: 1048576, description: 'Maximum bytes to inspect (default 262144).' },
    },
    ['path'],
  ),
  read_many_files: toolDefinition(
    'read_many_files',
    'Read several UTF-8 text files with a shared byte budget and per-file error reporting.',
    {
      paths: {
        type: 'array',
        minItems: 1,
        maxItems: 50,
        items: { type: 'string' },
        description: 'Workspace-relative or in-root absolute file paths.',
      },
      maxTotalBytes: { type: 'integer', minimum: 1, maximum: 2097152, description: 'Shared read budget (default 1048576).' },
    },
    ['paths'],
  ),
  search_text: toolDefinition(
    'search_text',
    'Search workspace text for a literal or regular expression. Results contain relative path, line, and secret-redacted text.',
    {
      query: { type: 'string', minLength: 1, maxLength: 512, description: 'Literal text or regular expression.' },
      path: { type: 'string', description: 'File or directory to search; defaults to workspace root.' },
      isRegex: { type: 'boolean', description: 'Treat query as a regular expression (default false).' },
      caseSensitive: { type: 'boolean', description: 'Match case exactly (default false).' },
      include: { type: 'string', maxLength: 512, description: 'Optional path glob such as **/*.ts.' },
      maxResults: { type: 'integer', minimum: 1, maximum: 200, description: 'Maximum matches (default 50).' },
    },
    ['query'],
  ),
  get_file_info: toolDefinition(
    'get_file_info',
    'Return compact metadata for a workspace file or directory.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute path.' },
    },
    ['path'],
  ),
  write_file: toolDefinition(
    'write_file',
    'Create or overwrite a UTF-8 text file, creating parent directories as needed.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute file path.' },
      content: { type: 'string', description: 'Complete UTF-8 text content.' },
      overwrite: { type: 'boolean', description: 'Allow replacing an existing file (default false).' },
    },
    ['path', 'content'],
  ),
  edit_file: toolDefinition(
    'edit_file',
    'Replace exact text in a UTF-8 file. By default oldText must occur exactly once.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute file path.' },
      oldText: { type: 'string', minLength: 1, description: 'Exact existing text.' },
      newText: { type: 'string', description: 'Replacement text; may be empty.' },
      replaceAll: { type: 'boolean', description: 'Replace every occurrence (default false).' },
    },
    ['path', 'oldText', 'newText'],
  ),
  apply_patch: toolDefinition(
    'apply_patch',
    'Apply standard unified-diff hunks to exactly one existing UTF-8 file using context matching.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute file path.' },
      patch: { type: 'string', description: 'Unified diff content, including @@ hunk headers.' },
    },
    ['path', 'patch'],
  ),
  create_directory: toolDefinition(
    'create_directory',
    'Create a workspace directory and any missing parents.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute directory path.' },
    },
    ['path'],
  ),
  move_file: toolDefinition(
    'move_file',
    'Move or rename a workspace file or directory.',
    {
      from: { type: 'string', description: 'Existing in-workspace source path.' },
      to: { type: 'string', description: 'Destination in the workspace.' },
      overwrite: { type: 'boolean', description: 'Replace an existing destination file (default false).' },
    },
    ['from', 'to'],
  ),
  delete_path: toolDefinition(
    'delete_path',
    'Delete a workspace file or directory. The workspace root can never be deleted.',
    {
      path: { type: 'string', description: 'Workspace-relative or in-root absolute path other than the root.' },
      recursive: { type: 'boolean', description: 'Allow deleting a non-empty directory (default false).' },
    },
    ['path'],
  ),
  project_overview: toolDefinition(
    'project_overview',
    'Summarize manifests, language counts, file count, and compact top-level entries.',
    {
      maxFiles: { type: 'integer', minimum: 1, maximum: 2000, description: 'Maximum files to scan (default 500).' },
    },
    [],
  ),
  find_symbols: toolDefinition(
    'find_symbols',
    'Find declarations in common JavaScript/TypeScript, Python, Go, Rust, and C-like source files without returning file bodies.',
    {
      query: { type: 'string', maxLength: 200, description: 'Optional case-insensitive symbol-name filter.' },
      path: { type: 'string', description: 'Optional source file or directory.' },
      maxResults: { type: 'integer', minimum: 1, maximum: 200, description: 'Maximum symbols (default 100).' },
    },
    [],
  ),
  project_map: toolDefinition(
    'project_map',
    'Return a compact, depth-limited workspace tree with generated/dependency directories omitted.',
    {
      path: { type: 'string', description: 'Optional directory or file to map; defaults to workspace root.' },
      depth: { type: 'integer', minimum: 1, maximum: 6, description: 'Tree depth (default 2).' },
      maxEntries: { type: 'integer', minimum: 1, maximum: 200, description: 'Maximum entries (default 150).' },
    },
    [],
  ),
});

class WorkspaceTools {
  constructor({ root, trashItem } = {}) {
    this._trashItem = undefined;
    this._sensitivePaths = new Set();
    if (trashItem !== undefined && typeof trashItem !== 'function') {
      throw new TypeError('trashItem must be a function when provided.');
    }
    this._trashItem = trashItem;
    this.setRoot(root);
  }

  setRoot(root) {
    if (typeof root !== 'string' || root.length === 0) {
      throw new TypeError('root must be a non-empty absolute path.');
    }
    if (root.includes('\0')) throw new TypeError('root contains a null byte.');
    if (!path.isAbsolute(root)) throw new TypeError('root must be an absolute path.');

    let canonical;
    try {
      canonical = fs.realpathSync(root);
    } catch (error) {
      throw new Error(`Workspace root is unavailable: ${errorMessage(error)}`);
    }

    let stats;
    try {
      stats = fs.statSync(canonical);
    } catch (error) {
      throw new Error(`Workspace root is unavailable: ${errorMessage(error)}`);
    }
    if (!stats.isDirectory()) throw new Error('Workspace root must be a directory.');

    const previousRoot = this._root;
    this._root = canonical;
    if (!previousRoot || !isSamePath(previousRoot, canonical)) this._sensitivePaths.clear();
    return this;
  }

  getRoot() {
    return this._root;
  }

  _isSensitivePath(target) {
    if (isSensitiveFile(target)) return true;
    for (const sensitivePath of this._sensitivePaths) {
      if (isSamePath(sensitivePath, target) || isInside(sensitivePath, target)) return true;
    }
    return false;
  }

  _rememberSensitivePath(target) {
    if (typeof target !== 'string' || target.length === 0) return;
    if ([...this._sensitivePaths].some((entry) => isSamePath(entry, target))) return;
    if (this._sensitivePaths.size >= 256) this._sensitivePaths.delete(this._sensitivePaths.values().next().value);
    this._sensitivePaths.add(path.normalize(target));
  }

  definitions(mode = 'agent') {
    if (!['chat', 'plan', 'agent'].includes(mode)) {
      throw new RangeError('mode must be chat, plan, or agent.');
    }

    const allowed = mode === 'plan' ? READ_ONLY_TOOLS : mode === 'chat' ? CHAT_TOOLS : null;
    return Object.entries(TOOL_DEFINITIONS)
      .filter(([name]) => allowed === null || allowed.has(name))
      .map(([, definition]) => ({
        type: definition.type,
        function: {
          name: definition.function.name,
          description: definition.function.description,
          parameters: {
            type: 'object',
            properties: structuredClone(definition.function.parameters.properties),
            required: [...definition.function.parameters.required],
            additionalProperties: false,
          },
        },
      }));
  }

  resolveWorkspacePath(input) {
    if (typeof input !== 'string' || input.length === 0) {
      throw new TypeError('Path must be a non-empty string.');
    }
    if (input.length > 4096) throw new TypeError('Path is too long.');
    if (input.includes('\0')) throw new TypeError('Path contains a null byte.');

    const root = this._root;
    const lexical = path.resolve(root, input);
    if (!isInside(root, lexical)) {
      throw new Error(`Path escapes the workspace root: ${input}`);
    }

    try {
      const canonical = fs.realpathSync(lexical);
      if (!isInside(root, canonical)) {
        throw new Error(`Path resolves outside the workspace root: ${input}`);
      }
      return canonical;
    } catch (error) {
      if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error;
    }

    let ancestor = lexical;
    const suffix = [];
    while (true) {
      let ancestorStats;
      try {
        ancestorStats = fs.lstatSync(ancestor);
      } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
        const next = path.dirname(ancestor);
        if (next === ancestor) break;
        suffix.push(path.basename(ancestor));
        ancestor = next;
        continue;
      }

      let canonicalAncestor;
      try {
        canonicalAncestor = fs.realpathSync(ancestor);
      } catch (error) {
        if (ancestorStats.isSymbolicLink()) {
          throw new Error(`Cannot safely resolve dangling symbolic link: ${ancestor}`);
        }
        throw error;
      }
      if (!isInside(root, canonicalAncestor)) {
        throw new Error(`Path resolves outside the workspace root through a symbolic link: ${input}`);
      }

      const candidate = path.resolve(canonicalAncestor, ...suffix.reverse());
      if (!isInside(root, candidate)) {
        throw new Error(`Path escapes the workspace root: ${input}`);
      }
      return candidate;
    }

    throw new Error(`Unable to find an existing ancestor for path: ${input}`);
  }

  _revalidateCanonicalPath(expected, signal, label) {
    throwIfAborted(signal);
    const current = this.resolveWorkspacePath(expected);
    throwIfAborted(signal);
    if (!isSamePath(current, expected)) {
      throw new Error(`${label} changed while the operation was in progress.`);
    }
    return current;
  }

  _revalidatePathPair(target, parent, signal, label) {
    const currentTarget = this._revalidateCanonicalPath(target, signal, `${label} target`);
    const currentParent = this._revalidateCanonicalPath(parent, signal, `${label} parent`);
    throwIfAborted(signal);
    if (!isSamePath(currentParent, path.dirname(currentTarget))) {
      throw new Error(`${label} parent changed while the operation was in progress.`);
    }
    return { target: currentTarget, parent: currentParent };
  }

  async _revalidateMutationPath(target, parent, signal, label, options = {}) {
    const pair = this._revalidatePathPair(target, parent, signal, label);
    const parentStats = await fsp.stat(pair.parent);
    throwIfAborted(signal);
    if (!parentStats.isDirectory()) {
      throw new Error(`${label} parent is not a directory: ${displayPath(this._root, pair.parent)}`);
    }

    let targetStats = null;
    try {
      targetStats = await fsp.lstat(pair.target);
      throwIfAborted(signal);
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (!(options.allowMissing === true && error.code === 'ENOENT')) throw error;
    }
    const finalPair = this._revalidatePathPair(target, parent, signal, label);
    if (!isSamePath(finalPair.target, pair.target) || !isSamePath(finalPair.parent, pair.parent)) {
      throw new Error(`${label} changed while the operation was in progress.`);
    }
    return { ...finalPair, targetStats };
  }

  async execute(name, args = {}, context = {}) {
    const safeContext = context && typeof context === 'object' && !Array.isArray(context) ? context : {};
    try {
      throwIfAborted(safeContext.signal);
      if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(TOOL_DEFINITIONS, name)) {
        return {
          ok: false,
          summary: 'Unknown workspace tool',
          data: null,
          error: `Unknown workspace tool: ${String(name)}`,
        };
      }
      if (args === null || typeof args !== 'object' || Array.isArray(args)) {
        throw new TypeError('args must be an object.');
      }

      const handlers = this._handlers();
      const result = await handlers[name](args, safeContext);
      throwIfAborted(safeContext.signal);
      if (!result || typeof result.ok !== 'boolean' || typeof result.summary !== 'string') {
        throw new Error('Workspace tool returned an invalid result.');
      }
      return {
        ok: result.ok,
        summary: result.summary,
        data: result.data === undefined ? null : result.data,
        ...(result.error === undefined ? {} : { error: String(result.error) }),
      };
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (safeContext.signal && safeContext.signal.aborted === true) throw createAbortError();
      return {
        ok: false,
        summary: `${name || 'Workspace tool'} failed`,
        data: null,
        error: errorMessage(error),
      };
    }
  }

  _handlers() {
    return {
      list_directory: (args, context) => this._listDirectory(args, context),
      find_files: (args, context) => this._findFiles(args, context),
      read_file: (args, context) => this._readFile(args, context),
      read_many_files: (args, context) => this._readManyFiles(args, context),
      search_text: (args, context) => this._searchText(args, context),
      get_file_info: (args, context) => this._getFileInfo(args, context),
      write_file: (args, context) => this._writeFile(args, context),
      edit_file: (args, context) => this._editFile(args, context),
      apply_patch: (args, context) => this._applyPatch(args, context),
      create_directory: (args, context) => this._createDirectory(args, context),
      move_file: (args, context) => this._moveFile(args, context),
      delete_path: (args, context) => this._deletePath(args, context),
      project_overview: (args, context) => this._projectOverview(args, context),
      find_symbols: (args, context) => this._findSymbols(args, context),
      project_map: (args, context) => this._projectMap(args, context),
    };
  }

  async _readLimited(target, limit, signal) {
    throwIfAborted(signal);
    const handle = await fsp.open(target, 'r');
    try {
      throwIfAborted(signal);
      const stats = await handle.stat();
      throwIfAborted(signal);
      if (!stats.isFile()) throw new Error(`Not a file: ${displayPath(this._root, target)}`);
      const allocation = Math.min(stats.size, limit + 1);
      const buffer = Buffer.alloc(allocation);
      let offset = 0;
      while (offset < allocation) {
        throwIfAborted(signal);
        const result = await handle.read(buffer, offset, allocation - offset, offset);
        throwIfAborted(signal);
        if (result.bytesRead === 0) break;
        offset += result.bytesRead;
      }
      throwIfAborted(signal);
      return {
        buffer: offset === buffer.length ? buffer : buffer.subarray(0, offset),
        fileSize: stats.size,
        bytesRead: offset,
        truncated: stats.size > offset,
      };
    } finally {
      await handle.close();
    }
  }

  async _readUtf8(target, limit, signal) {
    throwIfAborted(signal);
    const result = await this._readLimited(target, limit, signal);
    throwIfAborted(signal);
    if (isLikelyBinary(result.buffer)) {
      const error = new Error(`Binary file cannot be read as text: ${displayPath(this._root, target)}`);
      error.code = 'EBINARY';
      throw error;
    }
    const visible = result.buffer.subarray(0, Math.min(limit, result.buffer.length));
    return {
      ...result,
      visibleBytes: visible.length,
      text: decodeUtf8(visible),
    };
  }

  async _listDirectory(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const includeHidden = optionalBoolean(args, 'includeHidden', false);
    const target = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, target)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, target)}`);
    }

    const stats = await fsp.stat(target);
    throwIfAborted(signal);
    if (!stats.isDirectory()) throw new Error(`Not a directory: ${displayPath(this._root, target)}`);

    const entries = [];
    let scanned = 0;
    let truncated = false;
    const handle = await fsp.opendir(target);
    try {
      throwIfAborted(signal);
      for await (const entry of handle) {
        throwIfAborted(signal);
        scanned += 1;
        if (scanned > MAX_DIRECTORY_ENTRIES_SCANNED) {
          truncated = true;
          break;
        }
        if (!includeHidden && entry.name.startsWith('.')) continue;
        if (IGNORED_DIRECTORY_NAMES.has(entry.name.toLowerCase())) continue;
        entries.push(entry);
        if (entries.length > MAX_LIST_ENTRIES) {
          truncated = true;
          break;
        }
      }
    } finally {
      await handle.close().catch(() => {});
    }

    throwIfAborted(signal);
    entries.sort((left, right) => {
      const leftDirectory = left.isDirectory() ? 0 : 1;
      const rightDirectory = right.isDirectory() ? 0 : 1;
      return leftDirectory - rightDirectory || left.name.localeCompare(right.name);
    });
    const visibleEntries = entries.slice(0, MAX_LIST_ENTRIES);

    const dataEntries = await Promise.all(visibleEntries.map(async (entry) => {
      throwIfAborted(signal);
      const absolute = path.join(target, entry.name);
      const type = entry.isDirectory() ? 'directory' : entry.isSymbolicLink() ? 'symlink' : entry.isFile() ? 'file' : 'other';
      const item = { name: entry.name, path: displayPath(this._root, absolute), type };
      if (entry.isFile()) {
        try {
          const itemStats = await fsp.lstat(absolute);
          throwIfAborted(signal);
          item.size = itemStats.size;
          item.modified = itemStats.mtime.toISOString();
        } catch (error) {
          if (isAbortError(error)) throw error;
          // The name and type are still useful if metadata disappears concurrently.
        }
      }
      return item;
    }));

    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Listed ${dataEntries.length} entries in ${displayPath(this._root, target)}`,
      data: { path: displayPath(this._root, target), entries: dataEntries, truncated },
    };
  }

  async _findFiles(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const pattern = optionalString(args, 'pattern', { maxLength: MAX_PATTERN_LENGTH });
    const query = optionalString(args, 'query', { maxLength: MAX_PATTERN_LENGTH });
    const maxResults = clampInteger(args.maxResults, 100, 1, MAX_RESULTS);
    if (pattern !== undefined && pattern.length === 0) throw new TypeError('pattern must not be empty when provided.');
    if (query !== undefined && query.length === 0) throw new TypeError('query must not be empty when provided.');
    if (pattern !== undefined && hasGlobSyntax(pattern)) globToRegExp(pattern);
    if (query !== undefined && hasGlobSyntax(query)) globToRegExp(query);

    const matches = (relative, basename) => {
      let matched = true;
      if (pattern !== undefined) {
        matched = matched && (
          hasGlobSyntax(pattern)
            ? matchesGlob(relative, basename, pattern)
            : basename.toLowerCase() === pattern.toLowerCase() || relative.toLowerCase().includes(`/${pattern.toLowerCase()}`)
        );
      }
      if (query !== undefined) {
        matched = matched && (
          hasGlobSyntax(query)
            ? matchesGlob(relative, basename, query)
            : relative.toLowerCase().includes(query.toLowerCase())
        );
      }
      return matched;
    };

    const files = [];
    const state = {
      fileCount: 0,
      directoryCount: 0,
      scannedEntries: 0,
      sensitiveFilesSkipped: 0,
      truncated: false,
      stopped: false,
    };

    for await (const item of this._walkFiles(this._root, {
      maxFiles: Math.max(maxResults, 2000),
      maxDirectories: 10_000,
      followSymlinkFiles: false,
      signal,
    }, state)) {
      throwIfAborted(signal);
      const relative = displayPath(this._root, item.absolute);
      const basename = path.basename(relative);
      if (!matches(relative, basename)) continue;
      let size = item.size;
      if (size === undefined || size === null) {
        try {
          size = (await fsp.lstat(item.absolute)).size;
          throwIfAborted(signal);
        } catch (error) {
          if (isAbortError(error)) throw error;
          size = null;
        }
      }
      files.push({ path: relative, type: 'file', size });
      if (files.length >= maxResults) {
        state.stopped = true;
        state.truncated = true;
        break;
      }
    }

    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Found ${files.length} files`,
      data: {
        files,
        truncated: state.truncated || state.scannedEntries >= MAX_DIRECTORY_ENTRIES_SCANNED,
      },
    };
  }

  async _readFile(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const startLine = clampInteger(args.startLine, 1, 1, Number.MAX_SAFE_INTEGER);
    const endLine = clampInteger(args.endLine, startLine + 999, startLine, Number.MAX_SAFE_INTEGER);
    if (endLine - startLine + 1 > 2000) {
      throw new RangeError('A read_file call may return at most 2000 lines.');
    }
    const maxBytes = clampInteger(args.maxBytes, DEFAULT_READ_BYTES, 1, MAX_READ_BYTES);
    const target = this.resolveWorkspacePath(requestedPath);
    const allowSecretRead = allowsSecretRead(context);
    if (!allowSecretRead && this._isSensitivePath(target)) return sensitiveReadResult(this._root, target);

    const verifiedTarget = this._revalidateCanonicalPath(target, signal, 'Read target');
    const result = await this._readUtf8(verifiedTarget, maxBytes, signal);
    if (!allowSecretRead && isSensitiveContent(verifiedTarget, result.text, signal)) {
      this._rememberSensitivePath(verifiedTarget);
      return sensitiveReadResult(this._root, verifiedTarget);
    }
    throwIfAborted(signal);
    const lines = splitTextLines(result.text, signal);

    if (startLine > lines.length && result.truncated) {
      throw new Error(`startLine ${startLine} is beyond the ${maxBytes}-byte inspection limit.`);
    }

    const selected = lines.slice(startLine - 1, endLine);
    const visibleEnd = selected.length === 0 ? 0 : startLine + selected.length - 1;
    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Read ${displayPath(this._root, verifiedTarget)} (${selected.length} lines)`,
      data: {
        path: displayPath(this._root, verifiedTarget),
        content: selected.join('\n'),
        startLine,
        endLine: visibleEnd,
        lineCount: result.truncated ? null : lines.length,
        fileSize: result.fileSize,
        bytesRead: result.visibleBytes,
        truncated: result.truncated,
        encoding: 'utf8',
      },
    };
  }

  async _readManyFiles(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    if (!Array.isArray(args.paths) || args.paths.length === 0 || args.paths.length > 50) {
      throw new TypeError('paths must be an array containing 1 to 50 paths.');
    }
    if (!args.paths.every((value) => typeof value === 'string' && value.length > 0)) {
      throw new TypeError('Every path must be a non-empty string.');
    }
    const maxTotalBytes = clampInteger(args.maxTotalBytes, DEFAULT_MANY_FILES_BYTES, 1, MAX_MANY_FILES_BYTES);
    const allowSecretRead = allowsSecretRead(context);
    const files = [];
    let remaining = maxTotalBytes;
    let totalBytes = 0;
    let allOk = true;
    let sensitiveFilesBlocked = 0;

    for (const requestedPath of args.paths) {
      throwIfAborted(signal);
      if (remaining <= 0) {
        files.push({ path: toPortablePath(requestedPath), ok: false, error: 'Shared byte budget exhausted.' });
        allOk = false;
        continue;
      }

      try {
        const target = this.resolveWorkspacePath(requestedPath);
        if (!allowSecretRead && this._isSensitivePath(target)) {
          sensitiveFilesBlocked += 1;
          files.push({
            path: displayPath(this._root, target),
            ok: false,
            blocked: true,
            redacted: true,
            content: SENSITIVE_REDACTION,
            error: SENSITIVE_FILE_ERROR,
          });
          allOk = false;
          continue;
        }
        const verifiedTarget = this._revalidateCanonicalPath(target, signal, 'Read target');
        const result = await this._readUtf8(verifiedTarget, Math.min(256 * 1024, remaining), signal);
        if (!allowSecretRead && isSensitiveContent(verifiedTarget, result.text, signal)) {
          this._rememberSensitivePath(verifiedTarget);
          sensitiveFilesBlocked += 1;
          files.push({
            path: displayPath(this._root, verifiedTarget),
            ok: false,
            blocked: true,
            redacted: true,
            content: SENSITIVE_REDACTION,
            error: SENSITIVE_FILE_ERROR,
          });
          allOk = false;
          continue;
        }
        remaining -= result.visibleBytes;
        totalBytes += result.visibleBytes;
        const lines = splitTextLines(result.text, signal);
        files.push({
          path: displayPath(this._root, verifiedTarget),
          ok: true,
          content: result.text,
          lineCount: result.truncated ? null : lines.length,
          fileSize: result.fileSize,
          truncated: result.truncated,
          encoding: 'utf8',
        });
      } catch (error) {
        if (isAbortError(error)) throw error;
        allOk = false;
        files.push({ path: toPortablePath(requestedPath), ok: false, error: errorMessage(error) });
      }
    }

    throwIfAborted(signal);
    const successCount = files.filter((file) => file.ok).length;
    return {
      ok: allOk,
      summary: `Read ${successCount} of ${files.length} files`,
      data: {
        files,
        totalBytes,
        maxTotalBytes,
        truncated: remaining <= 0 || files.some((file) => file.ok && file.truncated),
        ...(sensitiveFilesBlocked > 0 ? { sensitiveFilesBlocked } : {}),
      },
      ...(allOk ? {} : { error: 'One or more files could not be read.' }),
    };
  }

  async _searchText(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const query = optionalString(args, 'query', { allowEmpty: false, maxLength: MAX_PATTERN_LENGTH });
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const isRegex = optionalBoolean(args, 'isRegex', false);
    const caseSensitive = optionalBoolean(args, 'caseSensitive', false);
    const include = optionalString(args, 'include', { maxLength: MAX_PATTERN_LENGTH });
    const maxResults = clampInteger(args.maxResults, 50, 1, MAX_RESULTS);
    if (isRegex) {
      if (query.length > MAX_REGEX_PATTERN_LENGTH) {
        throw new RangeError(`Regular expression must be at most ${MAX_REGEX_PATTERN_LENGTH} characters.`);
      }
      if (looksUnsafeRegex(query)) {
        throw new Error('The regular expression appears unsafe or computationally expensive.');
      }
    }

    const flags = `g${caseSensitive ? '' : 'i'}u`;
    let expression;
    try {
      const source = isRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      expression = new RegExp(source, flags);
    } catch {
      throw new Error('Invalid regular expression.');
    }
    if (include !== undefined && hasGlobSyntax(include)) globToRegExp(include);

    const start = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, start)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, start)}`);
    }
    const startStats = await fsp.stat(start);
    throwIfAborted(signal);
    const allowSecretRead = allowsSecretRead(context);
    const matches = [];
    let filesScanned = 0;
    let bytesScanned = 0;
    let unreadableFiles = 0;
    let stopped = false;
    const state = {
      fileCount: 0,
      directoryCount: 0,
      scannedEntries: 0,
      sensitiveFilesSkipped: 0,
      truncated: false,
      stopped: false,
    };

    const searchFile = async (absolute, policyPath = absolute) => {
      if (stopped) return;
      throwIfAborted(signal);
      if (!allowSecretRead && this._isSensitivePath(policyPath)) {
        markSensitiveFileSkipped(state);
        return;
      }
      const relative = displayPath(this._root, absolute);
      if (include !== undefined && !matchesGlob(relative, path.basename(relative), include)) return;
      if (bytesScanned >= SEARCH_TOTAL_BYTES) {
        state.truncated = true;
        stopped = true;
        return;
      }

      try {
        const readLimit = Math.min(SEARCH_FILE_BYTES, SEARCH_TOTAL_BYTES - bytesScanned);
        const result = await this._readUtf8(policyPath, readLimit, signal);
        if (!allowSecretRead && isSensitiveContent(policyPath, result.text, signal)) {
          this._rememberSensitivePath(policyPath);
          markSensitiveFileSkipped(state);
          return;
        }
        bytesScanned += result.visibleBytes;
        filesScanned += 1;
        if (result.truncated) state.truncated = true;

        const lines = splitTextLines(result.text, signal);
        const starts = lineStartIndexes(result.text, signal);
        expression.lastIndex = 0;
        for (const match of result.text.matchAll(expression)) {
          throwIfAborted(signal);
          const lineNumber = lineNumberForOffset(starts, match.index, signal);
          matches.push({
            path: relative,
            line: lineNumber,
            text: compactText(lines[lineNumber - 1] || ''),
          });
          if (matches.length >= maxResults) {
            stopped = true;
            state.truncated = true;
            break;
          }
        }
      } catch (error) {
        if (isAbortError(error)) throw error;
        if (!allowSecretRead && this._isSensitivePath(policyPath)) {
          markSensitiveFileSkipped(state);
          return;
        }
        if (['ENOENT', 'EACCES', 'EPERM', 'EISDIR', 'EBINARY'].includes(error.code)) {
          unreadableFiles += 1;
          return;
        }
        throw error;
      }
    };

    if (startStats.isFile()) {
      await searchFile(start);
    } else if (startStats.isDirectory()) {
      for await (const item of this._walkFiles(start, {
        maxFiles: 5000,
        maxDirectories: 10_000,
        followSymlinkFiles: true,
        skipSensitive: !allowSecretRead,
        signal,
      }, state)) {
        await searchFile(item.absolute, item.resolved || item.absolute);
        if (stopped) break;
      }
    } else {
      throw new Error('Search path must be a file or directory.');
    }

    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Found ${matches.length} matches in ${filesScanned} files`,
      data: {
        matches,
        filesScanned,
        bytesScanned,
        unreadableFiles,
        truncated: state.truncated || matches.length >= maxResults,
        ...(state.sensitiveFilesSkipped > 0
          ? { sensitiveFilesSkipped: state.sensitiveFilesSkipped, blocked: true, redacted: true }
          : {}),
      },
    };
  }

  async _getFileInfo(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const target = this.resolveWorkspacePath(requestedPath);
    const stats = await fsp.stat(target);
    throwIfAborted(signal);
    const extension = path.extname(target);
    return {
      ok: true,
      summary: `Inspected ${displayPath(this._root, target)}`,
      data: {
        path: displayPath(this._root, target),
        type: stats.isFile() ? 'file' : stats.isDirectory() ? 'directory' : 'other',
        size: stats.size,
        extension: extension ? extension.slice(1).toLowerCase() : '',
        created: stats.birthtime.toISOString(),
        modified: stats.mtime.toISOString(),
        accessed: stats.atime.toISOString(),
      },
    };
  }

  async _writeFile(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const content = optionalString(args, 'content', { allowEmpty: true, required: true });
    const overwrite = optionalBoolean(args, 'overwrite', false);
    const byteLength = Buffer.byteLength(content, 'utf8');
    if (byteLength > MAX_WRITE_BYTES) throw new RangeError('content exceeds the 10 MiB write limit.');

    const target = this.resolveWorkspacePath(requestedPath);
    const parent = this.resolveWorkspacePath(path.dirname(target));
    let existed = false;
    try {
      const existing = await fsp.lstat(target);
      throwIfAborted(signal);
      existed = true;
      if (existing.isDirectory()) throw new Error(`Destination is a directory: ${displayPath(this._root, target)}`);
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (error.code !== 'ENOENT') throw error;
    }
    if (existed && !overwrite) throw new Error(`File already exists: ${displayPath(this._root, target)}`);

    // The parent may not exist yet, so do a lexical/canonical containment
    // revalidation first and a full parent check after creating it.
    this._revalidatePathPair(target, parent, signal, 'Write destination');
    throwIfAborted(signal);
    await fsp.mkdir(parent, { recursive: true });
    throwIfAborted(signal);
    const revalidated = await this._revalidateMutationPath(target, parent, signal, 'Write destination', {
      allowMissing: true,
    });
    if (revalidated.targetStats) {
      if (revalidated.targetStats.isDirectory()) {
        throw new Error(`Destination is a directory: ${displayPath(this._root, target)}`);
      }
      if (!overwrite) throw new Error(`File already exists: ${displayPath(this._root, target)}`);
    }
    throwIfAborted(signal);
    try {
      await fsp.writeFile(revalidated.target, content, { encoding: 'utf8', flag: overwrite ? 'w' : 'wx' });
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (error.code === 'EEXIST') throw new Error(`File already exists: ${displayPath(this._root, target)}`);
      throw error;
    }
    throwIfAborted(signal);

    return {
      ok: true,
      summary: `${existed ? 'Wrote' : 'Created'} ${displayPath(this._root, target)}`,
      data: {
        path: displayPath(this._root, target),
        bytesWritten: byteLength,
        created: !existed,
      },
    };
  }

  async _editFile(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const oldText = optionalString(args, 'oldText', { allowEmpty: false });
    const newText = optionalString(args, 'newText', { allowEmpty: true, required: true });
    const replaceAll = optionalBoolean(args, 'replaceAll', false);
    const target = this.resolveWorkspacePath(requestedPath);
    const parent = this.resolveWorkspacePath(path.dirname(target));
    const verifiedTarget = this._revalidateCanonicalPath(target, signal, 'Edit target');
    const result = await this._readUtf8(verifiedTarget, MAX_WRITE_BYTES, signal);
    if (result.truncated) throw new Error('File is too large to edit (maximum 10 MiB).');

    let count = 0;
    let offset = 0;
    while (true) {
      throwIfAborted(signal);
      const found = result.text.indexOf(oldText, offset);
      if (found === -1) break;
      count += 1;
      offset = found + oldText.length;
    }
    if (count === 0) throw new Error(`oldText was not found in ${displayPath(this._root, target)}.`);
    if (!replaceAll && count !== 1) {
      throw new Error(`oldText occurs ${count} times; provide more context or set replaceAll.`);
    }

    const updated = replaceAll
      ? result.text.split(oldText).join(newText)
      : result.text.replace(oldText, () => newText);
    const byteLength = Buffer.byteLength(updated, 'utf8');
    if (byteLength > MAX_WRITE_BYTES) throw new RangeError('Edited file would exceed the 10 MiB limit.');
    await this._revalidateMutationPath(verifiedTarget, parent, signal, 'Edit destination');
    throwIfAborted(signal);
    await fsp.writeFile(verifiedTarget, updated, 'utf8');
    throwIfAborted(signal);

    return {
      ok: true,
      summary: `Replaced ${count} occurrence${count === 1 ? '' : 's'} in ${displayPath(this._root, verifiedTarget)}`,
      data: {
        path: displayPath(this._root, verifiedTarget),
        replacements: count,
        bytesWritten: byteLength,
      },
    };
  }

  async _applyPatch(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const patch = optionalString(args, 'patch', { allowEmpty: false });
    const target = this.resolveWorkspacePath(requestedPath);
    const parent = this.resolveWorkspacePath(path.dirname(target));
    const verifiedTarget = this._revalidateCanonicalPath(target, signal, 'Patch target');
    const result = await this._readUtf8(verifiedTarget, MAX_WRITE_BYTES, signal);
    if (result.truncated) throw new Error('File is too large to patch (maximum 10 MiB).');

    const hunks = parseUnifiedDiff(patch, requestedPath, signal);
    const patched = applyParsedHunks(result.text, hunks, signal);
    const byteLength = Buffer.byteLength(patched.content, 'utf8');
    if (byteLength > MAX_WRITE_BYTES) throw new RangeError('Patched file would exceed the 10 MiB limit.');
    if (patched.content !== result.text) {
      await this._revalidateMutationPath(verifiedTarget, parent, signal, 'Patch destination');
      throwIfAborted(signal);
      await fsp.writeFile(verifiedTarget, patched.content, 'utf8');
      throwIfAborted(signal);
    } else {
      throwIfAborted(signal);
    }

    return {
      ok: true,
      summary: `Applied ${hunks.length} hunk${hunks.length === 1 ? '' : 's'} to ${displayPath(this._root, verifiedTarget)}`,
      data: {
        path: displayPath(this._root, verifiedTarget),
        hunksApplied: hunks.length,
        relocatedHunks: patched.relocatedHunks,
        bytesWritten: byteLength,
        changed: patched.content !== result.text,
      },
    };
  }

  async _createDirectory(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const target = this.resolveWorkspacePath(requestedPath);
    const parent = this.resolveWorkspacePath(path.dirname(target));
    let existed = false;
    try {
      const stats = await fsp.stat(target);
      throwIfAborted(signal);
      existed = true;
      if (!stats.isDirectory()) throw new Error(`Path exists and is not a directory: ${displayPath(this._root, target)}`);
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (error.code !== 'ENOENT') throw error;
    }

    this._revalidatePathPair(target, parent, signal, 'Directory destination');
    throwIfAborted(signal);
    await fsp.mkdir(target, { recursive: true });
    throwIfAborted(signal);
    const revalidated = await this._revalidateMutationPath(target, parent, signal, 'Directory destination', {
      allowMissing: true,
    });
    if (revalidated.targetStats && !revalidated.targetStats.isDirectory()) {
      throw new Error(`Path exists and is not a directory: ${displayPath(this._root, target)}`);
    }
    throwIfAborted(signal);
    return {
      ok: true,
      summary: `${existed ? 'Directory already exists' : 'Created directory'} ${displayPath(this._root, target)}`,
      data: { path: displayPath(this._root, target), created: !existed },
    };
  }

  async _moveFile(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const fromInput = optionalString(args, 'from', { allowEmpty: false });
    const toInput = optionalString(args, 'to', { allowEmpty: false });
    const overwrite = optionalBoolean(args, 'overwrite', false);
    const source = this.resolveWorkspacePath(fromInput);
    const destination = this.resolveWorkspacePath(toInput);
    const sourceSensitive = this._isSensitivePath(source);

    if (isSamePath(source, destination)) throw new Error('Source and destination are the same path.');
    if (isSamePath(source, this._root)) throw new Error('The workspace root cannot be moved.');
    if (isInside(source, destination) && source !== destination) {
      throw new Error('A directory cannot be moved inside itself.');
    }
    const sourceParent = this.resolveWorkspacePath(path.dirname(source));
    const destinationParent = this.resolveWorkspacePath(path.dirname(destination));

    const sourceStats = await fsp.stat(source);
    throwIfAborted(signal);
    let destinationExists = false;
    try {
      const destinationStats = await fsp.lstat(destination);
      throwIfAborted(signal);
      destinationExists = true;
      if (destinationStats.isDirectory()) {
        throw new Error('Destination is a directory; provide a full destination file or directory name.');
      }
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (error.code !== 'ENOENT') throw error;
    }
    if (destinationExists && !overwrite) {
      throw new Error(`Destination already exists: ${displayPath(this._root, destination)}`);
    }

    // The destination parent can be created recursively, so validate its
    // canonical containment before mkdir and validate the actual parent again
    // immediately before rename.
    this._revalidatePathPair(source, sourceParent, signal, 'Move source');
    this._revalidatePathPair(destination, destinationParent, signal, 'Move destination');
    throwIfAborted(signal);
    await fsp.mkdir(destinationParent, { recursive: true });
    throwIfAborted(signal);

    let verifiedSource = await this._revalidateMutationPath(source, sourceParent, signal, 'Move source');
    let verifiedDestination = await this._revalidateMutationPath(destination, destinationParent, signal, 'Move destination', {
      allowMissing: true,
    });
    if (verifiedDestination.targetStats) {
      if (verifiedDestination.targetStats.isDirectory()) {
        throw new Error('Destination is a directory; provide a full destination file or directory name.');
      }
      if (!overwrite) {
        throw new Error(`Destination already exists: ${displayPath(this._root, destination)}`);
      }
    }
    if (verifiedSource.targetStats?.isDirectory() && isInside(source, destination)) {
      throw new Error('A directory cannot be moved inside itself.');
    }
    throwIfAborted(signal);
    try {
      await fsp.rename(verifiedSource.target, verifiedDestination.target);
      if (sourceSensitive) this._rememberSensitivePath(verifiedDestination.target);
    } catch (error) {
      if (isAbortError(error)) throw error;
      if (!overwrite || !['EEXIST', 'EPERM'].includes(error.code)) throw error;

      verifiedSource = await this._revalidateMutationPath(source, sourceParent, signal, 'Move source');
      verifiedDestination = await this._revalidateMutationPath(destination, destinationParent, signal, 'Move destination');
      if (!verifiedDestination.targetStats || verifiedDestination.targetStats.isDirectory()) {
        throw new Error('Destination changed before it could be replaced.');
      }
      throwIfAborted(signal);
      await fsp.unlink(verifiedDestination.target);
      throwIfAborted(signal);
      verifiedSource = await this._revalidateMutationPath(source, sourceParent, signal, 'Move source');
      verifiedDestination = await this._revalidateMutationPath(destination, destinationParent, signal, 'Move destination', {
        allowMissing: true,
      });
      throwIfAborted(signal);
      await fsp.rename(verifiedSource.target, verifiedDestination.target);
      if (sourceSensitive) this._rememberSensitivePath(verifiedDestination.target);
    }
    throwIfAborted(signal);

    return {
      ok: true,
      summary: `Moved ${displayPath(this._root, source)} to ${displayPath(this._root, destination)}`,
      data: {
        from: displayPath(this._root, source),
        to: displayPath(this._root, destination),
        type: sourceStats.isDirectory() ? 'directory' : 'file',
        overwritten: destinationExists,
      },
    };
  }

  async _deletePath(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const recursive = optionalBoolean(args, 'recursive', false);
    const target = this.resolveWorkspacePath(requestedPath);
    if (isSamePath(target, this._root)) throw new Error('Refusing to delete the workspace root.');
    const parent = this.resolveWorkspacePath(path.dirname(target));

    const stats = await fsp.lstat(target);
    throwIfAborted(signal);
    if (this._trashItem) {
      const revalidated = await this._revalidateMutationPath(target, parent, signal, 'Delete target');
      if (isSamePath(revalidated.target, this._root)) throw new Error('Refusing to delete the workspace root.');
      if (revalidated.targetStats.isDirectory() !== stats.isDirectory()) {
        throw new Error('Delete target changed before commit.');
      }
      throwIfAborted(signal);
      await this._trashItem(revalidated.target);
      throwIfAborted(signal);
      return {
        ok: true,
        summary: `Moved ${displayPath(this._root, revalidated.target)} to trash`,
        data: { path: displayPath(this._root, revalidated.target), trashed: true, type: revalidated.targetStats.isDirectory() ? 'directory' : 'file' },
      };
    }

    if (stats.isDirectory() && !recursive) {
      const handle = await fsp.opendir(target);
      let hasEntries = false;
      try {
        for await (const _entry of handle) {
          throwIfAborted(signal);
          hasEntries = true;
          break;
        }
      } finally {
        await handle.close().catch(() => {});
      }
      if (hasEntries) throw new Error('Directory is not empty; set recursive to true.');
      const revalidated = await this._revalidateMutationPath(target, parent, signal, 'Delete target');
      if (isSamePath(revalidated.target, this._root)) throw new Error('Refusing to delete the workspace root.');
      if (!revalidated.targetStats?.isDirectory()) throw new Error('Delete target changed before commit.');
      throwIfAborted(signal);
      await fsp.rmdir(revalidated.target);
    } else if (stats.isDirectory()) {
      const revalidated = await this._revalidateMutationPath(target, parent, signal, 'Delete target');
      if (isSamePath(revalidated.target, this._root)) throw new Error('Refusing to delete the workspace root.');
      if (!revalidated.targetStats?.isDirectory()) throw new Error('Delete target changed before commit.');
      throwIfAborted(signal);
      await fsp.rm(revalidated.target, { recursive: true, force: false });
    } else {
      const revalidated = await this._revalidateMutationPath(target, parent, signal, 'Delete target');
      if (isSamePath(revalidated.target, this._root)) throw new Error('Refusing to delete the workspace root.');
      if (revalidated.targetStats?.isDirectory()) throw new Error('Delete target changed before commit.');
      throwIfAborted(signal);
      await fsp.unlink(revalidated.target);
    }
    throwIfAborted(signal);

    return {
      ok: true,
      summary: `Deleted ${displayPath(this._root, target)}`,
      data: { path: displayPath(this._root, target), trashed: false, type: stats.isDirectory() ? 'directory' : 'file' },
    };
  }

  async _projectOverview(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const maxFiles = clampInteger(args.maxFiles, 500, 1, 2000);
    const languageCounts = new Map();
    const manifests = [];
    const manifestNames = new Set([
      'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb',
      'deno.json', 'deno.jsonc', 'jsconfig.json', 'pyproject.toml', 'pipfile', 'poetry.lock',
      'cargo.toml', 'cargo.lock', 'go.mod', 'go.sum', 'pom.xml', 'build.gradle',
      'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts', 'gemfile', 'composer.json',
      'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    ]);

    const state = {
      fileCount: 0,
      directoryCount: 0,
      scannedEntries: 0,
      sensitiveFilesSkipped: 0,
      truncated: false,
      stopped: false,
    };
    for await (const item of this._walkFiles(this._root, {
      maxFiles,
      maxDirectories: 10_000,
      followSymlinkFiles: false,
      signal,
    }, state)) {
      throwIfAborted(signal);
      const basename = path.basename(item.absolute).toLowerCase();
      const relative = displayPath(this._root, item.absolute);
      const extension = path.extname(basename);
      const language = extension ? extension.slice(1).toLowerCase() : '[none]';
      languageCounts.set(language, (languageCounts.get(language) || 0) + 1);
      const isManifest = manifestNames.has(basename) ||
        /^tsconfig(?:\..+)?\.json$/.test(basename) ||
        /^requirements(?:-[^.]+)?\.txt$/.test(basename);
      if (isManifest && manifests.length < 30) manifests.push(relative);
    }

    const topLevel = [];
    let topLevelTruncated = false;
    let topLevelScanned = 0;
    const handle = await fsp.opendir(this._root);
    try {
      throwIfAborted(signal);
      for await (const entry of handle) {
        throwIfAborted(signal);
        topLevelScanned += 1;
        if (topLevelScanned > MAX_DIRECTORY_ENTRIES_SCANNED) {
          state.truncated = true;
          break;
        }
        if (IGNORED_DIRECTORY_NAMES.has(entry.name.toLowerCase())) continue;
        topLevel.push({
          name: entry.name,
          type: entry.isDirectory() ? 'directory' : entry.isSymbolicLink() ? 'symlink' : entry.isFile() ? 'file' : 'other',
        });
        if (topLevel.length > 50) break;
      }
    } finally {
      await handle.close().catch(() => {});
    }
    topLevelTruncated = topLevel.length > 50;
    if (topLevelTruncated) topLevel.length = 50;
    topLevel.sort((left, right) => left.name.localeCompare(right.name));

    const languages = [...languageCounts.entries()]
      .map(([extension, count]) => ({ extension, count }))
      .sort((left, right) => right.count - left.count || left.extension.localeCompare(right.extension))
      .slice(0, 15);

    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Scanned ${state.fileCount} project files`,
      data: {
        root: '.',
        fileCount: state.fileCount,
        directoryCount: state.directoryCount,
        languages,
        manifests,
        topLevel,
        topLevelTruncated,
        truncated: state.truncated,
      },
    };
  }

  async _findSymbols(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const query = optionalString(args, 'query', { maxLength: 200 });
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const maxResults = clampInteger(args.maxResults, 100, 1, MAX_RESULTS);
    if (query !== undefined && query.length === 0) throw new TypeError('query must not be empty when provided.');

    const start = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, start)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, start)}`);
    }
    const startStats = await fsp.stat(start);
    throwIfAborted(signal);
    const allowSecretRead = allowsSecretRead(context);
    const symbols = [];
    let filesScanned = 0;
    let bytesScanned = 0;
    let truncated = false;
    let sensitiveFilesSkipped = 0;

    const scanFile = async (absolute, policyPath = absolute) => {
      throwIfAborted(signal);
      if (!allowSecretRead && this._isSensitivePath(policyPath)) {
        sensitiveFilesSkipped += 1;
        return;
      }
      if (bytesScanned >= 10 * 1024 * 1024) {
        truncated = true;
        return;
      }
      try {
        const result = await this._readUtf8(policyPath, Math.min(SEARCH_FILE_BYTES, 10 * 1024 * 1024 - bytesScanned), signal);
        if (!allowSecretRead && isSensitiveContent(policyPath, result.text, signal)) {
          this._rememberSensitivePath(policyPath);
          sensitiveFilesSkipped += 1;
          return;
        }
        bytesScanned += result.visibleBytes;
        filesScanned += 1;
        if (result.truncated) truncated = true;
        const extension = path.extname(absolute).toLowerCase();
        const found = extractSymbols(result.text, extension, signal);
        for (const symbol of found) {
          throwIfAborted(signal);
          if (query && !symbol.name.toLowerCase().includes(query.toLowerCase())) continue;
          symbols.push({ path: displayPath(this._root, absolute), ...symbol });
          if (symbols.length >= maxResults) {
            truncated = true;
            return;
          }
        }
      } catch (error) {
        if (isAbortError(error)) throw error;
        if (!allowSecretRead && this._isSensitivePath(policyPath)) {
          sensitiveFilesSkipped += 1;
          return;
        }
        if (['ENOENT', 'EACCES', 'EPERM', 'EISDIR', 'EBINARY'].includes(error.code)) return;
        throw error;
      }
    };

    if (startStats.isFile()) {
      await scanFile(start);
    } else if (startStats.isDirectory()) {
      const state = {
        fileCount: 0,
        directoryCount: 0,
        scannedEntries: 0,
        sensitiveFilesSkipped: 0,
        truncated: false,
        stopped: false,
      };
      for await (const item of this._walkFiles(start, {
        maxFiles: 2000,
        maxDirectories: 10_000,
        followSymlinkFiles: true,
        skipSensitive: !allowSecretRead,
        signal,
      }, state)) {
        await scanFile(item.absolute, item.resolved || item.absolute);
        if (symbols.length >= maxResults) break;
      }
      truncated = truncated || state.truncated;
      sensitiveFilesSkipped += state.sensitiveFilesSkipped;
    } else {
      throw new Error('Symbol search path must be a file or directory.');
    }

    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Found ${symbols.length} symbols in ${filesScanned} files`,
      data: {
        symbols,
        filesScanned,
        bytesScanned,
        truncated,
        ...(sensitiveFilesSkipped > 0
          ? { sensitiveFilesSkipped, blocked: true, redacted: true }
          : {}),
      },
    };
  }

  async _projectMap(args, context) {
    const signal = getSignal(context);
    throwIfAborted(signal);
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const depth = clampInteger(args.depth, 2, 1, 6);
    const maxEntries = clampInteger(args.maxEntries, 150, 1, MAX_RESULTS);
    const start = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, start)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, start)}`);
    }
    const startStats = await fsp.stat(start);
    throwIfAborted(signal);
    const entries = [];
    let fileCount = 0;
    let directoryCount = 0;
    let inaccessibleDirectories = 0;
    let truncated = false;

    if (startStats.isFile()) {
      entries.push({ path: displayPath(this._root, start), type: 'file', depth: 0, size: startStats.size });
      fileCount = 1;
    } else if (startStats.isDirectory()) {
      const visit = async (directory, level) => {
        throwIfAborted(signal);
        if (entries.length >= maxEntries) {
          truncated = true;
          return;
        }

        const collected = [];
        let scanned = 0;
        const handle = await fsp.opendir(directory).catch((error) => {
          if (isAbortError(error)) throw error;
          inaccessibleDirectories += 1;
          return null;
        });
        if (!handle) return;
        try {
          for await (const entry of handle) {
            throwIfAborted(signal);
            scanned += 1;
            if (scanned > MAX_DIRECTORY_ENTRIES_SCANNED) {
              truncated = true;
              break;
            }
            if (IGNORED_DIRECTORY_NAMES.has(entry.name.toLowerCase())) continue;
            collected.push(entry);
            if (collected.length > maxEntries - entries.length) break;
          }
        } finally {
          await handle.close().catch(() => {});
        }
        throwIfAborted(signal);
        collected.sort((left, right) => {
          const leftDirectory = left.isDirectory() ? 0 : 1;
          const rightDirectory = right.isDirectory() ? 0 : 1;
          return leftDirectory - rightDirectory || left.name.localeCompare(right.name);
        });

        for (const entry of collected) {
          throwIfAborted(signal);
          if (entries.length >= maxEntries) {
            truncated = true;
            break;
          }
          const absolute = path.join(directory, entry.name);
          const type = entry.isDirectory() ? 'directory' : entry.isSymbolicLink() ? 'symlink' : entry.isFile() ? 'file' : 'other';
          const item = { path: displayPath(this._root, absolute), type, depth: level };
          if (entry.isFile()) {
            try {
              item.size = (await fsp.lstat(absolute)).size;
              throwIfAborted(signal);
            } catch (error) {
              if (isAbortError(error)) throw error;
              item.size = null;
            }
            fileCount += 1;
          } else if (entry.isDirectory()) {
            directoryCount += 1;
          }
          entries.push(item);

          if (entry.isDirectory() && level < depth) await visit(absolute, level + 1);
        }
      };
      await visit(start, 1);
    } else {
      throw new Error('Project map path must be a file or directory.');
    }

    throwIfAborted(signal);
    return {
      ok: true,
      summary: `Mapped ${entries.length} entries`,
      data: {
        root: displayPath(this._root, start),
        depth,
        entries,
        fileCount,
        directoryCount,
        inaccessibleDirectories,
        truncated,
      },
    };
  }

  async *_walkFiles(start, options, state) {
    const signal = options.signal;
    const maxFiles = options.maxFiles ?? 5000;
    const maxDirectories = options.maxDirectories ?? 10_000;
    const followSymlinkFiles = options.followSymlinkFiles === true;
    throwIfAborted(signal);
    const startStats = await fsp.stat(start);
    throwIfAborted(signal);

    if (startStats.isFile()) {
      if (options.skipSensitive && this._isSensitivePath(start)) {
        markSensitiveFileSkipped(state);
        return;
      }
      state.fileCount += 1;
      yield { absolute: start, size: startStats.size, symlink: false };
      return;
    }
    if (!startStats.isDirectory()) return;
    if (options.skipSensitive && this._isSensitivePath(start)) {
      markSensitiveFileSkipped(state);
      return;
    }

    const stack = [start];
    while (stack.length > 0 && !state.stopped) {
      throwIfAborted(signal);
      const directory = stack.pop();
      if (state.directoryCount >= maxDirectories) {
        state.truncated = true;
        break;
      }
      state.directoryCount += 1;

      const handle = await fsp.opendir(directory).catch((error) => {
        if (isAbortError(error)) throw error;
        return null;
      });
      if (!handle) continue;
      try {
        for await (const entry of handle) {
          throwIfAborted(signal);
          if (state.stopped) break;
          state.scannedEntries += 1;
          if (state.scannedEntries > MAX_DIRECTORY_ENTRIES_SCANNED) {
            state.truncated = true;
            break;
          }

          const absolute = path.join(directory, entry.name);
          if (IGNORED_DIRECTORY_NAMES.has(entry.name.toLowerCase())) continue;
          if (entry.isDirectory()) {
            if (options.skipSensitive && this._isSensitivePath(absolute)) {
              markSensitiveFileSkipped(state);
              continue;
            }
            stack.push(absolute);
            continue;
          }
          if (entry.isSymbolicLink()) {
            if (!followSymlinkFiles) continue;
            const resolved = this.resolveWorkspacePath(absolute);
            throwIfAborted(signal);
            const linkedStats = await fsp.stat(resolved);
            throwIfAborted(signal);
            if (!linkedStats.isFile()) continue;
            if (options.skipSensitive && this._isSensitivePath(resolved)) {
              markSensitiveFileSkipped(state);
              continue;
            }
            if (state.fileCount >= maxFiles) {
              state.truncated = true;
              break;
            }
            state.fileCount += 1;
            yield { absolute, resolved, size: linkedStats.size, symlink: true };
          } else if (entry.isFile()) {
            if (options.skipSensitive && this._isSensitivePath(absolute)) {
              markSensitiveFileSkipped(state);
              continue;
            }
            if (state.fileCount >= maxFiles) {
              state.truncated = true;
              break;
            }
            state.fileCount += 1;
            let size;
            try {
              size = (await fsp.lstat(absolute)).size;
              throwIfAborted(signal);
            } catch (error) {
              if (isAbortError(error)) throw error;
              size = undefined;
            }
            yield { absolute, size, symlink: false };
          }
        }
      } finally {
        await handle.close().catch(() => {});
      }
    }

    throwIfAborted(signal);
    if (stack.length > 0) state.truncated = true;
  }
}

module.exports = WorkspaceTools;
module.exports.WorkspaceTools = WorkspaceTools;
module.exports.default = WorkspaceTools;
