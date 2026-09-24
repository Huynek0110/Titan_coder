'use strict';

const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');

const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;
const DEFAULT_MAX_FILES = 14;
const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40 });
const REDACTED = '[REDACTED]';

/**
 * Redact values before they reach either a log file or a console.  Logging is
 * often used while handling errors, so this function is intentionally very
 * defensive and never throws on cyclic or unusual values.
 */
function redact(value, key = '', seen = new WeakSet(), depth = 0) {
  if (depth > 20) return '[Object]';

  if (key && isSecretKey(key)) return REDACTED;
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactString(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return value;
  if (typeof value === 'symbol') return value.toString();
  if (typeof value === 'function') return '[Function]';
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    try {
      if (value instanceof Error) {
        return {
          name: value.name,
          message: redactString(value.message || ''),
          stack: value.stack ? redactString(value.stack) : '',
        };
      }
      if (Buffer.isBuffer(value)) return redactString(value.toString('utf8'));
      if (Array.isArray(value)) return value.map((item) => redact(item, '', seen, depth + 1));
      if (value instanceof Date) return Number.isNaN(value.getTime()) ? '[Invalid Date]' : value.toISOString();
      if (value instanceof RegExp) return value.toString();
      const result = {};
      for (const [childKey, childValue] of Object.entries(value)) {
        result[childKey] = redact(childValue, childKey, seen, depth + 1);
      }
      return result;
    } finally {
      seen.delete(value);
    }
  }
  return String(value);
}

function isSecretKey(key) {
  const normalized = String(key).replace(/[-\s]/g, '').toLowerCase();
  return normalized === 'authorization'
    || normalized === 'proxyauthorization'
    || normalized === 'authorizationheader'
    || normalized === 'apikey'
    || normalized === 'apikeys'
    || normalized === 'xapikey'
    || normalized === 'braveapikey'
    || normalized === 'accesskey'
    || normalized === 'secretkey'
    || normalized === 'privatekey'
    || normalized === 'password'
    || normalized === 'passwords'
    || normalized === 'passwd'
    || normalized === 'pwd'
    || normalized === 'token'
    || normalized === 'tokens'
    || normalized === 'subscriptiontoken'
    || normalized === 'xsubscriptiontoken'
    || normalized === 'accesstoken'
    || normalized === 'refreshtoken'
    || normalized === 'idtoken'
    || normalized === 'authtoken'
    || normalized === 'apitoken'
    || normalized === 'credential'
    || normalized === 'credentials'
    || normalized === 'clientsecret'
    || normalized === 'secret'
    || normalized === 'cookie'
    || normalized === 'setcookie';
}

function redactString(value) {
  let text = String(value);
  const secretName = '(?:authorization|proxy-authorization|x[-_ ]?api[-_ ]?key|api[-_ ]?key|apikey|access[-_ ]?key|secret[-_ ]?key|private[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|id[-_ ]?token|auth[-_ ]?token|api[-_ ]?token|subscription[-_ ]?token|x[-_ ]?subscription[-_ ]?token|client[-_ ]?secret|passwords?|passwd|pwd|tokens?|secrets?|credential|credentials|key)';

  // Quoted values must be handled before the unquoted form so values such as
  // `api_key: "value with spaces"` cannot leave a suffix behind.
  text = text.replace(
    /(["']?(?:authorization|proxy-authorization|api[-_ ]?key|apikey|access[-_ ]?key|secret[-_ ]?key|private[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|id[-_ ]?token|client[-_ ]?secret|password|passwd|pwd|token|secret)["']?\s*[:=]\s*)(["'])([\s\S]*?)\2/gi,
    `$1$2${REDACTED}$2`,
  );

  // An Authorization header often contains a second credential-bearing word
  // (`Bearer`/`Basic`).  Redact the complete credential before handling other
  // assignment forms.
  text = text.replace(
    new RegExp(`(\\b${secretName}\\b\\s*[:=]\\s*)(?:Bearer|Basic)\\s+[^\\s,;}"']+`, 'gi'),
    `$1${REDACTED}`,
  );
  text = text.replace(/\b(Bearer|Basic)\s+[^\s,;}"']+/gi, `$1 ${REDACTED}`);

  // Finally cover ordinary unquoted assignment/query values.  Delimiters keep
  // neighbouring log fields readable while ensuring the credential itself is
  // never emitted.
  text = text.replace(
    new RegExp(`(\\b${secretName}\\b\\s*[:=]\\s*)[^\\s,;}"']+`, 'gi'),
    `$1${REDACTED}`,
  );
  // Passwords and bearer-like tokens may contain spaces when supplied as a
  // free-form assignment.  Consume the remainder of that field rather than
  // leaving a suffix behind.
  text = text.replace(
    /(\b(?:passwords?|passwd|pwd|secrets?|tokens?)\b\s*[:=]\s*)[^\r\n,;}]+/gi,
    `$1${REDACTED}`,
  );
  // Common standalone credential shapes cover values that were logged
  // without an obvious property name.
  text = text.replace(/\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/g, REDACTED);
  text = text.replace(/\b(?:sk|pk|rk)-[a-zA-Z0-9_-]{12,}\b/g, REDACTED);
  text = text.replace(/\b(?:gh[pousr]|github_pat)_[a-zA-Z0-9_]{12,}\b/g, REDACTED);
  text = text.replace(/\bxox[baprs]-[a-zA-Z0-9-]{12,}\b/g, REDACTED);
  text = text.replace(/(https?:\/\/)[^\/\s:@]+:[^\/@\s]+@/gi, `$1${REDACTED}@`);
  return text;
}

function utf8PrefixBuffer(buffer, maxBytes) {
  const source = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  let end = Math.min(source.length, Math.max(0, maxBytes));
  while (end > 0) {
    try {
      // Fatal decoding makes the byte boundary explicit instead of writing a
      // replacement character into an otherwise UTF-8 log.
      new util.TextDecoder('utf-8', { fatal: true }).decode(source.subarray(0, end));
      return source.subarray(0, end);
    } catch {
      end -= 1;
    }
  }
  return Buffer.alloc(0);
}

function utf8SuffixBuffer(buffer, maxBytes) {
  const source = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  let start = Math.max(0, source.length - Math.max(0, maxBytes));
  while (start < source.length) {
    try {
      new util.TextDecoder('utf-8', { fatal: true }).decode(source.subarray(start));
      return source.subarray(start);
    } catch {
      start += 1;
    }
  }
  return Buffer.alloc(0);
}

function safeOptions(options) {
  if (typeof options === 'string' || options instanceof URL) return { logDir: String(options) };
  if (!options || typeof options !== 'object') return {};
  return options;
}

function finitePositive(value, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return fallback;
  return Math.floor(number);
}

function formatArgument(value) {
  try {
    if (typeof value === 'string') return redactString(value);
    const redacted = redact(value);
    return util.inspect(redacted, {
      depth: 6,
      maxArrayLength: 100,
      maxStringLength: 16_384,
      breakLength: 120,
      compact: false,
    });
  } catch {
    return '[Unloggable value]';
  }
}

class Logger {
  constructor(options = {}) {
    const opts = safeOptions(options);
    this.logDir = typeof opts.logDir === 'string'
      ? opts.logDir
      : (typeof opts.dir === 'string' ? opts.dir : path.join(process.cwd(), 'logs'));
    this.level = Logger.normalizeLevel(opts.level == null ? 'info' : opts.level);
    this.maxBytes = finitePositive(
      opts.maxBytes == null
        ? (opts.maxSizeBytes == null
          ? (opts.maxSize == null ? opts.maxLogBytes : opts.maxSize)
          : opts.maxSizeBytes)
        : opts.maxBytes,
      DEFAULT_MAX_BYTES,
    );
    this.maxFiles = finitePositive(opts.maxFiles == null ? opts.maxLogFiles : opts.maxFiles, DEFAULT_MAX_FILES);
    this.filePrefix = typeof opts.filePrefix === 'string' && opts.filePrefix
      ? opts.filePrefix.replace(/[^a-zA-Z0-9_.-]/g, '-')
      : 'codepilot';
    this.consoleEnabled = opts.console !== false && opts.consoleEnabled !== false;
    this.consoleOutput = opts.consoleOutput || opts.logger || console;
    this._stopped = false;
    this._lastFile = null;
    this._ensureDirectory();
  }

  static normalizeLevel(level) {
    if (typeof level === 'number' && Number.isFinite(level)) return level;
    if (typeof level !== 'string') return LEVELS.info;
    const normalized = level.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(LEVELS, normalized)) return LEVELS[normalized];
    const numeric = Number(normalized);
    return Number.isFinite(numeric) ? numeric : LEVELS.info;
  }

  static get levels() {
    return { ...LEVELS };
  }

  static redact(value) {
    return redact(value);
  }

  static redactString(value) {
    return redactString(value);
  }

  redact(value) {
    return redact(value);
  }

  redactString(value) {
    return redactString(value);
  }

  _ensureDirectory() {
    try {
      fs.mkdirSync(this.logDir, { recursive: true });
    } catch {
      // Logging must not make the application fail if a configured directory
      // is read-only or otherwise unavailable.
    }
  }

  _dateStamp(date = new Date()) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  fileNameForDate(date = new Date()) {
    return `${this.filePrefix}-${this._dateStamp(date)}.log`;
  }

  get currentFile() {
    return path.join(this.logDir, this.fileNameForDate());
  }

  get logFile() {
    return this.currentFile;
  }

  get logFilePath() {
    return this.currentFile;
  }

  get recentFile() {
    return this.getRecentFile();
  }

  isLevelEnabled(level) {
    return this._stopped ? false : Logger.normalizeLevel(level) >= this.level;
  }

  log(level, ...args) {
    if (!this.isLevelEnabled(level)) return this;
    const normalizedLevel = typeof level === 'string' ? level.toLowerCase() : 'info';
    let message;
    try {
      message = args.map(formatArgument).join(' ');
      message = message.replace(/[\r\n]+/g, '\\n');
    } catch {
      message = '[Unable to format log message]';
    }
    const line = `${new Date().toISOString()} [${normalizedLevel.toUpperCase()}] ${message}\n`;
    this._writeLine(line, normalizedLevel);
    return this;
  }

  debug(...args) { return this.log('debug', ...args); }
  info(...args) { return this.log('info', ...args); }
  warn(...args) { return this.log('warn', ...args); }
  warning(...args) { return this.log('warn', ...args); }
  error(...args) { return this.log('error', ...args); }

  _writeLine(line, level) {
    // Console output is intentionally performed after redaction and inside a
    // try/catch.  A broken console implementation must not affect the app.
    if (this.consoleEnabled) {
      try {
        const method = typeof this.consoleOutput?.[level] === 'function'
          ? this.consoleOutput[level]
          : (typeof this.consoleOutput?.log === 'function' ? this.consoleOutput.log : null);
        if (method) method.call(this.consoleOutput, line.replace(/\n$/, ''));
      } catch {
        // Ignore console failures.
      }
    }

    let bytes;
    try {
      bytes = Buffer.from(line, 'utf8');
    } catch {
      return;
    }
    if (bytes.length > this.maxBytes) {
      bytes = utf8PrefixBuffer(bytes, this.maxBytes);
    }

    let filePath;
    try {
      this._ensureDirectory();
      filePath = this.currentFile;
      const existing = this._readIfPresent(filePath);
      if (!existing) {
        fs.writeFileSync(filePath, bytes, { mode: 0o600 });
      } else if (existing.length + bytes.length > this.maxBytes) {
        const room = Math.max(0, this.maxBytes - bytes.length);
        let retained = room > 0 ? utf8SuffixBuffer(existing, room) : Buffer.alloc(0);
        // Prefer a line boundary when possible, but never exceed the cap.
        const newline = retained.indexOf(0x0a);
        if (newline >= 0 && newline < retained.length - 1) retained = retained.subarray(newline + 1);
        const combined = Buffer.concat([retained, bytes]);
        fs.writeFileSync(filePath, combined, { mode: 0o600 });
      } else {
        fs.appendFileSync(filePath, bytes, { mode: 0o600 });
      }
      this._lastFile = filePath;
      this._pruneFiles();
    } catch {
      // Never propagate filesystem errors from logging.
    }
  }

  _readIfPresent(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) return null;
      if (stat.size > this.maxBytes) {
        return utf8SuffixBuffer(fs.readFileSync(filePath), this.maxBytes);
      }
      return fs.readFileSync(filePath);
    } catch {
      return null;
    }
  }

  _listFiles() {
    try {
      return fs.readdirSync(this.logDir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.startsWith(`${this.filePrefix}-`) && entry.name.endsWith('.log'))
        .map((entry) => {
          const full = path.join(this.logDir, entry.name);
          let mtime = 0;
          try { mtime = fs.statSync(full).mtimeMs; } catch { /* ignore */ }
          return { path: full, name: entry.name, mtime };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      return [];
    }
  }

  _pruneFiles() {
    const files = this._listFiles();
    const excess = files.length - this.maxFiles;
    if (excess <= 0) return;
    for (const file of files.slice(0, excess)) {
      try { fs.unlinkSync(file.path); } catch { /* ignore */ }
    }
  }

  /** Return the path to the newest daily log, or null if none exists. */
  getRecentFile() {
    const files = this._listFiles();
    if (!files.length) return null;
    return files[files.length - 1].path;
  }

  getRecentFilePath() {
    return this.getRecentFile();
  }

  /** Return the contents of the newest daily log, or an empty string. */
  getRecentContent() {
    const file = this.getRecentFile();
    if (!file) return '';
    try { return fs.readFileSync(file, 'utf8'); } catch { return ''; }
  }

  getRecentLog() {
    return this.getRecentContent();
  }

  getRecentFileContent() {
    return this.getRecentContent();
  }

  /** Return safe log text for the renderer/debug panel. */
  recent() {
    return this.getRecentContent();
  }

  getRecent() {
    return this.getRecentContent();
  }

  getRecentFileInfo() {
    const file = this.getRecentFile();
    if (!file) return null;
    return { path: file, name: path.basename(file), content: this.getRecentContent() };
  }

  async flush() {
    // Writes are synchronous by design, so this is intentionally a resolved
    // promise.  Keeping the async API makes it compatible with buffered
    // logger implementations and UI shutdown code.
    return this;
  }

  async stop() {
    this._stopped = true;
    await this.flush();
    return this;
  }

  async close() {
    return this.stop();
  }
}

Logger.LEVELS = Object.freeze({ ...LEVELS });
Logger.MAX_BYTES = DEFAULT_MAX_BYTES;
Logger.MAX_FILES = DEFAULT_MAX_FILES;
module.exports = Logger;
module.exports.Logger = Logger;
module.exports.default = Logger;
module.exports.LEVELS = Logger.LEVELS;
module.exports.redact = redact;
module.exports.redactString = redactString;
module.exports.DEFAULT_MAX_BYTES = DEFAULT_MAX_BYTES;
module.exports.DEFAULT_MAX_FILES = DEFAULT_MAX_FILES;
module.exports.MAX_BYTES = DEFAULT_MAX_BYTES;
module.exports.MAX_FILES = DEFAULT_MAX_FILES;
