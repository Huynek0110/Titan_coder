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
  const name = path.basename(filePath).toLowerCase();
  if (name === '.env' || name.startsWith('.env.') || name === '.envrc') return true;
  if (name === '.npmrc' || name === '.pypirc' || name === '.netrc') return true;
  if (name === 'credentials' || name.startsWith('credentials.') || name === 'secrets' || name.startsWith('secrets.')) return true;
  if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(name)) return true;
  return /\.(pem|key|p12|pfx|jks|keystore)$/.test(name);
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

function splitTextLines(text) {
  if (text.length === 0) return [];
  const lines = text.split(/\r\n|\n|\r/);
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function splitLineRecords(text) {
  const records = [];
  let offset = 0;

  while (offset < text.length) {
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

function globToRegExp(glob) {
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
      const closing = normalized.indexOf(']', index + 1);
      if (closing !== -1) {
        let content = normalized.slice(index + 1, closing);
        if (content.startsWith('!')) content = `^${content.slice(1)}`;
        source += `[${content}]`;
        index = closing;
        continue;
      }
    }
    source += character.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  }

  source += '$';
  return new RegExp(source, 'i');
}

function matchesGlob(relativePath, basename, pattern) {
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

function lineStartIndexes(text) {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') starts.push(index + 1);
  }
  return starts;
}

function lineNumberForOffset(starts, offset) {
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (starts[middle] <= offset) low = middle + 1;
    else high = middle - 1;
  }
  return high + 1;
}

function looksUnsafeRegex(pattern) {
  return /\((?:\?:)?[^()]*[+*][^()]*\)\s*[+*]/.test(pattern) || /\\\d/.test(pattern);
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

function parseUnifiedDiff(patch, expectedPath) {
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
    if (current.lines.length === 0) throw new Error(`Hunk ${hunks.length + 1} is empty.`);

    const oldCount = current.lines.filter((line) => line.kind !== '+').length;
    const newCount = current.lines.filter((line) => line.kind !== '-').length;
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

function hunkRecordsMatch(records, expected) {
  if (records.length !== expected.length) return false;
  return expected.every((line, index) => {
    const record = records[index];
    if (record.text !== line.text) return false;
    return !line.noNewline || record.ending === '';
  });
}

function applyParsedHunks(content, hunks) {
  let records = splitLineRecords(content);
  let cursor = 0;
  let relocatedHunks = 0;
  const preferredEnding = records.find((record) => record.ending)?.ending ||
    (content.includes('\r\n') ? '\r\n' : os.EOL);

  for (let hunkIndex = 0; hunkIndex < hunks.length; hunkIndex += 1) {
    const hunk = hunks[hunkIndex];
    const oldLines = hunk.lines.filter((line) => line.kind !== '+');
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
        if (hunkRecordsMatch(records.slice(candidate, candidate + oldLines.length), oldLines)) {
          matchIndex = candidate;
          break;
        }
      }
      if (matchIndex === -1) {
        for (let candidate = cursor; candidate <= records.length - oldLines.length; candidate += 1) {
          if (hunkRecordsMatch(records.slice(candidate, candidate + oldLines.length), oldLines)) {
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

function extractSymbols(text, extension) {
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
    const lines = splitTextLines(text);
    for (let index = 0; index < lines.length; index += 1) {
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
    splitTextLines(text).forEach((line, index) => {
      if (/^\s*class\s+[A-Za-z_][\w]*\s*(?:\([^)]*\))?\s*:/.test(line)) {
        const name = /\bclass\s+([A-Za-z_][\w]*)/.exec(line)[1];
        add(name, 'class', index + 1, line);
      } else if (/^\s*(?:async\s+)?def\s+[A-Za-z_][\w]*\s*\(/.test(line)) {
        const name = /\bdef\s+([A-Za-z_][\w]*)/.exec(line)[1];
        add(name, 'function', index + 1, line);
      }
    });
  } else if (extension === '.go') {
    splitTextLines(text).forEach((line, index) => {
      let match = /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)\s*\(/.exec(line);
      if (match) add(match[1], 'function', index + 1, line);
      if (!(match = /^\s*type\s+([A-Za-z_][\w]*)\s+(?:struct|interface)\b/.exec(line))) {
        match = /^\s*type\s+([A-Za-z_][\w]*)\b/.exec(line);
        if (match) add(match[1], 'type', index + 1, line);
      }
    });
  } else if (extension === '.rs') {
    splitTextLines(text).forEach((line, index) => {
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
    splitTextLines(text).forEach((line, index) => {
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
      pattern: { type: 'string', description: 'Glob such as **/*.ts or *.test.js.' },
      query: { type: 'string', description: 'Case-insensitive file-name substring or glob.' },
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
      include: { type: 'string', description: 'Optional path glob such as **/*.ts.' },
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
      query: { type: 'string', description: 'Optional case-insensitive symbol-name filter.' },
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

    this._root = canonical;
    return this;
  }

  getRoot() {
    return this._root;
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

  async execute(name, args = {}, context = {}) {
    try {
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
      if (context && context.signal && context.signal.aborted) {
        throw new Error('Workspace operation was cancelled.');
      }

      const handlers = this._handlers();
      const result = await handlers[name](args, context || {});
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
      list_directory: (args) => this._listDirectory(args),
      find_files: (args) => this._findFiles(args),
      read_file: (args) => this._readFile(args),
      read_many_files: (args) => this._readManyFiles(args),
      search_text: (args) => this._searchText(args),
      get_file_info: (args) => this._getFileInfo(args),
      write_file: (args) => this._writeFile(args),
      edit_file: (args) => this._editFile(args),
      apply_patch: (args) => this._applyPatch(args),
      create_directory: (args) => this._createDirectory(args),
      move_file: (args) => this._moveFile(args),
      delete_path: (args) => this._deletePath(args),
      project_overview: (args) => this._projectOverview(args),
      find_symbols: (args) => this._findSymbols(args),
      project_map: (args) => this._projectMap(args),
    };
  }

  async _readLimited(target, limit) {
    const handle = await fsp.open(target, 'r');
    try {
      const stats = await handle.stat();
      if (!stats.isFile()) throw new Error(`Not a file: ${displayPath(this._root, target)}`);
      const allocation = Math.min(stats.size, limit + 1);
      const buffer = Buffer.alloc(allocation);
      let offset = 0;
      while (offset < allocation) {
        const result = await handle.read(buffer, offset, allocation - offset, offset);
        if (result.bytesRead === 0) break;
        offset += result.bytesRead;
      }
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

  async _readUtf8(target, limit) {
    const result = await this._readLimited(target, limit);
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

  async _listDirectory(args) {
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const includeHidden = optionalBoolean(args, 'includeHidden', false);
    const target = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, target)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, target)}`);
    }

    const stats = await fsp.stat(target);
    if (!stats.isDirectory()) throw new Error(`Not a directory: ${displayPath(this._root, target)}`);

    const entries = [];
    let scanned = 0;
    let truncated = false;
    const handle = await fsp.opendir(target);
    try {
      for await (const entry of handle) {
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

    entries.sort((left, right) => {
      const leftDirectory = left.isDirectory() ? 0 : 1;
      const rightDirectory = right.isDirectory() ? 0 : 1;
      return leftDirectory - rightDirectory || left.name.localeCompare(right.name);
    });
    const visibleEntries = entries.slice(0, MAX_LIST_ENTRIES);

    const dataEntries = await Promise.all(visibleEntries.map(async (entry) => {
      const absolute = path.join(target, entry.name);
      const type = entry.isDirectory() ? 'directory' : entry.isSymbolicLink() ? 'symlink' : entry.isFile() ? 'file' : 'other';
      const item = { name: entry.name, path: displayPath(this._root, absolute), type };
      if (entry.isFile()) {
        try {
          const itemStats = await fsp.lstat(absolute);
          item.size = itemStats.size;
          item.modified = itemStats.mtime.toISOString();
        } catch {
          // The name and type are still useful if metadata disappears concurrently.
        }
      }
      return item;
    }));

    return {
      ok: true,
      summary: `Listed ${dataEntries.length} entries in ${displayPath(this._root, target)}`,
      data: { path: displayPath(this._root, target), entries: dataEntries, truncated },
    };
  }

  async _findFiles(args) {
    const pattern = optionalString(args, 'pattern');
    const query = optionalString(args, 'query');
    const maxResults = clampInteger(args.maxResults, 100, 1, MAX_RESULTS);
    if (pattern !== undefined && pattern.length === 0) throw new TypeError('pattern must not be empty when provided.');
    if (query !== undefined && query.length === 0) throw new TypeError('query must not be empty when provided.');

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
      truncated: false,
      stopped: false,
    };

    for await (const item of this._walkFiles(this._root, {
      maxFiles: Math.max(maxResults, 2000),
      maxDirectories: 10_000,
      followSymlinkFiles: false,
    }, state)) {
      const relative = displayPath(this._root, item.absolute);
      const basename = path.basename(relative);
      if (!matches(relative, basename)) continue;
      let size = item.size;
      if (size === undefined || size === null) {
        try {
          size = (await fsp.lstat(item.absolute)).size;
        } catch {
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

    return {
      ok: true,
      summary: `Found ${files.length} files`,
      data: {
        files,
        truncated: state.truncated || state.scannedEntries >= MAX_DIRECTORY_ENTRIES_SCANNED,
      },
    };
  }

  async _readFile(args) {
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const startLine = clampInteger(args.startLine, 1, 1, Number.MAX_SAFE_INTEGER);
    const endLine = clampInteger(args.endLine, startLine + 999, startLine, Number.MAX_SAFE_INTEGER);
    if (endLine - startLine + 1 > 2000) {
      throw new RangeError('A read_file call may return at most 2000 lines.');
    }
    const maxBytes = clampInteger(args.maxBytes, DEFAULT_READ_BYTES, 1, MAX_READ_BYTES);
    const target = this.resolveWorkspacePath(requestedPath);
    const result = await this._readUtf8(target, maxBytes);
    const lines = splitTextLines(result.text);

    if (startLine > lines.length && result.truncated) {
      throw new Error(`startLine ${startLine} is beyond the ${maxBytes}-byte inspection limit.`);
    }

    const selected = lines.slice(startLine - 1, endLine);
    const visibleEnd = selected.length === 0 ? 0 : startLine + selected.length - 1;
    return {
      ok: true,
      summary: `Read ${displayPath(this._root, target)} (${selected.length} lines)`,
      data: {
        path: displayPath(this._root, target),
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

  async _readManyFiles(args) {
    if (!Array.isArray(args.paths) || args.paths.length === 0 || args.paths.length > 50) {
      throw new TypeError('paths must be an array containing 1 to 50 paths.');
    }
    if (!args.paths.every((value) => typeof value === 'string' && value.length > 0)) {
      throw new TypeError('Every path must be a non-empty string.');
    }
    const maxTotalBytes = clampInteger(args.maxTotalBytes, DEFAULT_MANY_FILES_BYTES, 1, MAX_MANY_FILES_BYTES);
    const files = [];
    let remaining = maxTotalBytes;
    let totalBytes = 0;
    let allOk = true;

    for (const requestedPath of args.paths) {
      if (remaining <= 0) {
        files.push({ path: toPortablePath(requestedPath), ok: false, error: 'Shared byte budget exhausted.' });
        allOk = false;
        continue;
      }

      try {
        const target = this.resolveWorkspacePath(requestedPath);
        const result = await this._readUtf8(target, Math.min(256 * 1024, remaining));
        remaining -= result.visibleBytes;
        totalBytes += result.visibleBytes;
        const lines = splitTextLines(result.text);
        files.push({
          path: displayPath(this._root, target),
          ok: true,
          content: result.text,
          lineCount: result.truncated ? null : lines.length,
          fileSize: result.fileSize,
          truncated: result.truncated,
          encoding: 'utf8',
        });
      } catch (error) {
        allOk = false;
        files.push({ path: toPortablePath(requestedPath), ok: false, error: errorMessage(error) });
      }
    }

    const successCount = files.filter((file) => file.ok).length;
    return {
      ok: allOk,
      summary: `Read ${successCount} of ${files.length} files`,
      data: {
        files,
        totalBytes,
        maxTotalBytes,
        truncated: remaining <= 0 || files.some((file) => file.ok && file.truncated),
      },
      ...(allOk ? {} : { error: 'One or more files could not be read.' }),
    };
  }

  async _searchText(args) {
    const query = optionalString(args, 'query', { allowEmpty: false, maxLength: 512 });
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const isRegex = optionalBoolean(args, 'isRegex', false);
    const caseSensitive = optionalBoolean(args, 'caseSensitive', false);
    const include = optionalString(args, 'include');
    const maxResults = clampInteger(args.maxResults, 50, 1, MAX_RESULTS);
    if (isRegex && looksUnsafeRegex(query)) {
      throw new Error('The regular expression appears unsafe or computationally expensive.');
    }

    const flags = `g${caseSensitive ? '' : 'i'}u`;
    let expression;
    try {
      const source = isRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      expression = new RegExp(source, flags);
    } catch {
      throw new Error('Invalid regular expression.');
    }

    const start = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, start)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, start)}`);
    }
    const startStats = await fsp.stat(start);
    const matches = [];
    let filesScanned = 0;
    let bytesScanned = 0;
    let unreadableFiles = 0;
    let stopped = false;
    const state = {
      fileCount: 0,
      directoryCount: 0,
      scannedEntries: 0,
      truncated: false,
      stopped: false,
    };

    const searchFile = async (absolute) => {
      if (stopped) return;
      if (isSensitiveFile(absolute)) return;
      const relative = displayPath(this._root, absolute);
      if (include !== undefined && !matchesGlob(relative, path.basename(relative), include)) return;
      if (bytesScanned >= SEARCH_TOTAL_BYTES) {
        state.truncated = true;
        stopped = true;
        return;
      }

      try {
        const readLimit = Math.min(SEARCH_FILE_BYTES, SEARCH_TOTAL_BYTES - bytesScanned);
        const result = await this._readUtf8(absolute, readLimit);
        bytesScanned += result.visibleBytes;
        filesScanned += 1;
        if (result.truncated) state.truncated = true;

        const lines = splitTextLines(result.text);
        const starts = lineStartIndexes(result.text);
        expression.lastIndex = 0;
        for (const match of result.text.matchAll(expression)) {
          const lineNumber = lineNumberForOffset(starts, match.index);
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
        if (isSensitiveFile(absolute)) return;
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
        skipSensitive: true,
      }, state)) {
        await searchFile(item.absolute);
        if (stopped) break;
      }
    } else {
      throw new Error('Search path must be a file or directory.');
    }

    return {
      ok: true,
      summary: `Found ${matches.length} matches in ${filesScanned} files`,
      data: {
        matches,
        filesScanned,
        bytesScanned,
        unreadableFiles,
        truncated: state.truncated || matches.length >= maxResults,
      },
    };
  }

  async _getFileInfo(args) {
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const target = this.resolveWorkspacePath(requestedPath);
    const stats = await fsp.stat(target);
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

  async _writeFile(args) {
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
      existed = true;
      if (existing.isDirectory()) throw new Error(`Destination is a directory: ${displayPath(this._root, target)}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (existed && !overwrite) throw new Error(`File already exists: ${displayPath(this._root, target)}`);

    await fsp.mkdir(parent, { recursive: true });
    try {
      await fsp.writeFile(target, content, { encoding: 'utf8', flag: overwrite ? 'w' : 'wx' });
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error(`File already exists: ${displayPath(this._root, target)}`);
      throw error;
    }

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

  async _editFile(args) {
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const oldText = optionalString(args, 'oldText', { allowEmpty: false });
    const newText = optionalString(args, 'newText', { allowEmpty: true, required: true });
    const replaceAll = optionalBoolean(args, 'replaceAll', false);
    const target = this.resolveWorkspacePath(requestedPath);
    const result = await this._readUtf8(target, MAX_WRITE_BYTES);
    if (result.truncated) throw new Error('File is too large to edit (maximum 10 MiB).');

    let count = 0;
    let offset = 0;
    while (true) {
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
    await fsp.writeFile(target, updated, 'utf8');

    return {
      ok: true,
      summary: `Replaced ${count} occurrence${count === 1 ? '' : 's'} in ${displayPath(this._root, target)}`,
      data: {
        path: displayPath(this._root, target),
        replacements: count,
        bytesWritten: byteLength,
      },
    };
  }

  async _applyPatch(args) {
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const patch = optionalString(args, 'patch', { allowEmpty: false });
    const target = this.resolveWorkspacePath(requestedPath);
    const result = await this._readUtf8(target, MAX_WRITE_BYTES);
    if (result.truncated) throw new Error('File is too large to patch (maximum 10 MiB).');

    const hunks = parseUnifiedDiff(patch, requestedPath);
    const patched = applyParsedHunks(result.text, hunks);
    const byteLength = Buffer.byteLength(patched.content, 'utf8');
    if (byteLength > MAX_WRITE_BYTES) throw new RangeError('Patched file would exceed the 10 MiB limit.');
    if (patched.content !== result.text) await fsp.writeFile(target, patched.content, 'utf8');

    return {
      ok: true,
      summary: `Applied ${hunks.length} hunk${hunks.length === 1 ? '' : 's'} to ${displayPath(this._root, target)}`,
      data: {
        path: displayPath(this._root, target),
        hunksApplied: hunks.length,
        relocatedHunks: patched.relocatedHunks,
        bytesWritten: byteLength,
        changed: patched.content !== result.text,
      },
    };
  }

  async _createDirectory(args) {
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const target = this.resolveWorkspacePath(requestedPath);
    let existed = false;
    try {
      const stats = await fsp.stat(target);
      existed = true;
      if (!stats.isDirectory()) throw new Error(`Path exists and is not a directory: ${displayPath(this._root, target)}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }

    await fsp.mkdir(target, { recursive: true });
    return {
      ok: true,
      summary: `${existed ? 'Directory already exists' : 'Created directory'} ${displayPath(this._root, target)}`,
      data: { path: displayPath(this._root, target), created: !existed },
    };
  }

  async _moveFile(args) {
    const fromInput = optionalString(args, 'from', { allowEmpty: false });
    const toInput = optionalString(args, 'to', { allowEmpty: false });
    const overwrite = optionalBoolean(args, 'overwrite', false);
    const source = this.resolveWorkspacePath(fromInput);
    const destination = this.resolveWorkspacePath(toInput);

    if (isSamePath(source, destination)) throw new Error('Source and destination are the same path.');
    if (isSamePath(source, this._root)) throw new Error('The workspace root cannot be moved.');
    if (isInside(source, destination) && source !== destination) {
      throw new Error('A directory cannot be moved inside itself.');
    }

    const sourceStats = await fsp.stat(source);
    const destinationParent = this.resolveWorkspacePath(path.dirname(destination));
    let destinationExists = false;
    try {
      const destinationStats = await fsp.lstat(destination);
      destinationExists = true;
      if (destinationStats.isDirectory()) {
        throw new Error('Destination is a directory; provide a full destination file or directory name.');
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (destinationExists && !overwrite) {
      throw new Error(`Destination already exists: ${displayPath(this._root, destination)}`);
    }

    await fsp.mkdir(destinationParent, { recursive: true });
    try {
      await fsp.rename(source, destination);
    } catch (error) {
      if (!overwrite || !['EEXIST', 'EPERM'].includes(error.code)) throw error;
      await fsp.unlink(destination);
      await fsp.rename(source, destination);
    }

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

  async _deletePath(args) {
    const requestedPath = optionalString(args, 'path', { allowEmpty: false });
    const recursive = optionalBoolean(args, 'recursive', false);
    const target = this.resolveWorkspacePath(requestedPath);
    if (isSamePath(target, this._root)) throw new Error('Refusing to delete the workspace root.');

    const stats = await fsp.lstat(target);
    if (this._trashItem) {
      await this._trashItem(target);
      return {
        ok: true,
        summary: `Moved ${displayPath(this._root, target)} to trash`,
        data: { path: displayPath(this._root, target), trashed: true, type: stats.isDirectory() ? 'directory' : 'file' },
      };
    }

    if (stats.isDirectory() && !recursive) {
      const handle = await fsp.opendir(target);
      let hasEntries = false;
      try {
        for await (const _entry of handle) {
          hasEntries = true;
          break;
        }
      } finally {
        await handle.close().catch(() => {});
      }
      if (hasEntries) throw new Error('Directory is not empty; set recursive to true.');
      await fsp.rmdir(target);
    } else if (stats.isDirectory()) {
      await fsp.rm(target, { recursive: true, force: false });
    } else {
      await fsp.unlink(target);
    }

    return {
      ok: true,
      summary: `Deleted ${displayPath(this._root, target)}`,
      data: { path: displayPath(this._root, target), trashed: false, type: stats.isDirectory() ? 'directory' : 'file' },
    };
  }

  async _projectOverview(args) {
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
      truncated: false,
      stopped: false,
    };
    for await (const item of this._walkFiles(this._root, {
      maxFiles,
      maxDirectories: 10_000,
      followSymlinkFiles: false,
    }, state)) {
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
      for await (const entry of handle) {
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

  async _findSymbols(args) {
    const query = optionalString(args, 'query');
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const maxResults = clampInteger(args.maxResults, 100, 1, MAX_RESULTS);
    if (query !== undefined && query.length === 0) throw new TypeError('query must not be empty when provided.');
    if (query && query.length > 200) throw new RangeError('query must be at most 200 characters.');

    const start = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, start)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, start)}`);
    }
    const startStats = await fsp.stat(start);
    const symbols = [];
    let filesScanned = 0;
    let bytesScanned = 0;
    let truncated = false;

    const scanFile = async (absolute) => {
      if (isSensitiveFile(absolute)) return;
      if (bytesScanned >= 10 * 1024 * 1024) {
        truncated = true;
        return;
      }
      try {
        const result = await this._readUtf8(absolute, Math.min(SEARCH_FILE_BYTES, 10 * 1024 * 1024 - bytesScanned));
        bytesScanned += result.visibleBytes;
        filesScanned += 1;
        if (result.truncated) truncated = true;
        const extension = path.extname(absolute).toLowerCase();
        const found = extractSymbols(result.text, extension);
        for (const symbol of found) {
          if (query && !symbol.name.toLowerCase().includes(query.toLowerCase())) continue;
          symbols.push({ path: displayPath(this._root, absolute), ...symbol });
          if (symbols.length >= maxResults) {
            truncated = true;
            return;
          }
        }
      } catch (error) {
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
        truncated: false,
        stopped: false,
      };
      for await (const item of this._walkFiles(start, {
        maxFiles: 2000,
        maxDirectories: 10_000,
        followSymlinkFiles: true,
        skipSensitive: true,
      }, state)) {
        await scanFile(item.absolute);
        if (symbols.length >= maxResults) break;
      }
      truncated = truncated || state.truncated;
    } else {
      throw new Error('Symbol search path must be a file or directory.');
    }

    return {
      ok: true,
      summary: `Found ${symbols.length} symbols in ${filesScanned} files`,
      data: { symbols, filesScanned, bytesScanned, truncated },
    };
  }

  async _projectMap(args) {
    const requestedPath = optionalString(args, 'path', { fallback: '.' });
    const depth = clampInteger(args.depth, 2, 1, 6);
    const maxEntries = clampInteger(args.maxEntries, 150, 1, MAX_RESULTS);
    const start = this.resolveWorkspacePath(requestedPath);
    if (isIgnoredLocation(this._root, start)) {
      throw new Error(`Ignored directory: ${displayPath(this._root, start)}`);
    }
    const startStats = await fsp.stat(start);
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
        if (entries.length >= maxEntries) {
          truncated = true;
          return;
        }

        const collected = [];
        let scanned = 0;
        const handle = await fsp.opendir(directory).catch((error) => {
          inaccessibleDirectories += 1;
          return null;
        });
        if (!handle) return;
        try {
          for await (const entry of handle) {
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
        collected.sort((left, right) => {
          const leftDirectory = left.isDirectory() ? 0 : 1;
          const rightDirectory = right.isDirectory() ? 0 : 1;
          return leftDirectory - rightDirectory || left.name.localeCompare(right.name);
        });

        for (const entry of collected) {
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
            } catch {
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
    const maxFiles = options.maxFiles ?? 5000;
    const maxDirectories = options.maxDirectories ?? 10_000;
    const followSymlinkFiles = options.followSymlinkFiles === true;
    const startStats = await fsp.stat(start);

    if (startStats.isFile()) {
      if (isSensitiveFile(start) && options.skipSensitive) return;
      state.fileCount += 1;
      yield { absolute: start, size: startStats.size, symlink: false };
      return;
    }
    if (!startStats.isDirectory()) return;

    const stack = [start];
    while (stack.length > 0 && !state.stopped) {
      const directory = stack.pop();
      if (state.directoryCount >= maxDirectories) {
        state.truncated = true;
        break;
      }
      state.directoryCount += 1;

      const handle = await fsp.opendir(directory).catch(() => null);
      if (!handle) continue;
      try {
        for await (const entry of handle) {
          if (state.stopped) break;
          state.scannedEntries += 1;
          if (state.scannedEntries > MAX_DIRECTORY_ENTRIES_SCANNED) {
            state.truncated = true;
            break;
          }

          const absolute = path.join(directory, entry.name);
          if (IGNORED_DIRECTORY_NAMES.has(entry.name.toLowerCase())) continue;
          if (entry.isDirectory()) {
            stack.push(absolute);
            continue;
          }
          if (entry.isSymbolicLink()) {
            if (!followSymlinkFiles) continue;
            const resolved = this.resolveWorkspacePath(absolute);
            const linkedStats = await fsp.stat(resolved);
            if (!linkedStats.isFile()) continue;
            if (options.skipSensitive && isSensitiveFile(resolved)) continue;
            if (state.fileCount >= maxFiles) {
              state.truncated = true;
              break;
            }
            state.fileCount += 1;
            yield { absolute, size: linkedStats.size, symlink: true };
          } else if (entry.isFile()) {
            if (options.skipSensitive && isSensitiveFile(absolute)) continue;
            if (state.fileCount >= maxFiles) {
              state.truncated = true;
              break;
            }
            state.fileCount += 1;
            let size;
            try {
              size = (await fsp.lstat(absolute)).size;
            } catch {
              size = undefined;
            }
            yield { absolute, size, symlink: false };
          }
        }
      } finally {
        await handle.close().catch(() => {});
      }
    }

    if (stack.length > 0) state.truncated = true;
  }
}

module.exports = WorkspaceTools;
module.exports.WorkspaceTools = WorkspaceTools;
module.exports.default = WorkspaceTools;
