'use strict';

/**
 * Small, dependency-free web tools used by the main process.
 *
 * The URL checks in this file are deliberately performed before every request,
 * including every redirect.  DNS answers are checked immediately before a
 * request as well.  The normal, production transport is node:http/node:https
 * with a checked address supplied through `lookup`, so the address used for
 * the connection is the address that was checked.  A caller may explicitly
 * inject a fetch implementation (primarily for deterministic tests), but that
 * transport cannot provide the same portable address-pinning guarantee.
 * Neither transport ever evaluates HTML, JavaScript, or page content.
 */

const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const { TextDecoder } = require('node:util');

const APP_NAME = 'CoderLocally';
const APP_VERSION = '1.0.0';
const USER_AGENT = `${APP_NAME}/${APP_VERSION} (Electron coding-agent)`;
const DEFAULT_MAX_BYTES = 2_000_000;
const DEFAULT_MAX_CHARS = 100_000;
const DEFAULT_MAX_RESULTS = 10;
const MAX_RESULTS = 50;
const MAX_REDIRECTS = 4;
const DEFAULT_REQUEST_TIMEOUT = 20_000;

const STANDARD_PORTS = Object.freeze({
  'http:': 80,
  'https:': 443,
});

const BLOCKED_HOSTNAMES = new Set([
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

const SENSITIVE_KEY_RE = /(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|token|secret|password|passwd|credential|private[-_]?key|client[-_]?secret|(?:[A-Za-z0-9]+[-_])*api[-_]?key|(?:^|[-_])key(?:$|[-_])|(?<![A-Za-z])key(?![A-Za-z]))/i;
const SENSITIVE_QUERY_RE = /([?&](?:access[-_]?token|refresh[-_]?token|id[-_]?token|token|api[-_]?key|apikey|key|secret|password|passwd|auth|authorization|signature|sig)=)[^&#\s]*/gi;
const SENSITIVE_ASSIGNMENT_RE = /(?<![A-Za-z])((?:["']?)(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|token|secret|password|passwd|credential|private[-_]?key|client[-_]?secret|(?:[A-Za-z0-9]+[-_])*api[-_]?key|(?:^|[-_])key(?:$|[-_])|key)(?:["']?)\s*[:=]\s*)(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^\s,;\]}\[]+))/gi;

// These fields either describe a single hop or let a caller interfere with
// Node's framing/routing.  They are rejected rather than silently forwarded:
// forwarding them can enable request smuggling, connection reuse surprises,
// or a host-header override.
const UNSAFE_REQUEST_HEADERS = new Set([
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
const SENSITIVE_HEADER_RE = /(?:^|[-_])(?:authorization|authentication|proxy[-_]?authorization|cookie2?|set[-_]?cookie|apikey|api[-_]?key|access[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth(?:orization)?|bearer[-_]?token|client[-_]?secret|private[-_]?key|token|secret|password|passwd|credential|signature|sig|session|csrf|xsrf|key)(?:$|[-_])/i;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isSensitiveHeaderName(name) {
  const normalized = String(name || '').replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase().replace(/[_.]+/g, '-');
  return SENSITIVE_HEADER_RE.test(normalized);
}

function stripSensitiveHeaders(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    const text = String(value ?? '');
    if (!isSensitiveHeaderName(name) && redactString(text) === text) result[name] = value;
  }
  return result;
}

function clampInteger(value, fallback, minimum, maximum) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}

function getHeader(headers, name) {
  if (!headers) return undefined;
  const wanted = String(name).toLowerCase();
  if (typeof headers.get === 'function') {
    try {
      return headers.get(name) || undefined;
    } catch {
      return undefined;
    }
  }
  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === wanted) return Array.isArray(value) ? value.join(', ') : value;
  }
  return undefined;
}

function headersToObject(headers) {
  const result = Object.create(null);
  if (!headers) return result;
  if (typeof headers.forEach === 'function') {
    try {
      headers.forEach((value, key) => {
        result[String(key).toLowerCase()] = String(value);
      });
      return result;
    } catch {
      // Fall through to object-style headers.
    }
  }
  for (const [key, value] of Object.entries(headers)) {
    result[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return result;
}

function decodeEntities(value) {
  const named = {
    amp: '&',
    apos: "'",
    gt: '>',
    hellip: '…',
    ldquo: '“',
    lsquo: '‘',
    lt: '<',
    mdash: '—',
    nbsp: ' ',
    ndash: '–',
    quot: '"',
    rdquo: '”',
    rsquo: '’',
  };
  return String(value).replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]+);?/gi, (whole, entity) => {
    const lower = String(entity).toLowerCase();
    if (lower.startsWith('#x')) {
      const number = Number.parseInt(lower.slice(2), 16);
      return Number.isFinite(number) && number <= 0x10ffff ? String.fromCodePoint(number) : whole;
    }
    if (lower.startsWith('#')) {
      const number = Number.parseInt(lower.slice(1), 10);
      return Number.isFinite(number) && number <= 0x10ffff ? String.fromCodePoint(number) : whole;
    }
    return Object.prototype.hasOwnProperty.call(named, lower) ? named[lower] : whole;
  });
}

function redactString(value) {
  let text = String(value);
  // Header values can contain spaces and semicolons, so consume the complete
  // line for these names instead of only the first token.
  text = text.replace(/(\b(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key)\s*:\s*)[^\r\n]*/gi, '$1[REDACTED]');
  text = text.replace(SENSITIVE_ASSIGNMENT_RE, (whole, prefix, doubleQuoted, singleQuoted, bare) => {
    const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
    return `${prefix}${quote}[REDACTED]${quote}`;
  });
  text = text.replace(SENSITIVE_QUERY_RE, '$1[REDACTED]');
  text = text.replace(/(\bBearer\s+)[^\s,;]+/gi, '$1[REDACTED]');
  text = text.replace(/(\bBasic\s+)[^\s,;]+/gi, '$1[REDACTED]');
  text = text.replace(/(https?:\/\/)[^\/\s:@]+:[^\/@\s]+@/gi, '$1[REDACTED@');
  // Common bearer/token formats.  This intentionally does not treat every
  // long word as a secret, which would make ordinary search results unusable.
  text = text.replace(/\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/g, '[REDACTED]');
  text = text.replace(/\b(?:sk|pk|rk)-[a-zA-Z0-9_-]{12,}\b/g, '[REDACTED]');
  text = text.replace(/\b(?:gh[pousr]|github_pat)_[a-zA-Z0-9_]{12,}\b/g, '[REDACTED]');
  text = text.replace(/\bxox[baprs]-[a-zA-Z0-9-]{12,}\b/g, '[REDACTED]');
  return text;
}

/**
 * Recursively redact secrets from values that may be shown to a model, an
 * error message, or a log.  It intentionally returns a new value and handles
 * cycles rather than throwing while formatting an error.
 */
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

function ipv4ToNumber(address) {
  const parts = String(address).split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const number = Number(part);
    if (number > 255) return null;
    result = (result * 256) + number;
  }
  return result >>> 0;
}

function numberToIpv4(number) {
  return [24, 16, 8, 0].map((shift) => (number >>> shift) & 255).join('.');
}

function inIpv4Range(number, cidr, prefix) {
  const base = ipv4ToNumber(cidr);
  if (base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (number & mask) >>> 0 === (base & mask) >>> 0;
}

function parseIpv6(address) {
  let value = String(address).trim().toLowerCase();
  const zone = value.indexOf('%');
  if (zone >= 0) value = value.slice(0, zone);
  if (!net.isIP(value)) return null;

  // Convert a trailing dotted-quad into two hexadecimal groups.
  const embedded = value.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (embedded) {
    const ipv4 = ipv4ToNumber(embedded[1]);
    if (ipv4 === null) return null;
    const high = (ipv4 >>> 16).toString(16);
    const low = (ipv4 & 0xffff).toString(16);
    value = `${value.slice(0, embedded.index)}${high}:${low}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;
  let left = halves[0] ? halves[0].split(':') : [];
  let right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1) left = value.split(':');
  if (left.some((part) => !/^[0-9a-f]{1,4}$/.test(part)) || right.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if (halves.length === 2 && missing < 0) return null;
  const groups = halves.length === 2
    ? [...left, ...Array(Math.max(0, missing)).fill('0'), ...right]
    : left;
  if (groups.length !== 8) return null;
  return groups.reduce((result, group) => (result << 16n) + BigInt(`0x${group}`), 0n);
}

function ipv6InRange(bits, prefix, prefixLength) {
  if (prefixLength === 0) return true;
  const mask = ((1n << BigInt(prefixLength)) - 1n) << BigInt(128 - prefixLength);
  return (bits & mask) === (BigInt(prefix) << BigInt(128 - prefixLength));
}

function isPrivateIpv4(address) {
  const number = ipv4ToNumber(address);
  if (number === null) return true;
  // RFC1918 and RFC6598, loopback, link-local, documentation, benchmarking,
  // multicast, and reserved/unspecified space all fail closed.
  return inIpv4Range(number, '0.0.0.0', 8)
    || inIpv4Range(number, '10.0.0.0', 8)
    || inIpv4Range(number, '100.64.0.0', 10)
    || inIpv4Range(number, '127.0.0.0', 8)
    || inIpv4Range(number, '169.254.0.0', 16)
    || inIpv4Range(number, '172.16.0.0', 12)
    || number === ipv4ToNumber('168.63.129.16')
    || inIpv4Range(number, '192.0.0.0', 24)
    || inIpv4Range(number, '192.0.2.0', 24)
    || inIpv4Range(number, '192.31.196.0', 24)
    || inIpv4Range(number, '192.52.193.0', 24)
    || inIpv4Range(number, '192.88.99.0', 24)
    || inIpv4Range(number, '192.175.48.0', 24)
    || inIpv4Range(number, '192.168.0.0', 16)
    || inIpv4Range(number, '198.18.0.0', 15)
    || inIpv4Range(number, '198.51.100.0', 24)
    || inIpv4Range(number, '203.0.113.0', 24)
    || inIpv4Range(number, '224.0.0.0', 4)
    || inIpv4Range(number, '240.0.0.0', 4);
}

function isPrivateIpv6(address) {
  const bits = parseIpv6(address);
  if (bits === null) return true;

  // IPv4-mapped and IPv4-compatible IPv6 addresses inherit the IPv4 policy.
  const top96 = bits >> 32n;
  if (top96 === 0xffffn) return isPrivateIpv4(numberToIpv4(Number(bits & 0xffffffffn)));
  if (top96 === 0n) return true;

  const first16 = Number((bits >> 112n) & 0xffffn);
  const second16 = Number((bits >> 96n) & 0xffffn);

  return bits === 1n
    || (first16 & 0xfe00) === 0xfc00
    // fe00::/9 is reserved/transition space; fe80::/10 is link-local.
    || (first16 >= 0xfe00 && first16 <= 0xfeff)
    || (first16 & 0xff00) === 0xff00
    // IETF special-purpose, documentation, benchmarking, and transition
    // ranges are not safe web destinations.
    || (first16 === 0x2001 && (
      second16 === 0x0000 || second16 === 0x0001 || second16 === 0x0002 || second16 === 0xdb8
      || (second16 >= 0x0010 && second16 <= 0x001f)
      || (second16 >= 0x0020 && second16 <= 0x002f)
      || (second16 >= 0x0030 && second16 <= 0x003f)
    ))
    || first16 === 0x2002
    || (first16 === 0x0064 && second16 === 0xff9b)
    || first16 === 0x3fff;
}

/**
 * Returns true for addresses that must not be contacted by a web tool.
 * Invalid/non-IP input returns false here; URL validation rejects it before
 * DNS resolution.  The helper is exported so policy can be tested without
 * making a network request.
 */
function isPrivateAddress(address) {
  const raw = String(address || '').trim().replace(/^\[|\]$/g, '');
  const value = raw.split('%', 1)[0];
  const kind = net.isIP(value);
  if (kind === 4) return isPrivateIpv4(value);
  if (kind === 6) return isPrivateIpv6(value);
  // net.isIP intentionally rejects some legacy IPv4 spellings.  Treat a
  // dotted decimal value as IPv4 here so the policy remains fail-closed.
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return isPrivateIpv4(value);
  return false;
}

function isBlockedAddress(address) {
  const kind = net.isIP(String(address || '').trim());
  return kind === 0 || isPrivateAddress(address);
}

function htmlToText(input) {
  let text = input === null || input === undefined ? '' : String(input);
  text = text.replace(/<!--[\s\S]*?-->/g, ' ');
  text = text.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ');
  text = text.replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ');
  text = text.replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript\s*>/gi, ' ');
  text = text.replace(/<template\b[^>]*>[\s\S]*?<\/template\s*>/gi, ' ');
  text = text.replace(/<svg\b[^>]*>[\s\S]*?<\/svg\s*>/gi, ' ');
  text = text.replace(/<(?:br|hr)\s*\/?\s*>/gi, '\n');
  text = text.replace(/<li\b[^>]*>/gi, '\n- ');
  text = text.replace(/<\/(?:address|article|aside|blockquote|div|dl|dt|dd|footer|form|h[1-6]|header|hr|li|main|nav|ol|p|pre|section|table|tr|ul)\s*>/gi, '\n');
  text = text.replace(/<[^>]*>/g, ' ');
  text = decodeEntities(text).replace(/\r\n?/g, '\n');
  text = text.replace(/[\t\f\v ]+/g, ' ');
  text = text.replace(/ *\n */g, '\n');
  text = text.replace(/\n{3,}/g, '\n\n');
  return text.trim();
}

function getHtmlAttribute(tag, name) {
  const wanted = String(name).toLowerCase();
  const expression = new RegExp(`\\b${wanted}\\s*=\\s*(?:(["'])([\\s\\S]*?)\\1|([^\\s"'=<>` + '`' + `]+))`, 'i');
  const match = String(tag).match(expression);
  return match ? (match[2] ?? match[3] ?? '') : '';
}

function unwrapDuckDuckGoUrl(href) {
  if (!href) return null;
  let value = decodeEntities(String(href).trim());
  try {
    let url = new URL(value.startsWith('//') ? `https:${value}` : value, 'https://html.duckduckgo.com');
    if (/(?:^|\.)duckduckgo\.com$/i.test(url.hostname) && (url.pathname === '/l/' || url.pathname === '/link/')) {
      const wrapped = url.searchParams.get('uddg') || url.searchParams.get('u');
      if (wrapped) {
        let unwrapped = wrapped;
        // A few lite pages wrap the URL once more.
        try { unwrapped = decodeURIComponent(unwrapped); } catch { /* retain decoded value */ }
        try {
          const nested = new URL(unwrapped);
          if (nested.protocol === 'http:' || nested.protocol === 'https:') return nested.toString();
        } catch {
          const repaired = unwrapped.startsWith('//') ? `https:${unwrapped}` : unwrapped;
          const nested = new URL(repaired, 'https://html.duckduckgo.com');
          if (nested.protocol === 'http:' || nested.protocol === 'https:') return nested.toString();
        }
      }
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.toString();
  } catch {
    return null;
  }
}

function parseDuckDuckGoHtml(input, maxResults = DEFAULT_MAX_RESULTS) {
  const html = input === null || input === undefined ? '' : String(input);
  const limit = clampInteger(maxResults, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS);
  const results = [];
  const seen = new Set();
  const anchorPattern = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  let match;
  while ((match = anchorPattern.exec(html)) !== null) {
    const attributes = match[1];
    const className = getHtmlAttribute(attributes, 'class');
    if (!/(?:^|\s)(?:result__a|result-link|result-link)(?:\s|$)/i.test(className)) continue;
    const href = getHtmlAttribute(attributes, 'href');
    const url = unwrapDuckDuckGoUrl(href);
    if (!url || seen.has(url)) continue;
    const title = htmlToText(match[2]);
    if (!title) continue;

    // The snippet is normally in the next result sibling.  Bounded lookahead
    // keeps a malformed page from causing an unbounded scan.
    const following = html.slice(anchorPattern.lastIndex, Math.min(html.length, anchorPattern.lastIndex + 6000));
    const nextTitle = following.match(/<a\b[^>]*\bclass\s*=\s*(?:(["'])[^"']*\b(?:result__a|result-link)\b[^"']*\1|[^"']*\b(?:result__a|result-link)\b[^"']*)[^>]*>/i);
    const snippetSource = nextTitle ? following.slice(0, nextTitle.index) : following;
    const snippetMatch = snippetSource.match(/<[^>]+\bclass\s*=\s*(?:(["'])[^"']*\bresult__snippet\b[^"']*\1|[^"']*\bresult__snippet\b[^"']*)[^>]*>([\s\S]*?)<\/(?:a|div|span|p|td|th|li)>/i)
      || snippetSource.match(/<[^>]+\bclass\s*=\s*(?:(["'])[^"']*\bresult-snippet\b[^"']*\1|[^"']*\bresult-snippet\b[^"']*)[^>]*>([\s\S]*?)<\/(?:a|div|span|p|td|th|li)>/i);
    const snippet = snippetMatch ? htmlToText(snippetMatch[2]) : '';
    seen.add(url);
    results.push({ title, url, snippet });
    if (results.length >= limit) break;
  }
  return results;
}

function validateUrl(rawUrl, options = {}) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 8192) {
    throw new Error('URL must be a non-empty string');
  }
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('Only http and https URLs are allowed');
  if (url.username || url.password) throw new Error('URLs with credentials are not allowed');
  if (!url.hostname) throw new Error('URL hostname is required');
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!hostname || BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost') || hostname.endsWith('.localhost.localdomain')) {
    throw new Error('Localhost and metadata hostnames are not allowed');
  }
  if (net.isIP(hostname) && isPrivateAddress(hostname)) throw new Error('Private or reserved IP addresses are not allowed');
  if (url.port) {
    const port = Number(url.port);
    const standard = STANDARD_PORTS[url.protocol];
    const explicitlyAllowed = (Array.isArray(options.allowedPorts) ? options.allowedPorts : []).map(Number).includes(port);
    if (port !== standard && !explicitlyAllowed) throw new Error('Non-standard ports are not allowed');
  }
  return url;
}

function normalizeContentType(value) {
  return String(value || '').split(';', 1)[0].trim().toLowerCase();
}

function contentKind(contentType) {
  const mime = normalizeContentType(contentType);
  if (!mime) return 'text';
  if (mime === 'text/html' || mime === 'application/xhtml+xml') return 'html';
  if (mime === 'application/json' || mime.endsWith('+json')) return 'json';
  if (mime === 'application/xml' || mime === 'text/xml' || mime.endsWith('+xml')) return 'xml';
  if (mime === 'text/csv' || mime === 'application/csv') return 'csv';
  if (mime.startsWith('text/')) return 'text';
  if ([
    'application/javascript', 'application/x-javascript', 'application/ecmascript',
    'application/x-sh', 'application/x-shellscript', 'application/sql', 'application/graphql',
    'application/yaml', 'application/x-yaml', 'application/toml',
  ].includes(mime)) return 'code';
  return null;
}

function decodeBody(buffer, contentType) {
  const charsetMatch = String(contentType || '').match(/charset\s*=\s*["']?([^;\s"']+)/i);
  const charset = charsetMatch ? charsetMatch[1] : 'utf-8';
  try {
    return new TextDecoder(charset).decode(buffer);
  } catch {
    return new TextDecoder('utf-8').decode(buffer);
  }
}

function isRedirectStatus(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

class WebTools {
  constructor(options = {}) {
    const opts = isObject(options) ? options : {};
    this.searchProvider = String(opts.searchProvider || 'duckduckgo').toLowerCase();
    this.braveApiKey = typeof opts.braveApiKey === 'string' ? opts.braveApiKey.trim() : '';
    this.maxBytes = clampInteger(opts.maxBytes, DEFAULT_MAX_BYTES, 1, 50_000_000);
    this.requestTimeout = clampInteger(opts.requestTimeout, DEFAULT_REQUEST_TIMEOUT, 100, 300_000);
    this.allowedPorts = Array.isArray(opts.allowedPorts)
      ? [...new Set(opts.allowedPorts.map(Number).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535))]
      : [];
    this.lookup = opts.lookup || opts.dnsLookup || opts.resolve || dns.promises.lookup.bind(dns.promises);
    const suppliedFetch = opts.fetchImpl || opts.fetch;
    this.fetchImpl = suppliedFetch || null;
    // Native http/https is the safe production default.  An explicitly
    // supplied fetch implementation remains a supported, deterministic
    // injection point for callers and tests; callers can still force either
    // transport with nativeTransport.
    this.nativeTransport = opts.nativeTransport === undefined
      ? !suppliedFetch
      : opts.nativeTransport === true;
    this.userAgent = USER_AGENT;
  }

  definitions() {
    return [
      {
        type: 'function',
        function: {
          name: 'web_search',
          description: 'Search the web and return titles, URLs, and short snippets. Search result pages are not executed.',
          parameters: {
            type: 'object',
            properties: {
              query: { type: 'string', description: 'Search query.' },
              maxResults: { type: 'integer', minimum: 1, maximum: MAX_RESULTS, description: 'Maximum number of results.' },
              freshness: { type: 'string', description: 'Optional freshness filter, such as pd, pw, pm, py, or YYYY-MM-DD..YYYY-MM-DD.' },
            },
            required: ['query'],
            additionalProperties: false,
          },
        },
      },
      {
        type: 'function',
        function: {
          name: 'web_fetch',
          description: 'Fetch one HTTP or HTTPS resource and return bounded, readable text. HTML is extracted without executing it.',
          parameters: {
            type: 'object',
            properties: {
              url: { type: 'string', description: 'Absolute http or https URL.' },
              maxChars: { type: 'integer', minimum: 0, description: 'Maximum returned characters.' },
              format: { type: 'string', enum: ['text', 'html', 'json', 'csv', 'xml', 'code', 'raw', 'markdown'], description: 'Output format.' },
            },
            required: ['url'],
            additionalProperties: false,
          },
        },
      },
      {
        type: 'function',
        function: {
          name: 'http_request',
          description: 'Make a bounded HTTP request. Only GET, POST, PUT, PATCH, DELETE, and HEAD are allowed.',
          parameters: {
            type: 'object',
            properties: {
              url: { type: 'string', description: 'Absolute http or https URL.' },
              method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] },
              headers: { type: 'object', additionalProperties: { type: 'string' }, description: 'Request headers.' },
              body: { type: 'string', description: 'Optional request body, bounded by the configured byte limit.' },
              maxChars: { type: 'integer', minimum: 0, description: 'Maximum returned characters.' },
            },
            required: ['url'],
            additionalProperties: false,
          },
        },
      },
    ];
  }

  async execute(name, args, context = {}) {
    const safeContext = isObject(context) ? context : {};
    try {
      if (safeContext.signal && safeContext.signal.aborted) return this._failure('Request cancelled', 'Request cancelled');
      const input = isObject(args) ? args : {};
      switch (name) {
        case 'web_search':
          return await this._webSearch(input, safeContext);
        case 'web_fetch':
          return await this._webFetch(input, safeContext);
        case 'http_request':
          return await this._httpRequest(input, safeContext);
        default:
          return this._failure('Unknown web tool', `Unknown web tool: ${redactString(String(name || '').slice(0, 200))}`);
      }
    } catch (error) {
      return this._failure('Web tool request failed', this._safeError(error));
    }
  }

  _failure(summary, error) {
    const safeSummary = this._scrubKnownSecret(redactString(String(summary || 'Web tool request failed'))).slice(0, 500);
    return { ok: false, summary: safeSummary, data: null, error: this._scrubKnownSecret(redactString(String(error || 'Request failed'))).slice(0, 2_000) };
  }

  _scrubKnownSecret(value) {
    let text = String(value ?? '');
    if (this.braveApiKey) text = text.split(this.braveApiKey).join('[REDACTED]');
    return text;
  }

  _safeError(error) {
    if (error && (error.name === 'AbortError' || error.code === 'ABORT_ERR')) return 'Request cancelled';
    if (error && error.code === 'ETIMEDOUT') return 'Request timed out';
    const message = error && error.message ? error.message : String(error || 'Request failed');
    return this._scrubKnownSecret(redactString(message)).replace(/[\r\n]+/g, ' ').slice(0, 2_000);
  }

  _validateString(value, field, maximum, { allowEmpty = false } = {}) {
    if (typeof value !== 'string' || (!allowEmpty && value.trim().length === 0) || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new Error(`${field} is invalid`);
    }
    return value;
  }

  _maxChars(value) {
    if (value === undefined || value === null) return Math.min(DEFAULT_MAX_CHARS, this.maxBytes);
    const number = Number(value);
    if (!Number.isInteger(number) || number < 0) throw new Error('maxChars is invalid');
    return Math.min(number, this.maxBytes);
  }

  _headers(input = {}) {
    if (!isObject(input)) throw new Error('headers must be an object');
    const result = {};
    const names = new Set();
    let count = 0;
    for (const [name, value] of Object.entries(input)) {
      const normalizedName = String(name).toLowerCase();
      if (++count > 100 || name.length > 256 || ['__proto__', 'prototype', 'constructor'].includes(name) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n]/.test(name)) throw new Error('headers contain an invalid name');
      if (UNSAFE_REQUEST_HEADERS.has(normalizedName)) throw new Error(`header ${name} is not allowed`);
      if (names.has(normalizedName)) throw new Error('headers contain a duplicate name');
      names.add(normalizedName);
      if (typeof value !== 'string' || value.length > 16_384 || /[\r\n]/.test(value)) throw new Error('headers contain an invalid value');
      result[name] = value;
    }
    if (!names.has('user-agent')) result['User-Agent'] = this.userAgent;
    return result;
  }

  async _lookupAll(hostname, context = {}) {
    const host = String(hostname).replace(/^\[|\]$/g, '');
    const direct = net.isIP(host);
    if (direct) return [{ address: host, family: direct }];

    const lookup = this.lookup;
    if (typeof lookup !== 'function') throw new Error('DNS resolver is unavailable');
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
    const result = await new Promise((resolve, reject) => {
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
      timer = setTimeout(() => finish(new Error('DNS lookup timed out')), this.requestTimeout);
      lookupPromise.then((value) => finish(null, value), (error) => finish(error));
    });

    const addresses = Array.isArray(result)
      ? result
      : result && typeof result === 'object' && result.address
        ? [result]
        : [];
    const normalized = addresses
      .map((item) => typeof item === 'string' ? { address: item, family: net.isIP(item) } : item)
      .filter((item) => item && typeof item.address === 'string' && net.isIP(item.address));
    if (!normalized.length) throw new Error('DNS returned no usable address');
    return normalized;
  }

  async _safeAddresses(url, context = {}) {
    const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
    if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost') || hostname.endsWith('.localhost.localdomain')) {
      throw new Error('Localhost and metadata hostnames are not allowed');
    }
    const addresses = await this._lookupAll(hostname, context);
    if (addresses.some((item) => isBlockedAddress(item.address))) throw new Error('URL resolves to a private or reserved address');
    return addresses;
  }

  async _requestWithRedirects(rawUrl, options = {}, context = {}) {
    const contextPorts = context.allowedPorts instanceof Set ? [...context.allowedPorts] : (Array.isArray(context.allowedPorts) ? context.allowedPorts : []);
    const allowedPorts = [...this.allowedPorts, ...contextPorts];
    let current = validateUrl(rawUrl, { allowedPorts });
    let method = String(options.method || 'GET').toUpperCase();
    let headers = options.headers || {};
    let body = options.body;
    let redirects = 0;

    while (true) {
      const addresses = await this._safeAddresses(current, context);
      const fetchImpl = !this.nativeTransport
        ? (this.fetchImpl || (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null))
        : null;
      let response;
      response = fetchImpl
        ? await this._sendFetch(current, { method, headers, body }, context, fetchImpl)
        : await this._sendNative(current, { method, headers, body, addresses }, context);

      if (isRedirectStatus(response.status)) {
        const location = getHeader(response.headers, 'location');
        if (location) {
          if (redirects >= MAX_REDIRECTS) throw new Error('Too many redirects');
          let next;
          try {
            next = new URL(String(location), current);
          } catch {
            throw new Error('Redirect URL is invalid');
          }
          const previousOrigin = current.origin;
          current = validateUrl(next.toString(), { allowedPorts });
          redirects += 1;
          if (current.origin !== previousOrigin) headers = stripSensitiveHeaders(headers);
          if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
            method = 'GET';
            body = undefined;
            headers = Object.fromEntries(Object.entries(headers).filter(([name]) => !['content-type', 'content-length'].includes(name.toLowerCase())));
          }
          continue;
        }
      }
      return { ...response, finalUrl: current.toString(), addresses };
    }
  }

  async _sendFetch(url, options, context, fetchImpl = this.fetchImpl) {
    const controller = new AbortController();
    let timedOut = false;
    let timer;
    const externalSignal = context && context.signal;
    const abort = () => controller.abort();
    if (externalSignal) {
      if (externalSignal.aborted) controller.abort();
      else externalSignal.addEventListener('abort', abort, { once: true });
    }
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.requestTimeout);
    try {
      const response = await fetchImpl(url.toString(), {
        method: options.method,
        headers: this._headers(options.headers),
        body: options.method === 'GET' || options.method === 'HEAD' ? undefined : options.body,
        redirect: 'manual',
        signal: controller.signal,
      });
      if (response && response.redirected) throw new Error('Redirects must be handled explicitly');
      if (response && response.url) {
        let responseUrl;
        try { responseUrl = new URL(response.url, url); } catch { throw new Error('Response URL is invalid'); }
        if (responseUrl.origin !== url.origin) throw new Error('Cross-origin redirects are not allowed');
      }
      const bodyPromise = this._readFetchBody(response, this.maxBytes, options.method);
      const body = await new Promise((resolve, reject) => {
        let settled = false;
        const onBodyAbort = () => finish(new Error('Request cancelled'));
        const finish = (error, value) => {
          if (settled) return;
          settled = true;
          try { controller.signal.removeEventListener('abort', onBodyAbort); } catch { /* native AbortSignal */ }
          if (error) reject(error);
          else resolve(value);
        };
        controller.signal.addEventListener('abort', onBodyAbort, { once: true });
        if (controller.signal.aborted) finish(new Error('Request cancelled'));
        bodyPromise.then((value) => finish(null, value), (error) => finish(error));
      });
      return {
        status: Number(response.status) || 0,
        headers: headersToObject(response.headers),
        body: body.buffer,
        truncated: body.truncated,
      };
    } catch (error) {
      if (timedOut) throw new Error('Request timed out');
      if (controller.signal.aborted || (externalSignal && externalSignal.aborted)) throw new Error('Request cancelled');
      throw error;
    } finally {
      clearTimeout(timer);
      if (externalSignal) externalSignal.removeEventListener('abort', abort);
    }
  }

  async _readFetchBody(response, limit, method = '') {
    if (response && (response.status === 204 || response.status === 304 || String(method || response.method || '').toUpperCase() === 'HEAD')) {
      return { buffer: Buffer.alloc(0), truncated: false };
    }
    const body = response && response.body;
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
              chunks.push(chunk.subarray(0, room));
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
        try { reader.releaseLock(); } catch { /* already released by cancel */ }
      }
      return { buffer: Buffer.concat(chunks, Math.min(total, limit)), truncated };
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
            chunks.push(chunk.subarray(0, room));
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
      return { buffer: Buffer.concat(chunks, Math.min(total, limit)), truncated };
    }
    let value;
    if (response && typeof response.arrayBuffer === 'function') value = await response.arrayBuffer();
    else if (response && typeof response.text === 'function') value = await response.text();
    else if (response && typeof response.json === 'function') value = JSON.stringify(await response.json());
    else value = response && response.body;
    const buffer = Buffer.isBuffer(value) ? value : value === undefined || value === null ? Buffer.alloc(0) : Buffer.from(String(value));
    if (buffer.length <= limit) return { buffer, truncated: false };
    return { buffer: buffer.subarray(0, limit), truncated: true };
  }

  _sendNative(url, options, context) {
    return new Promise((resolve, reject) => {
      const transport = url.protocol === 'https:' ? https : http;
      const hostname = url.hostname.replace(/^\[|\]$/g, '');
      const addresses = Array.isArray(options.addresses) && options.addresses.length ? options.addresses : [{ address: hostname, family: net.isIP(hostname) }];
      if (!addresses.length || addresses.some((item) => !item || isBlockedAddress(item.address))) throw new Error('URL resolves to a private or reserved address');
      const headers = this._headers(options.headers);
      const externalSignal = context && context.signal;
      let settled = false;
      let timer;
      let request;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (externalSignal) externalSignal.removeEventListener('abort', abort);
        if (error) reject(error);
        else resolve(value);
      };
      const abort = () => {
        if (request) request.destroy(new Error('Request cancelled'));
        else finish(new Error('Request cancelled'));
      };
      if (externalSignal) {
        if (externalSignal.aborted) {
          finish(new Error('Request cancelled'));
          return;
        }
        externalSignal.addEventListener('abort', abort, { once: true });
      }
      const requestOptions = {
        protocol: url.protocol,
        hostname,
        port: url.port || undefined,
        path: `${url.pathname || '/'}${url.search || ''}`,
        method: options.method,
        headers,
        agent: false,
        lookup: (requestedHost, lookupOptions, callback) => {
          const wantedFamily = typeof lookupOptions === 'object' && lookupOptions.family ? Number(lookupOptions.family) : 0;
          const eligible = addresses.filter((item) => !wantedFamily || Number(item.family) === wantedFamily);
          const selected = eligible[0] || addresses[0];
          if (isObject(lookupOptions) && lookupOptions.all) {
            callback(null, (eligible.length ? eligible : addresses).map((item) => ({ address: item.address, family: Number(item.family) || 4 })));
            return;
          }
          callback(null, selected.address, Number(selected.family) || 4);
        },
      };
      if (url.protocol === 'https:' && !net.isIP(hostname)) requestOptions.servername = hostname;
      try {
        request = transport.request(requestOptions, (response) => {
          const chunks = [];
          let total = 0;
          let truncated = false;
          response.on('data', (part) => {
            const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
            if (total < this.maxBytes) {
              const room = this.maxBytes - total;
              if (chunk.length > room) {
                if (room > 0) chunks.push(chunk.subarray(0, room));
                total = this.maxBytes;
                truncated = true;
                finish(null, {
                  status: Number(response.statusCode) || 0,
                  headers: headersToObject(response.headers),
                  body: Buffer.concat(chunks),
                  truncated,
                });
                response.destroy();
                request.destroy();
              } else {
                chunks.push(chunk);
                total += chunk.length;
              }
            } else {
              truncated = true;
            }
          });
          response.on('end', () => {
            finish(null, {
              status: Number(response.statusCode) || 0,
              headers: headersToObject(response.headers),
              body: Buffer.concat(chunks),
              truncated,
            });
          });
          response.on('aborted', () => finish(new Error('Response was aborted')));
          response.on('error', (error) => finish(error));
        });
        const timeoutRequest = () => {
          const error = new Error('Request timed out');
          error.code = 'ETIMEDOUT';
          try { if (request) request.destroy(error); } catch { /* best effort timeout */ }
          finish(error);
        };
        timer = setTimeout(timeoutRequest, this.requestTimeout);
        request.setTimeout(this.requestTimeout, timeoutRequest);
        request.on('error', (error) => finish(error));
        if (options.body !== undefined && options.method !== 'GET' && options.method !== 'HEAD') request.write(options.body);
        request.end();
      } catch (error) {
        finish(error);
      }
    });
  }

  _formatResponse(response, maxChars, format) {
    const contentType = getHeader(response.headers, 'content-type') || '';
    const kind = contentKind(contentType);
    const bodyText = decodeBody(response.body || Buffer.alloc(0), contentType);
    if (kind === null && bodyText.length > 0) throw new Error(`Unsupported content type: ${normalizeContentType(contentType).slice(0, 100)}`);
    let text;
    if (format === 'raw') {
      text = bodyText;
    } else if (format === 'json' || kind === 'json') {
      try {
        text = `${JSON.stringify(JSON.parse(bodyText), null, 2)}\n`;
      } catch {
        text = bodyText;
      }
    } else if (kind === 'html' || format === 'html' || format === 'text' || format === 'markdown') {
      text = htmlToText(bodyText);
    } else {
      text = bodyText;
    }
    let truncated = Boolean(response.truncated);
    if (text.length > maxChars) {
      text = text.slice(0, maxChars);
      truncated = true;
    }
    return {
      text,
      contentType: contentType.slice(0, 300),
      truncated,
    };
  }

  _responseData(response, formatted, maxChars = this._maxChars()) {
    const finalUrl = this._scrubKnownSecret(redactString(String(response.finalUrl || ''))).slice(0, 8192);
    let text = this._scrubKnownSecret(redactString(String(formatted.text || '')));
    let truncated = Boolean(formatted.truncated);
    if (text.length > maxChars) {
      text = text.slice(0, maxChars);
      truncated = true;
    }
    return {
      url: finalUrl,
      finalUrl,
      contentType: redactString(String(formatted.contentType || '')).slice(0, 300),
      status: Number(response.status) || 0,
      truncated,
      text,
    };
  }

  _resultForResponse(response, maxChars, format, summaryPrefix) {
    const formatted = this._formatResponse(response, maxChars, format);
    const data = this._responseData(response, formatted, maxChars);
    const status = data.status;
    return {
      ok: true,
      summary: `${summaryPrefix} (${status}, ${data.truncated ? 'truncated' : 'complete'})`,
      data,
    };
  }

  async _webFetch(args, context) {
    const url = this._validateString(args.url, 'url', 8192);
    const maxChars = this._maxChars(args.maxChars);
    const format = args.format === undefined ? undefined : this._validateString(args.format, 'format', 20);
    if (format && !['text', 'html', 'json', 'csv', 'xml', 'code', 'raw', 'markdown'].includes(format)) throw new Error('format is invalid');
    const response = await this._requestWithRedirects(url, { method: 'GET' }, context);
    return this._resultForResponse(response, maxChars, format, 'Fetched web resource');
  }

  async _httpRequest(args, context) {
    const url = this._validateString(args.url, 'url', 8192);
    const method = String(args.method || 'GET').toUpperCase();
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method)) throw new Error('method is not allowed');
    const headers = this._headers(args.headers || {});
    const body = args.body === undefined ? undefined : this._validateString(args.body, 'body', this.maxBytes, { allowEmpty: true });
    if (body !== undefined && Buffer.byteLength(body, 'utf8') > this.maxBytes) throw new Error('request body is too large');
    if (body !== undefined && (method === 'GET' || method === 'HEAD')) throw new Error(`A ${method} request cannot have a body`);
    const maxChars = this._maxChars(args.maxChars);
    const response = await this._requestWithRedirects(url, { method, headers, body }, context);
    return this._resultForResponse(response, maxChars, undefined, `Completed ${method} request`);
  }

  async _webSearch(args, context) {
    const query = this._validateString(args.query, 'query', 512);
    const maxResults = clampInteger(args.maxResults, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS);
    const freshness = args.freshness === undefined ? undefined : this._validateString(args.freshness, 'freshness', 64);
    const useBrave = Boolean(this.braveApiKey);
    if (useBrave) return this._braveSearch(query, maxResults, freshness, context);
    return this._duckDuckGoSearch(query, maxResults, freshness, context);
  }

  async _braveSearch(query, maxResults, freshness, context) {
    const endpoint = new URL('https://api.search.brave.com/res/v1/web/search');
    endpoint.searchParams.set('q', query);
    endpoint.searchParams.set('count', String(maxResults));
    if (freshness) endpoint.searchParams.set('freshness', freshness);
    const response = await this._requestWithRedirects(endpoint.toString(), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-Subscription-Token': this.braveApiKey,
      },
    }, context);
    let parsed;
    try {
      parsed = JSON.parse(decodeBody(response.body, getHeader(response.headers, 'content-type')));
    } catch {
      return this._failure('Web search failed', 'Search provider returned invalid JSON');
    }
    const source = parsed && parsed.web && Array.isArray(parsed.web.results) ? parsed.web.results : [];
    const results = source.slice(0, maxResults).map((item) => ({
      title: this._searchText(item && item.title, 500),
      url: this._searchText(item && item.url, 2048),
      snippet: this._searchText(item && (item.description ?? item.snippet), 2000),
    })).filter((item) => item.url);
    return { ok: true, summary: `Found ${results.length} web result${results.length === 1 ? '' : 's'}`, data: { provider: 'brave', query: this._scrubKnownSecret(redactString(query)), results } };
  }

  async _duckDuckGoSearch(query, maxResults, freshness, context) {
    const endpoint = new URL('https://html.duckduckgo.com/html/');
    endpoint.searchParams.set('q', query);
    if (freshness) endpoint.searchParams.set('df', freshness);
    const response = await this._requestWithRedirects(endpoint.toString(), { method: 'GET', headers: { Accept: 'text/html' } }, context);
    const html = decodeBody(response.body, getHeader(response.headers, 'content-type'));
    const parsed = parseDuckDuckGoHtml(html, maxResults);
    const results = parsed.map((item) => ({
      title: this._searchText(item.title, 500),
      url: this._searchText(item.url, 2048),
      snippet: this._searchText(item.snippet, 2000),
    }));
    return { ok: true, summary: `Found ${results.length} web result${results.length === 1 ? '' : 's'}`, data: { provider: 'duckduckgo', query: this._scrubKnownSecret(redactString(query)), results } };
  }

  _searchText(value, maximum) {
    if (value === null || value === undefined) return '';
    return this._scrubKnownSecret(redactString(htmlToText(String(value)))).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, maximum).trim();
  }
}

module.exports = {
  WebTools,
  APP_NAME,
  APP_VERSION,
  USER_AGENT,
  DEFAULT_MAX_BYTES,
  MAX_REDIRECTS,
  SECURITY_LIMITS: 'URLs and DNS answers are revalidated before every request and redirect. Native address-pinned transport is the default; an explicitly injected fetch transport is supported for deterministic callers but cannot provide the same DNS-pinning guarantee.',
  htmlToText,
  isPrivateAddress,
  isPrivateIP: isPrivateAddress,
  isBlockedAddress,
  parseDuckDuckGoHtml,
  redact,
  redactSecrets: redact,
  redactString,
  validateUrl,
};
