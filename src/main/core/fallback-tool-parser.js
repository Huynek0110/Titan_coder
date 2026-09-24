'use strict';

const crypto = require('node:crypto');
const { isMcpTool, isMutatingTool } = require('./tool-broker');

const MAX_FALLBACK_CONTENT_CHARS = 40_000;
const MAX_FALLBACK_ARGUMENT_CHARS = 16_000;
const OPEN_CLOSE = [
  ['tool_call', 'tool_call'],
  ['call', 'call'],
  ['function_call', 'function_call'],
];

function withoutInvisible(value) {
  return String(value || '').replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Parse one exact JSON tool call.  This function intentionally does not coerce
 * arrays, `tool`, `function.name`, or string arguments into a call.  Qwen
 * wrappers are an interoperability escape hatch, so ambiguity is safer than
 * executing a guessed request.
 */
function parseCandidate(raw, options = {}) {
  const safeOptions = isObject(options) ? options : {};
  if (typeof raw !== 'string') return null;
  let text = raw.trim();
  if (!text || text.length > MAX_FALLBACK_CONTENT_CHARS) return null;
  if (text.startsWith('```')) {
    const fenced = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
    if (!fenced) return null;
    text = fenced[1].trim();
  }
  if (!text || text.length > MAX_FALLBACK_CONTENT_CHARS) return null;

  let parsed;
  try { parsed = JSON.parse(text); } catch { return null; }
  if (!isObject(parsed)) return null;
  const keys = Object.keys(parsed);
  if (keys.length !== 2 || !keys.includes('name') || !keys.includes('arguments')) return null;
  if (typeof parsed.name !== 'string' || !parsed.name.trim() || parsed.name.length > 256) return null;
  if (!isObject(parsed.arguments)) return null;
  const maxArgumentChars = Number.isInteger(safeOptions.maxArgumentChars)
    ? Math.max(1, Math.min(safeOptions.maxArgumentChars, MAX_FALLBACK_ARGUMENT_CHARS))
    : MAX_FALLBACK_ARGUMENT_CHARS;
  let serialized;
  try { serialized = JSON.stringify(parsed.arguments); } catch { return null; }
  if (typeof serialized !== 'string' || serialized.length > maxArgumentChars) return null;
  return { name: parsed.name.trim(), arguments: parsed.arguments };
}

function protocolMarkerPresent(text) {
  return /<\s*\/?\s*(?:tool_call|tool_response|function_call|function_results?|call)\s*>|\[\/?\s*(?:TOOL_REQUEST|TOOL_RESULT|END_TOOL_REQUEST|END_TOOL_RESULT)\s*\]/i.test(String(text || ''));
}

function jsonProtocolMarkerPresent(text) {
  const value = String(text || '').trim();
  return /[{[]/.test(value)
    && /["'](?:name|arguments|parameters|tool|tool_calls|function)["']\s*:/i.test(value);
}

function definitionsByName(definitions) {
  const map = new Map();
  for (const definition of definitions || []) {
    const name = definition?.function?.name;
    if (typeof name === 'string' && name && !map.has(name)) map.set(name, definition);
  }
  return map;
}

/**
 * Conservative fallback for LM Studio versions that fail to adapt a model's
 * native Qwen call tag into OpenAI tool_calls.  Only exact single-call wrappers
 * are accepted, and the name must exist in the definitions for this turn.
 *
 * The returned `fallback`/risk fields are provenance markers.  The AgentRunner
 * and ToolBroker still enforce the current allowlist and approval policy; this
 * parser never grants authority to execute a recovered call.
 */
function parseFallbackToolCall(content, definitions, options = {}) {
  const safeOptions = isObject(options) ? options : {};
  if (typeof content !== 'string') return null;
  const source = withoutInvisible(content);
  if (!source || source.length > MAX_FALLBACK_CONTENT_CHARS) return null;
  const byName = definitionsByName(definitions);
  if (!byName.size) return null;
  const candidates = [];

  const directFence = source.match(/^```(?:json)?\s*(\{[\s\S]*\})\s*```$/i);
  const directJson = directFence ? directFence[1] : (/^\{[\s\S]*\}$/.test(source.trim()) ? source.trim() : '');
  if (directJson) {
    const parsed = parseCandidate(directJson, safeOptions);
    if (parsed) candidates.push({ parsed, remaining: '' });
  }

  for (const [openName, closeName] of OPEN_CLOSE) {
    const open = new RegExp(`<${openName}\\s*>`, 'gi');
    const close = new RegExp(`</${closeName}\\s*>`, 'gi');
    const matches = [...source.matchAll(new RegExp(`<${openName}\\s*>([\\s\\S]*?)<\\/${closeName}\\s*>`, 'gi'))];
    const openCount = [...source.matchAll(open)].length;
    const closeCount = [...source.matchAll(close)].length;
    // An unmatched/mismatched wrapper is malformed, not an ordinary prose
    // message.  Do not extract a partial JSON object from it.
    if ((openCount || closeCount) && openCount !== closeCount) return null;
    if (matches.length === 1 && openCount === 1 && closeCount === 1) {
      const parsed = parseCandidate(matches[0][1], safeOptions);
      if (parsed) candidates.push({ parsed, remaining: source.replace(matches[0][0], '').trim() });
    }
  }

  const requestOpen = /\[TOOL_REQUEST\]([\s\S]*?)\[END_TOOL_REQUEST\]/gi;
  const requestMatches = [...source.matchAll(requestOpen)];
  const requestOpenCount = [...source.matchAll(/\[TOOL_REQUEST\]/gi)].length;
  const requestCloseCount = [...source.matchAll(/\[END_TOOL_REQUEST\]/gi)].length;
  if ((requestOpenCount || requestCloseCount) && requestOpenCount !== requestCloseCount) return null;
  if (requestMatches.length === 1 && requestOpenCount === 1 && requestCloseCount === 1) {
    const parsed = parseCandidate(requestMatches[0][1], safeOptions);
    if (parsed) candidates.push({ parsed, remaining: source.replace(requestMatches[0][0], '').trim() });
  }

  // A second wrapper, malformed tool response, or any unparsed protocol marker
  // is ambiguous.  In particular, never let a malformed wrapper's inner JSON
  // leak into a user-visible answer.
  if (protocolMarkerPresent(source.replace(directFence ? directFence[0] : '', ''))) {
    if (candidates.length !== 1) return null;
  }
  if (candidates.length !== 1) return null;
  const [{ parsed, remaining }] = candidates;
  if (!byName.has(parsed.name)) return null;
  if (protocolMarkerPresent(remaining) || jsonProtocolMarkerPresent(remaining)) return null;

  const definition = byName.get(parsed.name);
  const mcp = isMcpTool(parsed.name, definition);
  const mutating = isMutatingTool(parsed.name, definition);
  // Optional policy is useful to callers which want parsing itself to fail
  // closed.  The runner intentionally parses first so it can return a useful
  // tool-result explaining an approval-policy rejection.
  if (safeOptions.requireReadOnlyFallback === true && (mcp || mutating)) return null;
  if (safeOptions.approvalMode !== undefined
    && String(safeOptions.approvalMode).toLowerCase() !== 'ask'
    && (mcp || mutating)) return null;
  return {
    id: `fallback_${crypto.randomUUID()}`,
    type: 'function',
    function: { name: parsed.name, arguments: JSON.stringify(parsed.arguments) },
    content: remaining,
    fallback: true,
    provenance: 'fallback',
    readOnly: !mcp && !mutating,
    mutating,
    mcp,
  };
}

module.exports = {
  parseFallbackToolCall,
  parseCandidate,
  withoutInvisible,
  MAX_FALLBACK_CONTENT_CHARS,
  MAX_FALLBACK_ARGUMENT_CHARS,
};
