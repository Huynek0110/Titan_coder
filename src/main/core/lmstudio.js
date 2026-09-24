'use strict';

const { execFile, spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const STATUS_TIMEOUT_MS = 2_500;
const MAX_SSE_BUFFER_CHARS = 2 * 1024 * 1024;
const MAX_SSE_EVENT_CHARS = 1024 * 1024;

function cleanBaseUrl(value) {
  let raw = String(value || 'http://127.0.0.1:1234/v1').trim().replace(/[\\/]+$/, '');
  raw = raw.replace(/\/chat\/completions$/i, '').replace(/\/responses$/i, '');
  if (!/^https?:\/\//i.test(raw)) raw = `http://${raw}`;
  const url = new URL(raw);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('LM Studio URL phải dùng http hoặc https.');
  if (!url.pathname.endsWith('/v1')) url.pathname = `${url.pathname.replace(/\/+$/, '')}/v1`;
  return url.toString().replace(/\/$/, '');
}

function nativeBaseUrl(openAiBase) {
  const url = new URL(cleanBaseUrl(openAiBase));
  url.pathname = url.pathname.replace(/\/v1$/i, '') + '/api/v1';
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function authHeaders(apiKey) {
  const key = String(apiKey || '').trim();
  return key ? { Authorization: `Bearer ${key}` } : {};
}

function isLoopbackHost(hostname) {
  const value = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  return value === 'localhost' || value === '127.0.0.1' || value === '::1' || value === '0:0:0:0:0:0:0:1';
}

function errorMessage(error) {
  if (!error) return 'Unknown LM Studio error';
  if (error.name === 'TimeoutError' || error.code === 'ABORT_ERR') return 'Yêu cầu LM Studio đã hết thời gian.';
  return error.message || String(error);
}

function abortError() {
  const error = new Error('Yêu cầu LM Studio đã bị hủy.');
  error.name = 'AbortError';
  return error;
}

function parseSseBlock(block) {
  const data = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith('data:')) data.push(line.slice(5).trimStart());
  }
  if (!data.length) return null;
  const payload = data.join('\n');
  if (payload === '[DONE]') return { done: true };
  try {
    return JSON.parse(payload);
  } catch {
    return { malformed: true, raw: payload };
  }
}

function mergeToolCallFragments(map, fragments) {
  for (const fragment of fragments || []) {
    const index = Number.isInteger(fragment?.index) ? fragment.index : map.size;
    if (!map.has(index)) {
      map.set(index, { id: '', type: 'function', function: { name: '', arguments: '' } });
    }
    const target = map.get(index);
    if (fragment.id) target.id += fragment.id;
    if (fragment.type) target.type = fragment.type;
    if (fragment.function?.name) target.function.name += fragment.function.name;
    if (fragment.function?.arguments) target.function.arguments += fragment.function.arguments;
  }
}

class LMStudioClient {
  constructor({ getSettings = async () => ({}), fetchImpl = globalThis.fetch } = {}) {
    this.getSettings = getSettings;
    this.fetchImpl = fetchImpl;
  }

  async settings() {
    const settings = await this.getSettings();
    const normalized = {
      baseUrl: cleanBaseUrl(settings.lmBaseUrl),
      apiKey: settings.lmApiKey || '',
      model: String(settings.model || '').trim(),
      temperature: Number(settings.temperature ?? 0.2),
      topP: Number(settings.topP ?? 0.9),
      maxTokens: Number(settings.maxTokens ?? 4096),
      timeoutMs: Number(settings.modelTimeoutMs ?? DEFAULT_TIMEOUT_MS),
      allowRemoteLm: settings.allowRemoteLm === true,
    };
    if (!normalized.allowRemoteLm && !isLoopbackHost(new URL(normalized.baseUrl).hostname)) {
      throw new Error('LM Studio endpoint không cục bộ đã bị chặn. Bật allowRemoteLm chỉ khi bạn thực sự tin endpoint.');
    }
    return normalized;
  }

  async request(pathname, options = {}) {
    const settings = await this.settings();
    const url = new URL(pathname.replace(/^\//, ''), `${nativeBaseUrl(settings.baseUrl)}/`).toString();
    const requestedTimeout = Number(options.timeoutMs ?? settings.timeoutMs);
    const timeoutMs = Math.min(Math.max(requestedTimeout, 500), 30 * 60_000);
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const signals = [timeoutSignal];
    if (options.signal) signals.push(options.signal);
    const signal = AbortSignal.any(signals);
    const response = await this.fetchImpl(url, {
      method: options.method || 'GET',
      headers: {
        Accept: 'application/json',
        ...authHeaders(settings.apiKey),
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options.headers || {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal,
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
    }
    if (!response.ok) {
      const detail = data?.error?.message || data?.message || data?.raw || response.statusText;
      const error = new Error(`LM Studio ${response.status}: ${String(detail).slice(0, 1000)}`);
      error.status = response.status;
      error.body = data;
      throw error;
    }
    return data;
  }

  async getStatus() {
    const settings = await this.settings();
    const result = {
      online: false,
      baseUrl: settings.baseUrl,
      configuredModel: settings.model,
      selectedModel: settings.model,
      installed: [],
      loaded: [],
      capabilities: { trainedForToolUse: false, toolUseMode: 'default', vision: false },
      reason: '',
    };

    try {
      const payload = await this.request('models', { timeoutMs: STATUS_TIMEOUT_MS });
      result.online = true;
      const models = (payload?.models || []).map((model) => ({
        id: model.key,
        variantId: model.selected_variant || model.key,
        displayName: model.display_name || model.key,
        publisher: model.publisher || '',
        type: model.type,
        architecture: model.architecture || '',
        format: model.format || '',
        quantization: model.quantization?.name || '',
        parameters: model.params_string || '',
        capabilities: {
          trainedForToolUse: Boolean(model.capabilities?.trained_for_tool_use),
          toolUseMode: model.capabilities?.trained_for_tool_use ? 'native' : 'default',
          vision: Boolean(model.capabilities?.vision),
        },
        maxContextLength: Number(model.max_context_length || 0),
        loadedInstances: (model.loaded_instances || []).map((instance) => ({
          id: instance.id,
          contextLength: Number(instance.config?.context_length || 0),
        })),
      }));
      result.installed = models;
      result.loaded = models.flatMap((model) => model.loadedInstances.map((instance) => ({
        ...instance,
        sourceId: model.variantId,
        displayName: model.displayName,
      })));
      const qwen = this.findPreferredModel(models, settings.model);
      result.selectedModel = settings.model || qwen?.variantId || result.loaded[0]?.id || '';
      result.capabilities = qwen?.capabilities || result.capabilities;
    } catch (error) {
      result.reason = `Server đang chạy nhưng không đọc được danh sách model: ${errorMessage(error)}`;
    }
    return result;
  }

  findPreferredModel(models, configured) {
    if (configured) {
      const exact = models.find((model) => [model.id, model.variantId, ...model.loadedInstances.map((item) => item.id)].includes(configured));
      if (exact) return exact;
    }
    const scored = models.filter((model) => model.type === 'llm').map((model) => {
      const value = `${model.id} ${model.displayName} ${model.quantization}`.toLowerCase();
      let score = 0;
      if (value.includes('qwen2.5-coder')) score += 100;
      if (value.includes('14b')) score += 30;
      if (value.includes('instruct')) score += 10;
      if (model.loadedInstances.length) score += 100;
      if (value.includes('q3_k_l')) score += 4;
      return { model, score };
    }).sort((a, b) => b.score - a.score);
    return scored[0]?.score > 0 ? scored[0].model : null;
  }

  async loadModel(modelId, options = {}) {
    const id = String(modelId || '').trim();
    if (!id) throw new Error('Chưa chọn model cần load.');
    const body = {
      model: id,
      echo_load_config: true,
    };
    if (options.contextLength) body.context_length = Number(options.contextLength);
    if (options.flashAttention !== undefined) body.flash_attention = Boolean(options.flashAttention);
    return this.request('models/load', { method: 'POST', body, signal: options.signal, timeoutMs: options.timeoutMs || 5 * 60_000 });
  }

  async findLmsExecutable() {
    const direct = path.join(os.homedir(), '.lmstudio', 'bin', process.platform === 'win32' ? 'lms.exe' : 'lms');
    if (fs.existsSync(direct)) return direct;
    if (process.platform === 'win32') {
      const found = await new Promise((resolve) => {
        execFile('where.exe', ['lms'], { windowsHide: true, timeout: 5000 }, (error, stdout) => {
          if (error) return resolve('');
          const first = String(stdout).split(/\r?\n/).find(Boolean);
          resolve(first || '');
        });
      });
      if (found) return found;
    }
    return '';
  }

  async startServer(port = 1234) {
    if ((await this.getStatus()).online) return { started: false, alreadyRunning: true };
    const executable = await this.findLmsExecutable();
    if (!executable) {
      const error = new Error('Chưa tìm thấy lệnh lms. Hãy bấm “Cài LMS CLI” trong hướng dẫn hoặc bật Start Server trong LM Studio.');
      error.code = 'LMS_CLI_MISSING';
      throw error;
    }
    const child = spawn(executable, ['server', 'start', '--port', String(port)], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.unref();
    for (let attempt = 0; attempt < 30; attempt += 1) {
      await delay(500);
      if (child.exitCode !== null) break;
      if ((await this.getStatus()).online) return { started: true, alreadyRunning: false };
    }
    const status = await this.getStatus();
    if (!status.online) throw new Error('Không thể bật LM Studio server bằng lms. Hãy mở LM Studio > Developer > Start Server.');
    return { started: true, alreadyRunning: false };
  }

  async installCli({ signal } = {}) {
    const command = process.platform === 'win32' ? 'cmd.exe' : 'sh';
    const args = process.platform === 'win32'
      ? ['/d', '/s', '/c', 'npx --yes lmstudio install-cli']
      : ['-lc', 'npx --yes lmstudio install-cli'];
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(abortError());
      const child = spawn(command, args, { windowsHide: true, shell: false });
      let settled = false;
      let output = '';
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        fn(value);
      };
      const stop = () => {
        try { child.kill(); } catch { /* already exited */ }
      };
      const onAbort = () => {
        stop();
        finish(reject, abortError());
      };
      const timer = setTimeout(() => {
        stop();
        finish(reject, new Error('LMS CLI installer vượt quá 5 phút.'));
      }, 5 * 60_000);
      signal?.addEventListener('abort', onAbort, { once: true });
      child.stdout.on('data', (chunk) => { output = (output + chunk.toString()).slice(-10_000); });
      child.stderr.on('data', (chunk) => { output = (output + chunk.toString()).slice(-10_000); });
      child.on('error', (error) => finish(reject, error));
      child.on('exit', (code) => {
        if (code === 0) finish(resolve, { ok: true, output: output.trim() });
        else finish(reject, new Error(output.trim() || `LMS CLI installer exited with code ${code}.`));
      });
    });
  }

  async chatStream({ messages, tools, signal, onDelta }) {
    const settings = await this.settings();
    const model = String(settings.model || '').trim();
    if (!model) throw new Error('Chưa chọn model. Hãy load model Qwen trong LM Studio hoặc cấu hình model ID.');
    const body = {
      model,
      messages,
      temperature: settings.temperature,
      top_p: settings.topP,
      max_tokens: settings.maxTokens,
      stream: true,
    };
    if (Array.isArray(tools) && tools.length) body.tools = tools;

    const timeoutSignal = AbortSignal.timeout(Math.min(Math.max(settings.timeoutMs, 2_000), 30 * 60_000));
    const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    const response = await this.fetchImpl(`${settings.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream, application/json',
        ...authHeaders(settings.apiKey),
      },
      body: JSON.stringify(body),
      signal: combinedSignal,
    });

    if (!response.ok) {
      const raw = await response.text();
      let message = raw;
      try { message = JSON.parse(raw)?.error?.message || raw; } catch { /* keep text */ }
      throw new Error(`LM Studio ${response.status}: ${String(message).slice(0, 1500)}`);
    }

    const contentType = String(response.headers.get('content-type') || '').toLowerCase();
    if (!response.body || contentType.includes('application/json')) {
      const payload = await response.json();
      const message = payload?.choices?.[0]?.message || {};
      const text = String(message.content || '');
      if (text && onDelta) onDelta(text);
      const toolMap = new Map();
      mergeToolCallFragments(toolMap, (message.tool_calls || []).map((call, index) => ({ ...call, index })));
      return {
        content: text,
        toolCalls: [...toolMap.values()],
        finishReason: payload?.choices?.[0]?.finish_reason || '',
        usage: payload?.usage || null,
      };
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let content = '';
    let finishReason = '';
    let usage = null;
    let streamEnded = false;
    let streamError = null;
    const toolMap = new Map();

    const consumeEvent = (event) => {
      if (!event) return;
      if (event.done) {
        streamEnded = true;
        return;
      }
      if (event.malformed) {
        streamError = new Error('LM Studio trả về một SSE event không hợp lệ.');
        return;
      }
      if (event.error) {
        streamError = new Error(`LM Studio stream error: ${String(event.error?.message || event.error).slice(0, 1000)}`);
        return;
      }
      if (event.usage) usage = event.usage;
      const choice = event.choices?.[0];
      if (!choice) {
        if (!event.usage && !event.id && !event.model) streamError = new Error('LM Studio stream event thiếu choices.');
        return;
      }
      if (choice.finish_reason) finishReason = choice.finish_reason;
      const delta = choice.delta || choice.message || {};
      if (typeof delta.content === 'string' && delta.content) {
        content += delta.content;
        if (onDelta) onDelta(delta.content);
      }
      mergeToolCallFragments(toolMap, delta.tool_calls);
    };

    try {
      while (!streamEnded && !streamError) {
        const { value, done } = await reader.read();
        buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
        if (buffer.length > MAX_SSE_BUFFER_CHARS) {
          streamError = new Error('LM Studio SSE buffer vượt giới hạn an toàn.');
          break;
        }
        buffer = buffer.replace(/\r\n/g, '\n');
        let boundary;
        while ((boundary = buffer.indexOf('\n\n')) !== -1) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          if (block.length > MAX_SSE_EVENT_CHARS) {
            streamError = new Error('LM Studio SSE event quá lớn.');
            break;
          }
          consumeEvent(parseSseBlock(block));
          if (streamEnded || streamError) break;
        }
        if (done) break;
      }
      if (!streamEnded && !streamError && buffer.trim()) {
        if (buffer.length > MAX_SSE_EVENT_CHARS) streamError = new Error('LM Studio SSE event quá lớn.');
        else consumeEvent(parseSseBlock(buffer));
      }
      if (streamError) throw streamError;
      if (!streamEnded && !content && !toolMap.size && !usage) {
        throw new Error('LM Studio đóng stream mà không trả nội dung.');
      }
    } finally {
      try { await reader.cancel(); } catch { /* already closed */ }
      try { reader.releaseLock(); } catch { /* already released */ }
    }

    const toolCalls = [...toolMap.entries()].sort(([a], [b]) => a - b).map(([, value]) => value);
    return { content, toolCalls, finishReason, usage };
  }
}

module.exports = {
  LMStudioClient,
  cleanBaseUrl,
  nativeBaseUrl,
  parseSseBlock,
  mergeToolCallFragments,
  isLoopbackHost,
};
