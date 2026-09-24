(function () {
  'use strict';

  var STORAGE = {
    activeSession: 'codepilot.activeSession',
    mode: 'codepilot.mode',
    theme: 'codepilot.theme',
    onboardingComplete: 'codepilot.onboardingComplete'
  };

  var DEFAULT_SETTINGS = {
    workspace: '',
    lmBaseUrl: 'http://127.0.0.1:1234/v1',
    model: '',
    modelPreset: 'qwen3-4b-1050ti',
    temperature: 0.2,
    maxTokens: 2048,
    contextLength: 2048,
    maxSteps: 8,
    contextChars: 8000,
    maxSubagents: 1,
    concurrentSubagents: 1,
    maxSubagentSteps: 6,
    flashAttention: true,
    approvalMode: 'automatic',
    allowFallbackTools: false,
    braveApiKey: '',
    ddgFallback: true,
    mcpServers: '{}',
    braveApiKeyPresent: false,
    theme: 'dark'
  };

  var MODEL_PRESETS = {
    'qwen3-4b-1050ti': {
      label: 'Qwen3 4B — GTX 1050 Ti 4GB',
      model: 'qwen3-4b-instruct-2507',
      contextLength: 2048,
      maxTokens: 2048,
      contextChars: 8000,
      maxSteps: 8,
      maxSubagents: 1,
      concurrentSubagents: 1,
      maxSubagentSteps: 6,
      flashAttention: true
    },
    'qwen25-coder-3b': {
      label: 'Qwen2.5 Coder 3B — nhẹ, ổn định',
      model: 'qwen2.5-coder-3b-instruct',
      contextLength: 4096,
      maxTokens: 2048,
      contextChars: 10000,
      maxSteps: 8,
      maxSubagents: 1,
      concurrentSubagents: 1,
      maxSubagentSteps: 6,
      flashAttention: true
    },
    'qwen25-coder-14b': {
      label: 'Qwen2.5 Coder 14B — chất lượng, chậm hơn',
      model: 'qwen2.5-coder-14b-instruct',
      contextLength: 4096,
      maxTokens: 2048,
      contextChars: 10000,
      maxSteps: 6,
      maxSubagents: 0,
      concurrentSubagents: 1,
      maxSubagentSteps: 4,
      flashAttention: true
    },
    custom: { label: 'Tùy chỉnh', model: '', contextLength: 2048, maxTokens: 2048, contextChars: 8000, maxSteps: 8, maxSubagents: 1, concurrentSubagents: 1, maxSubagentSteps: 6, flashAttention: true }
  };

  var MODES = {
    chat: { label: 'Hội thoại', hint: 'Trò chuyện và suy nghĩ cùng nhau' },
    agent: { label: 'Agent', hint: 'Tác nhân có thể đọc, sửa và kiểm thử trong workspace' },
    plan: { label: 'Lập kế hoạch', hint: 'Phân tích và lập kế hoạch trước khi hành động' }
  };

  var TOOL_LABELS = {
    read: 'Đọc nội dung',
    read_file: 'Đọc tệp',
    write: 'Ghi nội dung',
    write_file: 'Ghi tệp',
    edit: 'Chỉnh sửa tệp',
    edit_file: 'Chỉnh sửa tệp',
    list: 'Liệt kê thư mục',
    list_dir: 'Liệt kê thư mục',
    search: 'Tìm kiếm trong mã',
    glob: 'Tìm tệp',
    grep: 'Tìm kiếm nội dung',
    terminal: 'Chạy lệnh',
    shell: 'Chạy lệnh',
    command: 'Chạy lệnh',
    browser: 'Mở trình duyệt',
    web_search: 'Tra cứu web',
    web_content: 'Tải nội dung',
    test: 'Chạy kiểm thử',
    git: 'Thao tác Git'
  };

  var ICON_NAMES = {
    message: 'message',
    bot: 'bot',
    user: 'user',
    terminal: 'terminal',
    file: 'folder',
    check: 'check',
    error: 'alert',
    activity: 'activity',
    sparkles: 'sparkles',
    subagent: 'bot'
  };

  var dom = {};
  var bridge = window.codepilot || {};
  var unsubscribeEvents = null;
  var activityTimer = null;
  var toastCounter = 0;
  var streamMessageId = null;
  var modalReturnFocus = {};

  var state = {
    bootstrap: {},
    settings: Object.assign({}, DEFAULT_SETTINGS),
    workspace: '',
    sessions: [],
    activeSessionId: readStorage(STORAGE.activeSession, ''),
    activeSession: null,
    messages: [],
    mode: normalizeMode(readStorage(STORAGE.mode, 'chat')),
    isRunning: false,
    runId: null,
    lastPrompt: '',
    attachments: [],
    activity: [],
    activityStartedAt: 0,
    activityError: false,
    lmStatus: {
      reachable: false,
      loading: false,
      models: [],
      model: '',
      baseUrl: DEFAULT_SETTINGS.lmBaseUrl,
      detail: 'Chưa kiểm tra'
    },
    onboarding: {
      step: 1,
      reachable: false,
      model: '',
      modelLoaded: false,
      models: []
    },
    pendingAsk: null,
    pendingApproval: null,
    sessionFilter: 'all',
    apiAvailable: false,
    initialized: false,
    loading: true,
    loadError: ''
  };

  var DOM_IDS = [
    'app-shell', 'sidebar', 'sidebar-collapse', 'sidebar-scrim', 'sidebar-toggle', 'new-chat-btn',
    'session-search', 'session-filter-btn', 'session-list', 'session-list-empty', 'session-count',
    'workspace-selector', 'sidebar-workspace-name', 'settings-btn', 'theme-toggle', 'header-workspace',
    'header-workspace-name', 'model-status-pill', 'model-status-dot', 'model-status-text',
    'header-model-name', 'mode-select', 'activity-toggle', 'activity-count', 'activity-panel',
    'activity-close', 'activity-summary', 'summary-dot', 'summary-status-text', 'activity-duration',
    'activity-timeline', 'activity-empty', 'chat-loading', 'chat-error', 'chat-error-text',
    'retry-load-btn', 'welcome-screen', 'messages-container', 'composer-area', 'attachment-list',
    'composer-form', 'attach-btn', 'message-input', 'composer-mode-hint', 'stop-btn', 'send-btn',
    'context-indicator', 'token-indicator', 'onboarding-modal', 'onboarding-close',
    'onboarding-connection-dot', 'onboarding-connection-title', 'onboarding-connection-detail',
    'onboarding-test-btn', 'onboarding-start-btn', 'onboarding-install-btn', 'onboarding-error',
    'onboarding-model-select', 'onboarding-model-hint', 'onboarding-load-btn',
    'onboarding-model-loaded', 'onboarding-loaded-name', 'onboarding-workspace-name',
    'onboarding-workspace-path', 'onboarding-workspace-pick', 'onboarding-back-btn',
    'onboarding-continue', 'settings-modal', 'settings-close', 'settings-workspace',
    'settings-workspace-pick', 'settings-workspace-clear', 'settings-theme', 'settings-language',
    'settings-lm-url', 'settings-model', 'settings-model-preset', 'settings-model-preset-hint', 'settings-refresh-models', 'settings-load-model', 'settings-model-hint',
    'settings-temperature', 'settings-max-tokens', 'settings-context-length', 'settings-flash-attention', 'settings-context-chars', 'settings-connection-dot',
    'settings-connection-title', 'settings-connection-detail', 'settings-test-btn', 'settings-max-steps',
    'settings-approval-mode', 'settings-max-subagents', 'settings-concurrent-subagents', 'settings-allow-fallback-tools',
    'settings-brave-key', 'settings-ddg-fallback', 'settings-mcp-json', 'mcp-status-text',
    'mcp-status-detail', 'settings-reset-btn', 'settings-cancel-btn', 'settings-save-btn',
    'ask-user-modal', 'ask-user-close', 'ask-user-question', 'ask-user-options', 'ask-user-input',
    'ask-user-error', 'ask-user-reject', 'ask-user-cancel', 'ask-user-resolve', 'approval-modal',
    'approval-close', 'approval-description', 'approval-tool-name', 'approval-tool-args', 'approval-error',
    'approval-reject', 'approval-approve', 'toast-region', 'live-region'
  ];

  function cacheDom() {
    DOM_IDS.forEach(function (id) {
      dom[id] = document.getElementById(id);
    });
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function readStorage(key, fallback) {
    try {
      var value = localStorage.getItem(key);
      return value === null ? fallback : value;
    } catch (_) {
      return fallback;
    }
  }

  function writeStorage(key, value) {
    try {
      if (value === undefined || value === null || value === '') localStorage.removeItem(key);
      else localStorage.setItem(key, String(value));
    } catch (_) {}
  }

  function normalizeMode(mode) {
    var value = String(mode || '').toLowerCase();
    if (value === 'planning' || value === 'plan') return 'plan';
    if (value === 'agentic' || value === 'agent') return 'agent';
    if (value === 'conversation' || value === 'chat') return 'chat';
    return 'chat';
  }

  function numberOr(value, fallback, min, max) {
    var number = Number(value);
    if (!Number.isFinite(number)) number = fallback;
    if (min !== undefined) number = Math.max(min, number);
    if (max !== undefined) number = Math.min(max, number);
    return number;
  }

  function field(object, keys, fallback) {
    if (!object || typeof object !== 'object') return fallback;
    for (var i = 0; i < keys.length; i += 1) {
      var value = object[keys[i]];
      if (value !== undefined && value !== null) return value;
    }
    return fallback;
  }

  function unwrap(value, key) {
    if (value && typeof value === 'object' && value[key] !== undefined) return value[key];
    return value;
  }

  function stringOr(value, fallback) {
    if (value === undefined || value === null) return fallback || '';
    if (typeof value === 'string') return value;
    return String(value);
  }

  function safeError(error, fallback) {
    var message = error && error.message ? error.message : String(error || '');
    if (!message || /^\s*[\[{]/.test(message) || /json|protocol|payload/i.test(message) || (/[{}]/.test(message) && /:|"/.test(message))) {
      return fallback || 'Đã xảy ra lỗi. Vui lòng thử lại.';
    }
    message = message.replace(/[\r\n]+/g, ' ').replace(/(bearer\s+)[^\s,;]+/gi, '$1[redacted]').replace(/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}\b/g, '[redacted]').trim();
    return truncate(message, 180) || fallback || 'Đã xảy ra lỗi. Vui lòng thử lại.';
  }

  function truncate(value, length) {
    var text = stringOr(value, '');
    if (text.length <= length) return text;
    return text.slice(0, Math.max(0, length - 1)).trimEnd() + '…';
  }

  function createNode(tag, className, text) {
    var element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function createIcon(name, className) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    if (className) svg.setAttribute('class', className);
    var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-' + (ICON_NAMES[name] || name));
    svg.appendChild(use);
    return svg;
  }

  function setHidden(element, hidden) {
    if (element) element.hidden = Boolean(hidden);
  }

  function setText(element, value) {
    if (element) element.textContent = value === undefined || value === null ? '' : String(value);
  }

  function announce(message) {
    if (!dom['live-region']) return;
    dom['live-region'].textContent = '';
    window.setTimeout(function () {
      dom['live-region'].textContent = message;
    }, 20);
  }

  function showToast(title, detail, type) {
    if (!dom['toast-region']) return;
    var toast = createNode('div', 'toast ' + (type || 'success'));
    var iconBox = createNode('span', 'toast-icon');
    iconBox.appendChild(createIcon(type === 'error' ? 'alert' : type === 'warning' ? 'alert' : 'check'));
    var copy = createNode('div', 'toast-copy');
    copy.appendChild(createNode('strong', '', title));
    if (detail) copy.appendChild(createNode('span', '', detail));
    toast.appendChild(iconBox);
    toast.appendChild(copy);
    toast.dataset.toastId = String(++toastCounter);
    dom['toast-region'].appendChild(toast);
    var remove = function () {
      if (!toast.isConnected) return;
      toast.classList.add('is-leaving');
      window.setTimeout(function () { toast.remove(); }, 210);
    };
    toast.addEventListener('click', remove);
    window.setTimeout(remove, 4600);
  }

  function bridgeCall(method, argument) {
    if (!bridge || typeof bridge[method] !== 'function') {
      return Promise.reject(new Error('API ' + method + ' không khả dụng'));
    }
    try {
      return Promise.resolve(argument === undefined ? bridge[method]() : bridge[method](argument));
    } catch (error) {
      return Promise.reject(error);
    }
  }

  function normalizeWorkspace(value) {
    if (!value) return { path: '', name: '' };
    if (typeof value === 'string') {
      var clean = value.trim();
      return { path: clean, name: clean ? clean.split(/[\\/]/).filter(Boolean).pop() : '' };
    }
    var path = stringOr(field(value, ['path', 'workspacePath', 'folder', 'directory'], '')).trim();
    var name = stringOr(field(value, ['name', 'label', 'displayName'], '')).trim();
    if (!name && path) name = path.split(/[\\/]/).filter(Boolean).pop();
    return { path: path, name: name };
  }

  function formatWorkspaceName(value) {
    var workspace = normalizeWorkspace(value);
    return workspace.name || workspace.path || 'Chưa chọn';
  }

  function normalizeMcpValue(value) {
    if (typeof value === 'string') {
      try { value = JSON.parse(value); } catch (_) { return null; }
    }
    if (Array.isArray(value)) {
      var fromArray = Object.create(null);
      value.forEach(function (item, index) {
        if (item && typeof item === 'object' && !Array.isArray(item)) {
          var name = stringOr(field(item, ['name', 'id'], ''), 'mcp_' + (index + 1));
          var config = {};
          Object.keys(item).forEach(function (key) {
            if (key !== '__proto__' && key !== 'prototype' && key !== 'constructor' && key !== 'name' && key !== 'id') config[key] = item[key];
          });
          fromArray[name] = config;
        } else {
          fromArray['mcp_' + (index + 1)] = item;
        }
      });
      return fromArray;
    }
    return value && typeof value === 'object' ? value : {};
  }

  function normalizeSettings(raw) {
    var source = raw && typeof raw === 'object' && raw.settings && typeof raw.settings === 'object'
      ? Object.assign({}, raw, raw.settings)
      : (raw || {});
    var rawMcp = field(source, ['mcpServers', 'mcp', 'mcpConfig'], DEFAULT_SETTINGS.mcpServers);
    var mcpObject = normalizeMcpValue(rawMcp);
    var mcp = mcpObject === null ? stringOr(rawMcp, '{}') : JSON.stringify(mcpObject, null, 2);
    var secret = stringOr(field(source, ['braveApiKey', 'braveKey'], DEFAULT_SETTINGS.braveApiKey), DEFAULT_SETTINGS.braveApiKey);
    var webProvider = stringOr(field(source, ['webProvider', 'searchProvider'], ''), '').toLowerCase();
    var fallbackValue = field(source, ['ddgFallback', 'duckDuckGoFallback'], undefined);
    var themeFallback = state.settings && state.settings.theme ? state.settings.theme : readStorage(STORAGE.theme, DEFAULT_SETTINGS.theme);
    var modelPreset = stringOr(field(source, ['modelPreset', 'modelProfile'], DEFAULT_SETTINGS.modelPreset), DEFAULT_SETTINGS.modelPreset);
    if (!MODEL_PRESETS[modelPreset]) modelPreset = 'custom';
    return {
      workspace: stringOr(field(source, ['workspace', 'workspacePath', 'folder', 'fileRoot'], DEFAULT_SETTINGS.workspace), DEFAULT_SETTINGS.workspace),
      lmBaseUrl: stringOr(field(source, ['lmBaseUrl', 'baseUrl', 'lmUrl', 'lmStudioUrl'], DEFAULT_SETTINGS.lmBaseUrl), DEFAULT_SETTINGS.lmBaseUrl),
      model: stringOr(field(source, ['model', 'modelId', 'lmModel'], DEFAULT_SETTINGS.model), DEFAULT_SETTINGS.model),
      modelPreset: modelPreset,
      temperature: numberOr(field(source, ['temperature'], DEFAULT_SETTINGS.temperature), DEFAULT_SETTINGS.temperature, 0, 2),
      maxTokens: numberOr(field(source, ['maxTokens', 'maxOutputTokens'], DEFAULT_SETTINGS.maxTokens), DEFAULT_SETTINGS.maxTokens, 256, 8192),
      contextLength: numberOr(field(source, ['contextLength', 'lmContextLength'], DEFAULT_SETTINGS.contextLength), DEFAULT_SETTINGS.contextLength, 512, 32768),
      maxSteps: numberOr(field(source, ['maxSteps', 'agentMaxSteps'], DEFAULT_SETTINGS.maxSteps), DEFAULT_SETTINGS.maxSteps, 1, 100),
      contextChars: numberOr(field(source, ['contextChars', 'maxContextChars'], DEFAULT_SETTINGS.contextChars), DEFAULT_SETTINGS.contextChars, 1000, 2000000),
      maxSubagents: numberOr(field(source, ['maxSubagents', 'subagentsMax'], DEFAULT_SETTINGS.maxSubagents), DEFAULT_SETTINGS.maxSubagents, 0, 16),
      concurrentSubagents: numberOr(field(source, ['concurrentSubagents', 'maxConcurrentSubagents', 'parallelSubagents'], DEFAULT_SETTINGS.concurrentSubagents), DEFAULT_SETTINGS.concurrentSubagents, 1, 8),
      maxSubagentSteps: numberOr(field(source, ['maxSubagentSteps'], DEFAULT_SETTINGS.maxSubagentSteps), DEFAULT_SETTINGS.maxSubagentSteps, 1, 100),
      flashAttention: field(source, ['flashAttention'], DEFAULT_SETTINGS.flashAttention) === true,
      approvalMode: stringOr(field(source, ['approvalMode', 'approval'], DEFAULT_SETTINGS.approvalMode), DEFAULT_SETTINGS.approvalMode),
      allowFallbackTools: field(source, ['allowFallbackTools'], DEFAULT_SETTINGS.allowFallbackTools) === true,
      braveApiKey: secret,
      braveApiKeyPresent: Boolean(field(source, ['braveApiKeyPresent', 'hasBraveApiKey'], Boolean(secret))),
      ddgFallback: fallbackValue === undefined ? (!webProvider || webProvider === 'duckduckgo') : Boolean(fallbackValue),
      mcpServers: mcp || '{}',
      theme: stringOr(field(source, ['theme'], themeFallback), themeFallback)
    };
  }

  function settingsPatch(settings) {
    var patch = {
      workspace: settings.workspace,
      fileRoot: settings.workspace,
      lmBaseUrl: settings.lmBaseUrl,
      model: settings.model,
      modelPreset: settings.modelPreset,
      temperature: settings.temperature,
      maxTokens: settings.maxTokens,
      contextLength: settings.contextLength,
      maxSteps: settings.maxSteps,
      contextChars: settings.contextChars,
      maxSubagents: settings.maxSubagents,
      concurrentSubagents: settings.concurrentSubagents,
      maxConcurrentSubagents: settings.concurrentSubagents,
      maxSubagentSteps: settings.maxSubagentSteps,
      flashAttention: settings.flashAttention !== false,
      approvalMode: settings.approvalMode,
      allowFallbackTools: settings.allowFallbackTools !== false,
      braveApiKey: settings.braveApiKey,
      ddgFallback: settings.ddgFallback,
      webProvider: settings.ddgFallback ? 'duckduckgo' : 'brave',
      mcpServers: normalizeMcpValue(settings.mcpServers) || {},
      theme: settings.theme
    };
    if (settings.braveApiKeyPresent && !settings.braveApiKey) delete patch.braveApiKey;
    return patch;
  }

  function toDate(value) {
    if (value instanceof Date) return value;
    if (typeof value === 'number' || /^\d+$/.test(String(value || ''))) {
      var number = Number(value);
      if (number > 0 && number < 100000000000) number *= 1000;
      var fromNumber = new Date(number);
      if (!Number.isNaN(fromNumber.getTime())) return fromNumber;
    }
    var parsed = new Date(value || '');
    return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
  }

  function formatClock(value) {
    try {
      return new Intl.DateTimeFormat('vi-VN', { hour: '2-digit', minute: '2-digit' }).format(toDate(value));
    } catch (_) {
      return '';
    }
  }

  function formatShortDate(value) {
    try {
      return new Intl.DateTimeFormat('vi-VN', { day: '2-digit', month: '2-digit' }).format(toDate(value));
    } catch (_) {
      return '';
    }
  }

  function formatRelativeTime(value) {
    var date = toDate(value);
    var now = new Date();
    var startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    var startTomorrow = startToday + 86400000;
    if (date.getTime() >= startToday && date.getTime() < startTomorrow) return formatClock(date);
    if (date.getTime() >= startToday - 86400000 && date.getTime() < startToday) return 'Hôm qua';
    if (date.getTime() >= startToday - 7 * 86400000) {
      try { return new Intl.DateTimeFormat('vi-VN', { weekday: 'short' }).format(date); } catch (_) { return formatShortDate(date); }
    }
    return formatShortDate(date);
  }

  function sessionGroup(value) {
    var date = toDate(value);
    var now = new Date();
    var startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    if (date.getTime() >= startToday) return 'Hôm nay';
    if (date.getTime() >= startToday - 7 * 86400000) return '7 ngày trước';
    return 'Lâu hơn';
  }

  function deriveTitle(messages) {
    var userMessage = (messages || []).find(function (message) { return message.role === 'user' && message.text; });
    return userMessage ? truncate(userMessage.text.replace(/\s+/g, ' ').trim(), 45) : 'Cuộc trò chuyện mới';
  }

  function derivePreview(messages) {
    var list = messages || [];
    for (var i = list.length - 1; i >= 0; i -= 1) {
      if (!list[i] || !list[i].text) continue;
      var value = list[i].role === 'assistant' ? cleanModelText(list[i].text) : list[i].text;
      if (value) return truncate(value.replace(/\s+/g, ' ').trim(), 64);
    }
    return 'Chưa có tin nhắn';
  }

  function extractText(value) {
    if (value === undefined || value === null) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (Array.isArray(value)) {
      return value.map(function (part) {
        if (typeof part === 'string') return part;
        return extractText(field(part, ['text', 'content', 'value'], ''));
      }).join('');
    }
    if (typeof value === 'object') return extractText(field(value, ['text', 'content', 'value'], ''));
    return '';
  }

  function cleanModelText(value) {
    var text = stringOr(value, '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').replace(/(bearer\s+)[^\s,;]+/gi, '$1[redacted]').replace(/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}\b/g, '[redacted]').replace(/<(?:tool_call|tool_response|function_results?|call)>[\s\S]*?<\/(?:tool_call|tool_response|function_results?|call)>/gi, '').replace(/<\/?(?:tool_call|call|tool_response|function_results?)>/gi, '').trim();
    text = text.replace(/\[TOOL_REQUEST\][\s\S]*?\[END_TOOL_REQUEST\]/gi, '').replace(/\[TOOL_RESULT\][\s\S]*?\[END_TOOL_RESULT\]/gi, '').trim();
    var looksLikeJson = /^[\[{]/.test(text) || /^```(?:json)?\s*[\[{]/i.test(text);
    if (looksLikeJson || /["'](?:tool|function|tool_call|tool_calls|arguments|action|parameters)["']\s*:/i.test(text)) {
      try {
        var parsed = looksLikeJson ? JSON.parse(text.replace(/^```(?:json)?\s*|\s*```$/gi, '')) : null;
        var keys = parsed && typeof parsed === 'object' ? Object.keys(parsed) : [];
        if (keys.some(function (key) { return ['tool', 'function', 'tool_call', 'tool_calls', 'arguments', 'action', 'parameters', 'name'].indexOf(key) !== -1; }) || /["'](?:tool|function|tool_call|tool_calls|arguments|action|parameters)["']\s*:/i.test(text)) {
          return 'Tác nhân đã xử lý yêu cầu bằng công cụ. Xem phần Hoạt động để biết chi tiết.';
        }
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          var envelopeKeys = ['final_answer', 'natural_language_response', 'answer', 'response', 'message', 'content'];
          for (var envelopeIndex = 0; envelopeIndex < envelopeKeys.length; envelopeIndex += 1) {
            if (typeof parsed[envelopeKeys[envelopeIndex]] === 'string' && parsed[envelopeKeys[envelopeIndex]].trim()) return parsed[envelopeKeys[envelopeIndex]].trim();
          }
        }
      } catch (_) {
        if (/["'](?:tool|function|tool_call|tool_calls|arguments|action|parameters)["']\s*:/i.test(text)) return 'Tác nhân đã xử lý yêu cầu bằng công cụ. Xem phần Hoạt động để biết chi tiết.';
      }
    }
    return text;
  }

  function normalizeAttachments(value) {
    if (value && !Array.isArray(value) && typeof value === 'object') {
      if (Array.isArray(value.files)) value = value.files;
      else if (Array.isArray(value.attachments)) value = value.attachments;
    }
    var list = Array.isArray(value) ? value : (value ? [value] : []);
    return list.map(function (item, index) {
      if (typeof item === 'string') return { id: item + '-' + index, name: item.split(/[\\/]/).pop(), path: item };
      return {
        id: stringOr(field(item, ['id', 'path', 'name'], 'attachment-' + index), 'attachment-' + index),
        name: stringOr(field(item, ['name', 'fileName', 'filename', 'path'], 'Tệp đính kèm'), 'Tệp đính kèm').split(/[\\/]/).pop(),
        path: stringOr(field(item, ['path', 'filePath', 'url'], '')),
        content: stringOr(field(item, ['content', 'text', 'data'], ''), '').slice(0, 1000000),
        size: numberOr(field(item, ['size', 'bytes'], 0), 0, 0),
        type: stringOr(field(item, ['type', 'mimeType'], ''))
      };
    });
  }

  function normalizeMessage(raw, fallbackRole) {
    var source = raw && typeof raw === 'object' ? raw : { content: raw };
    var role = stringOr(field(source, ['role', 'author', 'type'], fallbackRole || 'assistant'), fallbackRole || 'assistant').toLowerCase();
    if (role !== 'user' && role !== 'assistant' && role !== 'system') role = fallbackRole || 'assistant';
    var textValue = field(source, ['content', 'text', 'body', 'message'], '');
    var text = extractText(textValue);
    if (role === 'assistant') text = cleanModelText(text);
    var id = stringOr(field(source, ['id', 'messageId', 'message_id', 'uuid'], ''), '');
    if (!id) id = 'message-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    return {
      id: id,
      sessionId: stringOr(field(source, ['sessionId', 'session_id'], ''), ''),
      runId: stringOr(field(source, ['runId', 'run_id'], ''), ''),
      role: role,
      text: text,
      createdAt: field(source, ['createdAt', 'created_at', 'timestamp', 'time'], new Date().toISOString()),
      attachments: normalizeAttachments(field(source, ['attachments', 'files'], [])),
      streaming: Boolean(field(source, ['streaming', 'isStreaming'], false)),
      error: field(source, ['error', 'errorMessage'], ''),
      status: stringOr(field(source, ['status', 'state'], ''), '')
    };
  }

  function normalizeSession(raw, index) {
    var source = raw && typeof raw === 'object' ? raw : {};
    var id = stringOr(field(source, ['id', 'sessionId', 'session_id', 'uuid'], ''), '');
    if (!id) id = 'session-' + (index || 0) + '-' + Date.now();
    var rawMessages = field(source, ['messages', 'history', 'conversation'], []);
    var messages = (Array.isArray(rawMessages) ? rawMessages : []).map(function (message) { return normalizeMessage(message); });
    var workspace = normalizeWorkspace(field(source, ['workspace', 'workspacePath', 'folder'], ''));
    return {
      id: id,
      title: stringOr(field(source, ['title', 'name'], ''), '') || deriveTitle(messages),
      messages: messages,
      preview: stringOr(field(source, ['preview'], ''), '') || derivePreview(messages),
      workspace: workspace.path,
      workspaceName: workspace.name,
      mode: normalizeMode(field(source, ['mode'], 'chat')),
      createdAt: field(source, ['createdAt', 'created_at'], new Date().toISOString()),
      updatedAt: field(source, ['updatedAt', 'updated_at', 'lastActivity', 'last_activity'], new Date().toISOString())
    };
  }

  function getMessageListFromResult(result) {
    var value = unwrap(result, 'sessions');
    if (Array.isArray(value)) return value;
    if (Array.isArray(result)) return result;
    if (result && Array.isArray(result.items)) return result.items;
    return [];
  }

  function updateWorkspace(value) {
    var workspace = normalizeWorkspace(value);
    state.workspace = workspace.path;
    if (workspace.path) state.settings.workspace = workspace.path;
    var name = workspace.name || workspace.path || 'Chưa chọn';
    setText(dom['sidebar-workspace-name'], name);
    setText(dom['header-workspace-name'], workspace.path ? name : 'Chưa chọn workspace');
    setText(dom['onboarding-workspace-name'], workspace.path ? name : 'Chưa chọn thư mục');
    setText(dom['onboarding-workspace-path'], workspace.path || 'Bạn có thể thay đổi sau trong Cài đặt.');
    if (dom['settings-workspace']) dom['settings-workspace'].value = workspace.path || '';
    if (dom['workspace-selector']) dom['workspace-selector'].title = workspace.path || 'Chọn workspace';
    if (dom['header-workspace']) dom['header-workspace'].title = workspace.path || 'Đổi workspace';
  }

  function applyTheme(theme, persist) {
    var requested = theme === 'light' || theme === 'dark' ? theme : 'system';
    var resolved = requested;
    if (requested === 'system') {
      resolved = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    document.documentElement.dataset.theme = resolved;
    if (persist !== false) writeStorage(STORAGE.theme, requested);
    if (dom['theme-toggle']) {
      dom['theme-toggle'].setAttribute('aria-label', resolved === 'dark' ? 'Chuyển sang giao diện sáng' : 'Chuyển sang giao diện tối');
    }
    if (dom['settings-theme'] && document.activeElement !== dom['settings-theme']) dom['settings-theme'].value = requested;
  }

  function setMode(mode, persist) {
    state.mode = normalizeMode(mode);
    if (dom['mode-select']) dom['mode-select'].value = state.mode;
    if (dom['composer-mode-hint']) {
      dom['composer-mode-hint'].textContent = state.isRunning ? 'Tác nhân đang làm việc…' : MODES[state.mode].hint;
    }
    if (persist !== false) writeStorage(STORAGE.mode, state.mode);
  }

  function setLoading(loading) {
    state.loading = Boolean(loading);
    setHidden(dom['chat-loading'], !loading);
    if (loading) {
      setHidden(dom['welcome-screen'], true);
      setHidden(dom['messages-container'], true);
      setHidden(dom['chat-error'], true);
    }
  }

  function setChatError(message, visible) {
    state.loadError = visible ? (message || 'Đã xảy ra lỗi. Bạn có thể thử lại.') : '';
    setText(dom['chat-error-text'], state.loadError || 'Đã xảy ra lỗi. Bạn có thể thử lại.');
    setHidden(dom['chat-error'], !visible);
    if (visible) {
      setHidden(dom['welcome-screen'], true);
      setHidden(dom['messages-container'], true);
    }
  }

  function setChatView() {
    var hasMessages = state.messages.length > 0;
    setHidden(dom['welcome-screen'], hasMessages || Boolean(state.loadError));
    setHidden(dom['messages-container'], !hasMessages);
    setHidden(dom['chat-error'], !state.loadError);
    if (hasMessages) renderMessages();
    updateContextIndicator();
  }

  function normalizeModels(value) {
    var list = Array.isArray(value) ? value : [];
    return list.map(function (item, index) {
      if (typeof item === 'string') return { id: item, name: item };
      return {
        id: stringOr(field(item, ['id', 'model', 'modelId', 'key', 'path'], ''), 'model-' + index),
        name: stringOr(field(item, ['name', 'displayName', 'label', 'id', 'model'], ''), 'Mô hình ' + (index + 1)),
        sourceId: stringOr(field(item, ['sourceId', 'variantId'], ''), '')
      };
    }).filter(function (item) { return Boolean(item.id); });
  }

  function normalizeLmStatus(raw) {
    var source = raw && typeof raw === 'object' ? (raw.status && typeof raw.status === 'object' ? raw.status : raw) : {};
    var statusText = stringOr(field(source, ['status', 'state', 'label'], ''), '').toLowerCase();
    var reachableValue = field(source, ['reachable', 'connected', 'online', 'ok', 'ready', 'available'], undefined);
    var reachable = reachableValue === undefined
      ? ['ready', 'connected', 'online', 'ok', 'reachable', 'success'].indexOf(statusText) !== -1
      : Boolean(reachableValue);
    if (['offline', 'disconnected', 'error', 'failed', 'unreachable'].indexOf(statusText) !== -1) reachable = false;
    var models = normalizeModels(field(source, ['models', 'availableModels', 'modelList', 'installed'], []));
    var loadedModels = normalizeModels(field(source, ['loaded', 'loadedModels'], []));
    var explicitLoaded = stringOr(field(source, ['loadedModel', 'activeModel'], ''), '');
    if (explicitLoaded && !loadedModels.some(function (loaded) { return loaded.id === explicitLoaded; })) loadedModels.push({ id: explicitLoaded, name: explicitLoaded });
    if (!models.length) models = loadedModels;
    var detailValue = stringOr(field(source, ['detail', 'reason', 'message', 'error', 'version'], ''), '');
    return {
      reachable: reachable,
      loading: false,
      status: statusText || (reachable ? 'online' : 'offline'),
      models: models,
      loadedModels: loadedModels,
      model: stringOr(field(source, ['model', 'selectedModel', 'configuredModel', 'loadedModel', 'activeModel', 'currentModel'], ''), ''),
      baseUrl: stringOr(field(source, ['baseUrl', 'url', 'endpoint'], state.settings.lmBaseUrl), state.settings.lmBaseUrl),
      detail: detailValue ? safeError(detailValue, 'Không thể đọc trạng thái LM Studio.') : ''
    };
  }

  function applyLmStatus(raw, options) {
    var next = normalizeLmStatus(raw);
    state.lmStatus = next;
    state.onboarding.reachable = next.reachable;
    state.onboarding.models = next.models;
    if (next.model && !state.settings.model) state.settings.model = next.model;
    if (next.baseUrl) state.settings.lmBaseUrl = next.baseUrl;
    if (next.reachable && next.models.length && !state.onboarding.model) {
      state.onboarding.model = state.settings.model || next.models[0].id;
    }
    if (next.model && (!state.onboarding.model || state.onboarding.model === state.settings.model)) {
      state.onboarding.model = next.model;
    }
    if (next.model && state.onboarding.model === next.model && next.loadedModels.some(function (loaded) { return loaded.id === next.model || loaded.name === next.model || loaded.sourceId === next.model; })) state.onboarding.modelLoaded = true;

    var text = 'Chưa kết nối';
    var dotClass = ' is-offline';
    if (next.loading) { text = 'Đang kiểm tra'; dotClass = ' is-warn'; }
    if (next.reachable) {
      text = 'Đã kết nối';
      dotClass = '';
    }
    if (dom['model-status-text']) dom['model-status-text'].textContent = text;
    if (dom['model-status-dot']) dom['model-status-dot'].className = 'status-pulse' + dotClass;
    if (dom['header-model-name']) dom['header-model-name'].textContent = next.model || state.settings.model || '—';
    updateConnectionUi('onboarding', next);
    updateConnectionUi('settings', next);
    populateModelSelect(dom['onboarding-model-select'], next.models, state.onboarding.model || state.settings.model);
    if (dom['settings-model'] && document.activeElement !== dom['settings-model'] && !dom['settings-model'].value) {
      dom['settings-model'].value = next.model || state.settings.model || '';
    }
    if (dom['onboarding-model-hint']) {
      dom['onboarding-model-hint'].textContent = next.reachable
        ? (next.models.length ? next.models.length + ' mô hình đã sẵn sàng.' : 'Chưa thấy mô hình. Hãy tải mô hình trong LM Studio.')
        : 'Kết nối LM Studio trước để xem danh sách mô hình.';
    }
    updateOnboardingContinue();
    if (options && options.quiet && !next.reachable) {
      // Background checks are intentionally quiet; the onboarding panel shows the detail.
    }
  }

  function populateModelSelect(select, models, selected) {
    if (!select) return;
    var current = selected || select.value || '';
    select.replaceChildren();
    var list = Array.isArray(models) ? models : [];
    if (!list.length) {
      var emptyOption = document.createElement('option');
      emptyOption.value = '';
      emptyOption.textContent = current ? current : 'Chưa có mô hình khả dụng';
      select.appendChild(emptyOption);
    } else {
      list.forEach(function (model) {
        var option = document.createElement('option');
        option.value = model.id;
        option.textContent = model.name || model.id;
        select.appendChild(option);
      });
      if (current && !list.some(function (model) { return model.id === current; })) {
        var manualOption = document.createElement('option');
        manualOption.value = current;
        manualOption.textContent = current + ' · nhập tay';
        select.appendChild(manualOption);
      }
    }
    select.value = current || '';
  }

  function updateConnectionUi(prefix, status) {
    var dot = dom[prefix + '-connection-dot'];
    var title = dom[prefix + '-connection-title'];
    var detail = dom[prefix + '-connection-detail'];
    if (dot) {
      dot.className = 'connection-dot' + (status.reachable ? '' : status.loading ? ' is-warn' : ' is-offline');
    }
    if (title) title.textContent = status.reachable ? 'Đã kết nối' : status.loading ? 'Đang kiểm tra' : 'Chưa kết nối';
    if (detail) detail.textContent = status.reachable
      ? (status.model || 'LM Studio sẵn sàng') + (status.models.length ? ' · ' + status.models.length + ' mô hình' : '')
      : status.detail || 'Chưa có phản hồi từ LM Studio';
  }

  function updateModelStatusLoading() {
    if (!dom['model-status-text']) return;
    dom['model-status-text'].textContent = 'Đang kiểm tra';
    if (dom['model-status-dot']) dom['model-status-dot'].className = 'status-pulse is-busy';
    updateConnectionUi('onboarding', { reachable: false, loading: true, detail: 'Đang kiểm tra kết nối…' });
    updateConnectionUi('settings', { reachable: false, loading: true, detail: 'Đang kiểm tra kết nối…' });
  }

  async function refreshLmStatus(options) {
    updateModelStatusLoading();
    try {
      var result = await bridgeCall('lmStatus');
      applyLmStatus(result, options || {});
      return result;
    } catch (error) {
      applyLmStatus({ reachable: false, status: 'offline', detail: safeError(error, 'Không thể kết nối LM Studio') }, options || {});
      return null;
    }
  }

  function updateWorkspaceSettingsFromResult(result) {
    var value = unwrap(result, 'workspace');
    if (value === undefined) value = result;
    if (value && typeof value === 'object' && (value.canceled || value.cancelled)) return false;
    var workspace = normalizeWorkspace(value);
    if (!workspace.path) return false;
    updateWorkspace(workspace);
    return true;
  }

  async function chooseWorkspace() {
    try {
      var result = await bridgeCall('selectWorkspace');
      if (!updateWorkspaceSettingsFromResult(result)) return false;
      try { await bridgeCall('updateSettings', { workspace: state.workspace }); } catch (_) {}
      renderSessions();
      showToast('Đã cập nhật workspace', state.workspace);
      return true;
    } catch (error) {
      showToast('Không thể chọn workspace', safeError(error, 'Thao tác chưa hoàn tất'), 'error');
      return false;
    }
  }

  function updateSessionInList(session) {
    if (!session || !session.id) return;
    var index = state.sessions.findIndex(function (item) { return item.id === session.id; });
    if (index === -1) state.sessions.push(session);
    else state.sessions[index] = session;
    state.sessions.sort(function (a, b) { return toDate(b.updatedAt).getTime() - toDate(a.updatedAt).getTime(); });
  }

  function renderSessions() {
    if (!dom['session-list']) return;
    var query = stringOr(dom['session-search'] && dom['session-search'].value, '').trim().toLocaleLowerCase('vi-VN');
    var filtered = state.sessions.filter(function (session) {
      if (state.sessionFilter === 'workspace' && state.workspace && session.workspace && session.workspace !== state.workspace) return false;
      if (!query) return true;
      var haystack = [session.title, session.preview, session.workspaceName, session.workspace].join(' ').toLocaleLowerCase('vi-VN');
      return haystack.indexOf(query) !== -1;
    });
    dom['session-list'].replaceChildren();
    if (dom['session-count']) dom['session-count'].textContent = String(filtered.length);
    setHidden(dom['session-list-empty'], filtered.length !== 0);
    if (!filtered.length) return;
    var groups = [];
    var groupMap = {};
    filtered.forEach(function (session) {
      var group = sessionGroup(session.updatedAt);
      if (!groupMap[group]) { groupMap[group] = []; groups.push(group); }
      groupMap[group].push(session);
    });
    var fragment = document.createDocumentFragment();
    groups.forEach(function (group) {
      var label = createNode('div', 'session-group-label', group);
      fragment.appendChild(label);
      groupMap[group].forEach(function (session) {
        var button = createNode('button', 'session-item');
        button.type = 'button';
        button.dataset.sessionId = session.id;
        button.setAttribute('aria-label', 'Mở cuộc trò chuyện: ' + session.title);
        if (session.id === state.activeSessionId) {
          button.classList.add('is-active');
          button.setAttribute('aria-current', 'page');
        }
        var iconBox = createNode('span', 'session-item-icon');
        iconBox.appendChild(createIcon('message'));
        var copy = createNode('span', 'session-item-copy');
        copy.appendChild(createNode('span', 'session-item-title', session.title));
        copy.appendChild(createNode('span', 'session-item-preview', session.preview));
        button.appendChild(iconBox);
        button.appendChild(copy);
        button.appendChild(createNode('span', 'session-item-time', formatRelativeTime(session.updatedAt)));
        button.addEventListener('click', function () { selectSession(session.id); });
        fragment.appendChild(button);
      });
    });
    dom['session-list'].appendChild(fragment);
  }

  async function refreshSessions() {
    try {
      var result = await bridgeCall('listSessions');
      state.sessions = getMessageListFromResult(result).map(function (session, index) { return normalizeSession(session, index); });
      state.sessions.sort(function (a, b) { return toDate(b.updatedAt).getTime() - toDate(a.updatedAt).getTime(); });
      renderSessions();
      return state.sessions;
    } catch (error) {
      renderSessions();
      throw error;
    }
  }

  function setActiveSession(session) {
    state.activeSession = session;
    state.activeSessionId = session.id;
    state.messages = session.messages || [];
    state.activity = [];
    state.activityStartedAt = 0;
    state.activityError = false;
    if (session.mode) setMode(session.mode, false);
    if (session.workspace) updateWorkspace(session.workspace);
    writeStorage(STORAGE.activeSession, session.id);
    streamMessageId = null;
    state.loadError = '';
    setHidden(dom['chat-error'], true);
    setChatView();
    renderActivity();
    renderSessions();
  }

  async function selectSession(id) {
    if (!id) return;
    var sessionId = String(id);
    if (state.isRunning && sessionId !== state.activeSessionId) {
      showToast('Tác nhân đang làm việc', 'Dừng lượt hiện tại trước khi chuyển cuộc trò chuyện.', 'warning');
      return;
    }
    try {
      var result = await bridgeCall('getSession', sessionId);
      var session = normalizeSession(unwrap(result, 'session') || result, 0);
      if (!session.id) session.id = sessionId;
      updateSessionInList(session);
      setActiveSession(session);
      closeMobileSidebar();
    } catch (error) {
      showToast('Không thể mở cuộc trò chuyện', safeError(error, 'Vui lòng thử lại'), 'error');
    }
  }

  async function createNewSession(options) {
    var request = { mode: (options && options.mode) || state.mode };
    var workspace = options && options.workspace !== undefined ? options.workspace : state.workspace;
    if (workspace) request.workspace = workspace;
    var result = await bridgeCall('createSession', request);
    var session = normalizeSession(unwrap(result, 'session') || result, state.sessions.length);
    if (!session.id) throw new Error('Không tạo được phiên');
    updateSessionInList(session);
    setActiveSession(session);
    closeMobileSidebar();
    return session;
  }

  function updateComposerState() {
    if (!dom['message-input'] || !dom['send-btn']) return;
    var hasText = Boolean(dom['message-input'].value.trim());
    dom['send-btn'].disabled = state.isRunning || !hasText;
    if (!state.isRunning && dom['composer-mode-hint']) dom['composer-mode-hint'].textContent = MODES[state.mode].hint;
    if (state.isRunning && dom['composer-mode-hint']) dom['composer-mode-hint'].textContent = 'Tác nhân đang làm việc…';
    resizeComposer();
  }

  function resizeComposer() {
    if (!dom['message-input']) return;
    dom['message-input'].style.height = 'auto';
    dom['message-input'].style.height = Math.min(dom['message-input'].scrollHeight, 190) + 'px';
  }

  function renderAttachmentList() {
    if (!dom['attachment-list']) return;
    dom['attachment-list'].replaceChildren();
    setHidden(dom['attachment-list'], state.attachments.length === 0);
    state.attachments.forEach(function (attachment) {
      var chip = createNode('span', 'attachment-chip');
      chip.appendChild(createIcon('paperclip'));
      chip.appendChild(createNode('span', '', attachment.name || attachment.path || 'Tệp'));
      var remove = createNode('button', '');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Bỏ tệp ' + (attachment.name || 'đính kèm'));
      remove.appendChild(createIcon('x'));
      remove.addEventListener('click', function () {
        state.attachments = state.attachments.filter(function (item) { return item.id !== attachment.id; });
        renderAttachmentList();
        updateComposerState();
      });
      chip.appendChild(remove);
      dom['attachment-list'].appendChild(chip);
    });
  }

  function isNearBottom() {
    if (!dom['messages-container']) return true;
    var element = dom['messages-container'];
    return element.scrollHeight - element.scrollTop - element.clientHeight < 150;
  }

  function scrollToBottom(force) {
    if (!dom['messages-container']) return;
    if (force || isNearBottom()) {
      window.requestAnimationFrame(function () {
        dom['messages-container'].scrollTop = dom['messages-container'].scrollHeight;
      });
    }
  }

  function renderMessages() {
    if (!dom['messages-container']) return;
    var nearBottom = isNearBottom();
    dom['messages-container'].replaceChildren();
    if (!state.messages.length) {
      setHidden(dom['welcome-screen'], false);
      setHidden(dom['messages-container'], true);
      updateContextIndicator();
      return;
    }
    setHidden(dom['welcome-screen'], true);
    setHidden(dom['messages-container'], false);
    var list = createNode('div', 'message-list');
    state.messages.forEach(function (message) { list.appendChild(createMessageElement(message)); });
    dom['messages-container'].appendChild(list);
    updateContextIndicator();
    if (nearBottom) scrollToBottom(true);
  }

  function createMessageElement(message) {
    var wrapper = createNode('article', 'message ' + (message.role === 'user' ? 'user' : 'assistant'));
    wrapper.dataset.messageId = message.id;
    var avatar = createNode('div', 'message-avatar');
    avatar.appendChild(createIcon(message.role === 'user' ? 'user' : 'bot'));
    var contentWrap = createNode('div', 'message-content-wrap');
    var meta = createNode('div', 'message-meta');
    meta.appendChild(createNode('span', 'message-role', message.role === 'user' ? 'Bạn' : 'CodePilot'));
    meta.appendChild(createNode('span', 'message-time', formatClock(message.createdAt)));
    contentWrap.appendChild(meta);
    var visibleText = message.role === 'assistant' ? cleanModelText(message.text) : message.text;
    var bubble = createNode('div', 'message-bubble');
    if (message.error) {
      bubble.appendChild(createNode('div', 'message-error', safeError(message.error, 'Tác nhân gặp lỗi.')));
    } else if (visibleText || message.streaming) {
      renderMarkdown(bubble, visibleText);
      if (message.streaming) bubble.appendChild(createNode('span', 'stream-cursor'));
    } else {
      bubble.appendChild(createNode('span', 'muted-placeholder', message.role === 'user' ? 'Tin nhắn trống' : 'Đang suy nghĩ…'));
    }
    contentWrap.appendChild(bubble);
    if (message.attachments && message.attachments.length) {
      var attachmentRow = createNode('div', 'message-attachment-row');
      message.attachments.forEach(function (attachment) {
        var chip = createNode('button', 'message-attachment');
        chip.type = 'button';
        chip.setAttribute('aria-label', 'Mở vị trí tệp ' + (attachment.name || 'đính kèm'));
        chip.appendChild(createIcon('paperclip'));
        chip.appendChild(createNode('span', '', attachment.name || 'Tệp đính kèm'));
        if (attachment.path) {
          chip.addEventListener('click', function () {
            bridgeCall('revealPath', attachment.path).catch(function (error) {
              showToast('Không thể mở vị trí tệp', safeError(error, 'Tệp có thể đã được di chuyển.'), 'warning');
            });
          });
        }
        attachmentRow.appendChild(chip);
      });
      contentWrap.appendChild(attachmentRow);
    }
    var actions = createNode('div', 'message-actions');
    if (visibleText) {
      var copyButton = createNode('button', 'message-action');
      copyButton.type = 'button';
      copyButton.appendChild(createIcon('copy'));
      copyButton.appendChild(createNode('span', '', 'Sao chép'));
      copyButton.addEventListener('click', function () { copyText(visibleText); });
      actions.appendChild(copyButton);
    }
    if (message.role === 'assistant' && !message.streaming) {
      var regenerate = createNode('button', 'message-action');
      regenerate.type = 'button';
      regenerate.appendChild(createIcon('refresh'));
      regenerate.appendChild(createNode('span', '', message.error ? 'Thử lại' : 'Tạo lại'));
      regenerate.addEventListener('click', function () { regenerateMessage(message.id); });
      actions.appendChild(regenerate);
    }
    if (actions.childNodes.length) contentWrap.appendChild(actions);
    wrapper.appendChild(avatar);
    wrapper.appendChild(contentWrap);
    return wrapper;
  }

  function addMessage(message, options) {
    var normalized = normalizeMessage(message, (options && options.role) || 'assistant');
    if (!normalized.text && !normalized.streaming && !normalized.error) return null;
    var existingIndex = state.messages.findIndex(function (item) { return item.id === normalized.id; });
    var last = state.messages[state.messages.length - 1];
    if (existingIndex === -1 && normalized.role === 'assistant' && last && last.role === 'assistant' && (last.streaming || (!state.isRunning && last.text === 'Tác nhân chưa trả lời.'))) {
      normalized.id = last.id;
      normalized.streaming = Boolean(last.streaming);
      existingIndex = state.messages.length - 1;
    }
    if (existingIndex !== -1) {
      var existing = state.messages[existingIndex];
      state.messages[existingIndex] = Object.assign({}, existing, normalized, {
        streaming: normalized.streaming || (Boolean(options && options.keepStreaming) && existing.streaming)
      });
    } else {
      if (normalized.role === 'user' && last && last.role === 'user' && last.text === normalized.text && options && options.dedupe) {
        return last;
      }
      state.messages.push(normalized);
    }
    if (state.activeSession) {
      state.activeSession.messages = state.messages;
      state.activeSession.title = state.activeSession.title || deriveTitle(state.messages);
      state.activeSession.preview = derivePreview(state.messages);
      state.activeSession.updatedAt = new Date().toISOString();
      updateSessionInList(state.activeSession);
      renderSessions();
    }
    renderMessages();
    scrollToBottom(true);
    return normalized;
  }

  function ensureStreamMessage(sessionId, messageId) {
    var id = messageId || (streamMessageId || 'stream-' + (state.runId || 'current'));
    streamMessageId = id;
    var existing = state.messages.find(function (item) { return item.id === id; });
    if (existing) {
      existing.streaming = true;
      existing.error = '';
      return existing;
    }
    var message = {
      id: id,
      role: 'assistant',
      text: '',
      createdAt: new Date().toISOString(),
      attachments: [],
      streaming: true,
      error: '',
      status: 'streaming'
    };
    state.messages.push(message);
    renderMessages();
    scrollToBottom(true);
    return message;
  }

  function appendAssistantDelta(event) {
    var payload = event && typeof event === 'object' ? event : {};
    var sessionId = stringOr(field(payload, ['sessionId', 'session_id'], ''), '');
    if (sessionId && state.activeSessionId && sessionId !== state.activeSessionId) return;
    var eventRunId = stringOr(field(payload, ['runId', 'run_id'], ''), '');
    if (eventRunId && !state.runId) state.runId = eventRunId;
    var messageId = stringOr(field(payload, ['messageId', 'message_id', 'assistantMessageId'], ''), '') || streamMessageId;
    var message = ensureStreamMessage(sessionId, messageId);
    var delta = extractText(field(payload, ['delta', 'text', 'content', 'chunk', 'token'], ''));
    if (payload.full === true || payload.isFull === true || payload.replace === true) message.text = delta;
    else message.text += delta;
    message.streaming = true;
    renderMessages();
    updateContextIndicator();
  }

  function setStreamComplete(event) {
    var payload = event && typeof event === 'object' ? event : {};
    var messageId = stringOr(field(payload, ['messageId', 'message_id'], ''), '') || streamMessageId;
    var message = state.messages.find(function (item) { return item.id === messageId; });
    if (!message && streamMessageId) message = state.messages.find(function (item) { return item.id === streamMessageId; });
    if (message) {
      var eventText = extractText(field(payload, ['text', 'content', 'message'], ''));
      if (eventText && !message.text) message.text = eventText;
      if (!message.text) message.text = 'Tác nhân chưa trả lời.';
      message.streaming = false;
      message.status = 'done';
      message.error = '';
    }
    streamMessageId = null;
  }

  async function copyText(text) {
    var value = stringOr(text, '');
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(value);
      else throw new Error('clipboard unavailable');
      showToast('Đã sao chép', 'Nội dung nằm trong clipboard.');
    } catch (_) {
      var helper = document.createElement('textarea');
      helper.value = value;
      helper.setAttribute('readonly', '');
      helper.style.position = 'fixed';
      helper.style.opacity = '0';
      document.body.appendChild(helper);
      helper.select();
      try { document.execCommand('copy'); showToast('Đã sao chép', 'Nội dung nằm trong clipboard.'); } catch (error) { showToast('Không thể sao chép', 'Hãy chọn và sao chép thủ công.', 'warning'); }
      helper.remove();
    }
  }

  function openSafeLink(url) {
    if (!isSafeHttpUrl(url)) return;
    bridgeCall('openExternal', url).catch(function (error) {
      showToast('Không thể mở liên kết', safeError(error, 'Hãy kiểm tra liên kết.'), 'warning');
    });
  }

  function isSafeHttpUrl(value) {
    if (typeof value !== 'string') return false;
    var url = value.trim();
    if (!/^https?:\/\//i.test(url)) return false;
    try {
      var parsed = new URL(url);
      if (parsed.username || parsed.password) return false;
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  // Model text is rendered with DOM text nodes and validated elements only. This
  // escape helper is the explicit boundary for any future markup sink; no model
  // string is ever interpreted as markup in this renderer.
  function escapeHtml(value) {
    return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, function (character) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character];
    });
  }

  function appendInline(parent, input) {
    var text = stringOr(input, '');
    var buffer = '';
    function flush() {
      if (buffer) { parent.appendChild(document.createTextNode(buffer)); buffer = ''; }
    }
    function findClosing(value, start, token) {
      var index = value.indexOf(token, start);
      while (index !== -1 && value[index - 1] === '\\') index = value.indexOf(token, index + 1);
      return index;
    }
    var index = 0;
    while (index < text.length) {
      var character = text[index];
      if (character === '\\' && index + 1 < text.length) {
        buffer += text[index + 1];
        index += 2;
        continue;
      }
      if (character === '`') {
        var codeEnd = findClosing(text, index + 1, '`');
        if (codeEnd !== -1) {
          flush();
          var inlineCode = createNode('code', 'inline-code', text.slice(index + 1, codeEnd).replace(/^ | $/g, ''));
          parent.appendChild(inlineCode);
          index = codeEnd + 1;
          continue;
        }
      }
      if (character === '[') {
        var labelEnd = text.indexOf('](', index + 1);
        if (labelEnd !== -1) {
          var urlEnd = text.indexOf(')', labelEnd + 2);
          if (urlEnd !== -1) {
            var label = text.slice(index + 1, labelEnd);
            var url = text.slice(labelEnd + 2, urlEnd).trim();
            if (isSafeHttpUrl(url)) {
              flush();
              var link = document.createElement('a');
              link.className = 'markdown-link';
              link.href = url;
              link.target = '_blank';
              link.rel = 'noopener noreferrer';
              appendInline(link, label);
              link.addEventListener('click', (function (safeUrl) {
                return function (event) {
                  event.preventDefault();
                  openSafeLink(safeUrl);
                };
              }(url)));
              parent.appendChild(link);
              index = urlEnd + 1;
              continue;
            }
          }
        }
      }
      if (character === '*' && text[index + 1] === '*') {
        var strongEnd = findClosing(text, index + 2, '**');
        if (strongEnd !== -1 && strongEnd > index + 2) {
          flush();
          var strong = createNode('strong');
          appendInline(strong, text.slice(index + 2, strongEnd));
          parent.appendChild(strong);
          index = strongEnd + 2;
          continue;
        }
      }
      if (character === '*' || character === '_') {
        if (character === '_' && (index > 0 && /\w/.test(text[index - 1]) || index + 1 < text.length && /\w/.test(text[index + 1]))) {
          buffer += character;
          index += 1;
          continue;
        }
        var italicEnd = findClosing(text, index + 1, character);
        if (italicEnd > index + 1 && !/\s/.test(text[index + 1])) {
          flush();
          var italic = createNode('em');
          appendInline(italic, text.slice(index + 1, italicEnd));
          parent.appendChild(italic);
          index = italicEnd + 1;
          continue;
        }
      }
      if (character === '~' && text[index + 1] === '~') {
        var delEnd = findClosing(text, index + 2, '~~');
        if (delEnd !== -1 && delEnd > index + 2) {
          flush();
          var deleted = createNode('del');
          appendInline(deleted, text.slice(index + 2, delEnd));
          parent.appendChild(deleted);
          index = delEnd + 2;
          continue;
        }
      }
      if ((character === 'h' || character === 'H') && /^https?:\/\/[^\s<]+/i.test(text.slice(index))) {
        var autoMatch = text.slice(index).match(/^https?:\/\/[^\s<]+/i);
        var autoUrl = autoMatch ? autoMatch[0].replace(/[),.!?;]+$/, '') : '';
        if (isSafeHttpUrl(autoUrl)) {
          flush();
          var autoLink = document.createElement('a');
          autoLink.className = 'markdown-link';
          autoLink.href = autoUrl;
          autoLink.target = '_blank';
          autoLink.rel = 'noopener noreferrer';
          autoLink.textContent = autoUrl;
          autoLink.addEventListener('click', (function (safeUrl) {
            return function (event) { event.preventDefault(); openSafeLink(safeUrl); };
          }(autoUrl)));
          parent.appendChild(autoLink);
          index += autoUrl.length;
          continue;
        }
      }
      if (character === '\n') {
        buffer += ' ';
        index += 1;
        continue;
      }
      buffer += character;
      index += 1;
    }
    flush();
  }

  function isBlockStart(line) {
    return /^\s*$/.test(line) || /^\s*```/.test(line) || /^\s*#{1,6}\s+/.test(line) || /^\s*[-*+]\s+/.test(line) || /^\s*\d+[.)]\s+/.test(line) || /^\s*>\s?/.test(line) || /^\s*(?:---+|___+|\*\*\*+)\s*$/.test(line);
  }

  function renderMarkdown(container, source) {
    container.replaceChildren();
    var text = stringOr(source, '').replace(/\r\n?/g, '\n');
    if (!text) return;
    var lines = text.split('\n');
    var index = 0;
    while (index < lines.length) {
      var line = lines[index];
      if (/^\s*$/.test(line)) { index += 1; continue; }
      var fence = line.match(/^\s*```\s*([A-Za-z0-9_+.-]*)\s*$/);
      if (fence) {
        var codeLines = [];
        index += 1;
        while (index < lines.length && !/^\s*```\s*$/.test(lines[index])) {
          codeLines.push(lines[index]);
          index += 1;
        }
        if (index < lines.length) index += 1;
        appendCodeBlock(container, fence[1] || 'text', codeLines.join('\n'));
        continue;
      }
      var heading = line.match(/^\s*(#{1,6})\s+(.+?)\s*#*\s*$/);
      if (heading) {
        var headingNode = createNode('h' + Math.min(6, heading[1].length));
        appendInline(headingNode, heading[2]);
        container.appendChild(headingNode);
        index += 1;
        continue;
      }
      if (/^\s*(?:---+|___+|\*\*\*+)\s*$/.test(line)) {
        container.appendChild(createNode('hr'));
        index += 1;
        continue;
      }
      var unordered = line.match(/^\s*[-*+]\s+(.+)$/);
      var ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (unordered || ordered) {
        var list = createNode(unordered ? 'ul' : 'ol');
        var listType = unordered ? 'unordered' : 'ordered';
        while (index < lines.length) {
          var listMatch = listType === 'unordered'
            ? lines[index].match(/^\s*[-*+]\s+(.+)$/)
            : lines[index].match(/^\s*\d+[.)]\s+(.+)$/);
          if (!listMatch) break;
          var item = createNode('li');
          appendInline(item, listMatch[1]);
          list.appendChild(item);
          index += 1;
        }
        container.appendChild(list);
        continue;
      }
      if (/^\s*>\s?/.test(line)) {
        var quoteLines = [];
        while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
          quoteLines.push(lines[index].replace(/^\s*>\s?/, ''));
          index += 1;
        }
        var quote = createNode('blockquote');
        appendInline(quote, quoteLines.join(' '));
        container.appendChild(quote);
        continue;
      }
      var paragraphLines = [line.trim()];
      index += 1;
      while (index < lines.length && !isBlockStart(lines[index])) {
        paragraphLines.push(lines[index].trim());
        index += 1;
      }
      var paragraph = createNode('p');
      appendInline(paragraph, paragraphLines.join('\n'));
      container.appendChild(paragraph);
    }
  }

  function appendCodeBlock(parent, language, code) {
    var wrapper = createNode('div', 'code-block');
    var header = createNode('div', 'code-header');
    header.appendChild(createNode('span', 'code-language', language || 'text'));
    var copyButton = createNode('button', 'code-copy-button');
    copyButton.type = 'button';
    copyButton.setAttribute('aria-label', 'Sao chép mã nguồn');
    copyButton.appendChild(createIcon('copy'));
    copyButton.appendChild(createNode('span', '', 'Sao chép'));
    copyButton.addEventListener('click', function () { copyText(code); });
    header.appendChild(copyButton);
    var pre = createNode('pre');
    var codeNode = createNode('code', '', code);
    pre.appendChild(codeNode);
    wrapper.appendChild(header);
    wrapper.appendChild(pre);
    parent.appendChild(wrapper);
  }

  function setRunning(running) {
    state.isRunning = Boolean(running);
    setHidden(dom['stop-btn'], !state.isRunning);
    updateComposerState();
    if (!state.isRunning && dom['composer-mode-hint']) dom['composer-mode-hint'].textContent = MODES[state.mode].hint;
    updateActivitySummary();
  }

  async function sendMessage(options) {
    var request = options || {};
    if (state.isRunning) return;
    var text = request.text !== undefined ? String(request.text || '').trim() : dom['message-input'].value.trim();
    var attachments = state.attachments.slice();
    if (!text && attachments.length === 0) return;
    try {
      if (!state.activeSessionId) await createNewSession();
      var sessionId = state.activeSessionId;
      if (!sessionId) throw new Error('Chưa có phiên');
      var userId = 'user-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
      var userMessage = {
        id: userId,
        role: 'user',
        text: text,
        createdAt: new Date().toISOString(),
        attachments: attachments,
        streaming: false,
        error: '',
        status: 'done'
      };
      state.lastPrompt = text;
      state.attachments = [];
      renderAttachmentList();
      dom['message-input'].value = '';
      resizeComposer();
      addMessage(userMessage, { dedupe: true });
      var assistantId = 'assistant-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
      ensureStreamMessage(sessionId, assistantId);
      state.runId = null;
      state.activityError = false;
      streamMessageId = state.messages[state.messages.length - 1] ? state.messages[state.messages.length - 1].id : streamMessageId;
      setRunning(true);
      addActivity('stage', { title: 'Bắt đầu lượt làm việc', detail: MODES[state.mode].label + ' · đang chuẩn bị ngữ cảnh', status: 'running' });
      var sendPayload = { sessionId: sessionId, text: text, mode: state.mode, clientMessageId: userId, clientAssistantMessageId: assistantId };
      if (attachments.length) sendPayload.attachments = attachments;
      var result = await bridgeCall('sendMessage', sendPayload);
      if (result && result.ok === false) throw new Error(field(result, ['error', 'message'], 'Tác nhân chưa thể bắt đầu.'));
      state.runId = stringOr(field(result, ['runId', 'run_id', 'id'], ''), '') || stringOr(field(field(result, 'run'), ['id', 'runId', 'run_id'], ''), '') || state.runId;
      var responseMessage = field(result, ['message', 'assistantMessage'], null);
      if (responseMessage) addMessage(responseMessage, { role: 'assistant', keepStreaming: true });
      var resultStatus = stringOr(field(result, ['status', 'state'], ''), '').toLowerCase();
      if (resultStatus === 'complete' || resultStatus === 'completed' || resultStatus === 'error' || resultStatus === 'cancelled') {
        if (resultStatus === 'error' || resultStatus === 'cancelled') finishRun({ type: 'run-' + resultStatus, error: field(result, ['error', 'message'], '') });
        else finishRun({ type: 'run-complete' });
      }
    } catch (error) {
      if (streamMessageId) {
        var stream = state.messages.find(function (message) { return message.id === streamMessageId; });
        if (stream) { stream.streaming = false; stream.error = safeError(error, 'Không thể gửi tin nhắn.'); }
      }
      setRunning(false);
      addActivity('error', { title: 'Không thể gửi tin nhắn', detail: 'Hãy kiểm tra kết nối LM Studio.', status: 'error' });
      showToast('Gửi tin nhắn thất bại', safeError(error, 'Tác nhân chưa thể bắt đầu.'), 'error');
      renderMessages();
    }
  }

  function clearInteractionUi() {
    if (state.pendingAsk) { state.pendingAsk = null; closeModal('ask-user-modal'); }
    if (state.pendingApproval) { state.pendingApproval = null; closeModal('approval-modal'); }
  }

  function finishRun(event) {
    var payload = event || {};
    clearInteractionUi();
    setStreamComplete(payload);
    setRunning(false);
    state.runId = null;
    state.activityError = false;
    var runningEntries = state.activity.filter(function (entry) { return entry.status === 'running'; });
    runningEntries.forEach(function (entry) { entry.status = 'success'; });
    renderActivity();
    if (state.activeSession) {
      state.activeSession.messages = state.messages;
      state.activeSession.title = stringOr(field(payload, ['title'], state.activeSession.title), state.activeSession.title) || deriveTitle(state.messages);
      state.activeSession.preview = derivePreview(state.messages);
      state.activeSession.updatedAt = new Date().toISOString();
      updateSessionInList(state.activeSession);
    }
    if (state.activeSessionId) {
      bridgeCall('getSession', state.activeSessionId).then(function (result) {
        var serverSession = normalizeSession(unwrap(result, 'session') || result, 0);
        if (serverSession.messages && serverSession.messages.length >= state.messages.length) {
          state.activeSession = serverSession;
          state.messages = serverSession.messages;
          renderMessages();
        }
        renderSessions();
      }).catch(function () {});
    }
    updateContextIndicator();
  }

  function failRun(event) {
    var payload = event || {};
    clearInteractionUi();
    var errorText = safeError(field(payload, ['error', 'message', 'detail'], ''), 'Tác nhân gặp lỗi.');
    if (streamMessageId) {
      var stream = state.messages.find(function (message) { return message.id === streamMessageId; });
      if (stream) { stream.streaming = false; stream.error = errorText; }
    }
    streamMessageId = null;
    state.activityError = true;
    setRunning(false);
    state.runId = null;
    addActivity('error', { title: 'Lượt chạy kết thúc lỗi', detail: 'Không có thay đổi nào được ghi đè.', status: 'error' });
    renderMessages();
    showToast('Tác nhân gặp lỗi', errorText, 'error');
  }

  function cancelRun() {
    if (!state.runId) {
      showToast('Chưa có lượt chạy', 'Không có tác vụ nào đang chờ dừng.', 'warning');
      return;
    }
    var runId = state.runId;
    bridgeCall('cancelRun', runId).then(function (result) {
      if (result && result.cancelled === false) {
        showToast('Lượt chạy đã kết thúc', 'Không còn tác vụ nào để dừng.', 'warning');
        return;
      }
      setRunning(false);
      if (streamMessageId) {
        var stoppingStream = state.messages.find(function (message) { return message.id === streamMessageId; });
        if (stoppingStream) {
          stoppingStream.streaming = false;
          if (!stoppingStream.text) stoppingStream.text = 'Đang dừng lượt trả lời…';
          renderMessages();
        }
      }
      streamMessageId = null;
      showToast('Đang dừng', 'Tác nhân sẽ dừng ở bước an toàn tiếp theo.');
    }).catch(function (error) {
      showToast('Không thể dừng', safeError(error, 'Hãy thử lại.'), 'error');
    });
  }

  function regenerateMessage(messageId) {
    if (state.isRunning) return;
    var index = state.messages.findIndex(function (message) { return message.id === messageId; });
    var prompt = '';
    for (var i = index - 1; i >= 0; i -= 1) {
      if (state.messages[i].role === 'user' && state.messages[i].text) { prompt = state.messages[i].text; break; }
    }
    if (!prompt) prompt = state.lastPrompt;
    if (!prompt) {
      showToast('Không tìm thấy câu hỏi', 'Hãy gửi một yêu cầu mới.', 'warning');
      return;
    }
    dom['message-input'].value = prompt;
    resizeComposer();
    sendMessage({ text: prompt });
  }

  function addActivity(kind, data) {
    var info = data || {};
    var id = stringOr(info.id, '') || 'activity-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
    var existingIndex = state.activity.findIndex(function (entry) { return entry.id === id; });
    var entry = {
      id: id,
      kind: kind,
      title: stringOr(info.title, humanizeLabel(kind)),
      detail: stringOr(info.detail, ''),
      status: stringOr(info.status, kind === 'error' ? 'error' : 'running'),
      tool: stringOr(info.tool, ''),
      startedAt: info.startedAt || Date.now(),
      duration: numberOr(info.duration, 0, 0),
      language: stringOr(info.language, '')
    };
    if (existingIndex !== -1) state.activity[existingIndex] = Object.assign({}, state.activity[existingIndex], entry);
    else state.activity.push(entry);
    if (entry.status === 'error') state.activityError = true;
    if (!state.activityStartedAt) state.activityStartedAt = Date.now();
    startActivityClock();
    renderActivity();
    return entry;
  }

  function humanizeLabel(value) {
    var text = stringOr(value, 'Hoạt động').replace(/[_-]+/g, ' ').trim();
    if (!text) return 'Hoạt động';
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  function humanizeTool(tool) {
    var name = stringOr(tool, 'tool').trim();
    var lower = name.toLowerCase();
    return TOOL_LABELS[lower] || humanizeLabel(name.replace(/[_-]+/g, ' '));
  }

  function summarizeValue(value, depth) {
    var level = depth || 0;
    if (value === undefined || value === null || value === '') return '';
    if (typeof value === 'string') {
      var clean = value.replace(/\s+/g, ' ').replace(/(bearer\s+)[^\s,;]+/gi, '$1[redacted]').replace(/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}\b/g, '[redacted]').trim();
      if (/^[\[{]/.test(clean) || /tool_call|tool_request|tool_response|TOOL_REQUEST|TOOL_RESULT/i.test(clean)) return 'Kết quả công cụ đã rút gọn';
      return truncate(clean, 150);
    }
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (Array.isArray(value)) return value.length ? value.length + ' mục' : 'mảng trống';
    if (typeof value === 'object') {
      if (level >= 1) return 'thông tin đã rút gọn';
      var keys = Object.keys(value).slice(0, 3);
      if (!keys.length) return 'thông tin đã rút gọn';
      return keys.map(function (key) { return humanizeLabel(key) + ': ' + summarizeValue(value[key], level + 1); }).join(' · ');
    }
    return 'thông tin đã rút gọn';
  }

  function formatDuration(milliseconds) {
    var value = numberOr(milliseconds, 0, 0);
    if (value < 1000) return Math.max(1, Math.round(value)) + 'ms';
    if (value < 60000) return (value / 1000).toFixed(value < 10000 ? 1 : 0) + 's';
    var minutes = Math.floor(value / 60000);
    var seconds = Math.floor((value % 60000) / 1000);
    return minutes + 'm ' + seconds + 's';
  }

  function activityIcon(entry) {
    if (entry.kind === 'tool') return 'terminal';
    if (entry.kind === 'subagent') return 'subagent';
    if (entry.kind === 'error') return 'error';
    if (entry.kind === 'result') return 'check';
    return entry.status === 'success' ? 'check' : 'activity';
  }

  function renderActivity() {
    if (!dom['activity-timeline']) return;
    dom['activity-timeline'].replaceChildren();
    if (!state.activity.length) {
      var empty = createNode('div', 'activity-empty');
      var emptyIcon = createNode('span', 'activity-empty-icon');
      emptyIcon.appendChild(createIcon('activity'));
      empty.appendChild(emptyIcon);
      empty.appendChild(createNode('strong', '', 'Chưa có hoạt động'));
      empty.appendChild(createNode('span', '', 'Các bước của tác nhân sẽ xuất hiện ở đây.'));
      dom['activity-timeline'].appendChild(empty);
    } else {
      var entries = state.activity.slice().reverse();
      entries.forEach(function (entry) {
        dom['activity-timeline'].appendChild(createActivityElement(entry));
      });
    }
    updateActivitySummary();
  }

  function createActivityElement(entry) {
    var wrapper = createNode('div', 'activity-entry ' + (entry.status || 'running'));
    var dot = createNode('div', 'activity-entry-dot');
    dot.appendChild(createIcon(activityIcon(entry)));
    var body = createNode('div', 'activity-entry-body');
    if (entry.kind === 'tool') {
      var card = createNode('div', 'activity-tool-card is-' + (entry.status || 'running'));
      var toggle = createNode('button', 'activity-tool-toggle');
      toggle.type = 'button';
      toggle.setAttribute('aria-expanded', 'false');
      toggle.appendChild(createIcon('chevron-right'));
      toggle.appendChild(createNode('strong', '', entry.title));
      var toolStatus = entry.status === 'running' ? 'đang chạy' : entry.status === 'error' ? 'lỗi' : 'xong';
      var toolDuration = entry.duration || (entry.status !== 'running' ? Math.max(0, Date.now() - entry.startedAt) : 0);
      if (toolDuration) toolStatus += ' · ' + formatDuration(toolDuration);
      toggle.appendChild(createNode('span', 'activity-tool-status', toolStatus));
      var detail = createNode('p', 'activity-tool-detail');
      detail.textContent = entry.detail || 'Không có chi tiết bổ sung.';
      toggle.addEventListener('click', function () {
        var open = toggle.getAttribute('aria-expanded') === 'true';
        toggle.setAttribute('aria-expanded', String(!open));
        detail.classList.toggle('is-open', !open);
      });
      card.appendChild(toggle);
      card.appendChild(detail);
      body.appendChild(card);
    } else if (entry.kind === 'subagent') {
      var subagentCard = createNode('div', 'subagent-card');
      var subagentHeading = createNode('div', 'subagent-heading');
      subagentHeading.appendChild(createIcon('bot'));
      subagentHeading.appendChild(createNode('strong', '', entry.title));
      subagentHeading.appendChild(createNode('span', 'subagent-state', entry.status === 'running' ? 'đang chạy' : entry.status === 'error' ? 'lỗi' : 'xong'));
      subagentCard.appendChild(subagentHeading);
      if (entry.detail) subagentCard.appendChild(createNode('p', 'subagent-detail', entry.detail));
      body.appendChild(subagentCard);
    } else {
      var title = createNode('div', 'activity-entry-title');
      title.appendChild(createNode('span', '', entry.title));
      title.appendChild(createNode('span', '', entry.status === 'running' ? 'đang chạy' : entry.status === 'error' ? 'lỗi' : 'xong'));
      body.appendChild(title);
      if (entry.detail) body.appendChild(createNode('p', 'activity-entry-detail', entry.detail));
    }
    wrapper.appendChild(dot);
    wrapper.appendChild(body);
    return wrapper;
  }

  function updateActivitySummary() {
    var running = state.activity.some(function (entry) { return entry.status === 'running'; });
    var statusText = state.isRunning ? 'Đang làm việc' : state.activityError ? 'Có lỗi' : state.activity.length ? 'Đã hoàn tất' : 'Sẵn sàng';
    if (dom['summary-status-text']) dom['summary-status-text'].textContent = statusText;
    if (dom['summary-dot']) dom['summary-dot'].className = 'summary-dot' + (state.activityError ? ' is-offline' : running || state.isRunning ? ' is-warn' : '');
    var count = state.activity.filter(function (entry) { return entry.status === 'running'; }).length;
    if (dom['activity-count']) {
      dom['activity-count'].textContent = String(count);
      setHidden(dom['activity-count'], count === 0);
    }
    if (dom['activity-duration']) {
      dom['activity-duration'].textContent = state.activityStartedAt ? formatDuration(Date.now() - state.activityStartedAt) : '—';
    }
  }

  function startActivityClock() {
    if (activityTimer) return;
    activityTimer = window.setInterval(updateActivitySummary, 1000);
  }

  function updateContextIndicator() {
    var chars = state.messages.reduce(function (total, message) { return total + (message.text ? message.text.length : 0); }, 0);
    var limit = numberOr(state.settings.contextChars, DEFAULT_SETTINGS.contextChars, 1000, 2000000);
    if (dom['context-indicator']) {
      var contextText = dom['context-indicator'].querySelector('span');
      if (contextText) contextText.textContent = formatLimit(chars) + ' / ' + formatLimit(limit) + ' ngữ cảnh';
    }
    if (dom['token-indicator']) {
      var tokenText = dom['token-indicator'].querySelector('span');
      var estimatedTokens = Math.ceil(chars / 4);
      if (tokenText) tokenText.textContent = '~' + formatLimit(estimatedTokens) + ' token' + (state.settings.model ? ' · ' + truncate(state.settings.model, 22) : ' · Không dùng API ngoài');
    }
  }

  function formatLimit(value) {
    var number = numberOr(value, 0, 0);
    if (number >= 1000000) return (number / 1000000).toFixed(number % 1000000 ? 1 : 0) + 'M';
    if (number >= 1000) return (number / 1000).toFixed(number % 1000 ? 0 : 0) + 'k';
    return String(Math.round(number));
  }

  function openModal(id, focusSelector) {
    var element = dom[id] || byId(id);
    if (!element) return;
    modalReturnFocus[id] = document.activeElement;
    setHidden(element, false);
    element.setAttribute('aria-hidden', 'false');
    window.setTimeout(function () {
      var focusTarget = focusSelector ? element.querySelector(focusSelector) : null;
      if (focusTarget) focusTarget.focus();
    }, 20);
  }

  function closeModal(id) {
    var element = dom[id] || byId(id);
    if (!element) return;
    setHidden(element, true);
    element.setAttribute('aria-hidden', 'true');
    var previous = modalReturnFocus[id];
    if (previous && typeof previous.focus === 'function') previous.focus();
  }

  function setOnboardingStep(step) {
    state.onboarding.step = numberOr(step, 1, 1, 3);
    document.querySelectorAll('[data-onboarding-step]').forEach(function (panel) {
      var active = Number(panel.getAttribute('data-onboarding-step')) === state.onboarding.step;
      panel.hidden = !active;
      panel.classList.toggle('is-visible', active);
    });
    document.querySelectorAll('[data-onboarding-indicator]').forEach(function (indicator) {
      var indicatorStep = Number(indicator.getAttribute('data-onboarding-indicator'));
      indicator.classList.toggle('is-active', indicatorStep === state.onboarding.step);
      indicator.classList.toggle('is-done', indicatorStep < state.onboarding.step);
    });
    setHidden(dom['onboarding-back-btn'], state.onboarding.step === 1);
    if (dom['onboarding-continue']) {
      dom['onboarding-continue'].replaceChildren();
      dom['onboarding-continue'].appendChild(document.createTextNode(state.onboarding.step === 3 ? 'Hoàn tất' : 'Tiếp tục'));
      dom['onboarding-continue'].appendChild(createIcon('chevron-right'));
    }
    updateOnboardingContinue();
  }

  function updateOnboardingContinue() {
    if (!dom['onboarding-continue']) return;
    var disabled = true;
    if (state.onboarding.step === 1) disabled = !state.onboarding.reachable;
    if (state.onboarding.step === 2) disabled = !state.onboarding.reachable || !state.onboarding.model;
    if (state.onboarding.step === 3) disabled = !state.onboarding.reachable;
    dom['onboarding-continue'].disabled = disabled;
    if (dom['onboarding-load-btn']) dom['onboarding-load-btn'].disabled = !state.onboarding.model;
    if (dom['onboarding-model-loaded']) {
      setHidden(dom['onboarding-model-loaded'], !state.onboarding.modelLoaded);
      if (state.onboarding.modelLoaded) setText(dom['onboarding-loaded-name'], state.onboarding.model + ' đã sẵn sàng');
    }
  }

  function openOnboarding() {
    setOnboardingStep(1);
    openModal('onboarding-modal', '#onboarding-test-btn');
    window.setTimeout(function () { refreshLmStatus({ quiet: true }); }, 120);
  }

  function closeOnboarding() {
    closeModal('onboarding-modal');
  }

  async function testOnboardingConnection() {
    var button = dom['onboarding-test-btn'];
    if (button) button.disabled = true;
    setText(dom['onboarding-connection-title'], 'Đang kiểm tra');
    setText(dom['onboarding-connection-detail'], 'Đang tìm LM Studio trên localhost…');
    setHidden(dom['onboarding-error'], true);
    var result = await refreshLmStatus({ quiet: false });
    if (button) button.disabled = false;
    var reachable = result && normalizeLmStatus(result).reachable;
    if (reachable) {
      setText(dom['onboarding-connection-title'], 'Kết nối thành công');
      setText(dom['onboarding-connection-detail'], 'LM Studio đã sẵn sàng. Bạn có thể chọn mô hình.');
      showToast('Đã kết nối LM Studio', 'Có thể tiếp tục thiết lập.');
    } else {
      setText(dom['onboarding-connection-title'], 'Chưa kết nối');
      setText(dom['onboarding-connection-detail'], 'Hãy bật Local Server trong LM Studio rồi thử lại.');
      setText(dom['onboarding-error'], 'Không tìm thấy LM Studio. Bạn có thể bật ứng dụng hoặc kiểm tra cổng 1234.');
      setHidden(dom['onboarding-error'], false);
    }
  }

  async function startLmStudio() {
    var button = dom['onboarding-start-btn'];
    if (button) button.disabled = true;
    try {
      await bridgeCall('startLmStudio');
      showToast('Đang mở LM Studio', 'Đợi ứng dụng khởi động rồi kiểm tra lại.');
      window.setTimeout(testOnboardingConnection, 1200);
    } catch (error) {
      showToast('Không thể mở LM Studio', safeError(error, 'Hãy mở LM Studio thủ công.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function installLmCli() {
    var button = dom['onboarding-install-btn'];
    if (button) button.disabled = true;
    try {
      var result = await bridgeCall('installLmCli');
      if (result === false || (result && result.ok === false)) throw new Error('Cài đặt chưa hoàn tất');
      showToast('Đã yêu cầu cài lms CLI', 'Lệnh sẽ được xử lý qua ứng dụng.');
    } catch (error) {
      showToast('Không thể cài lms CLI', safeError(error, 'Hãy cài CLI theo hướng dẫn của LM Studio.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function loadOnboardingModel() {
    var modelId = state.onboarding.model || (dom['onboarding-model-select'] && dom['onboarding-model-select'].value);
    if (!modelId) {
      showToast('Chưa chọn mô hình', 'Hãy chọn một mô hình trong danh sách.', 'warning');
      return false;
    }
    var button = dom['onboarding-load-btn'];
    if (button) button.disabled = true;
    try {
      var result = await bridgeCall('loadModel', modelId);
      if (result === false || (result && result.ok === false)) throw new Error('Mô hình chưa được nạp');
      state.onboarding.model = modelId;
      state.onboarding.modelLoaded = true;
      state.settings.model = modelId;
      updateOnboardingContinue();
      showToast('Mô hình đã sẵn sàng', modelId);
      return true;
    } catch (error) {
      showToast('Không thể nạp mô hình', safeError(error, 'Kiểm tra lại LM Studio.'), 'error');
      return false;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function onboardingContinue() {
    if (state.onboarding.step === 1) {
      if (!state.onboarding.reachable) return;
      setOnboardingStep(2);
      return;
    }
    if (state.onboarding.step === 2) {
      if (!state.onboarding.model) return;
      if (!state.onboarding.modelLoaded) {
        var loaded = await loadOnboardingModel();
        if (!loaded) return;
      }
      setOnboardingStep(3);
      return;
    }
    writeStorage(STORAGE.onboardingComplete, '1');
    try { await bridgeCall('updateSettings', { workspace: state.workspace, model: state.onboarding.model || state.settings.model }); } catch (_) {}
    closeOnboarding();
    showToast('Thiết lập hoàn tất', 'Chào mừng bạn đến với CodePilot.');
  }

  function modelForPreset(presetId) {
    var preset = MODEL_PRESETS[presetId];
    if (!preset || presetId === 'custom') return '';
    var models = state.lmStatus && Array.isArray(state.lmStatus.models) ? state.lmStatus.models : [];
    var terms = presetId === 'qwen3-4b-1050ti'
      ? ['qwen3', '4b']
      : presetId === 'qwen25-coder-3b'
        ? ['qwen2.5-coder', '3b']
        : ['qwen2.5-coder', '14b'];
    var match = models.find(function (item) {
      var value = (String(item.id || '') + ' ' + String(item.name || '') + ' ' + String(item.displayName || '')).toLowerCase();
      return terms.every(function (term) { return value.includes(term); });
    });
    return match ? String(match.id || '') : preset.model;
  }

  function applyModelPreset(presetId) {
    var preset = MODEL_PRESETS[presetId];
    if (!preset) return;
    if (dom['settings-model-preset']) dom['settings-model-preset'].value = presetId;
    if (dom['settings-model-preset-hint']) {
      dom['settings-model-preset-hint'].textContent = presetId === 'custom'
        ? 'Đang dùng cấu hình tùy chỉnh; app không tự tải model.'
        : 'Preset chỉ điền cấu hình; app không tự tải model.';
    }
    if (presetId === 'custom') return;
    if (dom['settings-model']) dom['settings-model'].value = modelForPreset(presetId);
    if (dom['settings-max-tokens']) dom['settings-max-tokens'].value = preset.maxTokens;
    if (dom['settings-context-length']) dom['settings-context-length'].value = preset.contextLength;
    if (dom['settings-context-chars']) dom['settings-context-chars'].value = preset.contextChars;
    if (dom['settings-max-steps']) dom['settings-max-steps'].value = preset.maxSteps;
    if (dom['settings-max-subagents']) dom['settings-max-subagents'].value = preset.maxSubagents;
    if (dom['settings-concurrent-subagents']) dom['settings-concurrent-subagents'].value = preset.concurrentSubagents;
    if (dom['settings-flash-attention']) dom['settings-flash-attention'].checked = preset.flashAttention;
  }

  function markModelPresetCustom() {
    if (dom['settings-model-preset'] && dom['settings-model-preset'].value !== 'custom') {
      dom['settings-model-preset'].value = 'custom';
      if (dom['settings-model-preset-hint']) dom['settings-model-preset-hint'].textContent = 'Đang dùng cấu hình tùy chỉnh; app không tự tải model.';
    }
  }

  function populateSettingsForm() {
    var settings = state.settings;
    if (!dom['settings-workspace']) return;
    dom['settings-workspace'].value = settings.workspace || '';
    dom['settings-theme'].value = settings.theme || 'dark';
    dom['settings-lm-url'].value = settings.lmBaseUrl || DEFAULT_SETTINGS.lmBaseUrl;
    dom['settings-model-preset'].value = MODEL_PRESETS[settings.modelPreset] ? settings.modelPreset : 'custom';
    dom['settings-model'].value = settings.model || '';
    dom['settings-temperature'].value = settings.temperature;
    dom['settings-max-tokens'].value = settings.maxTokens;
    dom['settings-context-length'].value = settings.contextLength;
    dom['settings-context-chars'].value = settings.contextChars;
    dom['settings-flash-attention'].checked = settings.flashAttention !== false;
    dom['settings-max-steps'].value = settings.maxSteps;
    dom['settings-approval-mode'].value = settings.approvalMode;
    dom['settings-max-subagents'].value = settings.maxSubagents;
    dom['settings-concurrent-subagents'].value = settings.concurrentSubagents;
    dom['settings-allow-fallback-tools'].checked = settings.allowFallbackTools !== false;
    dom['settings-ddg-fallback'].checked = Boolean(settings.ddgFallback);
    dom['settings-brave-key'].value = '';
    dom['settings-brave-key'].placeholder = (settings.braveApiKeyPresent || settings.braveApiKey) ? 'Đã lưu — nhập lại để thay đổi' : 'Chưa cấu hình';
    dom['settings-mcp-json'].value = settings.mcpServers || '{}';
  }

  function collectSettingsForm() {
    if (!dom['settings-mcp-json']) return null;
    var mcpText = dom['settings-mcp-json'].value.trim() || '{}';
    var mcpValue;
    try { mcpValue = JSON.parse(mcpText); } catch (_) { showToast('JSON MCP chưa hợp lệ', 'Hãy kiểm tra dấu ngoặc và dấu phẩy.', 'error'); return null; }
    if (!mcpValue || typeof mcpValue !== 'object') { showToast('JSON MCP chưa hợp lệ', 'Danh sách phải là object.', 'error'); return null; }
    mcpValue = normalizeMcpValue(mcpValue);
    var brave = dom['settings-brave-key'].value.trim();
    var maxSubagents = numberOr(dom['settings-max-subagents'].value, DEFAULT_SETTINGS.maxSubagents, 0, 16);
    var concurrentSubagents = numberOr(dom['settings-concurrent-subagents'].value, DEFAULT_SETTINGS.concurrentSubagents, 1, 8);
    if (maxSubagents > 0) concurrentSubagents = Math.min(concurrentSubagents, maxSubagents);
    else concurrentSubagents = 1;
    return {
      workspace: dom['settings-workspace'].value.trim(),
      lmBaseUrl: dom['settings-lm-url'].value.trim() || DEFAULT_SETTINGS.lmBaseUrl,
      modelPreset: dom['settings-model-preset'].value,
      model: dom['settings-model'].value.trim(),
      temperature: numberOr(dom['settings-temperature'].value, DEFAULT_SETTINGS.temperature, 0, 2),
      maxTokens: numberOr(dom['settings-max-tokens'].value, DEFAULT_SETTINGS.maxTokens, 256, 8192),
      contextLength: numberOr(dom['settings-context-length'].value, DEFAULT_SETTINGS.contextLength, 512, 32768),
      contextChars: numberOr(dom['settings-context-chars'].value, DEFAULT_SETTINGS.contextChars, 1000, 2000000),
      maxSteps: numberOr(dom['settings-max-steps'].value, DEFAULT_SETTINGS.maxSteps, 1, 100),
      approvalMode: dom['settings-approval-mode'].value,
      maxSubagents: maxSubagents,
      concurrentSubagents: concurrentSubagents,
      maxSubagentSteps: numberOr(state.settings.maxSubagentSteps, DEFAULT_SETTINGS.maxSubagentSteps, 1, 100),
      flashAttention: dom['settings-flash-attention'].checked,
      allowFallbackTools: dom['settings-allow-fallback-tools'].checked,
      braveApiKey: brave || state.settings.braveApiKey,
      braveApiKeyPresent: Boolean(state.settings.braveApiKeyPresent || state.settings.braveApiKey || brave),
      ddgFallback: dom['settings-ddg-fallback'].checked,
      mcpServers: JSON.stringify(mcpValue, null, 2),
      theme: dom['settings-theme'].value
    };
  }

  function openSettings() {
    populateSettingsForm();
    setSettingsTab('general');
    openModal('settings-modal', '#settings-close');
  }

  function setSettingsTab(tab) {
    document.querySelectorAll('[data-settings-tab]').forEach(function (button) {
      var active = button.getAttribute('data-settings-tab') === tab;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', String(active));
    });
    document.querySelectorAll('[data-settings-panel]').forEach(function (panel) {
      var active = panel.getAttribute('data-settings-panel') === tab;
      panel.hidden = !active;
      panel.classList.toggle('is-active', active);
    });
  }

  async function saveSettings() {
    var values = collectSettingsForm();
    if (!values) return;
    var button = dom['settings-save-btn'];
    if (button) button.disabled = true;
    try {
      var result = await bridgeCall('updateSettings', settingsPatch(values));
      if (result && result.ok === false) throw new Error(field(result, ['error', 'message'], 'Cài đặt không hợp lệ.'));
      var returned = result && result.settings ? result.settings : result;
      state.settings = normalizeSettings(Object.assign({}, state.settings, values, returned || {}));
      updateWorkspace(state.settings.workspace);
      applyTheme(state.settings.theme, true);
      populateSettingsForm();
      closeModal('settings-modal');
      showToast('Đã lưu cài đặt', 'Thiết lập mới sẽ được áp dụng cho phiên tiếp theo.');
      refreshLmStatus({ quiet: true });
    } catch (error) {
      showToast('Không thể lưu cài đặt', safeError(error, 'Vui lòng kiểm tra lại các trường.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  function resetSettingsForm() {
    state.settings = Object.assign({}, DEFAULT_SETTINGS, { workspace: state.workspace || '' });
    populateSettingsForm();
    showToast('Đã đặt lại biểu mẫu', 'Nhớ lưu để áp dụng giá trị mặc định.', 'warning');
  }

  async function loadConfiguredModel() {
    var values = collectSettingsForm();
    if (!values || !values.model) {
      showToast('Chưa có model', 'Chọn hoặc nhập ID model trước khi load.', 'warning');
      return;
    }
    var button = dom['settings-load-model'];
    if (button) button.disabled = true;
    try {
      var saved = await bridgeCall('updateSettings', settingsPatch(values));
      var returned = saved && saved.settings ? saved.settings : saved;
      state.settings = normalizeSettings(Object.assign({}, state.settings, values, returned || {}));
      populateSettingsForm();
      var result = await bridgeCall('loadModel', values.model);
      applyLmStatus(result && result.status ? result.status : result);
      showToast('Đang load model', values.model + ' · context ' + values.contextLength + ' token.');
    } catch (error) {
      showToast('Không thể load model', safeError(error, 'Kiểm tra LM Studio và ID model.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function testSettingsConnection() {
    var values = collectSettingsForm();
    if (!values) return;
    var button = dom['settings-test-btn'];
    if (button) button.disabled = true;
    updateModelStatusLoading();
    try {
      await bridgeCall('updateSettings', { lmBaseUrl: values.lmBaseUrl, model: values.model });
      var result = await bridgeCall('lmStatus');
      var status = normalizeLmStatus(result);
      applyLmStatus(result);
      setText(dom['settings-connection-title'], status.reachable ? 'Kết nối thành công' : 'Không kết nối được');
      setText(dom['settings-connection-detail'], status.reachable ? (status.model || 'LM Studio đã sẵn sàng') : 'Kiểm tra địa chỉ và cổng LM Studio.');
      showToast(status.reachable ? 'Kết nối thành công' : 'Chưa kết nối được', status.reachable ? 'Cấu hình LM Studio đã sẵn sàng.' : 'Kiểm tra LM Base URL.', status.reachable ? 'success' : 'warning');
    } catch (error) {
      applyLmStatus({ reachable: false, status: 'offline', detail: safeError(error, 'Không thể kiểm tra kết nối') });
      showToast('Không thể kiểm tra', safeError(error, 'Vui lòng thử lại.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function refreshSettingsModels() {
    var values = collectSettingsForm();
    if (!values) return;
    try {
      await bridgeCall('updateSettings', { lmBaseUrl: values.lmBaseUrl, model: values.model });
      var result = await bridgeCall('lmStatus');
      applyLmStatus(result);
      showToast('Đã quét mô hình', state.lmStatus.models.length ? state.lmStatus.models.length + ' mô hình khả dụng.' : 'Chưa tìm thấy mô hình.', state.lmStatus.models.length ? 'success' : 'warning');
    } catch (error) {
      showToast('Không thể quét mô hình', safeError(error, 'Kiểm tra kết nối LM Studio.'), 'error');
    }
  }

  function showAskUser(payload) {
    var event = payload || {};
    state.pendingAsk = {
      id: stringOr(field(event, ['id', 'interactionId'], ''), ''),
      sessionId: stringOr(field(event, ['sessionId', 'session_id'], ''), '') || state.activeSessionId,
      runId: stringOr(field(event, ['runId', 'run_id'], ''), ''),
      options: field(event, ['options', 'choices'], [])
    };
    var question = cleanModelText(extractText(field(event, ['question', 'prompt', 'message', 'text'], 'Tác nhân cần thêm thông tin từ bạn.')));
    setText(dom['ask-user-question'], truncate(question, 500));
    setText(dom['ask-user-input'], '');
    setHidden(dom['ask-user-error'], true);
    var options = Array.isArray(state.pendingAsk.options) ? state.pendingAsk.options : [];
    dom['ask-user-options'].replaceChildren();
    options.forEach(function (option, index) {
      var label = cleanModelText(typeof option === 'string' ? option : extractText(field(option, ['label', 'text', 'name'], 'Lựa chọn ' + (index + 1))));
      var value = cleanModelText(typeof option === 'string' ? option : extractText(field(option, ['value', 'id', 'label'], label)));
      var button = createNode('button', 'ask-option', label || 'Lựa chọn ' + (index + 1));
      button.type = 'button';
      button.dataset.optionValue = value || label;
      button.addEventListener('click', function () {
        dom['ask-user-options'].querySelectorAll('.ask-option').forEach(function (item) { item.classList.remove('is-selected'); });
        button.classList.add('is-selected');
        dom['ask-user-input'].value = value || label;
        dom['ask-user-input'].focus();
      });
      dom['ask-user-options'].appendChild(button);
    });
    setHidden(dom['ask-user-options'], options.length === 0);
    openModal('ask-user-modal', '#ask-user-input');
  }

  async function respondToAsk(action, answer) {
    if (!state.pendingAsk) return;
    var request = state.pendingAsk;
    var text = String(answer || '').trim();
    if (action === 'resolve' && !text) {
      setText(dom['ask-user-error'], 'Hãy nhập câu trả lời hoặc chọn một tùy chọn.');
      setHidden(dom['ask-user-error'], false);
      return;
    }
    var buttons = [dom['ask-user-resolve'], dom['ask-user-reject'], dom['ask-user-cancel']];
    buttons.forEach(function (button) { if (button) button.disabled = true; });
    try {
      if (request.id) {
        await bridgeCall('respondInteraction', {
          id: request.id,
          type: 'ask-user',
          answer: action === 'resolve' ? text : (action === 'reject' ? 'Tôi từ chối yêu cầu này.' : 'Hãy dừng yêu cầu này.')
        });
      } else if (action === 'cancel' || action === 'reject') {
        if (request.runId) await bridgeCall('cancelRun', request.runId);
        else await sendConversationResponse(request.sessionId, action === 'reject' ? 'Tôi từ chối yêu cầu này.' : 'Tôi hủy yêu cầu này.');
      } else {
        await sendConversationResponse(request.sessionId, text);
      }
      state.pendingAsk = null;
      closeModal('ask-user-modal');
      showToast(action === 'resolve' ? 'Đã gửi câu trả lời' : 'Đã xử lý yêu cầu', action === 'resolve' ? 'Tác nhân sẽ tiếp tục.' : 'Tác nhân đã nhận phản hồi.');
    } catch (error) {
      setText(dom['ask-user-error'], safeError(error, 'Không thể gửi phản hồi.'));
      setHidden(dom['ask-user-error'], false);
    } finally {
      buttons.forEach(function (button) { if (button) button.disabled = false; });
    }
  }

  async function sendConversationResponse(sessionId, text) {
    if (!sessionId) return null;
    return bridgeCall('sendMessage', { sessionId: sessionId, text: text, mode: state.mode, attachments: [] });
  }

  function showApproval(payload) {
    var event = payload || {};
    var tool = field(event, ['tool', 'toolName', 'name'], 'Không xác định');
    if (tool && typeof tool === 'object') tool = field(tool, ['name', 'tool', 'id'], 'Không xác định');
    state.pendingApproval = {
      id: stringOr(field(event, ['id', 'interactionId'], ''), ''),
      sessionId: stringOr(field(event, ['sessionId', 'session_id'], ''), '') || state.activeSessionId,
      runId: stringOr(field(event, ['runId', 'run_id'], ''), ''),
      tool: stringOr(tool, 'Không xác định')
    };
    setText(dom['approval-description'], cleanModelText(extractText(field(event, ['description', 'message', 'reason'], 'Tác nhân muốn thực hiện một thao tác trong workspace.'))) || 'Tác nhân muốn thực hiện một thao tác trong workspace.');
    setText(dom['approval-tool-name'], humanizeTool(state.pendingApproval.tool));
    var args = field(event, ['args', 'arguments', 'input', 'parameters'], '');
    var summary = summarizeValue(args) || 'Không có tham số.';
    if (field(event, ['argumentsTruncated'], false)) summary += ' · tham số dài đã được rút gọn';
    setText(dom['approval-tool-args'], summary);
    setHidden(dom['approval-error'], true);
    openModal('approval-modal', '#approval-approve');
  }

  async function respondToApproval(approved) {
    if (!state.pendingApproval) return;
    var request = state.pendingApproval;
    dom['approval-approve'].disabled = true;
    dom['approval-reject'].disabled = true;
    try {
      if (request.id) {
        await bridgeCall('respondInteraction', { id: request.id, type: 'approval-request', approved: Boolean(approved) });
      } else if (approved) {
        await sendConversationResponse(request.sessionId, 'Tôi phê duyệt thao tác này một lần.');
      } else if (request.runId) {
        await bridgeCall('cancelRun', request.runId);
      } else {
        await sendConversationResponse(request.sessionId, 'Tôi từ chối thao tác này.');
      }
      if (approved) {
        addActivity('stage', { title: 'Đã phê duyệt thao tác', detail: request.tool, status: 'success' });
        showToast('Đã phê duyệt', 'Tác nhân được phép thực hiện thao tác này.');
      } else {
        addActivity('stage', { title: 'Đã từ chối thao tác', detail: request.tool, status: 'error' });
        showToast('Đã từ chối', 'Tác nhân sẽ không thực hiện thao tác này.', 'warning');
      }
      state.pendingApproval = null;
      closeModal('approval-modal');
    } catch (error) {
      setText(dom['approval-error'], safeError(error, 'Không thể gửi phản hồi phê duyệt.'));
      setHidden(dom['approval-error'], false);
    } finally {
      dom['approval-approve'].disabled = false;
      dom['approval-reject'].disabled = false;
    }
  }

  function renderMcpStatus(event) {
    var payload = field(event || {}, ['status', 'state'], event || {});
    var text = typeof payload === 'object'
      ? (payload.connected || payload.online || payload.running ? 'Đang hoạt động' : 'Chưa kết nối')
      : humanizeLabel(payload || 'Đã cập nhật');
    var serverValue = typeof payload === 'object' ? field(payload, ['servers', 'connected', 'items'], '') : field(event, ['servers', 'detail', 'message'], '');
    setText(dom['mcp-status-text'], text);
    setText(dom['mcp-status-detail'], summarizeValue(serverValue) || 'Các server sẽ hiển thị khi được kết nối.');
  }

  function handleEvent(event) {
    if (!event || !event.type) return;
    try {
      switch (event.type) {
        case 'status': {
          var statusValue = stringOr(field(event, ['status', 'state'], ''), '').toLowerCase();
          var looksLikeLmStatus = event.lmStatus || event.lm || event.reachable !== undefined || event.online !== undefined || event.baseUrl || event.models || event.installed || ['ready', 'connected', 'online', 'offline', 'disconnected', 'error', 'failed'].indexOf(statusValue) !== -1;
          if (looksLikeLmStatus) applyLmStatus(event.lmStatus || event.lm || event);
          if (event.state === 'running' || statusValue === 'running') {
            if (!state.isRunning) setRunning(true);
          }
          if ((event.state === 'idle' || event.state === 'complete' || statusValue === 'idle' || statusValue === 'complete') && state.isRunning) finishRun(event);
          break;
        }
        case 'session-created': {
          var created = normalizeSession(unwrap(event, 'session') || event, state.sessions.length);
          updateSessionInList(created);
          if (!state.activeSessionId || event.select !== false) setActiveSession(created);
          renderSessions();
          break;
        }
        case 'session-deleted': {
          var deletedId = stringOr(field(event, ['id', 'sessionId'], ''), '');
          state.sessions = state.sessions.filter(function (session) { return session.id !== deletedId; });
          if (state.activeSessionId === deletedId) {
            state.activeSessionId = null;
            state.activeSession = null;
            state.messages = [];
            writeStorage(STORAGE.activeSession, '');
            setChatView();
          }
          renderSessions();
          break;
        }
        case 'message': {
          var messagePayload = Object.prototype.hasOwnProperty.call(event, 'message') ? event.message : event;
          if (typeof messagePayload === 'string') messagePayload = { content: messagePayload, role: event.role || 'assistant' };
          var role = stringOr(typeof messagePayload === 'object' ? field(messagePayload, ['role', 'author'], event.role || 'assistant') : event.role, 'assistant');
          var message = normalizeMessage(messagePayload, role);
          if (!message.sessionId) message.sessionId = stringOr(field(event, ['sessionId', 'session_id'], ''), '');
          if (!message.sessionId || message.sessionId === state.activeSessionId) {
            addMessage(message, { role: role, keepStreaming: role === 'assistant' && state.isRunning });
          }
          break;
        }
        case 'run-start':
          state.runId = stringOr(field(event, ['runId', 'run_id', 'id'], ''), '') || state.runId;
          setRunning(true);
          addActivity('stage', { title: 'Tác nhân bắt đầu', detail: MODES[normalizeMode(field(event, ['mode'], state.mode))].label, status: 'running' });
          break;
        case 'agent-stage':
          addActivity('stage', {
            id: field(event, ['id', 'stageId'], ''),
            title: humanizeLabel(field(event, ['label', 'stage', 'phase', 'title', 'name'], 'Bước tác nhân')),
            detail: summarizeValue(field(event, ['detail', 'description', 'message'], '')) || summarizeValue(field(event, ['step', 'maxSteps'], '')),
            status: 'running'
          });
          break;
        case 'assistant-delta':
          appendAssistantDelta(event);
          break;
        case 'tool-start': {
          var toolStart = field(event, ['tool', 'toolName', 'name'], 'tool');
          var argsStart = field(event, ['args', 'arguments', 'input', 'parameters'], '');
          addActivity('tool', {
            id: field(event, ['toolCallId', 'callId', 'toolId', 'id'], ''),
            title: humanizeTool(toolStart),
            tool: stringOr(toolStart, 'tool'),
            detail: summarizeValue(argsStart) || 'Đang chuẩn bị thao tác…',
            status: 'running',
            startedAt: field(event, ['startedAt', 'startTime'], Date.now())
          });
          break;
        }
        case 'tool-result': {
          var resultId = field(event, ['toolCallId', 'callId', 'toolId', 'id'], '');
          var resultDetail = field(event, ['summary', 'result', 'output', 'message', 'detail'], '');
          var resultStatus = stringOr(field(event, ['status', 'state'], ''), '').toLowerCase();
          if (!resultStatus) resultStatus = field(event, ['ok', 'success'], true) === false ? 'error' : 'success';
          if (resultStatus === 'ok' || resultStatus === 'completed') resultStatus = 'success';
          if (resultStatus === 'failed') resultStatus = 'error';
          addActivity('tool', {
            id: resultId,
            title: humanizeTool(field(event, ['tool', 'toolName', 'name'], 'tool')),
            tool: stringOr(field(event, ['tool', 'toolName', 'name'], ''), 'tool'),
            detail: summarizeValue(resultDetail) || (resultStatus === 'error' ? 'Công cụ báo lỗi.' : 'Công cụ đã hoàn tất.'),
            status: resultStatus === 'error' ? 'error' : 'success',
            duration: numberOr(field(event, ['durationMs', 'duration', 'elapsedMs'], 0), 0, 0)
          });
          break;
        }
        case 'ask-user':
          showAskUser(event);
          break;
        case 'approval-request':
          showApproval(event);
          break;
        case 'subagent-start':
          addActivity('subagent', {
            id: field(event, ['subagentId', 'id'], ''),
            title: 'Tác nhân phụ · ' + humanizeLabel(field(event, ['title', 'name', 'label', 'role'], 'đang phân tích')),
            detail: summarizeValue(field(event, ['task', 'description', 'prompt', 'focus'], 'Đang xử lý một phần công việc.')),
            status: 'running'
          });
          break;
        case 'subagent-delta': {
          var subId = field(event, ['subagentId', 'id'], '');
          var subEntry = state.activity.find(function (entry) { return entry.kind === 'subagent' && entry.id === subId; });
          if (subEntry) {
            subEntry.detail = truncate(cleanModelText(extractText(field(event, ['delta', 'text', 'content'], ''))), 180) || subEntry.detail;
            renderActivity();
          }
          break;
        }
        case 'subagent-end':
          addActivity('subagent', {
            id: field(event, ['subagentId', 'id'], ''),
            title: 'Tác nhân phụ · ' + humanizeLabel(field(event, ['name', 'label', 'role'], 'đã hoàn tất')),
            detail: summarizeValue(field(event, ['summary', 'result', 'message'], 'Đã hoàn tất phần công việc.')),
            status: field(event, ['ok', 'success'], true) === false || stringOr(field(event, ['status', 'state'], ''), '').toLowerCase() === 'error' ? 'error' : 'success'
          });
          break;
        case 'run-complete':
          finishRun(event);
          break;
        case 'run-error':
          failRun(event);
          break;
        case 'run-cancelled':
          if (streamMessageId) {
            var cancelledStream = state.messages.find(function (message) { return message.id === streamMessageId; });
            if (cancelledStream) {
              cancelledStream.streaming = false;
              cancelledStream.status = 'cancelled';
              if (!cancelledStream.text) cancelledStream.text = 'Đã dừng lượt trả lời.';
            }
          }
          streamMessageId = null;
          setRunning(false);
          state.runId = null;
          if (state.pendingAsk) { state.pendingAsk = null; closeModal('ask-user-modal'); }
          if (state.pendingApproval) { state.pendingApproval = null; closeModal('approval-modal'); }
          addActivity('stage', { title: 'Đã dừng lượt chạy', detail: 'Tác nhân đã nhận yêu cầu dừng.', status: 'error' });
          renderMessages();
          break;
        case 'settings-updated': {
          var updatedSettings = normalizeSettings(unwrap(event, 'settings') || event);
          state.settings = Object.assign({}, state.settings, updatedSettings);
          updateWorkspace(state.settings.workspace);
          applyTheme(state.settings.theme, false);
          updateContextIndicator();
          if (!dom['settings-modal'].hidden) populateSettingsForm();
          break;
        }
        case 'workspace-changed':
          updateWorkspace(field(event, ['workspace', 'path', 'folder'], event));
          renderSessions();
          break;
        case 'notice':
          showToast('Thông báo từ tác nhân', safeError(field(event, ['message', 'detail'], 'Tác nhân đã cập nhật trạng thái.'), ''), field(event, ['level'], 'info') === 'error' ? 'error' : field(event, ['level'], 'info') === 'warning' ? 'warning' : 'success');
          break;
        case 'mcp-status':
          renderMcpStatus(event);
          break;
        default:
          break;
      }
    } catch (error) {
      // Event handlers must never take down the renderer. Keep protocol details out of the UI.
      console.warn('CodePilot event ignored:', safeError(error, 'event error'));
    }
  }

  function subscribeToEvents() {
    if (!bridge || typeof bridge.onEvent !== 'function') return;
    try {
      unsubscribeEvents = bridge.onEvent(handleEvent);
    } catch (_) {}
  }

  function closeMobileSidebar() {
    dom['app-shell'] && dom['app-shell'].classList.remove('mobile-sidebar-open');
    setHidden(dom['sidebar-scrim'], true);
    if (dom['sidebar-toggle']) dom['sidebar-toggle'].setAttribute('aria-expanded', 'false');
  }

  function toggleSidebar() {
    var shell = dom['app-shell'];
    if (!shell) return;
    if (window.innerWidth <= 720) {
      var open = shell.classList.toggle('mobile-sidebar-open');
      setHidden(dom['sidebar-scrim'], !open);
      if (dom['sidebar-toggle']) dom['sidebar-toggle'].setAttribute('aria-expanded', String(open));
    } else {
      var collapsed = shell.classList.toggle('sidebar-collapsed');
      if (dom['sidebar-toggle']) dom['sidebar-toggle'].setAttribute('aria-expanded', String(!collapsed));
      if (dom['sidebar-collapse']) dom['sidebar-collapse'].setAttribute('aria-label', collapsed ? 'Hiện thanh bên' : 'Ẩn thanh bên');
    }
  }

  function toggleActivity() {
    var shell = dom['app-shell'];
    if (!shell) return;
    var collapsed = shell.classList.toggle('activity-collapsed');
    if (dom['activity-toggle']) dom['activity-toggle'].setAttribute('aria-expanded', String(!collapsed));
    if (dom['activity-panel']) dom['activity-panel'].setAttribute('aria-hidden', String(collapsed));
  }

  function handleGlobalKeydown(event) {
    var key = event.key.toLowerCase();
    var modifier = event.ctrlKey || event.metaKey;
    if (modifier && key === 'b') { event.preventDefault(); toggleSidebar(); return; }
    if (modifier && key === 'i') { event.preventDefault(); toggleActivity(); return; }
    if (modifier && key === 'k') { event.preventDefault(); newChat(); return; }
    if (event.key === 'Escape') {
      if (!dom['ask-user-modal'].hidden) { event.preventDefault(); respondToAsk('cancel'); return; }
      if (!dom['approval-modal'].hidden) { event.preventDefault(); respondToApproval(false); return; }
      if (!dom['settings-modal'].hidden) { event.preventDefault(); closeModal('settings-modal'); return; }
      if (!dom['onboarding-modal'].hidden) { event.preventDefault(); closeOnboarding(); return; }
    }
    if (event.key === 'Tab') {
      var modal = [dom['ask-user-modal'], dom['approval-modal'], dom['settings-modal'], dom['onboarding-modal']].find(function (item) { return item && !item.hidden; });
      if (!modal) return;
      var focusable = Array.prototype.slice.call(modal.querySelectorAll('button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'));
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  }

  function bindEvents() {
    dom['new-chat-btn'].addEventListener('click', newChat);
    dom['sidebar-toggle'].addEventListener('click', toggleSidebar);
    dom['sidebar-collapse'].addEventListener('click', toggleSidebar);
    dom['sidebar-scrim'].addEventListener('click', closeMobileSidebar);
    dom['settings-btn'].addEventListener('click', openSettings);
    dom['workspace-selector'].addEventListener('click', chooseWorkspace);
    dom['header-workspace'].addEventListener('click', chooseWorkspace);
    dom['theme-toggle'].addEventListener('click', function () {
      var current = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      state.settings.theme = current;
      applyTheme(current, true);
    });
    dom['session-search'].addEventListener('input', renderSessions);
    dom['session-filter-btn'].addEventListener('click', function () {
      state.sessionFilter = state.sessionFilter === 'all' ? 'workspace' : 'all';
      dom['session-filter-btn'].classList.toggle('is-active', state.sessionFilter === 'workspace');
      renderSessions();
      if (state.sessionFilter === 'workspace' && !state.workspace) showToast('Chưa có workspace', 'Bộ lọc workspace sẽ có tác dụng sau khi bạn chọn thư mục.', 'warning');
    });
    dom['activity-toggle'].addEventListener('click', toggleActivity);
    dom['activity-close'].addEventListener('click', toggleActivity);
    dom['mode-select'].addEventListener('change', function () { setMode(dom['mode-select'].value); });
    dom['composer-form'].addEventListener('submit', function (event) { event.preventDefault(); sendMessage(); });
    dom['message-input'].addEventListener('input', function () { resizeComposer(); updateComposerState(); });
    dom['message-input'].addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
        event.preventDefault();
        if (!dom['send-btn'].disabled) dom['composer-form'].requestSubmit();
      }
    });
    dom['attach-btn'].addEventListener('click', openAttachments);
    dom['stop-btn'].addEventListener('click', cancelRun);
    dom['retry-load-btn'].addEventListener('click', loadInitialData);
    document.querySelectorAll('[data-prompt]').forEach(function (button) {
      button.addEventListener('click', function () {
        dom['message-input'].value = button.getAttribute('data-prompt') || '';
        resizeComposer();
        updateComposerState();
        dom['message-input'].focus();
      });
    });

    dom['onboarding-close'].addEventListener('click', closeOnboarding);
    dom['onboarding-test-btn'].addEventListener('click', testOnboardingConnection);
    dom['onboarding-start-btn'].addEventListener('click', startLmStudio);
    dom['onboarding-install-btn'].addEventListener('click', installLmCli);
    dom['onboarding-load-btn'].addEventListener('click', loadOnboardingModel);
    dom['onboarding-model-select'].addEventListener('change', function () {
      state.onboarding.model = dom['onboarding-model-select'].value;
      state.onboarding.modelLoaded = Boolean(state.onboarding.model && state.lmStatus.loadedModels && state.lmStatus.loadedModels.some(function (loaded) { return loaded.id === state.onboarding.model || loaded.name === state.onboarding.model || loaded.sourceId === state.onboarding.model; }));
      updateOnboardingContinue();
    });
    dom['onboarding-workspace-pick'].addEventListener('click', chooseWorkspace);
    dom['onboarding-back-btn'].addEventListener('click', function () { setOnboardingStep(state.onboarding.step - 1); });
    dom['onboarding-continue'].addEventListener('click', onboardingContinue);

    dom['settings-close'].addEventListener('click', function () { closeModal('settings-modal'); });
    dom['settings-cancel-btn'].addEventListener('click', function () { closeModal('settings-modal'); });
    dom['settings-save-btn'].addEventListener('click', saveSettings);
    dom['settings-model-preset'].addEventListener('change', function () { applyModelPreset(dom['settings-model-preset'].value); });
    ['settings-model', 'settings-max-tokens', 'settings-context-length', 'settings-context-chars', 'settings-temperature', 'settings-max-steps', 'settings-max-subagents', 'settings-concurrent-subagents', 'settings-flash-attention'].forEach(function (id) {
      var input = dom[id];
      if (input) input.addEventListener('input', markModelPresetCustom);
      if (input) input.addEventListener('change', markModelPresetCustom);
    });
    dom['settings-reset-btn'].addEventListener('click', resetSettingsForm);
    dom['settings-test-btn'].addEventListener('click', testSettingsConnection);
    dom['settings-refresh-models'].addEventListener('click', refreshSettingsModels);
    dom['settings-load-model'].addEventListener('click', loadConfiguredModel);
    dom['settings-workspace-pick'].addEventListener('click', chooseWorkspace);
    dom['settings-workspace-clear'].addEventListener('click', function () {
      state.settings.workspace = '';
      updateWorkspace('');
      populateSettingsForm();
    });
    document.querySelectorAll('[data-settings-tab]').forEach(function (button) {
      button.addEventListener('click', function () { setSettingsTab(button.getAttribute('data-settings-tab')); });
    });

    dom['ask-user-close'].addEventListener('click', function () { respondToAsk('reject'); });
    dom['ask-user-reject'].addEventListener('click', function () { respondToAsk('reject'); });
    dom['ask-user-cancel'].addEventListener('click', function () { respondToAsk('cancel'); });
    dom['ask-user-resolve'].addEventListener('click', function () { respondToAsk('resolve', dom['ask-user-input'].value); });
    dom['ask-user-input'].addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) { event.preventDefault(); respondToAsk('resolve', dom['ask-user-input'].value); }
    });
    dom['approval-close'].addEventListener('click', function () { respondToApproval(false); });
    dom['approval-reject'].addEventListener('click', function () { respondToApproval(false); });
    dom['approval-approve'].addEventListener('click', function () { respondToApproval(true); });

    [dom['onboarding-modal'], dom['settings-modal'], dom['ask-user-modal'], dom['approval-modal']].forEach(function (backdrop) {
      if (!backdrop) return;
      backdrop.addEventListener('click', function (event) {
        if (event.target !== backdrop) return;
        if (backdrop === dom['settings-modal']) closeModal('settings-modal');
        else if (backdrop === dom['onboarding-modal']) closeOnboarding();
        else if (backdrop === dom['ask-user-modal']) respondToAsk('cancel');
        else if (backdrop === dom['approval-modal']) respondToApproval(false);
      });
    });
    document.addEventListener('keydown', handleGlobalKeydown);
    if (window.matchMedia) {
      var media = window.matchMedia('(prefers-color-scheme: light)');
      if (media.addEventListener) media.addEventListener('change', function () { if (state.settings.theme === 'system') applyTheme('system', false); });
    }
  }

  async function openAttachments() {
    try {
      var result = await bridgeCall('openAttachments');
      var list = normalizeAttachments(unwrap(result, 'attachments') || result);
      if (list.length) {
        state.attachments = state.attachments.concat(list);
        renderAttachmentList();
        updateComposerState();
      }
    } catch (error) {
      showToast('Không thể đính kèm', safeError(error, 'Hãy thử chọn tệp khác.'), 'error');
    }
  }

  async function newChat() {
    if (state.isRunning) {
      showToast('Tác nhân đang làm việc', 'Dừng lượt hiện tại trước khi tạo cuộc trò chuyện mới.', 'warning');
      return;
    }
    try {
      await createNewSession();
      dom['message-input'].focus();
    } catch (error) {
      showToast('Không thể tạo cuộc trò chuyện', safeError(error, 'Vui lòng thử lại.'), 'error');
    }
  }

  function ingestBootstrap(raw) {
    var value = raw && raw.bootstrap ? raw.bootstrap : raw;
    state.bootstrap = value && typeof value === 'object' ? value : {};
    var bootstrapSettings = state.bootstrap.settings;
    if (bootstrapSettings) state.settings = normalizeSettings(Object.assign({}, state.settings, bootstrapSettings));
    var workspace = field(state.bootstrap, ['workspace', 'workspacePath', 'folder'], '');
    if (workspace) updateWorkspace(workspace);
    if (state.bootstrap.mode) setMode(state.bootstrap.mode, false);
    if (state.bootstrap.model && !state.settings.model) state.settings.model = state.bootstrap.model;
    if (state.bootstrap.lmStatus || state.bootstrap.lm) applyLmStatus(state.bootstrap.lmStatus || state.bootstrap.lm);
    if (state.bootstrap.mcpStatus) renderMcpStatus({ status: state.bootstrap.mcpStatus });
  }

  function shouldShowOnboarding() {
    var explicitComplete = state.bootstrap.onboardingComplete === true || state.bootstrap.needsOnboarding === false;
    var explicitNeeded = state.bootstrap.needsOnboarding === true || state.bootstrap.firstRun === true;
    if (explicitComplete) return false;
    if (explicitNeeded) return true;
    return readStorage(STORAGE.onboardingComplete, '') !== '1';
  }

  async function loadInitialData() {
    setLoading(true);
    setChatError('', false);
    state.apiAvailable = Boolean(bridge && typeof bridge.ready === 'function');
    try {
      var readyResult = null;
      try { readyResult = await bridgeCall('ready'); } catch (_) {}
      var bootstrap = readyResult && typeof readyResult === 'object' ? readyResult : null;
      if (!bootstrap || (!bootstrap.workspace && !bootstrap.settings && !bootstrap.onboardingComplete && !bootstrap.firstRun && !bootstrap.needsOnboarding && !bootstrap.model)) {
        try { bootstrap = await bridgeCall('getBootstrap'); } catch (_) {}
      }
      ingestBootstrap(bootstrap);
    } catch (error) {
      // Settings and sessions can still be loaded when bootstrap is unavailable.
    }
    try {
      var settingsResult = await bridgeCall('getSettings');
      state.settings = normalizeSettings(unwrap(settingsResult, 'settings') || settingsResult);
      if (state.settings.workspace) updateWorkspace(state.settings.workspace);
      applyTheme(state.settings.theme, false);
      populateSettingsForm();
    } catch (_) {}
    try { await refreshSessions(); } catch (error) {
      if (!state.sessions.length) setChatError('Không thể tải danh sách cuộc trò chuyện. Hãy thử lại.', true);
    }
    if (state.activeSessionId) {
      try {
        var activeResult = await bridgeCall('getSession', state.activeSessionId);
        var active = normalizeSession(unwrap(activeResult, 'session') || activeResult, 0);
        if (!active.id) active.id = state.activeSessionId;
        updateSessionInList(active);
        setActiveSession(active);
      } catch (_) {
        writeStorage(STORAGE.activeSession, '');
        state.activeSessionId = '';
        state.activeSession = null;
        state.messages = [];
        setChatView();
      }
    } else if (state.sessions.length) {
      setActiveSession(state.sessions[0]);
    } else {
      setChatView();
    }
    setLoading(false);
    updateComposerState();
    refreshLmStatus({ quiet: true });
    if (state.apiAvailable && shouldShowOnboarding()) window.setTimeout(openOnboarding, 180);
  }

  function applyTooltips() {
    var tooltips = {
      'settings-workspace': 'Thư mục mà tác nhân được phép đọc và thay đổi.',
      'settings-lm-url': 'API tương thích OpenAI của LM Studio. Mặc định là http://127.0.0.1:1234/v1.',
      'settings-model': 'ID mô hình đang được LM Studio nạp.',
      'settings-load-model': 'Lưu preset rồi yêu cầu LM Studio load model với context đã chọn.',
      'settings-model-preset': 'Chỉ điền cấu hình model; ứng dụng không tự tải.',
      'settings-temperature': 'Số cao hơn tạo câu trả lời sáng tạo hơn nhưng có thể kém ổn định hơn.',
      'settings-max-tokens': 'Giới hạn số token model được sinh trong một lượt.',
      'settings-context-length': 'Context được gửi khi Load model trong LM Studio.',
      'settings-flash-attention': 'Tối ưu bộ nhớ khi LM Studio hỗ trợ.',
      'settings-context-chars': 'Ước lượng số ký tự ngữ cảnh được phép đưa vào một lượt.',
      'settings-max-steps': 'Giới hạn số bước suy nghĩ, đọc tệp và kiểm thử trong một lượt.',
      'settings-approval-mode': 'Chọn khi nào tác nhân phải hỏi bạn trước thao tác nhạy cảm.',
      'settings-max-subagents': 'Số tác nhân phụ tối đa trong một lượt.',
      'settings-concurrent-subagents': 'Số tác nhân phụ được chạy song song.',
      'settings-brave-key': 'Khóa Brave Search được giữ trong kho cấu hình cục bộ.',
      'settings-mcp-json': 'Danh sách server MCP ở dạng JSON. Chỉ cấu hình server bạn tin cậy.',
      'message-input': 'Enter để gửi · Shift + Enter để xuống dòng.'
    };
    Object.keys(tooltips).forEach(function (id) {
      if (dom[id]) dom[id].setAttribute('title', tooltips[id]);
    });
  }

  function init() {
    cacheDom();
    applyTooltips();
    state.settings.theme = readStorage(STORAGE.theme, 'dark');
    applyTheme(state.settings.theme, false);
    setMode(state.mode, false);
    if (window.innerWidth <= 960 && dom['app-shell']) {
      dom['app-shell'].classList.add('activity-collapsed');
      if (dom['activity-toggle']) dom['activity-toggle'].setAttribute('aria-expanded', 'false');
      if (dom['activity-panel']) dom['activity-panel'].setAttribute('aria-hidden', 'true');
    }
    bindEvents();
    subscribeToEvents();
    renderSessions();
    renderActivity();
    updateContextIndicator();
    loadInitialData();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
