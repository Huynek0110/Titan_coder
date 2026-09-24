'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');
const {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  shell,
} = require('electron');

const { LMStudioClient } = require('./core/lmstudio');
const { ToolBroker } = require('./core/tool-broker');
const { AgentRunner } = require('./core/agent-runner');
const { InteractionManager } = require('./core/interaction-manager');
const { Logger, redact } = require('./core/logger');
const { SettingsStore } = require('./core/settings-store');
const { SessionStore } = require('./core/session-store');
const { WorkspaceTools } = require('./tools/workspace-tools');
const { WebTools } = require('./tools/web-tools');
const { SystemTools } = require('./tools/system-tools');
const { McpManager } = require('./core/mcp-manager');

const MAX_MESSAGE_CHARS = 40_000;
const MAX_ATTACHMENTS = 6;
const MAX_ATTACHMENT_BYTES = 750_000;

function safeClientId(value, prefix) {
  const text = String(value || '');
  return new RegExp(`^${prefix}-[A-Za-z0-9_-]{1,120}$`).test(text) ? text : `${prefix}-${crypto.randomUUID()}`;
}

let mainWindow = null;
let services = null;
let statusTimer = null;
let lastStatusSignature = '';
let statusPollInFlight = false;
let quitting = false;
let quitReady = false;

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });
}

function cloneEventPayload(payload) {
  try {
    const safe = redact(payload);
    return JSON.parse(JSON.stringify(safe, (_key, value) => {
      if (typeof value === 'function' || typeof value === 'symbol') return undefined;
      if (typeof value === 'string' && value.length > 100_000) return `${value.slice(0, 100_000)}…[event payload truncated]`;
      return value;
    }));
  } catch {
    return { type: 'notice', level: 'error', message: 'Một sự kiện nội bộ không thể hiển thị.' };
  }
}

function sendEvent(payload) {
  if (!payload || !mainWindow || mainWindow.isDestroyed()) return;
  try { mainWindow.webContents.send('codepilot:event', cloneEventPayload(payload)); } catch { /* window may be closing */ }
}

function createServices() {
  const logger = new Logger({ logDir: path.join(app.getPath('userData'), 'logs') });
  const settingsStore = new SettingsStore({ dir: path.join(app.getPath('userData'), 'config'), safeStorage: require('electron').safeStorage });
  const sessionStore = new SessionStore({ dir: path.join(app.getPath('userData'), 'data'), logger });
  const interactions = new InteractionManager();
  const lmClient = new LMStudioClient({ getSettings: () => settingsStore.getInternal() });
  const mcpManager = new McpManager({ requestTimeout: 25_000 });
  const webTools = new WebTools({});
  const broker = new ToolBroker({
    sources: [],
    onEvent: sendEvent,
    interactionProvider: (payload) => payload.type === 'approval' ? interactions.approve(payload, payload.signal) : interactions.ask(payload, payload.signal),
  });
  const runner = new AgentRunner({
    lmClient,
    broker,
    getSettings: () => settingsStore.getInternal(),
    interactionProvider: async (payload) => payload.type === 'approval' ? interactions.approve(payload, payload.signal) : interactions.ask(payload, payload.signal),
    onEvent: sendEvent,
  });

  interactions.on('request', (request) => sendEvent(request));
  mcpManager.on('status', (status) => sendEvent({ type: 'mcp-status', status }));

  return {
    logger,
    settingsStore,
    sessionStore,
    interactions,
    lmClient,
    mcpManager,
    webTools,
    broker,
    runner,
    runs: new Map(),
    activeSessionRuns: new Map(),
    globalRunId: null,
    toolRoot: null,
    revealPaths: new Set(),
    approvedRoots: new Set(),
    systemTools: null,
    workspaceTools: null,
  };
}

async function rebuildToolSources(root, { force = false, allowActive = false } = {}) {
  if (services.runs?.size && !allowActive) throw new Error('Không thể đổi workspace trong khi một lượt agent đang chạy.');
  const settings = await services.settingsStore.getInternal();
  const safeRoot = path.resolve(root && typeof root === 'string' && root ? root : app.getPath('userData'));
  const sameRoot = services.toolRoot && path.resolve(services.toolRoot).toLowerCase() === safeRoot.toLowerCase();
  if (sameRoot && !force) return;
  if (services.systemTools?.stop) await services.systemTools.stop();
  const logDir = path.join(app.getPath('userData'), 'logs');
  const workspaceTools = new WorkspaceTools({ root: safeRoot, trashItem: (target) => shell.trashItem(target) });
  const systemTools = new SystemTools({
    root: safeRoot,
    logDir,
    openPath: (target) => shell.openPath(target),
    revealPath: (target) => shell.showItemInFolder(target),
  });
  const webTools = new WebTools({
    searchProvider: settings.searchProvider,
    braveApiKey: settings.braveApiKey,
  });
  services.workspaceTools = workspaceTools;
  services.systemTools = systemTools;
  services.webTools = webTools;
  services.toolRoot = safeRoot;
  await rememberApprovedRoot(safeRoot);
  services.broker.setSources([workspaceTools, systemTools, webTools, services.mcpManager]);
}

async function reloadConfiguredMcp() {
  const settings = await services.settingsStore.getInternal();
  await services.mcpManager.stop();
  if (settings.mcpServers && typeof settings.mcpServers === 'object') {
    for (const [name, config] of Object.entries(settings.mcpServers)) {
      await services.mcpManager.addConfig(name, config);
    }
  }
  await services.mcpManager.start();
  services.broker.refresh();
  return await services.mcpManager.status();
}

async function initializeServices() {
  await services.settingsStore.init();
  await services.sessionStore.init();
  const initialSettings = await services.settingsStore.getInternal();
  if (initialSettings.fileRoot) await rememberApprovedRoot(initialSettings.fileRoot);
  await rebuildToolSources(initialSettings.fileRoot || app.getPath('userData'));
  services.logger.info('Application services initialized');
}

function expectedRendererPath() {
  return path.resolve(__dirname, '..', 'renderer', 'index.html');
}

function assertTrustedSender(event) {
  const rawUrl = event?.senderFrame?.url || event?.sender?.getURL?.() || '';
  if (!rawUrl || rawUrl === 'about:blank') throw new Error('IPC sender is not ready.');
  let parsed;
  try { parsed = new URL(rawUrl); } catch { throw new Error('IPC sender URL is invalid.'); }
  if (parsed.protocol !== 'file:') throw new Error('IPC sender must be the local renderer.');
  let filePath;
  try { filePath = path.resolve(fileURLToPath(parsed)); } catch { throw new Error('IPC sender file is invalid.'); }
  if (filePath.toLowerCase() !== expectedRendererPath().toLowerCase()) {
    throw new Error('IPC sender is not the approved CodePilot renderer.');
  }
}

function handle(channel, listener) {
  ipcMain.handle(channel, async (event, ...args) => {
    assertTrustedSender(event);
    return listener(event, ...args);
  });
}

function pathInside(root, target) {
  const relative = path.relative(path.resolve(root), path.resolve(target));
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function canonicalExistingPath(value) {
  try { return await fs.realpath(path.resolve(String(value || ''))); } catch { return null; }
}

async function rememberApprovedRoot(value) {
  const canonical = await canonicalExistingPath(value);
  if (canonical) {
    services.approvedRoots.add(canonical.toLowerCase());
    rememberRevealPath(canonical);
  }
  return canonical;
}

function isApprovedRoot(value) {
  return services.approvedRoots.has(path.resolve(String(value || '')).toLowerCase());
}

function rememberRevealPath(target) {
  if (target) services.revealPaths.add(path.resolve(target).toLowerCase());
}

function isAllowedRevealPath(target) {
  const value = path.resolve(target);
  if (services.toolRoot && pathInside(services.toolRoot, value)) return true;
  return services.revealPaths.has(value.toLowerCase());
}

function equivalentIgnoringRedacted(current, incoming) {
  if (incoming === '[REDACTED]') return true;
  if (Array.isArray(current) || Array.isArray(incoming)) {
    if (!Array.isArray(current) || !Array.isArray(incoming) || current.length !== incoming.length) return false;
    return current.every((value, index) => equivalentIgnoringRedacted(value, incoming[index]));
  }
  if (current && typeof current === 'object' && incoming && typeof incoming === 'object') {
    const currentKeys = Object.keys(current);
    const incomingKeys = Object.keys(incoming);
    if (currentKeys.length !== incomingKeys.length) return false;
    return incomingKeys.every((key) => Object.prototype.hasOwnProperty.call(current, key) && equivalentIgnoringRedacted(current[key], incoming[key]));
  }
  return current === incoming;
}

function releaseRun(runId, sessionId) {
  services.runs.delete(runId);
  if (services.activeSessionRuns.get(sessionId) === runId) services.activeSessionRuns.delete(sessionId);
  if (services.globalRunId === runId) services.globalRunId = null;
}

function registerIpc() {
  handle('app:ready', () => ({ ready: true, version: app.getVersion() }));
  handle('app:bootstrap', async () => {
    const [settings, sessions, status, mcpStatus] = await Promise.all([
      services.settingsStore.get(),
      services.sessionStore.listSessions(),
      services.lmClient.getStatus(),
      services.mcpManager.status(),
    ]);
    return { settings, sessions, lmStatus: status, mcpStatus, version: app.getVersion() };
  });
  handle('app:close', () => app.quit());

  handle('sessions:list', () => services.sessionStore.listSessions());
  handle('sessions:get', async (_event, { id } = {}) => {
    const session = await services.sessionStore.getSession(String(id || ''));
    if (!session) throw new Error('Không tìm thấy cuộc trò chuyện.');
    return session;
  });
  handle('sessions:create', async (_event, payload = {}) => {
    const requestedWorkspace = payload.workspace ? path.resolve(String(payload.workspace)) : '';
    if (requestedWorkspace && !isApprovedRoot(requestedWorkspace)) {
      throw new Error('Workspace chưa được chọn qua hộp thoại chính của CodePilot.');
    }
    const configuredWorkspace = (await services.settingsStore.getInternal()).fileRoot || '';
    const workspace = requestedWorkspace || (isApprovedRoot(configuredWorkspace) ? configuredWorkspace : '');
    const mode = ['chat', 'agent', 'plan'].includes(payload.mode) ? payload.mode : 'agent';
    const session = await services.sessionStore.createSession({ workspace, mode });
    sendEvent({ type: 'session-created', session });
    return session;
  });
  handle('sessions:delete', async (_event, { id } = {}) => {
    const sessionId = String(id || '');
    if (services.activeSessionRuns.has(sessionId)) throw new Error('Không thể xóa cuộc trò chuyện đang chạy.');
    const value = await services.sessionStore.delete(sessionId);
    sendEvent({ type: 'session-deleted', id: sessionId });
    return value;
  });

  handle('chat:send', async (_event, payload = {}) => {
    const sessionId = String(payload.sessionId || '');
    const text = String(payload.text || '').trim();
    if (!sessionId) throw new Error('Thiếu session ID.');
    if (!text || text.length > MAX_MESSAGE_CHARS) throw new Error(`Nội dung phải có 1–${MAX_MESSAGE_CHARS} ký tự.`);
    if (services.globalRunId) throw new Error('Mô hình local đang xử lý một lượt khác. Hãy dừng lượt hiện tại trước khi gửi tiếp.');

    const runId = `run_${crypto.randomUUID()}`;
    const controller = new AbortController();
    const reservation = { runId, sessionId, controller };
    services.globalRunId = runId;
    services.runs.set(runId, controller);
    services.activeSessionRuns.set(sessionId, runId);

    let session;
    let mode = 'agent';
    let attachments;
    let title = '';
    try {
      session = await services.sessionStore.getSession(sessionId);
      if (!session) throw new Error('Không tìm thấy cuộc trò chuyện.');
      session = structuredClone(session);
      mode = ['chat', 'agent', 'plan'].includes(payload.mode) ? payload.mode : session.mode || 'agent';
      attachments = Array.isArray(payload.attachments) ? payload.attachments.slice(0, MAX_ATTACHMENTS) : [];
      const workspace = session.workspace || (await services.settingsStore.getInternal()).fileRoot || '';
      if (workspace) await rebuildToolSources(workspace, { allowActive: true });
      const userMessage = {
        id: safeClientId(payload.clientMessageId, 'user'),
        role: 'user',
        content: text,
        createdAt: Date.now(),
        attachments: attachments.map((file) => ({
          name: String(file.name || path.basename(String(file.path || 'attachment'))).slice(0, 300),
          path: String(file.path || '').slice(0, 4096),
          size: Number(file.size || 0),
          truncated: Boolean(file.truncated),
        })),
      };
      await services.sessionStore.appendMessage(sessionId, userMessage);
      title = await ensureSessionTitle(sessionId, text);
      sendEvent({ type: 'message', sessionId, message: userMessage });
      await persistRun(sessionId, runId, { status: 'running', mode, startedAt: Date.now() });
      sendEvent({ type: 'run-start', runId, sessionId, mode });
    } catch (error) {
      releaseRun(runId, sessionId);
      throw error;
    }

    void (async () => {
      try {
        const result = await services.runner.run({
          session,
          text,
          mode,
          attachments,
          signal: controller.signal,
          runId,
        });
        if (controller.signal.aborted) throw abortError();
        const assistantMessage = {
          id: safeClientId(payload.clientAssistantMessageId, 'assistant'),
          role: 'assistant',
          content: result.text,
          createdAt: Date.now(),
          runId,
          usage: result.usage || null,
        };
        await services.sessionStore.appendMessage(sessionId, assistantMessage);
        await persistRun(sessionId, runId, { status: 'completed', endedAt: Date.now(), usage: result.usage || null });
        sendEvent({ type: 'message', sessionId, message: assistantMessage });
        sendEvent({ type: 'run-complete', runId, sessionId, messageId: assistantMessage.id, title });
      } catch (error) {
        if (error?.name === 'AbortError' || controller.signal.aborted) {
          await persistRun(sessionId, runId, { status: 'cancelled', endedAt: Date.now() });
          sendEvent({ type: 'run-cancelled', runId, sessionId });
          services.logger.info('Run cancelled', { runId, sessionId });
        } else {
          services.logger.error('Agent run failed', { runId, sessionId, error: error?.message || String(error) });
          await persistRun(sessionId, runId, { status: 'failed', endedAt: Date.now(), error: String(error?.message || error).slice(0, 2000) });
          const message = `Mình gặp lỗi khi xử lý yêu cầu: ${error?.message || String(error)}`;
          sendEvent({ type: 'run-error', runId, sessionId, error: message });
        }
      } finally {
        releaseRun(runId, sessionId);
      }
    })();
    return { runId, reservation: true };
  });

  handle('chat:cancel', (_event, { runId } = {}) => {
    const controller = services.runs.get(String(runId || ''));
    if (!controller) return { cancelled: false };
    controller.abort();
    services.logger.info('Cancellation requested', { runId: String(runId) });
    return { cancelled: true };
  });
  handle('interaction:respond', (_event, payload = {}) => {
    const responded = services.interactions.respond(String(payload.id || ''), {
      type: payload.type,
      answer: payload.answer,
      approved: payload.approved,
    });
    if (!responded) throw new Error('Tương tác không còn hoạt động.');
    return { ok: true };
  });

  handle('workspace:select', async () => {
    if (services.globalRunId) throw new Error('Hãy dừng lượt agent trước khi đổi workspace.');
    const parent = mainWindow;
    const result = await dialog.showOpenDialog(parent, {
      title: 'Chọn thư mục dự án',
      properties: ['openDirectory', 'createDirectory'],
    });
    if (result.canceled || !result.filePaths[0]) return null;
    const workspace = path.resolve(result.filePaths[0]);
    await rememberApprovedRoot(workspace);
    await services.settingsStore.update({ fileRoot: workspace });
    await rebuildToolSources(workspace);
    sendEvent({ type: 'workspace-changed', workspace });
    return workspace;
  });
  handle('workspace:open-attachments', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Chọn tệp đính kèm',
      properties: ['openFile', 'multiSelections'],
    });
    if (result.canceled) return [];
    return readSelectedFiles(result.filePaths.slice(0, MAX_ATTACHMENTS));
  });

  handle('shell:open-external', async (_event, { url } = {}) => {
    const parsed = new URL(String(url || ''));
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error('Chỉ được mở liên kết http/https không chứa credential.');
    await shell.openExternal(parsed.toString());
    return { ok: true };
  });
  handle('shell:reveal-path', async (_event, { path: targetPath } = {}) => {
    const requested = path.resolve(String(targetPath || ''));
    const value = await canonicalExistingPath(requested);
    if (!value) throw new Error('Đường dẫn không tồn tại.');
    const root = services.toolRoot ? await canonicalExistingPath(services.toolRoot) : null;
    const allowed = (root && pathInside(root, value)) || services.revealPaths.has(value.toLowerCase());
    if (!allowed) throw new Error('Đường dẫn không thuộc workspace hoặc tệp người dùng đã chọn.');
    shell.showItemInFolder(value);
    return { ok: true };
  });

  handle('settings:get', () => services.settingsStore.get());
  handle('settings:update', async (_event, patch = {}) => {
    if (services.globalRunId) throw new Error('Hãy dừng lượt agent trước khi đổi cấu hình.');
    const requestedRoot = Object.prototype.hasOwnProperty.call(patch, 'fileRoot') ? patch.fileRoot : patch.workspace;
    if (requestedRoot && !isApprovedRoot(path.resolve(String(requestedRoot)))) {
      throw new Error('Workspace chỉ được thay đổi qua hộp thoại chọn thư mục.');
    }
    if (patch.allowFallbackTools === true && (await services.settingsStore.getInternal()).allowFallbackTools !== true) {
      const fallbackConfirmation = await dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: 'Bật tương thích tool Qwen',
        message: 'Qwen Q3 có thể phát tool call dạng <call> thay vì tool_calls chuẩn.',
        detail: 'Bật tùy chọn này cho phép fallback dạng read-only/mutation trong Agent. Mọi tool vẫn bị giới hạn bởi workspace, allowlist và schema, nhưng đây là quyền thay đổi trạng thái.',
        buttons: ['Hủy', 'Bật'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      });
      if (fallbackConfirmation.response !== 1) throw new Error('Đã hủy bật fallback Qwen.');
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'mcpServers')) {
      const currentMcp = (await services.settingsStore.getInternal()).mcpServers || {};
      const requestedMcp = patch.mcpServers || {};
      if (!equivalentIgnoringRedacted(currentMcp, requestedMcp)) {
        const confirmation = await dialog.showMessageBox(mainWindow, {
          type: 'warning',
          title: 'Xác nhận cấu hình MCP',
          message: 'Cấu hình MCP có thể chạy chương trình hoặc gửi request đến server bên ngoài.',
          detail: 'Chỉ tiếp tục nếu bạn tin tưởng tất cả command, URL và secret trong cấu hình.',
          buttons: ['Hủy', 'Áp dụng'],
          defaultId: 0,
          cancelId: 0,
          noLink: true,
        });
        if (confirmation.response !== 1) throw new Error('Đã hủy cập nhật MCP.');
      }
    }
    const previous = await services.settingsStore.getInternal();
    let settings;
    try {
      settings = await services.settingsStore.update(patch);
      const internal = await services.settingsStore.getInternal();
      const toolKeys = ['fileRoot', 'webProvider', 'searchProvider', 'braveApiKey', 'mcpServers'];
      const toolsChanged = toolKeys.some((key) => Object.prototype.hasOwnProperty.call(patch, key));
      await rebuildToolSources(internal.fileRoot || app.getPath('userData'), { force: toolsChanged });
      const mcpStatus = Object.prototype.hasOwnProperty.call(patch, 'mcpServers') ? await reloadConfiguredMcp() : await services.mcpManager.status();
      sendEvent({ type: 'settings-updated', settings });
      sendEvent({ type: 'mcp-status', status: mcpStatus });
      return settings;
    } catch (error) {
      try {
        await services.settingsStore.update(previous);
        await rebuildToolSources(previous.fileRoot || app.getPath('userData'), { force: true });
        await reloadConfiguredMcp();
      } catch (rollbackError) {
        services.logger.error('Settings rollback failed', { error: rollbackError?.message || String(rollbackError) });
      }
      throw error;
    }
  });
  handle('settings:reset', async () => {
    if (services.globalRunId) throw new Error('Hãy dừng lượt agent trước khi reset cấu hình.');
    const settings = await services.settingsStore.reset();
    await rebuildToolSources(app.getPath('userData'), { force: true });
    const mcpStatus = await reloadConfiguredMcp();
    sendEvent({ type: 'settings-updated', settings });
    sendEvent({ type: 'mcp-status', status: mcpStatus });
    return settings;
  });

  handle('lm:status', async () => {
    const status = await services.lmClient.getStatus();
    sendEvent({ type: 'status', lm: status });
    return status;
  });
  handle('lm:start-server', async () => {
    const settings = await services.settingsStore.getInternal();
    const port = Number(new URL(settings.lmBaseUrl).port || 1234);
    const result = await services.lmClient.startServer(port);
    const status = await services.lmClient.getStatus();
    sendEvent({ type: 'status', lm: status });
    return { ...result, status };
  });
  handle('lm:install-cli', async () => {
    const result = await services.lmClient.installCli();
    services.logger.info('LM Studio CLI installer completed');
    return result;
  });
  handle('lm:load-model', async (_event, { id } = {}) => {
    const settings = await services.settingsStore.getInternal();
    const result = await services.lmClient.loadModel(id, {
      contextLength: settings.contextLength || 2048,
      flashAttention: settings.flashAttention !== false,
    });
    await services.settingsStore.update({ model: String(id) });
    const status = await services.lmClient.getStatus();
    sendEvent({ type: 'status', lm: status });
    return { result, status };
  });
  handle('mcp:reload', async () => {
    if (services.globalRunId) throw new Error('Hãy dừng lượt agent trước khi reload MCP.');
    const status = await reloadConfiguredMcp();
    sendEvent({ type: 'mcp-status', status });
    return status;
  });
  handle('tools:catalog', (_event, { mode } = {}) => services.broker.allDefinitions(mode));
  handle('debug:recent-log', () => services.logger.recent());
}

async function readSelectedFiles(filePaths) {
  const files = [];
  for (const filePath of filePaths) {
    const stat = await fs.stat(filePath).catch(() => null);
    if (!stat?.isFile()) continue;
    const base = { path: filePath, name: path.basename(filePath), size: stat.size, truncated: false };
    const canonical = await canonicalExistingPath(filePath);
    rememberRevealPath(canonical || filePath);
    if (stat.size > MAX_ATTACHMENT_BYTES) {
      const handle = await fs.open(filePath, 'r');
      try {
        const buffer = Buffer.alloc(MAX_ATTACHMENT_BYTES);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        files.push({ ...base, content: buffer.subarray(0, bytesRead).toString('utf8'), truncated: true });
      } finally {
        await handle.close();
      }
      continue;
    }
    const buffer = await fs.readFile(filePath);
    const isProbablyText = !buffer.subarray(0, Math.min(buffer.length, 4096)).includes(0);
    files.push({
      ...base,
      content: isProbablyText ? buffer.toString('utf8') : '[Tệp nhị phân — model text không thể đọc trực tiếp.]',
    });
  }
  return files;
}

async function persistRun(sessionId, runId, patch) {
  try {
    await services.sessionStore.updateRun(sessionId, runId, patch);
  } catch (error) {
    services.logger.warn('Could not persist run state', { sessionId, runId, error: error?.message || String(error) });
  }
}

async function ensureSessionTitle(sessionId, text) {
  const session = await services.sessionStore.getSession(sessionId);
  if (!session?.title || session.title === 'Cuộc trò chuyện mới') {
    const title = String(text).replace(/\s+/g, ' ').trim().slice(0, 70);
    await services.sessionStore.updateTitle(sessionId, title || 'Cuộc trò chuyện mới');
    return title;
  }
  return session.title;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 940,
    minWidth: 1050,
    minHeight: 680,
    show: false,
    backgroundColor: '#0b0e14',
    icon: path.join(__dirname, '..', '..', 'assets', 'icon.png'),
    title: 'CodePilot Local',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  mainWindow.removeMenu();
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url);
      if (['http:', 'https:'].includes(parsed.protocol)) shell.openExternal(url);
    } catch { /* ignore */ }
    return { action: 'deny' };
  });
  const approvedRendererUrl = pathToFileURL(expectedRendererPath()).toString();
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (url !== approvedRendererUrl) event.preventDefault();
  });
  mainWindow.webContents.on('will-redirect', (event, url) => {
    if (url !== approvedRendererUrl) event.preventDefault();
  });
  mainWindow.webContents.on('will-frame-navigate', (event, url) => {
    if (url !== approvedRendererUrl) event.preventDefault();
  });
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

async function pollStatus() {
  if (!services || !mainWindow || statusPollInFlight) return;
  statusPollInFlight = true;
  try {
    const status = await services.lmClient.getStatus();
    const signature = JSON.stringify({ online: status.online, selected: status.selectedModel, loaded: status.loaded.map((item) => item.id) });
    if (signature !== lastStatusSignature) {
      lastStatusSignature = signature;
      sendEvent({ type: 'status', lm: status });
    }
  } catch { /* status is best effort */ } finally {
    statusPollInFlight = false;
  }
}

app.setAppUserModelId('local.codepilot.desktop');
app.whenReady().then(async () => {
  services = createServices();
  try {
    await initializeServices();
  } catch (error) {
    dialog.showErrorBox('Không thể khởi tạo CodePilot Local', error?.stack || error?.message || String(error));
    quitReady = true;
    app.exit(1);
    return;
  }
  registerIpc();
  createWindow();
  statusTimer = setInterval(() => void pollStatus(), 5000);
  void pollStatus();
  void (async () => {
    try {
      const settings = await services.settingsStore.getInternal();
      if (!settings.model) {
        const status = await services.lmClient.getStatus();
        if (status.selectedModel) await services.settingsStore.update({ model: status.selectedModel });
      }
      if (settings.mcpServers && Object.keys(settings.mcpServers).length) {
        const mcpStatus = await reloadConfiguredMcp();
        sendEvent({ type: 'mcp-status', status: mcpStatus });
      }
    } catch (error) {
      sendEvent({ type: 'notice', level: 'warning', message: `MCP chưa sẵn sàng: ${error.message}` });
    }
  })();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
}).catch((error) => {
  console.error(error);
  app.quit();
});

app.on('before-quit', (event) => {
  if (quitReady) return;
  event.preventDefault();
  if (quitting) return;
  quitting = true;
  if (statusTimer) clearInterval(statusTimer);
  for (const controller of services?.runs?.values() || []) controller.abort();
  services?.interactions?.cancelAll('Application is closing.');
  const cleanup = Promise.allSettled([
    Promise.resolve(services?.systemTools?.stop?.()),
    Promise.resolve(services?.mcpManager?.stop?.()),
  ]);
  const timeout = new Promise((resolve) => setTimeout(resolve, 5000));
  void Promise.race([cleanup, timeout]).finally(() => {
    quitReady = true;
    app.quit();
  });
});

function abortError() {
  const error = new Error('Cancelled');
  error.name = 'AbortError';
  return error;
}
