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
const { Logger } = require('./core/logger');
const { SettingsStore } = require('./core/settings-store');
const { SessionStore } = require('./core/session-store');
const { WorkspaceTools } = require('./tools/workspace-tools');
const { WebTools } = require('./tools/web-tools');
const { SystemTools } = require('./tools/system-tools');
const { McpManager } = require('./core/mcp-manager');

const MAX_MESSAGE_CHARS = 40_000;
const MAX_ATTACHMENTS = 6;
const MAX_ATTACHMENT_BYTES = 750_000;

let mainWindow = null;
let services = null;
let statusTimer = null;
let lastStatusSignature = '';
let statusPollInFlight = false;

function cloneEventPayload(payload) {
  try { return structuredClone(payload); } catch { /* fall through to JSON-safe clone */ }
  try {
    return JSON.parse(JSON.stringify(payload, (_key, value) => {
      if (typeof value === 'function' || typeof value === 'symbol') return undefined;
      if (value instanceof Error) return { name: value.name, message: value.message };
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
  rememberRevealPath(safeRoot);
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
  await rebuildToolSources((await services.settingsStore.getInternal()).fileRoot || app.getPath('userData'));
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

function rememberRevealPath(target) {
  if (target) services.revealPaths.add(path.resolve(target).toLowerCase());
}

function isAllowedRevealPath(target) {
  const value = path.resolve(target);
  if (services.toolRoot && pathInside(services.toolRoot, value)) return true;
  return services.revealPaths.has(value.toLowerCase());
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
    const workspace = payload.workspace ? path.resolve(String(payload.workspace)) : '';
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
      const userMessage = { id: `msg_${crypto.randomUUID()}`, role: 'user', content: text, createdAt: Date.now() };
      await services.sessionStore.appendMessage(sessionId, userMessage);
      title = await ensureSessionTitle(sessionId, text);
      sendEvent({ type: 'message', sessionId, message: userMessage });
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
          id: `msg_${crypto.randomUUID()}`,
          role: 'assistant',
          content: result.text,
          createdAt: Date.now(),
          runId,
          usage: result.usage || null,
        };
        await services.sessionStore.appendMessage(sessionId, assistantMessage);
        sendEvent({ type: 'message', sessionId, message: assistantMessage });
        sendEvent({ type: 'run-complete', runId, sessionId, messageId: assistantMessage.id, title });
      } catch (error) {
        if (error?.name === 'AbortError' || controller.signal.aborted) {
          sendEvent({ type: 'run-cancelled', runId, sessionId });
          services.logger.info('Run cancelled', { runId, sessionId });
        } else {
          services.logger.error('Agent run failed', { runId, sessionId, error: error?.message || String(error) });
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
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Chỉ được mở liên kết http/https.');
    await shell.openExternal(parsed.toString());
    return { ok: true };
  });
  handle('shell:reveal-path', async (_event, { path: targetPath } = {}) => {
    const value = path.resolve(String(targetPath || ''));
    if (!isAllowedRevealPath(value)) throw new Error('Đường dẫn không thuộc workspace hoặc tệp người dùng đã chọn.');
    const stat = await fs.stat(value).catch(() => null);
    if (!stat) throw new Error('Đường dẫn không tồn tại.');
    shell.showItemInFolder(value);
    return { ok: true };
  });

  handle('settings:get', () => services.settingsStore.get());
  handle('settings:update', async (_event, patch = {}) => {
    if (services.globalRunId) throw new Error('Hãy dừng lượt agent trước khi đổi cấu hình.');
    const settings = await services.settingsStore.update(patch);
    const internal = await services.settingsStore.getInternal();
    const toolKeys = ['fileRoot', 'searchProvider', 'braveApiKey', 'mcpServers'];
    const toolsChanged = toolKeys.some((key) => Object.prototype.hasOwnProperty.call(patch, key));
    await rebuildToolSources(internal.fileRoot || app.getPath('userData'), { force: toolsChanged });
    const mcpStatus = toolsChanged ? await reloadConfiguredMcp() : await services.mcpManager.status();
    sendEvent({ type: 'settings-updated', settings });
    sendEvent({ type: 'mcp-status', status: mcpStatus });
    return settings;
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
      contextLength: settings.contextLength || 8192,
      flashAttention: settings.flashAttention,
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
    rememberRevealPath(filePath);
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

app.on('before-quit', () => {
  if (statusTimer) clearInterval(statusTimer);
  for (const controller of services?.runs?.values() || []) controller.abort();
  services?.interactions?.cancelAll('Application is closing.');
  void services?.systemTools?.stop?.();
  void services?.mcpManager?.stop?.();
});

function abortError() {
  const error = new Error('Cancelled');
  error.name = 'AbortError';
  return error;
}
