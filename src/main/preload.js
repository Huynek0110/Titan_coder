'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const invoke = (channel, payload) => ipcRenderer.invoke(channel, payload);

const api = {
  ready: () => invoke('app:ready'),
  getBootstrap: () => invoke('app:bootstrap'),
  listSessions: () => invoke('sessions:list'),
  getSession: (id) => invoke('sessions:get', { id }),
  createSession: (payload = {}) => invoke('sessions:create', payload),
  deleteSession: (id) => invoke('sessions:delete', { id }),
  sendMessage: (payload) => invoke('chat:send', payload),
  cancelRun: (runId) => invoke('chat:cancel', { runId }),
  respondInteraction: (payload) => invoke('interaction:respond', payload),

  selectWorkspace: () => invoke('workspace:select'),
  openAttachments: () => invoke('workspace:open-attachments'),
  openExternal: (url) => invoke('shell:open-external', { url }),
  revealPath: (targetPath) => invoke('shell:reveal-path', { path: targetPath }),

  getSettings: () => invoke('settings:get'),
  updateSettings: (patch) => invoke('settings:update', patch),
  resetSettings: () => invoke('settings:reset'),
  lmStatus: () => invoke('lm:status'),
  startLmStudio: () => invoke('lm:start-server'),
  installLmCli: () => invoke('lm:install-cli'),
  loadModel: (id) => invoke('lm:load-model', { id }),
  reloadMcp: () => invoke('mcp:reload'),

  getToolCatalog: (mode = 'agent') => invoke('tools:catalog', { mode }),
  getRecentLog: () => invoke('debug:recent-log'),
  close: () => invoke('app:close'),

  onEvent(handler) {
    if (typeof handler !== 'function') throw new TypeError('onEvent requires a function');
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on('codepilot:event', listener);
    return () => ipcRenderer.removeListener('codepilot:event', listener);
  },
};

contextBridge.exposeInMainWorld('codepilot', Object.freeze(api));
