'use strict';

// Finite Electron smoke test: it always kills its own process tree and never
// leaves a background app running. Intended for Node 24 on Windows.
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const electron = path.join(root, 'node_modules', 'electron', 'dist', 'electron.exe');
const port = 9337;
const outputDir = path.join(root, 'artifacts');
fs.mkdirSync(outputDir, { recursive: true });
const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'codepilot-smoke-'));

if (!fs.existsSync(electron)) {
  console.error('Electron binary is missing. Run npm.cmd install first.');
  process.exit(1);
}

const child = spawn(electron, [
  '.',
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${userData}`,
], {
  cwd: root,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let logs = '';
child.stdout.on('data', (chunk) => { logs = (logs + chunk).slice(-30_000); });
child.stderr.on('data', (chunk) => { logs = (logs + chunk).slice(-30_000); });

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function cdpClient() {
  let pages;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(800) });
      if (response.ok) {
        pages = await response.json();
        if (pages.some((page) => page.type === 'page')) break;
      }
    } catch { /* app is still starting */ }
    await delay(250);
  }
  const page = pages?.find((item) => item.type === 'page' && item.webSocketDebuggerUrl);
  if (!page) throw new Error(`Renderer CDP page did not appear.\n${logs}`);
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP connection timeout')), 2000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('CDP connection failed')); }, { once: true });
  });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data));
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    }
  });
  const call = (method, params = {}, timeoutMs = 3000) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
    setTimeout(() => {
      if (pending.delete(id)) reject(new Error(`CDP timeout: ${method}`));
    }, timeoutMs);
  });
  return { socket, call };
}

async function stopChild() {
  if (!child.pid || child.exitCode !== null) return;
  if (process.platform === 'win32') {
    spawnSync('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, timeout: 5000 });
  } else {
    child.kill('SIGKILL');
  }
  await Promise.race([
    new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('close', resolve);
      child.once('error', resolve);
    }),
    delay(3000),
  ]);
}

async function withDeadline(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} exceeded ${milliseconds}ms hard deadline`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

(async () => {
  let code = 1;
  try {
    const cdp = await withDeadline(cdpClient(), 20_000, 'Electron smoke');
    await cdp.call('Runtime.enable');
    await cdp.call('Page.enable');
    let details = null;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try {
        const evaluation = await cdp.call('Runtime.evaluate', {
          expression: `JSON.stringify({title: document.title, hasApi: Boolean(window.codepilot), body: document.body?.innerText?.slice(0, 300), ready: document.readyState})`,
          returnByValue: true,
        });
        if (evaluation?.result?.value) details = JSON.parse(evaluation.result.value);
        if (details?.ready === 'complete' && details.hasApi) break;
      } catch { /* renderer can still be loading or navigating */ }
      await delay(250);
    }
    if (!details || !String(details.title || '').startsWith('CodePilot') || !details.hasApi || details.ready !== 'complete') {
      throw new Error(`Unexpected renderer: ${JSON.stringify(details)}\n${logs}`);
    }
    const settingsProbe = await cdp.call('Runtime.evaluate', {
      expression: `window.codepilot.updateSettings({workspace:'',fileRoot:'',lmBaseUrl:'http://127.0.0.1:1234/v1',modelPreset:'qwen3-4b-1050ti',model:'qwen3-4b-instruct-2507',temperature:0.2,maxTokens:2048,contextLength:2048,contextChars:8000,maxSteps:8,maxSubagents:1,concurrentSubagents:1,maxConcurrentSubagents:1,maxSubagentSteps:6,flashAttention:true,approvalMode:'automatic',allowFallbackTools:false,braveApiKey:'',ddgFallback:true,webProvider:'duckduckgo',mcpServers:{},theme:'dark'}).then((value) => JSON.stringify({ok: Boolean(value), model: value?.model, contextLength: value?.contextLength})).catch((error) => JSON.stringify({error: String(error?.message || error)}))`,
      awaitPromise: true,
      returnByValue: true,
    });
    const settingsProbeValue = settingsProbe?.result?.value ? JSON.parse(settingsProbe.result.value) : {};
    if (settingsProbeValue.error) throw new Error(`Settings update probe failed: ${settingsProbeValue.error}\n${logs}`);

    try {
      const screenshot = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }, 15_000);
      if (screenshot?.data) {
        const screenshotPath = path.join(outputDir, 'electron-smoke.png');
        fs.writeFileSync(screenshotPath, Buffer.from(screenshot.data, 'base64'));
        console.log(`Screenshot: ${screenshotPath}`);
      }
    } catch (error) {
      console.warn(`Screenshot optional and unavailable: ${error.message}`);
    }
    console.log(`Electron smoke OK: ${JSON.stringify(details)}`);
    code = 0;
    cdp.socket.close();
  } catch (error) {
    console.error(error?.stack || error);
  } finally {
    await stopChild();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        fs.rmSync(userData, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        break;
      } catch (error) {
        if (attempt === 4) {
          console.warn(`Could not remove smoke profile: ${error.message}`);
        } else {
          await delay(250);
        }
      }
    }
  }
  process.exit(code);
})();
