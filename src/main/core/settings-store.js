'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { redact } = require('./logger');
const {
  APP_NAME,
  APP_VERSION,
  DEFAULT_SETTINGS,
  SAFE_LIMITS,
  SETTINGS_VERSION,
  decorateSettingsAliases,
  sanitizeSettings,
  validateSettingsPatch,
} = require('./defaults');

const SETTINGS_FILE = 'settings.json';
const ENCRYPTED_PREFIX = 'codepilot:safe-storage:v1:';
const SECRET_KEY = 'braveApiKey';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  if (value === null || value === undefined) return value;
  return JSON.parse(JSON.stringify(value));
}

function defaultState() {
  return {
    settings: sanitizeSettings(DEFAULT_SETTINGS),
    encryptedSecret: null,
  };
}

function directoryIsUsable(directory) {
  if (typeof directory !== 'string' || !directory.trim()) return false;
  try {
    const resolved = path.resolve(directory);
    fs.mkdirSync(resolved, { recursive: true });
    fs.accessSync(resolved, fs.constants.R_OK | fs.constants.W_OK);
    return resolved;
  } catch {
    return null;
  }
}

function chooseDirectory(requested) {
  const selected = directoryIsUsable(requested);
  if (selected) return { dir: selected, fallback: false };

  const base = path.join(os.tmpdir(), 'CodePilotLocal');
  const selectedFallback = directoryIsUsable(base);
  if (selectedFallback) return { dir: selectedFallback, fallback: true };

  // This last attempt is intentionally process-specific.  os.tmpdir() is
  // normally writable, but a locked-down environment should not make the
  // constructor throw merely because a settings directory is unavailable.
  const emergency = path.join(
    os.tmpdir(),
    `CodePilotLocal-${process.pid}-${crypto.randomBytes(4).toString('hex')}`,
  );
  try {
    fs.mkdirSync(emergency, { recursive: true });
    return { dir: emergency, fallback: true };
  } catch {
    return { dir: base, fallback: true };
  }
}

function makeTempName(filePath) {
  return `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
}

async function atomicWriteJson(filePath, value) {
  const tempPath = makeTempName(filePath);
  try {
    const text = `${JSON.stringify(value, null, 2)}\n`;
    await fsp.mkdir(path.dirname(filePath), { recursive: true });
    await fsp.writeFile(tempPath, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await fsp.rename(tempPath, filePath);
    try {
      await fsp.chmod(filePath, 0o600);
    } catch {
      // chmod is not meaningful on every platform/filesystem.
    }
  } catch (error) {
    try { await fsp.unlink(tempPath); } catch { /* best effort */ }
    throw error;
  }
}

class SettingsStore {
  constructor(options = {}) {
    const { dir, safeStorage } = isObject(options) ? options : {};
    const selected = chooseDirectory(dir);
    this.dir = selected.dir;
    this.usedFallbackDir = selected.fallback;
    this.filePath = path.join(this.dir, SETTINGS_FILE);
    this.version = SETTINGS_VERSION;
    this.safeStorage = safeStorage;
    this._state = defaultState();
    this._loaded = false;
    this._queue = Promise.resolve();
  }

  _enqueue(operation) {
    const run = this._queue.then(operation, operation);
    // Keep the chain usable after a failed operation while returning the
    // original rejection to the caller that initiated it.
    this._queue = run.catch(() => undefined);
    return run;
  }

  _storageIsAvailable() {
    const storage = this.safeStorage;
    if (!storage || typeof storage.encryptString !== 'function' || typeof storage.decryptString !== 'function') return false;
    try {
      if (typeof storage.isEncryptionAvailable === 'function') return storage.isEncryptionAvailable() !== false;
      if (typeof storage.isEncryptionAvailable === 'boolean') return storage.isEncryptionAvailable;
      return true;
    } catch {
      return false;
    }
  }

  _encodeEncrypted(value) {
    let buffer;
    if (Buffer.isBuffer(value)) buffer = value;
    else if (value instanceof Uint8Array) buffer = Buffer.from(value);
    else if (typeof value === 'string') buffer = Buffer.from(value, 'utf8');
    else return null;
    // Always encode the adapter's return value before writing it.  Some
    // test/host adapters return a string rather than a Buffer, and storing
    // that string directly could expose a secret if the adapter is merely
    // wrapping the plaintext.
    return `${ENCRYPTED_PREFIX}base64:${buffer.toString('base64')}`;
  }

  _encryptSecret(secret) {
    if (!this._storageIsAvailable()) return null;
    try {
      return this._encodeEncrypted(this.safeStorage.encryptString(String(secret)));
    } catch {
      return null;
    }
  }

  _decryptSecret(encoded) {
    if (typeof encoded !== 'string' || !encoded) return null;
    if (!encoded.startsWith(ENCRYPTED_PREFIX)) {
      if (!this._storageIsAvailable()) return null;
      try {
        const bytes = Buffer.from(encoded, 'base64');
        return String(this.safeStorage.decryptString(bytes));
      } catch {
        return null;
      }
    }
    const payload = encoded.slice(ENCRYPTED_PREFIX.length);
    const separator = payload.indexOf(':');
    if (separator < 0) return null;
    const encoding = payload.slice(0, separator);
    const value = payload.slice(separator + 1);
    try {
      if (encoding === 'text') {
        return String(this.safeStorage.decryptString(value));
      }
      if (encoding === 'base64') {
        const bytes = Buffer.from(value, 'base64');
        try {
          return String(this.safeStorage.decryptString(bytes));
        } catch {
          // A small number of safeStorage adapters accept the original
          // UTF-8 string rather than a Buffer; support those adapters too.
          return String(this.safeStorage.decryptString(bytes.toString('utf8')));
        }
      }
    } catch {
      return null;
    }
    return null;
  }

  _readStateFromDisk() {
    let text;
    try {
      text = fs.readFileSync(this.filePath, 'utf8');
    } catch (error) {
      if (error && error.code !== 'ENOENT') {
        // An unreadable file is treated like a corrupt one.  The store still
        // gives the caller a usable, safe configuration.
      }
      return { state: defaultState(), shouldPersist: true };
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return { state: defaultState(), shouldPersist: true };
    }

    if (!isObject(parsed)) return { state: defaultState(), shouldPersist: true };
    const version = parsed.version ?? parsed.schemaVersion;
    if (version !== undefined && version !== SETTINGS_VERSION) {
      return { state: defaultState(), shouldPersist: true };
    }
    const source = isObject(parsed.settings) ? parsed.settings : parsed;
    const encryptedSecret = source.braveApiKeyEncrypted
      ?? (isObject(parsed.secrets) ? (parsed.secrets.braveApiKeyEncrypted ?? parsed.secrets.braveApiKey) : undefined)
      ?? (isObject(parsed.encryptedSecrets) ? (parsed.encryptedSecrets.braveApiKeyEncrypted ?? parsed.encryptedSecrets.braveApiKey) : undefined)
      ?? parsed.braveApiKeyEncrypted
      ?? null;
    let secret = '';
    if (typeof encryptedSecret === 'string' && encryptedSecret) {
      secret = this._decryptSecret(encryptedSecret) || '';
    } else if (typeof source.braveApiKey === 'string') {
      secret = source.braveApiKey;
    } else if (isObject(parsed.secrets) && typeof parsed.secrets.braveApiKey === 'string') {
      secret = parsed.secrets.braveApiKey;
    }

    const sanitizedSource = { ...source, braveApiKey: secret };
    delete sanitizedSource.braveApiKeyEncrypted;
    const settings = sanitizeSettings(sanitizedSource);
    return {
      state: { settings, encryptedSecret: typeof encryptedSecret === 'string' ? encryptedSecret : null },
      shouldPersist: false,
    };
  }

  async _loadUnlocked() {
    const result = this._readStateFromDisk();
    this._state = result.state;
    this._loaded = true;
    if (result.shouldPersist) {
      try {
        await this._writeStateUnlocked();
      } catch {
        // A read-only fallback directory should not prevent startup.
      }
    }
    return this;
  }

  async init() {
    return this._enqueue(() => this._loadUnlocked());
  }

  async load() {
    return this._enqueue(() => this._loadUnlocked());
  }

  async _writeStateUnlocked() {
    const settings = {
      ...this._state.settings,
      mcpServers: clone(this._state.settings.mcpServers),
      searchProvider: this._state.settings.webProvider,
    };
    // Never put the decrypted key in a plaintext field when an encrypted
    // representation is available.
    if (this._state.encryptedSecret) {
      delete settings.braveApiKey;
      settings.braveApiKeyEncrypted = this._state.encryptedSecret;
    } else if (settings.braveApiKey) {
      // This is the documented fallback when the host has no safeStorage.
      // Public callers still never receive this field.
    } else {
      delete settings.braveApiKey;
      delete settings.braveApiKeyEncrypted;
    }

    const document = {
      version: SETTINGS_VERSION,
      app: APP_NAME,
      appVersion: APP_VERSION,
      settings,
    };
    await atomicWriteJson(this.filePath, document);
  }

  async save() {
    return this._enqueue(async () => {
      await this._writeStateUnlocked();
      return this;
    });
  }

  async flush() {
    await this._queue;
    return this;
  }

  _publicState() {
    const raw = clone(this._state.settings);
    const present = Boolean(
      this._state.encryptedSecret
      || (typeof raw.braveApiKey === 'string' && raw.braveApiKey.length > 0),
    );
    const settings = redact(raw);
    delete settings.braveApiKey;
    settings.searchProvider = settings.webProvider;
    settings.braveApiKeyPresent = present;
    return decorateSettingsAliases(settings);
  }

  get encryptedSecret() {
    return this._state.encryptedSecret;
  }

  get() {
    return this._publicState();
  }

  getInternal() {
    const settings = decorateSettingsAliases(clone(this._state.settings));
    Object.defineProperty(settings, 'searchProvider', {
      configurable: true,
      enumerable: true,
      writable: true,
      value: settings.webProvider,
    });
    return settings;
  }

  getPublic() {
    return this.get();
  }

  getPublicSettings() {
    return this.get();
  }

  getSettings() {
    return this.get();
  }

  async update(patch) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      const validated = validateSettingsPatch(patch, this._state.settings);
      this._state.settings = sanitizeSettings({ ...this._state.settings, ...validated });
      if (Object.prototype.hasOwnProperty.call(validated, SECRET_KEY)) {
        const secret = validated[SECRET_KEY];
        this._state.encryptedSecret = secret ? this._encryptSecret(secret) : null;
        this._state.settings.braveApiKey = secret;
      }
      await this._writeStateUnlocked();
      return this.get();
    });
  }

  async setEncryptedSecret(secret, alreadyEncrypted) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      let value = '';
      let encrypted = null;
      if (secret !== null && secret !== undefined) value = String(secret);

      if (alreadyEncrypted !== undefined && alreadyEncrypted !== null) {
        // Also accept the conventional (name, value) form for callers that
        // manage a secret map.  There is currently one supported name.
        if ((secret === SECRET_KEY || secret === 'brave') &&
            typeof alreadyEncrypted === 'string' && !alreadyEncrypted.startsWith(ENCRYPTED_PREFIX)) {
          value = alreadyEncrypted;
          encrypted = this._encryptSecret(value);
        } else if (Buffer.isBuffer(alreadyEncrypted) || alreadyEncrypted instanceof Uint8Array) {
          encrypted = this._encodeEncrypted(alreadyEncrypted);
          try { value = String(this.safeStorage?.decryptString(Buffer.isBuffer(alreadyEncrypted) ? alreadyEncrypted : Buffer.from(alreadyEncrypted))); } catch { value = ''; }
        } else if (typeof alreadyEncrypted === 'string' && alreadyEncrypted.startsWith(ENCRYPTED_PREFIX)) {
          encrypted = alreadyEncrypted;
          value = this._decryptSecret(alreadyEncrypted) || '';
        } else if (typeof alreadyEncrypted === 'string') {
          encrypted = this._encodeEncrypted(alreadyEncrypted);
        }
      } else if (value) {
        encrypted = this._encryptSecret(value);
      }

      this._state.settings[SECRET_KEY] = value;
      this._state.encryptedSecret = value ? encrypted : null;
      await this._writeStateUnlocked();
      return this.get();
    });
  }

  async setSecret(secret) {
    return this.setEncryptedSecret(secret);
  }

  async setBraveApiKey(secret) {
    return this.setEncryptedSecret(secret);
  }

  async clear(secretName) {
    return this._enqueue(async () => {
      if (!this._loaded) await this._loadUnlocked();
      // clear() is intentionally a secret clear, not a settings reset.  An
      // optional name is accepted for callers that manage more than one
      // secret in the future; the only current secret is braveApiKey.
      if (secretName && secretName !== SECRET_KEY && secretName !== 'brave') {
        return this.get();
      }
      this._state.settings[SECRET_KEY] = '';
      this._state.encryptedSecret = null;
      await this._writeStateUnlocked();
      return this.get();
    });
  }

  async clearSecret() {
    return this.clear(SECRET_KEY);
  }

  async reset() {
    return this._enqueue(async () => {
      this._state = defaultState();
      this._loaded = true;
      await this._writeStateUnlocked();
      return this.get();
    });
  }
}

SettingsStore.SETTINGS_FILE = SETTINGS_FILE;
SettingsStore.SETTINGS_VERSION = SETTINGS_VERSION;
SettingsStore.ENCRYPTED_PREFIX = ENCRYPTED_PREFIX;
SettingsStore.APP_NAME = APP_NAME;
SettingsStore.APP_VERSION = APP_VERSION;
SettingsStore.SAFE_LIMITS = SAFE_LIMITS;
SettingsStore.atomicWriteJson = atomicWriteJson;
module.exports = SettingsStore;
module.exports.SettingsStore = SettingsStore;
module.exports.default = SettingsStore;
module.exports.SETTINGS_FILE = SETTINGS_FILE;
module.exports.SETTINGS_VERSION = SETTINGS_VERSION;
module.exports.ENCRYPTED_PREFIX = ENCRYPTED_PREFIX;
module.exports.atomicWriteJson = atomicWriteJson;
