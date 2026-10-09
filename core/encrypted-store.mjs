/**
 * DOM Mail encrypted storage adapter.
 *
 * Wraps any key-value store (IndexedDB, memory, filesystem) with
 * authenticated encryption (XChaCha20-Poly1305) and Argon2id key derivation.
 *
 * Threat model: attacker has full read access to the underlying storage.
 * They cannot decrypt without the user's passphrase.
 */

import { MailEngine } from './mail.mjs';
import * as CRYPTO from './crypto.mjs';

const ENVELOPE_VERSION = 1;
const MASTER_KEY_LABEL = '__master_key__';
const SALT_LABEL = '__salt__';
const VERSION_LABEL = '__version__';

export class EncryptedStore {
  /**
   * @param {{get:Function,set:Function,del:Function,clear:Function,destroy?:Function}} backend
   * @param {object} opts
   * @param {Uint8Array} [opts.masterKey] - Pre-derived 32-byte key (for testing)
   * @param {string} [opts.passphrase] - User passphrase to derive key
   * @param {Uint8Array} [opts.salt] - Existing salt (for unlocking)
   */
  constructor(backend, opts = {}) {
    this.backend = backend;
    this.masterKey = opts.masterKey ?? null;
    this.passphrase = opts.passphrase ?? null;
    this.salt = opts.salt ?? null;
    this._locked = true;
    this._initPromise = null;
  }

  async _ensureInit() {
    if (this._initPromise) return this._initPromise;
    this._initPromise = (async () => {
      await CRYPTO.init();
      if (this.masterKey) {
        this._locked = false;
        return;
      }
      const storedSalt = await this.backend.get(SALT_LABEL);
      if (storedSalt) {
        this.salt = CRYPTO.fromBase64(storedSalt);
      }
    })();
    return this._initPromise;
  }

  async lock() {
    CRYPTO.zeroFill(this.masterKey);
    this.masterKey = null;
    this.passphrase = null;
    this._locked = true;
  }

  async unlock(passphrase) {
    await this._ensureInit();
    if (!this.salt) throw new Error('no salt stored: initialize first');
    this.passphrase = passphrase;
    this.masterKey = await CRYPTO.deriveKey(passphrase, this.salt);
    this._locked = false;
  }

  async initialize(passphrase) {
    await this._ensureInit();
    if (!this._locked) throw new Error('already initialized');
    this.passphrase = passphrase;
    this.salt = CRYPTO.randomBytes(CRYPTO.SALTBYTES);
    this.masterKey = await CRYPTO.deriveKey(passphrase, this.salt);
    await this.backend.set(SALT_LABEL, CRYPTO.base64(this.salt));
    await this.backend.set(VERSION_LABEL, ENVELOPE_VERSION);
    this._locked = false;
  }

  _checkUnlocked() {
    if (this._locked || !this.masterKey) throw new Error('store is locked: call unlock() or initialize() first');
  }

  _envelopeKey(key) {
    return `enc:${key}`;
  }

  async get(key) {
    this._checkUnlocked();
    const encKey = this._envelopeKey(key);
    const envelope = await this.backend.get(encKey);
    if (!envelope) return undefined;
    const ct = CRYPTO.fromBase64(envelope.ct);
    const ad = new TextEncoder().encode(key);
    const plain = await CRYPTO.decrypt(this.masterKey, ct, ad);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async set(key, value) {
    this._checkUnlocked();
    const encKey = this._envelopeKey(key);
    const plain = new TextEncoder().encode(JSON.stringify(value));
    const ad = new TextEncoder().encode(key);
    const ct = await CRYPTO.encrypt(this.masterKey, plain, ad);
    await this.backend.set(encKey, { v: ENVELOPE_VERSION, ct: CRYPTO.base64(ct) });
  }

  async del(key) {
    this._checkUnlocked();
    await this.backend.del(this._envelopeKey(key));
  }

  async clear() {
    this._checkUnlocked();
    const allKeys = await this._listEncryptedKeys();
    for (const k of allKeys) await this.backend.del(k);
    this.masterKey = null;
    this.passphrase = null;
    this._locked = true;
  }

  async destroy() {
    await this.clear();
    if (this.backend.destroy) await this.backend.destroy();
    await this.backend.del(SALT_LABEL);
    await this.backend.del(VERSION_LABEL);
    await this.backend.del(MASTER_KEY_LABEL);
  }

  async _listEncryptedKeys() {
    const all = await this.backend.get('__all_keys__');
    if (Array.isArray(all)) {
      return all.filter(k => k.startsWith('enc:')).map(k => k);
    }
    if (this.backend instanceof Map || typeof this.backend.keys === 'function') {
      const keys = [];
      for (const k of this.backend.keys()) {
        if (typeof k === 'string' && k.startsWith('enc:')) keys.push(k);
      }
      return keys;
    }
    return [];
  }

  async serialize() {
    this._checkUnlocked();
    const allKeys = await this._listEncryptedKeys();
    const out = {};
    for (const ek of allKeys) {
      const envelope = await this.backend.get(ek);
      if (envelope) out[ek.slice(4)] = envelope;
    }
    out[SALT_LABEL] = await this.backend.get(SALT_LABEL);
    out[VERSION_LABEL] = await this.backend.get(VERSION_LABEL);
    return out;
  }

  isLocked() {
    return this._locked;
  }
}

export function createEncryptedStore(backend, opts = {}) {
  return new EncryptedStore(backend, opts);
}

export async function createMailEngineWithEncryption(backend, passphrase, opts = {}) {
  const store = createEncryptedStore(backend);
  await store.initialize(passphrase);
  const engine = new MailEngine(store, opts);
  engine.store = store;
  return engine;
}

export async function unlockMailEngine(engine, passphrase) {
  if (!engine.store || !(engine.store instanceof EncryptedStore)) {
    throw new Error('engine not using encrypted store');
  }
  await engine.store.unlock(passphrase);
  await engine.load();
  return engine;
}