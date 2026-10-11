/**
 * DOM Mail cryptographic primitives.
 *
 * Zero dependencies. Pure ESM. No DOM, no Node globals.
 * Provides: Argon2id key derivation, XChaCha20-Poly1305 AEAD,
 * secure random, constant-time comparison, memory-zeroing helpers.
 */

const SODIUM_READY = (async () => {
  if (typeof window !== 'undefined' && window.sodium) return window.sodium;
  if (typeof globalThis !== 'undefined' && globalThis.sodium) return globalThis.sodium;
  try {
    const mod = await import('libsodium-wrappers');
    await mod.ready;
    return mod;
  } catch {
    return null;
  }
})();

let _sodium = null;
async function sodium() {
  if (!_sodium) _sodium = await SODIUM_READY;
  return _sodium;
}

export const CRYPTO = {
  KEYBYTES: 32,
  NONCEBYTES: 24,
  MACBYTES: 16,
  SALTBYTES: 16,
  /*
   * The bundled libsodium.js exposes no password-hashing function at all
   * (no crypto_pwhash / Argon2id, no scrypt) — only crypto_generichash
   * (BLAKE2b). deriveKey() therefore prefers Argon2id when the host provides
   * it and otherwise falls back to an iterated keyed-BLAKE2b construction.
   * See KDF_ID_* below: the identifier is mixed into the AEAD associated data
   * so data can never be silently reinterpreted under a different scheme.
   */
  PWHASH_OPSLIMIT: 4,
  PWHASH_MEMLIMIT: 1073741824,
  KDF_ITERATIONS: 120000,
};

export const KDF_ID_ARGON2ID = 1;
export const KDF_ID_BLAKE2B = 2;

/** True when the host libsodium provides Argon2id. */
function hasArgon2id() {
  assertSodium();
  return typeof _sodium.crypto_pwhash === 'function';
}

function assertSodium() {
  if (!_sodium) throw new Error('libsodium not initialized. Call CRYPTO.init() first.');
}

export async function init() {
  await sodium();
  if (!_sodium) throw new Error('libsodium failed to load. Ensure libsodium.js is available.');
}

export function randomBytes(len) {
  assertSodium();
  return _sodium.randombytes_buf(len);
}

export function zeroFill(buf) {
  if (buf && buf.fill) buf.fill(0);
}

/**
 * Stretch a passphrase into a symmetric key.
 *
 * Prefers Argon2id when available; otherwise uses an iterated keyed-BLAKE2b
 * construction, which the bundled libsodium can actually provide. Callers must
 * bind `kdfInfo()` into their AEAD associated data so a key derived under one
 * scheme is never accepted under the other.
 *
 * @param {string|Uint8Array} password
 * @param {Uint8Array} salt
 * @param {{opslimit?:number, memlimit?:number, keyLen?:number, iterations?:number}} opts
 * @returns {Promise<Uint8Array>}
 */
export async function deriveKey(password, salt, opts = {}) {
  assertSodium();
  if (!salt || salt.length < 8) throw new Error('deriveKey requires a salt of at least 8 bytes');
  const keyLen = opts.keyLen ?? CRYPTO.KEYBYTES;
  const pw = typeof password === 'string' ? new TextEncoder().encode(password) : password;

  if (hasArgon2id()) {
    const opslimit = opts.opslimit ?? CRYPTO.PWHASH_OPSLIMIT;
    const memlimit = opts.memlimit ?? CRYPTO.PWHASH_MEMLIMIT;
    return _sodium.crypto_pwhash(
      keyLen, pw, salt, opslimit, memlimit, _sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  }

  // Iterated keyed BLAKE2b. Not memory-hard; it trades that for portability.
  const iterations = Math.max(1, opts.iterations ?? CRYPTO.KDF_ITERATIONS);
  const counter = new Uint8Array(4);
  let block = _sodium.crypto_generichash(keyLen, pw, salt);
  for (let i = 0; i < iterations; i++) {
    counter[0] = i & 0xff;
    counter[1] = (i >>> 8) & 0xff;
    counter[2] = (i >>> 16) & 0xff;
    counter[3] = (i >>> 24) & 0xff;
    const input = new Uint8Array(block.length + 4);
    block.copyInto ? block.copyInto(input) : input.set(block);
    input.set(counter, block.length);
    block = _sodium.crypto_generichash(keyLen, input, salt);
  }
  return block;
}

/**
 * Bytes to mix into AEAD associated data so the KDF scheme and parameters are
 * authenticated. Both encryption and decryption must compute the same value or
 * the tag check fails, which is exactly what we want.
 */
export function kdfInfo(salt, opts = {}) {
  const id = hasArgon2id() ? KDF_ID_ARGON2ID : KDF_ID_BLAKE2B;
  const iterations = opts.iterations ?? CRYPTO.KDF_ITERATIONS;
  const memlimit = opts.memlimit ?? CRYPTO.PWHASH_MEMLIMIT;
  const out = new Uint8Array(12);
  out[0] = id;
  out[1] = 0; out[2] = 0; out[3] = 0;
  // Params, little-endian, so a future change cannot collide with old data.
  out[4] = iterations & 0xff;
  out[5] = (iterations >>> 8) & 0xff;
  out[6] = (iterations >>> 16) & 0xff;
  out[7] = (iterations >>> 24) & 0xff;
  out[8] = memlimit & 0xff;
  out[9] = (memlimit >>> 8) & 0xff;
  out[10] = (memlimit >>> 16) & 0xff;
  out[11] = (memlimit >>> 24) & 0xff;
  return out;
}

/** Concatenate salt + kdfInfo into AEAD associated data. */
export function kdfAad(salt, opts = {}) {
  const info = kdfInfo(salt, opts);
  const out = new Uint8Array(salt.length + info.length);
  out.set(salt, 0);
  out.set(info, salt.length);
  return out;
}

export async function encrypt(key, plaintext, associatedData = new Uint8Array()) {
  assertSodium();
  const nonce = randomBytes(CRYPTO.NONCEBYTES);
  const ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, associatedData, null, nonce, key);
  const out = new Uint8Array(CRYPTO.NONCEBYTES + ct.length);
  out.set(nonce);
  out.set(ct, CRYPTO.NONCEBYTES);
  return out;
}

export async function decrypt(key, ciphertext, associatedData = new Uint8Array()) {
  assertSodium();
  if (ciphertext.length < CRYPTO.NONCEBYTES + CRYPTO.MACBYTES) throw new Error('ciphertext too short');
  const nonce = ciphertext.slice(0, CRYPTO.NONCEBYTES);
  const ct = ciphertext.slice(CRYPTO.NONCEBYTES);
  try {
    return _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, associatedData, nonce, key);
  } catch {
    throw new Error('decryption failed: authentication tag mismatch');
  }
}

export function constantTimeEqual(a, b) {
  assertSodium();
  if (a.length !== b.length) return false;
  return _sodium.sodium_memcmp(a, b) === 0;
}

export function base64(bytes) {
  assertSodium();
  return _sodium.to_base64(bytes, _sodium.base64_variants.ORIGINAL);
}

export function fromBase64(str) {
  assertSodium();
  return _sodium.from_base64(str, _sodium.base64_variants.ORIGINAL);
}

export async function generateKeyPair() {
  assertSodium();
  const kp = _sodium.crypto_box_keypair();
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
}

export async function seal(publicKey, message) {
  assertSodium();
  return _sodium.crypto_box_seal(message, publicKey);
}

export async function openSealed(privateKey, publicKey, ciphertext) {
  assertSodium();
  return _sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey);
}

export async function sign(detached, message, privateKey) {
  assertSodium();
  if (detached) return _sodium.crypto_sign_detached(message, privateKey);
  return _sodium.crypto_sign(message, privateKey);
}

export async function verify(detached, signature, message, publicKey) {
  assertSodium();
  try {
    if (detached) {
      /*
       * libsodium's JS bindings are inconsistent about how a failed
       * verification is reported. The stock `libsodium-wrappers` build throws,
       * but the bundled build returns a boolean. Ignoring the return value
       * here made every signature look valid, so honour both conventions:
       * a missing/false/!==0 result means the signature is NOT valid.
       */
      const ok = _sodium.crypto_sign_verify_detached(signature, message, publicKey);
      return ok === true || ok === 0;
    }
    // crypto_sign_open returns the signed message on success and throws on
    // failure, so reaching this point means the signature checked out.
    _sodium.crypto_sign_open(signature, publicKey);
    return true;
  } catch {
    return false;
  }
}