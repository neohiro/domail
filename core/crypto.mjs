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
  PWHASH_OPSLIMIT: 4,
  PWHASH_MEMLIMIT: 1073741824,
};

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

export async function deriveKey(password, salt, opts = {}) {
  assertSodium();
  const opslimit = opts.opslimit ?? CRYPTO.PWHASH_OPSLIMIT;
  const memlimit = opts.memlimit ?? CRYPTO.PWHASH_MEMLIMIT;
  const keyLen = opts.keyLen ?? CRYPTO.KEYBYTES;
  const pw = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const key = _sodium.crypto_pwhash(keyLen, pw, salt, opslimit, memlimit, _sodium.crypto_pwhash_ALG_ARGON2ID13);
  return key;
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
    if (detached) _sodium.crypto_sign_verify_detached(signature, message, publicKey);
    else _sodium.crypto_sign_open(signature, publicKey);
    return true;
  } catch {
    return false;
  }
}