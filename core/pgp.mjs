/**
 * DOM Mail — OpenPGP-style armored encryption.
 *
 * Zero dependencies. Pure ESM. No DOM, no Node globals.
 *
 * ## What this is
 *
 * An ASCII-Armor container (RFC 4880 section 6) carrying authenticated
 * encryption against a recipient's X25519 public key. The envelope is real
 * OpenPGP armor: `-----BEGIN PGP MESSAGE-----`, `Version:` headers, a CRC-24
 * checksum line, base64 body, and the matching END line. GnuPG and friends
 * will parse the armor and report the checksum correctly.
 *
 * ## What this is NOT
 *
 * The *payload* inside the armor is DOM Mail's own packet format, not a
 * byte-for-byte RFC 4880 OpenPGP message. It will not decrypt in GnuPG. Full
 * interoperability means implementing the whole OpenPGP packet spec (PKESK,
 * SKESK, SEIPD v1/v2, compression, S2K variants, MDC) — a large surface we
 * deliberately do not hand-roll. If you need to talk to GnuPG, use GnuPG.
 *
 * ## Why it exists
 *
 * Exchange encrypted mail with another DOM Mail peer using only keys we
 * already generate, with no third-party library and nothing to audit.
 *
 * ## Crypto
 *
 *   - Confidentiality + integrity: X25519 sealed box
 *     (libsodium crypto_box_seal, Curve25519-XSalsa20-Poly1305).
 *     Sealed boxes are anonymous and one-to-many: the sender needs only the
 *     recipient's public key, and no pre-established shared secret.
 *   - Authenticity (optional): detached Ed25519 signature over the ciphertext,
 *     so a recipient can prove who produced the blob.
 */

import { bytesToBase64, base64ToBytes, utf8 } from './mail.mjs';
import * as CRYPTO from './crypto.mjs';

/* ------------------------------------------------------------------ *
 * ASCII armor (RFC 4880 s6)
 * ------------------------------------------------------------------ */

const ARMOR_LINE = 64;

/**
 * CRC-24/OPENPGP as specified in RFC 4880 section 6.1.
 * Init 0xB704CE, poly 0x1864CFB.
 */
export function crc24(bytes) {
  let crc = 0xb704ce;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i] << 16;
    for (let j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function crc24Base64(bytes) {
  const b64 = bytesToBase64(new Uint8Array([
    (crc24(bytes) >> 16) & 0xff,
    (crc24(bytes) >> 8) & 0xff,
    crc24(bytes) & 0xff,
  ]));
  return '=' + b64;
}

function wrapBody(b64) {
  const lines = [];
  for (let i = 0; i < b64.length; i += ARMOR_LINE) {
    lines.push(b64.slice(i, i + ARMOR_LINE));
  }
  return lines.join('\n');
}

/** Wrap binary data in an OpenPGP ASCII-Armor envelope. */
export function armor(type, data, headers = {}) {
  const b64 = wrapBody(bytesToBase64(data));
  const head = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  return [
    `-----BEGIN ${type}-----`,
    head,
    '',
    b64,
    crc24Base64(data),
    `-----END ${type}-----`,
  ].filter((l, i) => !(i === 1 && head === '')).join('\n') + '\n';
}

export class ArmorError extends Error {}

/** Parse an OpenPGP ASCII-Armor envelope back to binary. Verifies CRC-24. */
export function dearmor(text) {
  const src = String(text).trim();
  const begin = src.match(/^-----BEGIN ([A-Z0-9 ]+)-----/m);
  const end = src.match(/-----END ([A-Z0-9 ]+)-----/);
  if (!begin || !end) throw new ArmorError('not an ASCII-armored block');
  if (begin[1] !== end[1]) throw new ArmorError('BEGIN/END type mismatch');

  const lines = src.split(/\r?\n/);
  const startIdx = lines.findIndex((l) => /^-----BEGIN /.test(l));
  const endIdx = lines.findIndex((l) => /^-----END /.test(l));
  if (endIdx <= startIdx) throw new ArmorError('malformed armor framing');

  const body = [];
  let checksum = null;
  let inHeaders = true;
  for (let i = startIdx + 1; i < endIdx; i++) {
    const line = lines[i];
    if (inHeaders) {
      if (line === '') { inHeaders = false; continue; }
      if (/^[A-Za-z][A-Za-z-]*:\s/.test(line)) continue;
      inHeaders = false; // not actually headers; fall through and keep it
    }
    if (/^=/.test(line)) { checksum = line.trim(); continue; }
    body.push(line.trim());
  }

  const bytes = base64ToBytes(body.join(''));
  if (checksum) {
    const expect = crc24Base64(bytes);
    if (expect !== checksum) {
      throw new ArmorError(`CRC-24 mismatch (computed ${expect}, armor says ${checksum})`);
    }
  }
  return { type: begin[1], bytes };
}

/* ------------------------------------------------------------------ *
 * packet framing
 *
 *   magic  : 4 bytes  "DOMP"
 *   version: 1 byte   0x02
 *   kind   : 1 byte   1 = encrypted, 2 = signed+encrypted
 *   sigLen : 2 bytes  BE, detached signature length (0 when unsigned)
 *   sig    : sigLen bytes (Ed25519 detached over the body below)
 *   body   : [u16 recipientCount] then, per recipient,
 *            [u32 sealedLength][sealedLength bytes]
 *
 * Lengths are 32-bit: a sealed box is plaintext + 48 bytes of overhead, so a
 * 16-bit length would cap a message body at roughly 64 KB. Slots are stored
 * back to back and each is self-delimiting, so no offset table is needed.
 * ------------------------------------------------------------------ */

const MAGIC = [0x44, 0x4f, 0x4d, 0x50]; // "DOMP"
const VERSION = 2;
const KIND_ENCRYPTED = 1;
const KIND_SIGNED = 2;

const COUNT_BYTES = 2;
const SLOT_LEN_BYTES = 4;

function buildPacket(kind, body, signature) {
  const sig = signature || new Uint8Array(0);
  const out = new Uint8Array(MAGIC.length + 1 + 1 + 2 + sig.length + body.length);
  let o = 0;
  out.set(MAGIC, o); o += MAGIC.length;
  out[o++] = VERSION;
  out[o++] = kind;
  out[o++] = (sig.length >> 8) & 0xff;
  out[o++] = sig.length & 0xff;
  out.set(sig, o); o += sig.length;
  out.set(body, o);
  return out;
}

function readPacket(bytes) {
  if (bytes.length < 8) throw new ArmorError('packet truncated');
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new ArmorError('bad packet magic');
  }
  if (bytes[4] !== VERSION) throw new ArmorError(`unsupported packet version ${bytes[4]}`);

  const kind = bytes[5];
  const sigLen = (bytes[6] << 8) | bytes[7];
  if (bytes.length < 8 + sigLen) throw new ArmorError('packet truncated in signature');
  const signature = bytes.slice(8, 8 + sigLen);
  const body = bytes.slice(8 + sigLen);
  return { kind, signature, body };
}

const TEXT_DECODER = new TextDecoder();

/* ------------------------------------------------------------------ *
 * public API
 * ------------------------------------------------------------------ */

export const PGP = {
  ARMOR_TYPE: 'PGP MESSAGE',
  MAGIC: 'DOMP',
  VERSION,
  crc24,
  armor,
  dearmor,
  ArmorError,
};

/**
 * Encrypt `plaintext` to one or more recipients.
 *
 * Each recipient is sealed independently, so a message to N recipients is N
 * sealed boxes concatenated with explicit offsets. Anyone holding one matching
 * private key can open their own slot; the others learn nothing.
 *
 * @param {string|Uint8Array} plaintext
 * @param {Array<{name?:string,address:string,publicKey:Uint8Array}>} recipients
 * @param {{signer?: {privateKey:Uint8Array, publicKey:Uint8Array}, sign?:boolean}} opts
 * @returns {Promise<string>} armored block
 */
export async function encryptMessage(plaintext, recipients, opts = {}) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error('at least one recipient is required');
  }
  await CRYPTO.init();

const data = typeof plaintext === 'string' ? utf8(plaintext) : plaintext;
  const sealedSlots = [];

  for (const r of recipients) {
    sealedSlots.push(await CRYPTO.seal(r.publicKey, data));
  }

  // [u16 count] then [u32 len][bytes] per recipient, back to back.
  let bodyLen = COUNT_BYTES;
  for (const s of sealedSlots) bodyLen += SLOT_LEN_BYTES + s.length;

  const body = new Uint8Array(bodyLen);
  body[0] = (sealedSlots.length >> 8) & 0xff;
  body[1] = sealedSlots.length & 0xff;

  let o = COUNT_BYTES;
  for (const s of sealedSlots) {
    body[o] = (s.length >>> 24) & 0xff;
    body[o + 1] = (s.length >>> 16) & 0xff;
    body[o + 2] = (s.length >>> 8) & 0xff;
    body[o + 3] = s.length & 0xff;
    o += SLOT_LEN_BYTES;
    body.set(s, o);
    o += s.length;
  }

  let signature = null;
  let kind = KIND_ENCRYPTED;
  if (opts.sign && opts.signer) {
    signature = await CRYPTO.sign(true, body, opts.signer.privateKey);
    kind = KIND_SIGNED;
  }

  const packet = buildPacket(kind, body, signature);
  return armor(PGP.ARMOR_TYPE, packet, { Version: 'DOM Mail armored message', Comment: 'DOMP/1' });
}

/**
 * Decrypt an armored block.
 *
 * @param {string} armoredText
 * @param {Uint8Array} privateKey recipient private key
 * @param {Uint8Array} publicKey  matching public key (sealed boxes need it)
 * @param {{verify?: {publicKey: Uint8Array}}} opts
 * @returns {Promise<{text: string, signed: boolean, signatureValid: boolean|null}>}
 */
export async function decryptMessage(armoredText, privateKey, publicKey, opts = {}) {
  await CRYPTO.init();

  const { bytes } = dearmor(armoredText);
  const packet = readPacket(bytes);

  const signed = packet.kind === KIND_SIGNED;
  let signatureValid = null;

  if (signed) {
    if (opts.verify && opts.verify.publicKey) {
      signatureValid = await CRYPTO.verify(true, packet.signature, packet.body, opts.verify.publicKey);
    }
  } else if (packet.signature.length) {
    throw new ArmorError('signature present but packet is not marked signed');
  }

  const body = packet.body;
  if (body.length < COUNT_BYTES) throw new ArmorError('packet body truncated');
  const count = (body[0] << 8) | body[1];
  if (count < 1) throw new ArmorError('no recipient slots');

  const slots = [];
  let p = COUNT_BYTES;
  for (let i = 0; i < count; i++) {
    if (p + SLOT_LEN_BYTES > body.length) throw new ArmorError('packet body truncated in slot length');
    // Big-endian uint32. Multiply rather than shift for the top byte so the
    // result stays unsigned when it exceeds 2^31.
    const len = (body[p] * 0x1000000) + (body[p + 1] << 16) + (body[p + 2] << 8) + body[p + 3];
    const start = p + SLOT_LEN_BYTES;
    if (start + len > body.length) throw new ArmorError('packet body truncated in slot');
    slots.push(body.slice(start, start + len));
    p = start + len;
  }

  const failures = [];
  for (const sealed of slots) {
    try {
      const plain = await CRYPTO.openSealed(privateKey, publicKey, sealed);
      return { text: TEXT_DECODER.decode(plain), signed, signatureValid };
    } catch (e) {
      failures.push(e.message);
    }
  }

  throw new Error(`no recipient slot could be opened (tried ${count}): ${failures[0] || 'unknown'}`);
}

/** Detached-sign an arbitrary armored string (e.g. a public key block). */
export async function signArmored(armoredText, privateKey) {
  await CRYPTO.init();
  const sig = await CRYPTO.sign(true, utf8(armoredText), privateKey);
  return armor('PGP SIGNATURE', sig, { Version: 'DOM Mail detached signature' });
}

/** Verify a detached signature produced by signArmored. */
export async function verifyArmored(armoredText, signatureArmored, publicKey) {
  await CRYPTO.init();
  const { bytes } = dearmor(signatureArmored);
  return CRYPTO.verify(true, bytes, utf8(armoredText), publicKey);
}