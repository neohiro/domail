/**
 * Tests for the optional OpenPGP-style armor layer and the opt-in relay client.
 *
 * These cover the two highest-risk pieces of optional functionality:
 * a crypto path that must never silently produce garbage, and a network path
 * that must never connect unless explicitly asked.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RelayClient, RelayError, RELAY_DISCLOSURE, PGP_DISCLOSURE } from '../core/relay.mjs';
import { loadSodium } from './load-sodium.mjs';

/*
 * core/pgp.mjs pulls in core/crypto.mjs, which resolves libsodium from
 * globalThis the moment it is evaluated. So EVERY import of pgp.mjs must be
 * dynamic and must come after loadSodium(), otherwise crypto.mjs caches a null
 * libsodium and every crypto test fails with "libsodium failed to load".
 */
const sodium = await loadSodium();
const skipCrypto = sodium ? false : 'bundled libsodium.js could not be loaded in this runtime';

const pgp = await import('../core/pgp.mjs');
const {
  crc24, armor, dearmor, ArmorError,
  encryptMessage, decryptMessage, signArmored, verifyArmored,
} = pgp;

/* ------------------------------------------------------------------ *
 * CRC-24 (RFC 4880 s6.1)
 * ------------------------------------------------------------------ */

/**
 * Table-driven reference for CRC-24/OPENPGP. Deliberately a different code
 * path from the bitwise implementation in core/pgp.mjs, so agreeing with it
 * is real evidence rather than a tautology.
 */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let crc = i << 16;
    for (let j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
    t[i] = crc & 0xffffff;
  }
  return t;
})();

function crc24Reference(bytes) {
  let crc = 0xb704ce;
  for (const b of bytes) {
    crc = CRC_TABLE[(crc >>> 16) ^ b] ^ ((crc << 8) & 0xffffff);
  }
  return crc & 0xffffff;
}

test('crc24 starts from the value RFC 4880 specifies', () => {
  assert.equal(crc24(new Uint8Array(0)), 0xb704ce);
});

test('crc24 agrees with an independent table-driven implementation', () => {
  for (let n = 0; n <= 256; n++) {
    const data = new Uint8Array(n);
    for (let i = 0; i < n; i++) data[i] = (i * 37 + n * 11) & 0xff;
    assert.equal(crc24(data), crc24Reference(data), `mismatch at length ${n}`);
  }
});

test('crc24 is sensitive to a single flipped bit', () => {
  const a = crc24(new TextEncoder().encode('message one'));
  const b = crc24(new TextEncoder().encode('message two'));
  assert.notEqual(a, b);
});

/* ------------------------------------------------------------------ *
 * armor / dearmor
 * ------------------------------------------------------------------ */

test('armor roundtrips arbitrary binary through dearmor', () => {
  const data = new Uint8Array(300);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7) & 0xff;
  const block = armor('PGP MESSAGE', data);
  const out = dearmor(block);
  assert.equal(out.type, 'PGP MESSAGE');
  assert.deepEqual(Array.from(out.bytes), Array.from(data));
});

test('armor emits a BEGIN line, a checksum line and an END line', () => {
  const block = armor('PGP MESSAGE', new Uint8Array([1, 2, 3]));
  assert.match(block, /^-----BEGIN PGP MESSAGE-----/);
  assert.match(block, /-----END PGP MESSAGE-----\s*$/);
  assert.match(block, /^=[A-Za-z0-9+/]{4}$/m);
});

test('armor body is wrapped at 64 characters per line', () => {
  const block = armor('PGP MESSAGE', new Uint8Array(400));
  const bodyLines = block.split('\n').filter((l) => /^[A-Za-z0-9+/]+$/.test(l));
  assert.ok(bodyLines.length > 1);
  for (const line of bodyLines) assert.ok(line.length <= 64, `line too long: ${line.length}`);
});

test('armor preserves supplied headers', () => {
  const block = armor('PGP MESSAGE', new Uint8Array([9]), { Version: 'DOM Mail armored message' });
  assert.match(block, /^Version: DOM Mail armored message$/m);
});

test('dearmor rejects a corrupted body via CRC-24', () => {
  // Enough bytes that the base64 body spans multiple lines.
  const data = new Uint8Array(200);
  for (let i = 0; i < data.length; i++) data[i] = i & 0xff;
  const lines = armor('PGP MESSAGE', data).split('\n');
  const i = lines.findIndex((l) => /^[A-Za-z0-9+/]{40,}$/.test(l));
  assert.ok(i >= 0, 'expected a long base64 body line');
  lines[i] = (lines[i][0] === 'A' ? 'B' : 'A') + lines[i].slice(1);
  assert.throws(() => dearmor(lines.join('\n')), ArmorError);
});

test('dearmor rejects mismatched BEGIN and END types', () => {
  const block = armor('PGP MESSAGE', new Uint8Array([1]))
    .replace('-----END PGP MESSAGE-----', '-----END PGP SIGNATURE-----');
  assert.throws(() => dearmor(block), ArmorError);
});

test('dearmor rejects text that is not armored at all', () => {
  assert.throws(() => dearmor('just some plain text'), ArmorError);
});

/* ------------------------------------------------------------------ *
 * encryption roundtrip (requires libsodium)
 * ------------------------------------------------------------------ */

test('the bundled libsodium provides the primitives the PGP layer needs', () => {
  assert.ok(sodium, 'libsodium should load from the bundled libsodium.js');
  for (const fn of [
    'crypto_box_seal', 'crypto_box_seal_open', 'crypto_box_keypair',
    'crypto_sign_detached', 'crypto_sign_verify_detached', 'crypto_sign_keypair',
  ]) {
    assert.equal(typeof sodium[fn], 'function', `missing ${fn}`);
  }
});

test('encrypted message roundtrips for a single recipient', { skip: skipCrypto }, async () => {
  const kp = sodium.crypto_box_keypair();
  const armored = await encryptMessage('meet at dawn', [{ address: 'a@b.c', publicKey: kp.publicKey }]);
  assert.match(armored, /-----BEGIN PGP MESSAGE-----/);
  const out = await decryptMessage(armored, kp.privateKey, kp.publicKey);
  assert.equal(out.text, 'meet at dawn');
});

test('a wrong private key cannot open the message', { skip: skipCrypto }, async () => {
  const kp = sodium.crypto_box_keypair();
  const other = sodium.crypto_box_keypair();
  const armored = await encryptMessage('secret', [{ address: 'a@b.c', publicKey: kp.publicKey }]);
  await assert.rejects(
    () => decryptMessage(armored, other.privateKey, other.publicKey),
    /no recipient slot could be opened/,
  );
});

test('a message to several recipients opens only for the right key', { skip: skipCrypto }, async () => {
  const alice = sodium.crypto_box_keypair();
  const bob = sodium.crypto_box_keypair();
  const eve = sodium.crypto_box_keypair();
  const armored = await encryptMessage('shared secret', [
    { address: 'alice@a.c', publicKey: alice.publicKey },
    { address: 'bob@b.c', publicKey: bob.publicKey },
  ]);
  const asAlice = await decryptMessage(armored, alice.privateKey, alice.publicKey);
  assert.equal(asAlice.text, 'shared secret');
  const asBob = await decryptMessage(armored, bob.privateKey, bob.publicKey);
  assert.equal(asBob.text, 'shared secret');
  await assert.rejects(() => decryptMessage(armored, eve.privateKey, eve.publicKey));
});

test('unicode survives the encrypt/decrypt roundtrip', { skip: skipCrypto }, async () => {
  const kp = sodium.crypto_box_keypair();
  const text = 'héllo — 日本語 🔐';
  const armored = await encryptMessage(text, [{ address: 'a@b.c', publicKey: kp.publicKey }]);
  const out = await decryptMessage(armored, kp.privateKey, kp.publicKey);
  assert.equal(out.text, text);
});

test('a large body roundtrips intact', { skip: skipCrypto }, async () => {
  const kp = sodium.crypto_box_keypair();
  const text = 'x'.repeat(200000);
  const armored = await encryptMessage(text, [{ address: 'a@b.c', publicKey: kp.publicKey }]);
  const out = await decryptMessage(armored, kp.privateKey, kp.publicKey);
  assert.equal(out.text.length, text.length);
  assert.equal(out.text, text);
});

test('two encryptions of the same text differ (fresh nonce each time)', { skip: skipCrypto }, async () => {
  const kp = sodium.crypto_box_keypair();
  const r = [{ address: 'a@b.c', publicKey: kp.publicKey }];
  const a = await encryptMessage('same', r);
  const b = await encryptMessage('same', r);
  assert.notEqual(a, b);
  // ...but both still open to the original.
  assert.equal((await decryptMessage(a, kp.privateKey, kp.publicKey)).text, 'same');
  assert.equal((await decryptMessage(b, kp.privateKey, kp.publicKey)).text, 'same');
});

test('signed messages report a valid signature', { skip: skipCrypto }, async () => {
  const signer = sodium.crypto_sign_keypair();
  const recipient = sodium.crypto_box_keypair();
  const armored = await encryptMessage('signed and sealed', [
    { address: 'a@b.c', publicKey: recipient.publicKey },
  ], { sign: true, signer: { privateKey: signer.privateKey, publicKey: signer.publicKey } });
  const out = await decryptMessage(armored, recipient.privateKey, recipient.publicKey, {
    verify: { publicKey: signer.publicKey },
  });
  assert.equal(out.signed, true);
  assert.equal(out.signatureValid, true);
  assert.equal(out.text, 'signed and sealed');
});

test('a tampered signature is reported invalid', { skip: skipCrypto }, async () => {
  const signer = sodium.crypto_sign_keypair();
  const other = sodium.crypto_sign_keypair();
  const recipient = sodium.crypto_box_keypair();
  const armored = await encryptMessage('signed', [
    { address: 'a@b.c', publicKey: recipient.publicKey },
  ], { sign: true, signer: { privateKey: signer.privateKey, publicKey: signer.publicKey } });
  const out = await decryptMessage(armored, recipient.privateKey, recipient.publicKey, {
    verify: { publicKey: other.publicKey },
  });
  assert.equal(out.signed, true);
  assert.equal(out.signatureValid, false);
});

test('encryptMessage refuses an empty recipient list', { skip: skipCrypto }, async () => {
  await assert.rejects(() => encryptMessage('x', []), /at least one recipient/);
});

test('detached signature over an armored block verifies', { skip: skipCrypto }, async () => {
  const kp = sodium.crypto_sign_keypair();
  const text = 'a document';
  const sig = await signArmored(text, kp.privateKey);
  assert.match(sig, /-----BEGIN PGP SIGNATURE-----/);
  assert.equal(await verifyArmored(text, sig, kp.publicKey), true);
  assert.equal(await verifyArmored('tampered', sig, kp.publicKey), false);
});

/* ------------------------------------------------------------------ *
 * regression: core/crypto.mjs verify() must not report a forged
 * signature as valid.
 *
 * The bundled libsodium returns a boolean from
 * crypto_sign_verify_detached instead of throwing. An implementation that
 * ignores the return value reports EVERY signature as valid. This test pins
 * the correct behaviour so the bug cannot come back.
 * ------------------------------------------------------------------ */

test('verify() rejects a forged detached signature', { skip: skipCrypto }, async () => {
  const CRYPTO = await import('../core/crypto.mjs');
  await CRYPTO.init();
  const signer = sodium.crypto_sign_keypair();
  const attacker = sodium.crypto_sign_keypair();
  const message = sodium.randombytes_buf ? sodium.randombytes_buf(32) : new Uint8Array(32);

  const good = await CRYPTO.sign(true, message, signer.privateKey);
  assert.equal(await CRYPTO.verify(true, good, message, signer.publicKey), true, 'valid signature must verify');

  // Same message, wrong public key.
  assert.equal(await CRYPTO.verify(true, good, message, attacker.publicKey), false,
    'signature must not verify under a different public key');

  // Right key, different message.
  const other = new Uint8Array(message.length);
  other.set(message);
  other[0] ^= 0xff;
  assert.equal(await CRYPTO.verify(true, good, other, signer.publicKey), false,
    'signature must not verify over a modified message');
});

/* ------------------------------------------------------------------ *
 * relay URL validation
 * ------------------------------------------------------------------ */

test('relay rejects an empty URL', () => {
  assert.throws(() => RelayClient.validateUrl(''), RelayError);
});

test('relay rejects a non-absolute URL', () => {
  assert.throws(() => RelayClient.validateUrl('/relay'), RelayError);
});

test('relay rejects http and https schemes', () => {
  assert.throws(() => RelayClient.validateUrl('https://relay.example'), /must use ws/);
  assert.throws(() => RelayClient.validateUrl('http://relay.example'), /must use ws/);
});

test('relay accepts wss to any host', () => {
  assert.equal(
    RelayClient.validateUrl('wss://relay.example/ws', 'domail.space'),
    'wss://relay.example/ws',
  );
});

test('relay rejects plaintext ws to a remote host', () => {
  assert.throws(
    () => RelayClient.validateUrl('ws://relay.example/ws', 'domail.space'),
    /only permitted between local clients/,
  );
});

test('relay accepts plaintext ws only between local endpoints', () => {
  // URL normalisation appends the root path, so compare the parsed result.
  assert.equal(
    RelayClient.validateUrl('ws://localhost:7654', 'localhost'),
    new URL('ws://localhost:7654').href,
  );
  // Local relay, but the page is remote: still refused.
  assert.throws(() => RelayClient.validateUrl('ws://localhost:7654', 'domail.space'), RelayError);
});

/* ------------------------------------------------------------------ *
 * relay client behaviour
 * ------------------------------------------------------------------ */

/** Minimal in-memory WebSocket stand-in so tests need no real network. */
class FakeSocket {
  static instances = [];
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.sent = [];
    FakeSocket.instances.push(this);
  }
  send(text) { this.sent.push(text); }
  close() { this.readyState = 3; this.onclose?.(); }
  open() { this.readyState = 1; this.onopen?.(); }
  deliver(obj) { this.onmessage?.({ data: JSON.stringify(obj) }); }
}

test('a disabled relay performs no I/O and refuses to connect', () => {
  FakeSocket.instances = [];
  const client = new RelayClient({ enabled: false, url: 'wss://relay.example', WebSocketImpl: FakeSocket });
  assert.equal(client.connect(), false);
  assert.equal(FakeSocket.instances.length, 0);
  assert.equal(client.status, 'disabled');
});

test('an enabled relay connects and completes a handshake', () => {
  FakeSocket.instances = [];
  const client = new RelayClient({
    enabled: true, url: 'wss://relay.example/ws', WebSocketImpl: FakeSocket,
  });
  client.setIdentity({ address: 'me@domail.space' });
  assert.equal(client.connect(), true);
  const socket = FakeSocket.instances[0];
  socket.open();
  assert.equal(client.status, 'connected');
  const hello = JSON.parse(socket.sent[0]);
  assert.equal(hello.type, 'hello');
  assert.equal(hello.address, 'me@domail.space');
});

test('an enabled relay with a bad URL reports an error and opens nothing', () => {
  FakeSocket.instances = [];
  const errors = [];
  const client = new RelayClient({
    enabled: true, url: 'nonsense', WebSocketImpl: FakeSocket, onError: (e) => errors.push(e),
  });
  assert.equal(client.connect(), false);
  assert.equal(FakeSocket.instances.length, 0);
  assert.equal(client.status, 'error');
  assert.ok(errors.length > 0);
});

test('publish queues while disconnected instead of dropping the message', () => {
  FakeSocket.instances = [];
  const client = new RelayClient({ enabled: true, url: 'wss://relay.example/ws', WebSocketImpl: FakeSocket });
  const res = client.publish({ subject: 'queued', to: ['a@b.c'] });
  assert.equal(res.queued, true);
  assert.equal(res.depth, 1);
  assert.equal(client.stats().queued, 1);
});

test('publish is a no-op when the relay is disabled', () => {
  const client = new RelayClient({ enabled: false, WebSocketImpl: FakeSocket });
  const res = client.publish({ subject: 'nope' });
  assert.equal(res.queued, false);
  assert.equal(res.reason, 'relay disabled');
});

test('the queue drains on connect', () => {
  FakeSocket.instances = [];
  const client = new RelayClient({ enabled: true, url: 'wss://relay.example/ws', WebSocketImpl: FakeSocket });
  client.publish({ subject: 'first' });
  client.publish({ subject: 'second' });
  client.connect();
  FakeSocket.instances[0].open();
  assert.equal(client.stats().queued, 0);
  const published = FakeSocket.instances[0].sent
    .map((s) => JSON.parse(s))
    .filter((m) => m.type === 'publish');
  assert.equal(published.length, 2);
});

test('incoming mail frames are delivered and pings are ignored', () => {
  FakeSocket.instances = [];
  const received = [];
  const client = new RelayClient({
    enabled: true, url: 'wss://relay.example/ws',
    WebSocketImpl: FakeSocket,
    onMessage: (m) => received.push(m),
  });
  client.connect();
  const socket = FakeSocket.instances[0];
  socket.open();
  socket.deliver({ type: 'ping' });
  socket.deliver({ type: 'mail', mail: { subject: 'hello' } });
  assert.equal(received.length, 1);
  assert.equal(received[0].mail.subject, 'hello');
});

test('non-JSON frames are rejected without throwing', () => {
  FakeSocket.instances = [];
  const errors = [];
  const client = new RelayClient({
    enabled: true, url: 'wss://relay.example/ws',
    WebSocketImpl: FakeSocket,
    onError: (e) => errors.push(e),
  });
  client.connect();
  const socket = FakeSocket.instances[0];
  socket.open();
  socket.onmessage({ data: 'not json' });
  assert.equal(errors.length, 1);
});

test('shutdown disables the client and prevents later connections', () => {
  FakeSocket.instances = [];
  const client = new RelayClient({ enabled: true, url: 'wss://relay.example/ws', WebSocketImpl: FakeSocket });
  client.publish({ subject: 'dropped' });
  client.shutdown();
  assert.equal(client.enabled, false);
  assert.equal(client.status, 'disabled');
  assert.equal(client.connect(), false);
  assert.equal(FakeSocket.instances.length, 0);
});

/* ------------------------------------------------------------------ *
 * disclosure text
 * ------------------------------------------------------------------ */

test('both disclosures state the metadata and vulnerability cost', () => {
  assert.match(RELAY_DISCLOSURE, /IP address/i);
  assert.match(RELAY_DISCLOSURE, /metadata|From, To, Subject/i);
  assert.match(RELAY_DISCLOSURE, /malicious relay/i);
  assert.match(RELAY_DISCLOSURE, /offline/i);
  assert.match(PGP_DISCLOSURE, /not decrypt in GnuPG|will not decrypt/i);
  assert.match(PGP_DISCLOSURE, /metadata/i);
});