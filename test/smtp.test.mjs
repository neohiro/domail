// Loopback SMTP integration test.
//
// Validates that the engine's smtpSubmit() can deliver a dot-stuffed RFC 5321
// message over real TCP to a standards-shaped ESMTP relay with AUTH LOGIN —
// the same protocol path used to reach Gmail (smtp.gmail.com:587) and
// Microsoft 365 / Outlook (smtp.office365.com:587) when supplied with app
// credentials. The engine does the talking; this test is the relay.

import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { smtpSubmit, buildMessage, parseMessage } from '../core/mail.mjs';

function lineReader(socket) {
  let buf = '';
  const pending = [];
  const waiters = [];
  socket.on('data', (chunk) => {
    buf += chunk;
    for (;;) {
      const idx = buf.indexOf('\r\n');
      if (idx === -1) break;
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      if (waiters.length) waiters.shift()(line);
      else pending.push(line);
    }
  });
  return {
    next(timeoutMs = 5000) {
      if (pending.length) return Promise.resolve(pending.shift());
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('fake relay line timeout')), timeoutMs);
        waiters.push((line) => { clearTimeout(timer); resolve(line); });
      });
    },
  };
}

/** Start a minimal ESMTP relay. Returns { ready, close, received } */
function startRelay(opts = {}) {
  const received = { envelope: null, message: null, raw: null, auth: null };
  const server = net.createServer((socket) => {
    const lines = lineReader(socket);
    socket.write('220 domail-fake.esmtp ready\r\n');

    (async () => {
      try {
        for (;;) {
          const line = await lines.next();
          const cmd = line.split(' ')[0].toUpperCase();

          if (cmd === 'EHLO' || cmd === 'HELO') {
            socket.write('250-domail-fake.esmtp\r\n');
            socket.write('250-PIPELINING\r\n');
            socket.write('250-AUTH LOGIN\r\n');
            socket.write('250 SIZE 35882577\r\n');
          } else if (cmd === 'AUTH') {
            received.auth = { user: '', pass: '' };
            socket.write('334 VXNlcm5hbWU6\r\n');
            received.auth.user = Buffer.from((await lines.next()), 'base64').toString();
            socket.write('334 UGFzc3dvcmQ6\r\n');
            received.auth.pass = Buffer.from((await lines.next()), 'base64').toString();
            socket.write('235 2.7.0 Authentication successful\r\n');
          } else if (cmd === 'MAIL') {
            received.envelope = { from: (line.match(/<([^>]*)>/) || [])[1] || '', rcpt: [] };
            socket.write('250 2.1.0 Ok\r\n');
          } else if (cmd === 'RCPT') {
            received.envelope.rcpt.push((line.match(/<([^>]*)>/) || [])[1] || '');
            socket.write('250 2.1.5 Ok\r\n');
          } else if (cmd === 'DATA') {
            socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
            const raw = [];
            for (;;) {
              const data = await lines.next();
              if (data === '.') break;
              raw.push(data);
            }
            // A real SMTP receiver un-stuffs one leading dot per line (RFC 5321 4.5.2).
            received.raw = raw.join('\r\n');
            received.message = raw.map((l) => (l.startsWith('.') ? l.slice(1) : l)).join('\r\n');
            socket.write('250 2.0.0 Ok: queued as TEST123\r\n');
          } else if (cmd === 'QUIT') {
            socket.write('221 2.0.0 Bye\r\n');
            socket.end();
            return;
          } else {
            socket.write('250 2.0.0 Ok\r\n');
          }
        }
      } catch {
        try { socket.destroy(); } catch { /* already closed */ }
      }
    })();
  });

  let readyResolve;
  const ready = new Promise((resolve) => { readyResolve = resolve; });
  server.once('listening', () => readyResolve(server.address().port));
  server.listen(0, '127.0.0.1');

  return {
    port: 0,
    received,
    ready,
    close() {
      return new Promise((resolve) => {
        server.close(() => resolve());
        server.unref();
      });
    },
  };
}

let relay;
before(async () => {
  relay = startRelay();
  await relay.ready;
});
after(() => relay.close());

test('smtpSubmit delivers a dot-stuffed message to a real TCP relay with AUTH LOGIN', async () => {
  const from = { address: 'alice@domail.invalid', name: 'Alice' };
  const to = [{ address: 'recipient@gmail.com', name: 'Recipient' }];
  const msg = buildMessage({
    from,
    to,
    subject: 'hello from domail',
    text: '.leading-dot line\nsecond line',
  });

  const result = await smtpSubmit(
    {
      host: '127.0.0.1',
      port: (await relay.ready),
      secure: false,
      user: 'alice@domail.invalid',
      pass: 'app-password-123',
      connect: (host, port) =>
        new Promise((resolve, reject) => {
          const s = net.connect(port, host);
          s.setMaxListeners(0);
          s.once('connect', () => resolve(s));
          s.once('error', reject);
        }),
    },
    msg,
    { from: 'alice@domail.invalid', rcpt: ['recipient@gmail.com'] },
  );

  assert.equal(result.ok, true);
  assert.deepEqual(relay.received.envelope, {
    from: 'alice@domail.invalid',
    rcpt: ['recipient@gmail.com'],
  });
  assert.equal(relay.received.auth.user, 'alice@domail.invalid');
  assert.equal(relay.received.auth.pass, 'app-password-123');

  // The body must be dot-stuffed on the wire ...
  assert.ok(relay.received.raw.includes('\r\n..leading-dot line\r\n'));
  // ... and the relay's un-stuffing yields a parseable message.
  const parsed = parseMessage(relay.received.message);
  assert.equal(parsed.bodyText, '.leading-dot line\nsecond line');
});

test('smtpSubmit surfaces a rejected greeting as an error', async () => {
  const rejected = net.createServer((socket) => socket.write('554 no soup for you\r\n'));
  rejected.listen(0, '127.0.0.1');
  await new Promise((resolve) => rejected.once('listening', resolve));
  const port = rejected.address().port;

  await assert.rejects(
    smtpSubmit(
      {
        host: '127.0.0.1',
        port,
        secure: false,
        connect: (host, port) =>
          new Promise((resolve, reject) => {
            const s = net.connect(port, host);
            s.once('connect', () => resolve(s));
            s.once('error', reject);
          }),
      },
      'Subject: test\r\n\r\nbody',
      { from: 'a@b.c', rcpt: ['d@e.f'] },
    ),
    /554/,
  );

  rejected.close();
});