#!/usr/bin/env node
/**
 * DOM Mail SMTP bridge.
 *
 * Drains a DOM Mail message out toward real clearnet mailboxes (Gmail,
 * Outlook/Microsoft 365, etc.) over ESMTP. Zero dependencies: it speaks
 * SMTP with the engine's smtpSubmit() using Node's net/tls and adds a
 * SOCKS5 CONNECT hop so the TCP leg can exit through the kernel host's
 * VPN egress (gluetun) instead of your real IP.
 *
 * The browser/CLI app itself never does network I/O; this is the optional
 * companion daemon pattern from NETWORKS.md. Secrets come from env vars,
 * never argv.
 *
 * Usage:
 *   SMTP_USER=you@example.com SMTP_PASS=app-password \
 *     node tools/smtp-bridge.mjs \
 *       --server smtp.gmail.com:587 --mode starttls \
 *       --from you@example.com --to friend@gmail.com \
 *       --subject "hello" --body "hi" \
 *       [--via socks5://127.0.0.1:8080] [--validate] [--debug]
 *
 *   --validate  connect + EHLO + AUTH only; sends nothing. Use this to prove
 *               an Outlook/Gmail relay is reachable and accepts your creds.
 */

import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import { smtpSubmit, buildMessage } from '../core/mail.mjs';

function usage() {
  console.log(`
DOM Mail SMTP bridge
  --server host:port    e.g. smtp.gmail.com:587, smtp.office365.com:587
  --mode starttls|implicit|plain   (default starttls)
  --from       envelope + header sender
  --to         recipient(s), comma-separated
  --subject    subject line
  --body       text body (or --body-file path / read stdin)
  --via        SOCKS5 hop, e.g. socks5://127.0.0.1:8080 (kernel vpn-egress)
  --validate   run greeting+auth only, never send
  --debug      print SMTP transcript
  env SMTP_USER / SMTP_PASS for AUTH LOGIN
  `);
  process.exit(1);
}

function parseArgs(argv) {
  const o = { mode: 'starttls', to: [], via: '', validate: false, debug: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => argv[++i];
    if (a === '--server') o.server = val();
    else if (a === '--mode') o.mode = val();
    else if (a === '--from') o.from = val();
    else if (a === '--to') o.to.push(val());
    else if (a === '--subject') o.subject = val();
    else if (a === '--body') o.body = val();
    else if (a === '--body-file') o.body = readFileSync(val(), 'utf8');
    else if (a === '--via') o.via = val();
    else if (a === '--validate') o.validate = true;
    else if (a === '--debug') o.debug = true;
    else { console.error(`unknown arg: ${a}`); usage(); }
  }
  if (!o.server || !o.from || (!o.validate && !o.to.length)) usage();
  // Accept host:port, [v6]:port, and bare host (default port by mode).
  const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(o.server);
  if (!m) { console.error(`bad --server: ${o.server}`); usage(); }
  let host = m[1];
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  o.host = host;
  o.port = Number(m[2] || (o.mode === 'implicit' ? 465 : 587));
  return o;
}

/** Minimal SOCKS5 CONNECT (RFC 1928) over a fresh TCP socket. */
function socks5Connect(proxy, targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const u = new URL(proxy);
    const sock = net.connect(Number(u.port || 1080), u.hostname);
    sock.setNoDelay(true);
    sock.once('error', reject);
    sock.once('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
    let stage = 0;
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0) {
        if (buf.length < 2) return;
        const ver = buf[0];
        const method = buf[1];
        buf = buf.subarray(2);
        if (ver !== 5 || method !== 0) {
          sock.destroy();
          reject(new Error(`SOCKS5 auth negotiation failed (ver ${ver}, method ${method})`));
          return;
        }
        stage = 1;
        const host = Buffer.from(targetHost, 'utf8');
        sock.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
          host,
          Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
        ]));
      } else {
        if (buf.length < 4) return;
        const rep = buf[1];
        if (rep !== 0) {
          sock.destroy();
          reject(new Error(`SOCKS5 CONNECT failed, rep=0x${rep.toString(16)} (1=general, 2=not allowed, 4=host unreachable)`));
          return;
        }
        let addrLen;
        if (buf[3] === 1) addrLen = 4;
        else if (buf[3] === 4) addrLen = 16;
        else if (buf[3] === 3) addrLen = 1 + buf[4];
        else { sock.destroy(); reject(new Error(`SOCKS5 bad atyp 0x${buf[3].toString(16)}`)); return; }
        const headerEnd = 4 + addrLen + 2;
        if (buf.length < headerEnd) return;
        sock.removeListener('data', onData);
        sock.setKeepAlive(true);
        resolve(sock);
      }
    };
    sock.on('data', onData);
  });
}

/** Plain or SOCKS5-tunneled TCP leg; implicit TLS (465) wrapped in connect. */
async function openSocket(o, host, port) {
  let sock;
  if (o.via) sock = await socks5Connect(o.via, host, port);
  else {
    sock = await new Promise((resolve, reject) => {
      const s = net.connect(port, host);
      s.setNoDelay(true);
      s.once('connect', () => resolve(s));
      s.once('error', reject);
    });
  }
  sock.setMaxListeners(0);
  if (o.mode === 'implicit') {
    await new Promise((resolve, reject) => {
      const t = tls.connect({ socket: sock, servername: host });
      t.once('secureConnect', resolve);
      t.once('error', reject);
    });
  }
  return sock;
}

function starttlsUpgrade(socket, host) {
  return new Promise((resolve, reject) => {
    const t = tls.connect({ socket, servername: host });
    t.setMaxListeners(0);
    t.once('secureConnect', () => resolve(t));
    t.once('error', reject);
  });
}

class SmtpSession {
  constructor(socket, log) {
    this.socket = socket;
    this.log = log;
    this.buf = '';
  }
  _waitLine() {
    return new Promise((resolve, reject) => {
      const grab = () => {
        const idx = this.buf.indexOf('\r\n');
        if (idx === -1) return false;
        const line = this.buf.slice(0, idx);
        this.buf = this.buf.slice(idx + 2);
        resolve(line);
        return true;
      };
      if (grab()) return;
      const onData = (chunk) => {
        this.buf += chunk;
        if (grab()) {
          this.socket.removeListener('data', onData);
          this.socket.removeListener('error', onErr);
        }
      };
      const onErr = (e) => reject(e);
      this.socket.on('data', onData);
      this.socket.on('error', onErr);
    });
  }
  async reply() {
    // A reply may span multiple 250- lines; collect until a final <code><sp>.
    let code = 0;
    let lines = [];
    for (;;) {
      const line = await this._waitLine();
      lines.push(line);
      const m = line.match(/^(\d{3})([ -])(.*)$/);
      if (!m) continue;
      code = Number(m[1]);
      if (m[2] === ' ') return { code, lines };
      if (code >= 500 && code < 600) return { code, lines }; // hard errors finalize
    }
  }
  async send(cmd) {
    this.log(`> ${cmd}`);
    this.socket.write(`${cmd}\r\n`);
    return this.reply();
  }
  close() {
    try { this.socket.end(); } catch { /* already closed */ }
  }
}

/** Validate reachability + EHLO + STARTTLS + AUTH; never sends a letter. */
async function validateRelay(o) {
  const user = process.env.SMTP_USER || '';
  const pass = process.env.SMTP_PASS || '';
  const log = (l) => { if (o.debug) console.error(l); };

  let sock = await openSocket(o, o.host, o.port);
  let s = new SmtpSession(sock, log);

  let r = await s.reply();
  if (r.code !== 220) throw new Error(`greeting ${r.code}: ${r.lines[0]}`);
  console.log('OK  greeting 220');

  r = await s.send('EHLO domail.invalid');
  if (r.code !== 250) throw new Error(`EHLO ${r.code}: ${r.lines[0]}`);
  const caps = r.lines.join('\n').toUpperCase();
  console.log('OK  EHLO (extensions accepted)');

  if (o.mode === 'starttls') {
    if (!caps.includes('STARTTLS')) throw new Error('relay does not advertise STARTTLS (use --mode implicit for 465)');
    r = await s.send('STARTTLS');
    if (r.code !== 220) throw new Error(`STARTTLS ${r.code}: ${r.lines[0]}`);
    sock = await starttlsUpgrade(sock, o.host);
    s = new SmtpSession(sock, log);
    console.log('OK  STARTTLS handshake complete');
    r = await s.send('EHLO domail.invalid');
    if (r.code !== 250) throw new Error(`EHLO-after-TLS ${r.code}`);
  }

  if (user) {
    if (!caps.includes('AUTH')) throw new Error('relay offers no AUTH');
    r = await s.send('AUTH LOGIN');
    if (r.code !== 334) throw new Error(`AUTH LOGIN ${r.code}`);
    r = await s.send(Buffer.from(user).toString('base64'));
    if (r.code !== 334) throw new Error(`AUTH username rejected ${r.code}: ${r.lines[0]}`);
    r = await s.send(Buffer.from(pass).toString('base64'));
    if (r.code !== 235) throw new Error(`AUTH credentials rejected ${r.code}: ${r.lines[0]}`);
    console.log('OK  AUTH LOGIN accepted');
  } else {
    console.log('OK  no SMTP_USER set; skipping auth');
  }

  r = await s.send(`MAIL FROM:<${o.from}>`);
  if (r.code !== 250) throw new Error(`sender rejected ${r.code}: ${r.lines[0]}`);
  console.log('OK  MAIL FROM accepted');
  s.send('QUIT').catch(() => {});
  s.close();
  console.log('VALIDATED: this relay accepts a message from this sender now.');
  return true;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  const user = process.env.SMTP_USER || '';
  const pass = process.env.SMTP_PASS || '';
  const log = (l) => { if (o.debug) console.error(l); };

  if (o.validate) {
    try {
      await validateRelay(o);
      process.exit(0);
    } catch (err) {
      console.error(`NOT VALIDATED: ${err.message || err}`);
      process.exit(1);
    }
  }

  const recipients = o.to.flatMap((t) => t.split(',').map((s) => s.trim()).filter(Boolean));
  const msg = buildMessage({
    from: { address: o.from },
    to: recipients.map((address) => ({ address })),
    subject: o.subject || '',
    text: o.body ?? '',
  });

  const cfg = {
    host: o.host,
    port: o.port,
    secure: o.mode !== 'plain',
    connect: (host, port) => openSocket(o, host, port),
    ...(o.mode === 'starttls'
      ? { tls: (socket, _opts) => starttlsUpgrade(socket, o.host) }
      : {}),
    user,
    pass,
    timeout: 30000,
  };

  try {
    const res = await smtpSubmit(cfg, msg, { from: o.from, rcpt: recipients }, log);
    console.log(`Delivered ${o.from} -> ${recipients.join(', ')} via ${o.server} (${o.mode})${o.via ? ` over ${o.via}` : ''} [${res.code}]`);
  } catch (err) {
    console.error(`Delivery failed: ${err.message || err}`);
    process.exit(1);
  }
}

main();