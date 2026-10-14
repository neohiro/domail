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
  --body       text body; "-" reads piped stdin (or --body-file path)
  --via        SOCKS5 hop, e.g. socks5://127.0.0.1:8080 (kernel vpn-egress)
  --validate   run greeting+auth only, never send
  --debug      print SMTP transcript
  env SMTP_USER / SMTP_PASS for AUTH LOGIN
  `);
  process.exit(1);
}

/** Read whatever is piped on stdin (for --body -). */
function readStdin(maxBytes = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    let bytes = 0;
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > maxBytes) {
        reject(new Error(`stdin exceeds ${maxBytes} byte limit`));
        return;
      }
      data += chunk;
    });
    process.stdin.on('error', reject);
    process.stdin.on('end', () => resolve(data));
  });
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
    else if (a === '--subject') o.subject = argv[i + 1]?.startsWith('--') ? '' : val();
    else if (a === '--body') o.body = argv[i + 1]?.startsWith('--') ? '' : val();
    else if (a === '--body-file') o.body = readFileSync(val(), 'utf8');
    else if (a === '--via') o.via = val();
    else if (a === '--validate') o.validate = true;
    else if (a === '--debug') o.debug = true;
    else { console.error(`unknown arg: ${a}`); usage(); }
  }
  if (!o.server || !o.from || (!o.validate && !o.to.length)) usage();
  if (!['starttls', 'implicit', 'plain'].includes(o.mode)) {
    console.error(`bad --mode: ${o.mode} (starttls|implicit|plain)`);
    usage();
  }
  if (o.via && !/^socks5h?:/.test(o.via)) {
    console.error(`bad --via: ${o.via} (use socks5:// or socks5h://)`);
    usage();
  }
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
function socks5Connect(proxy, targetHost, targetPort, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const u = new URL(proxy);
    const sock = net.connect(Number(u.port || 1080), u.hostname);
    sock.setNoDelay(true);
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.removeListener('data', onData);
      sock.destroy();
      reject(err);
    };
    const timer = setTimeout(
      () => fail(new Error(`SOCKS5 ${u.hostname}:${u.port || 1080} timed out`)),
      timeoutMs,
    );
    sock.once('error', (e) => fail(e));
    sock.once('end', () => fail(new Error('SOCKS5 connection closed prematurely')));
    sock.once('close', () => fail(new Error('SOCKS5 connection closed prematurely')));
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
          fail(new Error(`SOCKS5 auth negotiation failed (ver ${ver}, method ${method})`));
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
          fail(new Error(`SOCKS5 CONNECT failed, rep=0x${rep.toString(16)} (1=general, 2=not allowed, 4=host unreachable)`));
          return;
        }
        let addrLen;
        if (buf[3] === 1) addrLen = 4;
        else if (buf[3] === 4) addrLen = 16;
        else if (buf[3] === 3) {
          // Domain length byte must be present before we can size the reply.
          if (buf.length < 5) return;
          addrLen = 1 + buf[4];
        } else {
          fail(new Error(`SOCKS5 bad atyp 0x${buf[3].toString(16)}`));
          return;
        }
        const headerEnd = 4 + addrLen + 2;
        if (!Number.isFinite(headerEnd) || buf.length < headerEnd) return;
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        sock.removeListener('data', onData);
        sock.setKeepAlive(true);
        resolve(sock);
      }
    };
    sock.on('data', onData);
  });
}

/** Open a TCP (or SOCKS5-tunneled) socket to the given host:port. */
async function openSocket(o, host, port, timeoutMs = 15000) {
  if (o.via) {
    return socks5Connect(o.via, host, port, timeoutMs);
  }
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, host);
    sock.setNoDelay(true);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`connection to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    sock.once('connect', () => {
      clearTimeout(timer);
      resolve(sock);
    });
    sock.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// Auto-detect public IP for UPnP NAT-PMP port forwarding
async function getPublicIP() {
  try {
    // Use ifconfig.io which supports clean JSON responses
    const http = await import('http');
    return new Promise((resolve, reject) => {
      const req = http.get('http://ifconfig.io/ip', { timeout: 5000 }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data.trim()));
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy());
    });
  } catch {
    return null;
  }
}

// UPnP IGD discovery via SSDP (Simple Service Discovery Protocol)
async function discoverUpnpGateway() {
  return new Promise((resolve) => {
    try {
      const dgram = require('dgram');
      const socket = dgram.createSocket('udp4');
      const message = Buffer.from(
        'M-SEARCH * HTTP/1.1\r\n' +
        'HOST: 239.255.255.250:1900\r\n' +
        'MAN: "ssdp:discover"\r\n' +
        'MX: 2\r\n' +
        'ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n'
      );
      
      const timer = setTimeout(() => {
        socket.close();
        resolve(null);
      }, 2000);

      let handled = false;
      socket.on('message', (msg, rinfo) => {
        if (handled) return;
        handled = true;
        clearTimeout(timer);
        socket.close();
        const response = msg.toString();
        const locationMatch = response.match(/LOCATION:\s*(.+)/i);
        if (locationMatch) {
          resolve({ location: locationMatch[1].trim(), host: rinfo.address });
        } else {
          resolve(null);
        }
      });

      socket.bind(() => {
        try {
          socket.addMembership('239.255.255.250');
          socket.send(message, 1900, '239.255.255.250');
        } catch {
          clearTimeout(timer);
          socket.close();
          resolve(null);
        }
      });
    } catch {
      resolve(null);
    }
  });
}

// Port 25 forwarding via UPnP/NAT-PMP
async function setupUpnpPortForward(pubIp) {
  try {
    const gw = await discoverUpnpGateway();
    if (!gw) {
      return { success: false, reason: 'UPnP gateway not found on network' };
    }

    // Parse the gateway location URL to get control URL
    const gwUrl = new URL(gw.location);
    const baseUrl = `${gwUrl.protocol}//${gwUrl.host}`;

    // Fetch the device description to get the control URL
    const http = await import('http');
    const https = await import('https');
    const { URL } = await import('url');

    const fetchControlUrl = (url) => new Promise((resolve) => {
      const client = url.startsWith('https:') ? https : http;
      client.get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
      }).on('error', () => resolve(null));
    });

    const deviceDesc = await fetchControlUrl(gw.location);
    if (!deviceDesc) {
      return { success: false, reason: 'Failed to fetch UPnP device description' };
    }

    // Parse XML to find WANIPConnection control URL - more robust parsing
    const controlUrlMatch = deviceDesc.match(/<controlURL>([^<]+)<\/controlURL>/i);
    const serviceTypeMatch = deviceDesc.match(/<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1<\/serviceType>/i);
    const serviceIdMatch = deviceDesc.match(/<serviceId>urn:upnp-org:serviceId:WANIPConnection:1<\/serviceId>/i);

    // Accept either serviceType or serviceId for compatibility
    if (!controlUrlMatch || !(serviceTypeMatch || serviceIdMatch)) {
      return { success: false, reason: 'WANIPConnection service not found in device description' };
    }

    const controlUrl = new URL(controlUrlMatch[1], baseUrl).href;
    const localIp = await getLocalIp();

    // SOAP request to AddPortMapping
    const soapBody = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>25</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>25</NewInternalPort>
      <NewInternalClient>${localIp}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>DOM Mail SMTP Inbound</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>`;

    const soapResult = await sendSoapRequest(controlUrl, 'AddPortMapping', soapBody);
    
    if (soapResult.success) {
      return { 
        success: true, 
        reason: `Port 25 forwarding configured on UPnP gateway at ${gw.location}`,
        externalPort: 25,
        internalPort: 25,
        protocol: 'TCP'
      };
    } else {
      return { success: false, reason: `UPnP port mapping failed: ${soapResult.error}` };
    }
  } catch (e) {
    return { success: false, reason: e.message };
  }
}

async function getLocalIp() {
  return new Promise((resolve, reject) => {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) {
          resolve(net.address);
          return;
        }
      }
    }
    // Don't resolve to 127.0.0.1 for UPnP - it would create an invalid port mapping
    reject(new Error('No non-internal IPv4 interface found for UPnP port mapping'));
  });
}

async function sendSoapRequest(controlUrl, action, soapBody) {
  return new Promise((resolve) => {
    const { URL } = require('url');
    const url = new URL(controlUrl);
    const http = url.protocol === 'https:' ? require('https') : require('http');
    
    const postData = soapBody;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset="utf-8"',
        'Content-Length': Buffer.byteLength(postData),
        'SOAPAction': `"urn:schemas-upnp-org:service:WANIPConnection:1#${action}"`,
        'User-Agent': 'DOM-Mail/1.0 UPnP/1.0'
      },
      timeout: 10000 // 10 second timeout for SOAP request
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true, response: data });
        } else {
          resolve({ success: false, error: `HTTP ${res.statusCode}: ${data}` });
        }
      });
    });

    req.on('error', (err) => {
      resolve({ success: false, error: err.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'SOAP request timeout' });
    });

    req.write(postData);
    req.end();
  });
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
    // Protect against infinite loops on malformed server responses.
    const MAX_LINES = 100;
    let code = 0;
    let lines = [];
    for (let i = 0; i < MAX_LINES; i++) {
      const line = await this._waitLine();
      lines.push(line);
      const m = line.match(/^(\d{3})([ -])(.*)$/);
      if (!m) {
        // Malformed line - treat as protocol error to avoid infinite loop
        throw new Error(`malformed SMTP reply line: ${line}`);
      }
      code = Number(m[1]);
      if (m[2] === ' ') return { code, lines };
      if (code >= 500 && code < 600) return { code, lines }; // hard errors finalize
    }
    throw new Error('SMTP reply exceeded maximum line count');
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

  let sock = await openSocket(o, o.host, o.port, 15000);
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
  await s.send('QUIT');
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
    text: o.body === '-' ? await readStdin() : o.body ?? '',
  });

  const cfg = {
    host: o.host,
    port: o.port,
    secure: o.mode !== 'plain',
    connect: (host, port) => openSocket(o, host, port, 15000),
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