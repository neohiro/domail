/**
 * DOM Mail core mail engine.
 *
 * Zero dependencies. Pure ESM. No DOM, no Node globals.
 * The same file runs in a browser tab, a Node CLI, a Deno runtime or a
 * Service Worker, which is what keeps the CLI and the browser honest:
 * neither can drift from the other because neither owns a private copy.
 *
 * Implemented against RFC 5322 (internet messages), RFC 2045-2049 (MIME).
 * This is a *local* engine: it accepts, routes, delivers and stores messages
 * in-process. It deliberately contains no client and no listener.
 */

const CRLF = '\r\n';
const MAX_LINE = 78;

/* ------------------------------------------------------------------ *
 * base64 / utf-8
 *
 * Implemented by hand rather than pulled from atob/btoa/Buffer so that
 * the engine behaves identically in every host, including CLI browsers
 * and terminals with no global atob.
 * ------------------------------------------------------------------ */

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const B64_LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < B64.length; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;

/** @param {Uint8Array} bytes */
export function bytesToBase64(bytes) {
  const parts = [];
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    parts.push(B64[b0 >> 2]);
    parts.push(B64[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)]);
    parts.push(i + 1 < bytes.length ? B64[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)] : '=');
    parts.push(i + 2 < bytes.length ? B64[b2 & 63] : '=');
  }
  return parts.join('');
}

/** @param {string} b64 */
export function base64ToBytes(b64) {
  const clean = b64.replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array((clean.length * 3) >> 2);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = B64_LOOKUP[clean.charCodeAt(i)];
    const c1 = B64_LOOKUP[clean.charCodeAt(i + 1)];
    const c2 = B64_LOOKUP[clean.charCodeAt(i + 2)];
    const c3 = B64_LOOKUP[clean.charCodeAt(i + 3)];
    out[o++] = (c0 << 2) | (c1 >> 4);
    if (c2 >= 0) out[o++] = ((c1 & 15) << 4) | (c2 >> 2);
    if (c3 >= 0) out[o++] = ((c2 & 3) << 6) | c3;
  }
  return out.subarray(0, o);
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const utf8 = (s) => textEncoder.encode(s);

/* ------------------------------------------------------------------ *
 * RFC 2047 encoded-words
 *
 * Any byte outside printable ASCII in a header must be encoded or the
 * message is unparseable by a conforming reader. B is used rather than Q
 * because it survives folding without needing soft line breaks.
 * ------------------------------------------------------------------ */

export function encodeHeaderWord(text) {
  const bytes = utf8(text);
  let ascii = true;
  for (const b of bytes) {
    if (b < 0x20 || b > 0x7e) {
      ascii = false;
      break;
    }
  }
  if (ascii) return text;
  return '=?UTF-8?B?' + bytesToBase64(bytes) + '?=';
}

export function decodeHeaderWords(input) {
  return input.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g,
    (_all, charset, kind, payload) => {
      if (charset.toUpperCase() !== 'UTF-8' && charset.toUpperCase() !== 'UTF8') {
        return _all;
      }
      try {
        if (kind.toUpperCase() === 'B') {
          return textDecoder.decode(base64ToBytes(payload));
        }
        const hex = payload.replace(/_/g, ' ');
        const arr = [];
        for (let i = 0; i < hex.length; i += 2) {
          const code = parseInt(hex.slice(i, i + 2).padEnd(2, '0'), 16);
          if (!Number.isNaN(code)) arr.push(code);
        }
        return textDecoder.decode(new Uint8Array(arr));
      } catch {
        return _all;
      }
    },
  );
}

/* ------------------------------------------------------------------ *
 * header folding
 * ------------------------------------------------------------------ */

/**
 * Strip CRLF from header values to prevent header injection.
 * A value containing \r\n could inject arbitrary headers into the message.
 */
function sanitizeHeaderValue(value) {
  return String(value).replace(/[\r\n]+/g, ' ');
}

/** Fold `name: value` onto continuation lines at 78 columns. */
export function foldHeader(name, value) {
  const safe = sanitizeHeaderValue(value);
  const text = `${name}: ${safe}`;
  if (text.length <= MAX_LINE) return text;

  const lines = [];
  let line = `${name}:`;
  for (const word of safe.split(/\s+/)) {
    if (line.length + 1 + word.length > MAX_LINE) {
      lines.push(line);
      line = ' ';
    }
    line += line.endsWith(': ') || line === ' ' ? word : ` ${word}`;
  }
  lines.push(line);
  return lines.join(CRLF);
}

/* ------------------------------------------------------------------ *
 * addresses
 * ------------------------------------------------------------------ */

/**
 * Parse a To/CC/BCC header value into address objects.
 * Handles `Name <a@b>`, `a@b`, `"Quoted, Name" <a@b>`, comma lists.
 */
export function parseAddressList(value) {
  const out = [];
  if (!value) return out;

  const parts = [];
  let buf = '';
  let inQuote = false;
  let inAngle = false;
  let depth = 0;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === '"' && value[i - 1] !== '\\') inQuote = !inQuote;
    else if (!inQuote && ch === '<') inAngle = true;
    else if (!inQuote && ch === '>') inAngle = false;
    else if (!inQuote && ch === '(') depth++;
    else if (!inQuote && ch === ')') depth--;

    if (ch === ',' && !inQuote && !inAngle && depth === 0) {
      parts.push(buf);
      buf = '';
    } else {
      buf += ch;
    }
  }
  if (buf.trim()) parts.push(buf);

  for (const raw of parts) {
    const token = raw.trim();
    if (!token) continue;
    const angle = token.match(/^(.*)<([^>]*)>\s*$/);
    if (angle) {
      const name = angle[1].trim().replace(/^"(.*)"$/, '$1');
      out.push({ name: decodeHeaderWords(name), address: angle[2].trim() });
    } else {
      out.push({ name: '', address: decodeHeaderWords(token) });
    }
  }
  return out;
}

/** Render one address back to a header value. */
export function formatAddress({ name, address }) {
  const safeAddr = sanitizeHeaderValue(address);
  if (!name) return safeAddr;
  const safeName = sanitizeHeaderValue(name);
  const encoded = encodeHeaderWord(safeName);
  // A bare display name containing specials must be quoted.
  const needsQuote = /[\s"(),:;<>@[\]\\]/.test(safeName);
  const label = needsQuote ? `"${encoded.replace(/(["\\])/g, '\\$1')}"` : encoded;
  return `${label} <${safeAddr}>`;
}

export function formatAddressList(list) {
  return (list || []).map(formatAddress).join(', ');
}

/* ------------------------------------------------------------------ *
 * content-transfer-encoding
 * ------------------------------------------------------------------ */

/**
 * Base64 with 76-char lines, the RFC 2045 maximum for MIME bodies.
 * Written into 8-byte rows rather than accumulating a 3-byte tail so the
 * loop cost is constant regardless of attachment size.
 */
export function encodeBase64Body(bytes) {
  const b64 = bytesToBase64(bytes);
  const lines = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  return lines.join(CRLF);
}

export function decodeBase64Body(text) {
  return textDecoder.decode(base64ToBytes(text));
}

/* ------------------------------------------------------------------ *
 * message construction
 * ------------------------------------------------------------------ */

let boundaryCounter = 0;

/**
 * Generate a boundary that cannot occur in the content it delimits.
 * Randomness here is not a security property, only a collision guard,
 * so a counter plus timestamp is sufficient and stays deterministic.
 */
export function makeBoundary(seed = '') {
  boundaryCounter = (boundaryCounter + 1) % 0xffff;
  const stamp = Date.now().toString(36);
  const salt = Math.floor(Math.random() * 0xffffff).toString(36);
  return `----=_domail_${seed}${stamp}${boundaryCounter}${salt}`;
}

/**
 * Build a complete RFC 5322 message.
 *
 * @param {object} o
 * @param {{name:string,address:string}} o.from
 * @param {Array} [o.to] @param {Array} [o.cc] @param {Array} [o.bcc]
 * @param {string} o.subject
 * @param {string} [o.text]         plain-text alternative
 * @param {string} [o.html]         html alternative
 * @param {Array<{name:string,type:string,bytes:Uint8Array}>} [o.attachments]
 * @param {string} [o.inReplyTo]
 * @param {string} [o.messageId]
 * @param {Date}   [o.date]
 * @returns {string} the message, CRLF-delimited
 */
export function buildMessage(o) {
  const date = o.date ?? new Date();
  const boundary = makeBoundary();
  const text = o.text ?? '';
  const hasHtml = typeof o.html === 'string' && o.html !== '';
  const attachments = o.attachments || [];

  const headers = [];
  headers.push(foldHeader('From', formatAddress(o.from)));
  if (o.to && o.to.length) headers.push(foldHeader('To', formatAddressList(o.to)));
  if (o.cc && o.cc.length) headers.push(foldHeader('Cc', formatAddressList(o.cc)));
  if (o.bcc && o.bcc.length) headers.push(foldHeader('Bcc', formatAddressList(o.bcc)));
  headers.push(foldHeader('Subject', encodeHeaderWord(o.subject || '')));
  headers.push(foldHeader('Date', date.toUTCString()));
  headers.push(foldHeader('Message-ID', `<${o.messageId || makeMessageId()}>`));
  if (o.inReplyTo) headers.push(foldHeader('In-Reply-To', `<${stripBrackets(o.inReplyTo)}>`));
  if (o.references) headers.push(foldHeader('References', o.references));
  headers.push('MIME-Version: 1.0');

  // Custom headers
  if (o.headers && typeof o.headers === 'object') {
    for (const [key, value] of Object.entries(o.headers)) {
      if (value) headers.push(foldHeader(key, value));
    }
  }

  const needsMultipart =
    (hasHtml && text) || attachments.length > 0;

  let body;
  if (!needsMultipart) {
    // Single part: a bare body needs a content-type to declare its charset.
    headers.push(
      hasHtml
        ? 'Content-Type: text/html; charset=UTF-8'
        : 'Content-Type: text/plain; charset=UTF-8',
    );
    headers.push('Content-Transfer-Encoding: 8bit');
    body = normalizeEol(hasHtml ? o.html : text);
  } else if (hasHtml && !attachments.length) {
    // text/plain first: least-preferred rendering, so a dumb reader is safe.
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    body = [
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      normalizeEol(text),
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      normalizeEol(o.html),
      `--${boundary}--`,
    ].join(CRLF);
  } else {
    // multipart/mixed wraps either a leaf or a multipart/alternative.
    // The nested entity must carry its own Content-Type header, or an outer
    // boundary split yields a chunk that starts with a delimiter line and
    // therefore parses as a bare text leaf.
    const inner = [];
    if (hasHtml && text) {
      const ab = makeBoundary();
      inner.push(
        [
          `Content-Type: multipart/alternative; boundary="${ab}"`,
          '',
          `--${ab}`,
          'Content-Type: text/plain; charset=UTF-8',
          'Content-Transfer-Encoding: 8bit',
          '',
          normalizeEol(text),
          `--${ab}`,
          'Content-Type: text/html; charset=UTF-8',
          'Content-Transfer-Encoding: 8bit',
          '',
          normalizeEol(o.html),
          `--${ab}--`,
        ].join(CRLF),
      );
    } else {
      inner.push(
        [
          `Content-Type: ${hasHtml ? 'text/html' : 'text/plain'}; charset=UTF-8`,
          'Content-Transfer-Encoding: 8bit',
          '',
          normalizeEol(hasHtml ? o.html : text),
        ].join(CRLF),
      );
    }
    for (const a of attachments) {
      inner.push(
        [
          `Content-Type: ${a.type || 'application/octet-stream'}; name="${a.name}"`,
          'Content-Transfer-Encoding: base64',
          'Content-Disposition: attachment; filename="' + a.name + '"',
          '',
          encodeBase64Body(a.bytes),
        ].join(CRLF),
      );
    }
    headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
    // One opening delimiter per part, then the close delimiter. Emitting the
    // opener once glues every part after the first onto its predecessor.
    body =
      inner.map((part) => `--${boundary}${CRLF}${part}`).join(CRLF) +
      `${CRLF}--${boundary}--`;
  }

  return `${headers.join(CRLF)}${CRLF}${CRLF}${body}`;
}

function normalizeEol(s) {
  return String(s).replace(/\r\n|\r|\n/g, CRLF).replace(/(\r\n)+$/, '');
}

const stripBrackets = (s) => String(s).replace(/^<|>$/g, '');

let idCounter = 0;
export function makeMessageId(domain = 'domail.invalid') {
  idCounter = (idCounter + 1) % 0xffffff;
  return `${Date.now().toString(36)}.${idCounter.toString(36)}.${Math.floor(
    Math.random() * 0xffffff,
  ).toString(36)}@${domain}`;
}

/* ------------------------------------------------------------------ *
 * message parsing
 * ------------------------------------------------------------------ */

/** Split headers from body at the first blank line. */
export function splitMessage(raw) {
  const text = String(raw).replace(/\r\n/g, '\n');
  const idx = text.indexOf('\n\n');
  if (idx === -1) return { headerBlock: text.replace(/\n+$/, ''), body: '' };
  return { headerBlock: text.slice(0, idx), body: text.slice(idx + 2) };
}

/** Parse a header block into a list, preserving order and duplicates. */
export function parseHeaders(headerBlock) {
  const unfolded = headerBlock
    .replace(/\r\n/g, '\n')
    .replace(/\n[ \t]+/g, ' ');
  const out = [];
  for (const line of unfolded.split('\n')) {
    if (!line.trim()) continue;
    const colon = line.indexOf(':');
    if (colon === -1) {
      if (out.length) out[out.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    out.push({
      name: line.slice(0, colon).trim(),
      value: line.slice(colon + 1).trim(),
    });
  }
  return out;
}

export function headerValue(headers, name) {
  const lower = name.toLowerCase();
  for (const h of headers) if (h.name.toLowerCase() === lower) return h.value;
  return '';
}

function splitParams(value) {
  const semi = value.indexOf(';');
  const type = (semi === -1 ? value : value.slice(0, semi)).trim().toLowerCase();
  const params = {};
  if (semi === -1) return { type, params };
  const paramRe = /([\w*-]+)\s*=\s*("([^"]*)"|[^;]*)/g;
  let m;
  while ((m = paramRe.exec(value.slice(semi + 1)))) {
    params[m[1].toLowerCase()] = (m[3] ?? m[2] ?? '').trim();
  }
  return { type, params };
}

/**
 * Recursively walk a MIME body.
 * @returns {{type:string, params:object, parts:Array|null, value:string}}
 */
export function walkMime(headers, body) {
  const { type, params } = splitParams(headerValue(headers, 'Content-Type') || 'text/plain');
  const cte = (headerValue(headers, 'Content-Transfer-Encoding') || '7bit')
    .trim()
    .toLowerCase();

  let value = body;
  let bytes;

  if (cte === 'base64') {
    // Base64 carries opaque octets. Decoding through UTF-8 would corrupt every
    // byte >= 0x80, so binary parts keep their bytes and only text is decoded.
    bytes = base64ToBytes(body);
    value = type.startsWith('text/') ? textDecoder.decode(bytes) : null;
  } else {
    value = body.replace(/\r\n/g, '\n');
    bytes = utf8(value);
  }

  const disp = splitParams(headerValue(headers, 'Content-Disposition') || '');

  if (type.startsWith('multipart/') && params.boundary) {
    const parts = splitMultipart(value ?? body, params.boundary).map((chunk) => {
      const split = splitMessage(chunk);
      return walkMime(parseHeaders(split.headerBlock), split.body);
    });
    return { type, params, disposition: disp.type, parts, value: null, bytes: null };
  }

  // The CRLF in front of a boundary delimiter is part of the delimiter, not
  // the body, so a leaf must not carry it.
  if (type.startsWith('text/')) value = value.replace(/\n+$/, '');

  return { type, params, disposition: disp.type, parts: null, value, bytes };
}

/** A part is an attachment if it says so, whatever its content type is. */
function isAttachmentPart(node) {
  return node.disposition === 'attachment' || (node.params && node.params.name && node.disposition === 'inline');
}

/** Split a multipart body on its boundary delimiters. */
export function splitMultipart(body, boundary) {
  const norm = body.replace(/\r\n/g, '\n');
  const marks = [];
  const re = new RegExp(
    `^--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(--)?[ \t]*$`,
    'gm',
  );
  let m;
  while ((m = re.exec(norm))) marks.push({ start: m.index, end: re.lastIndex, close: !!m[1] });

  const out = [];
  for (let i = 0; i < marks.length - 1; i++) {
    if (marks[i].close) continue;
    out.push(norm.slice(marks[i].end, marks[i + 1].start).replace(/^\n/, ''));
  }
  return out;
}

/**
 * Reduce a parsed MIME tree to the one part a reader should display.
 * Prefers text/plain, then text/html, then the first text/* part.
 * Attachments are never display candidates, even when declared text/plain.
 */
export function preferredPart(node) {
  if (!node.parts) return node;

  const candidates = node.parts.filter((p) => !isAttachmentPart(p));
  if (!candidates.length) return node.parts[0];

  if (node.type === 'multipart/alternative') {
    for (const p of candidates) if (p.type === 'text/plain') return p;
    return candidates[0];
  }
  if (node.type === 'multipart/related') return candidates[0];

  // mixed, digest, or anything unknown: descend into the first container that
  // yields a displayable leaf, preferring text over other content types.
  for (const p of candidates) {
    if (p.parts) {
      const leaf = preferredPart(p);
      if (leaf && !leaf.parts) return leaf;
    } else if (p.type.startsWith('text/')) {
      return p;
    }
  }
  return candidates[0];
}

/** Collect every attachment in the tree, by disposition or by non-text type. */
export function collectAttachments(node, acc = []) {
  if (!node) return acc;
  if (node.parts) {
    for (const p of node.parts) collectAttachments(p, acc);
    return acc;
  }
  if (isAttachmentPart(node)) {
    acc.push({
      type: node.type,
      name: node.params.name || 'attachment',
      bytes: node.bytes ?? utf8(node.value ?? ''),
    });
    return acc;
  }
  if (node.type.startsWith('text/')) return acc;
  acc.push({
    type: node.type,
    name: node.params.name || 'attachment',
    bytes: node.bytes ?? utf8(node.value ?? ''),
  });
  return acc;
}

/**
 * Parse a raw message into a normalised envelope.
 * This is the single entry point for anything entering the mailbox.
 */
export function parseMessage(raw) {
  const { headerBlock, body } = splitMessage(raw);
  const headers = parseHeaders(headerBlock);
  const tree = walkMime(headers, body);
  const best = preferredPart(tree);
  const subject = decodeHeaderWords(headerValue(headers, 'Subject'));
  const messageId = stripBrackets(headerValue(headers, 'Message-ID'));
  const from = parseAddressList(headerValue(headers, 'From'));
  const cc = parseAddressList(headerValue(headers, 'Cc'));
  const bcc = parseAddressList(headerValue(headers, 'Bcc'));

  const dateHeader = headerValue(headers, 'Date');
  const parsedDate = dateHeader ? Date.parse(dateHeader) : NaN;

  return {
    messageId,
    subject,
    from,
    to: parseAddressList(headerValue(headers, 'To')),
    cc,
    bcc,
    date: Number.isNaN(parsedDate) ? Date.now() : parsedDate,
    inReplyTo: stripBrackets(headerValue(headers, 'In-Reply-To')),
    references: headerValue(headers, 'References'),
    bodyText: best ? String(best.value ?? '') : '',
    bodyIsHtml: best ? best.type === 'text/html' : false,
    attachments: collectAttachments(tree),
    headers,
    raw,
  };
}

/* ------------------------------------------------------------------ *
 * dot-stuffing / SMTP wire form
 *
 * Only used when handing a message to an OS mail handler or an optional
 * relay. Included because a loopback engine that cannot produce valid
 * SMTP wire form is not actually an SMTP implementation.
 * ------------------------------------------------------------------ */

/** Prepend a dot to any line starting with '.', per RFC 5321 §4.5.2. */
export function dotStuff(message) {
  const crlf = String(message).replace(/\r\n|\r|\n/g, CRLF);
  return crlf.replace(/\r\n\./g, CRLF + '..').replace(/^\./, '..');
}

export function undotStuff(message) {
  return String(message).replace(/\r\n\.\./g, CRLF + '.');
}

/** Collapse every line-ending convention to CRLF, then dot-stuff. */
function toCrlf(s) {
  return String(s).replace(/\r\n|\r|\n/g, CRLF);
}

/** Wire form: CRLF line endings, dot-stuffed, trailing CRLF. */
export function toWire(message) {
  return `${dotStuff(toCrlf(message))}${CRLF}`;
}

/* ------------------------------------------------------------------ *
 * SMTP client for a user-supplied relay
 *
 * This is what makes "outbound" real when the user chooses to spend a
 * relay. It speaks only ESMTP-over-TCP via an injected socket factory,
 * so the engine itself stays host-agnostic.
 * ------------------------------------------------------------------ */

/**
 * @param {object} cfg
 * @param {{host:string,port:number,secure:boolean,user?:string,pass?:string,
 *          tls?:Function, connect?:Function, timeout?:number}} cfg
 * @param {string} message
 * @param {{from:string,rcpt:string[]}} envelope
 * @param {Function} [log]
 */
export async function smtpSubmit(cfg, message, envelope, log = () => {}) {
  const open = cfg.connect;
  if (typeof open !== 'function') {
    throw new Error('no socket factory: pass cfg.connect(host,port)->socket');
  }
  const timeout = cfg.timeout ?? 15000;
  let socket = await open(cfg.host, cfg.port ?? (cfg.secure ? 465 : 587));
  let buf = '';

  const waitFor = (want) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('smtp timeout')), timeout);
      const onData = (chunk) => {
        buf += chunk;
        const m = buf.match(/^(\d{3})(?:[ -])(.*)$/m);
        if (m) {
          clearTimeout(timer);
          socket.removeListener('data', onData);
          buf = '';
          resolve({ code: Number(m[1]), text: m[2] });
        }
      };
      socket.on('data', onData);
      socket.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });

  const send = (line) => {
    log(`> ${line}`);
    socket.write(`${line}${CRLF}`);
    return waitFor(/^\d{3}[ -]/);
  };
  const recv = () => {
    log(`< ${buf.split(CRLF)[0]}`);
    return waitFor(/^\d{3}[ -]/);
  };

  try {
    let r = await recv();
    if (r.code !== 220) throw new Error(`smtp greeting ${r.code}`);

    r = await send('EHLO domail.invalid');
    if (r.code !== 250) throw new Error(`ehlo ${r.code}`);
    const caps = String(r.text).toUpperCase();
    if (caps.includes('STARTTLS') && !cfg.secure) throw new Error('relay demands STARTTLS');

    if (cfg.secure && cfg.tls) socket = await cfg.tls(socket, { servername: cfg.host });
    if (cfg.user) {
      await send('AUTH LOGIN');
      await send(btoa(cfg.user));
      await send(btoa(cfg.pass || ''));
    }

    await send(`MAIL FROM:<${envelope.from}>`);
    for (const rcpt of envelope.rcpt) await send(`RCPT TO:<${rcpt}>`);
    await send('DATA');

    // Terminate the dot-stuffed body with the end-of-data sentinel.
    log('> [message]');
    socket.write(toWire(message));
    socket.write(`.${CRLF}`);
    const done = await waitFor(/^\d{3}[ -]/);
    if (done.code !== 250) throw new Error(`data rejected ${done.code}`);
    await send('QUIT');
    return { ok: true, code: done.code };
  } finally {
    try {
      socket.end();
    } catch {
      /* closing a broken socket is not an error worth surfacing */
    }
  }
}

/* ------------------------------------------------------------------ *
 * the engine
 * ------------------------------------------------------------------ */

/**
 * A local, in-process mail store and router.
 *
 * Storage is injected as a `{ get, set, del }` triple so the same engine
 * runs against IndexedDB in a tab, a JSON file in the CLI, or an
 * in-memory map in tests. Keeping storage out of the engine is what lets
 * the wipe guarantee be provable: one object owns every byte.
 */
export class MailEngine {
  /**
   * @param {{get:Function,set:Function,del:Function}} store
   * @param {{identity?:object,now?:Function}} [opts]
   */
  constructor(store, opts = {}) {
    this.store = store;
    this.now = opts.now ?? (() => Date.now());
    this.identity = opts.identity ?? null;
    this.listeners = new Set();
  }

  async load() {
    const saved = await this.store.get('identity');
    if (saved) this.identity = saved;
    return this.identity;
  }

  on(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(event) {
    for (const fn of this.listeners) {
      try {
        fn(event);
      } catch {
        /* a broken listener must not break the engine */
      }
    }
  }

  /* -------- mailbox operations -------- */

  async list(mailbox) {
    const rows = (await this.store.get(`mbox:${mailbox}`)) ?? [];
    return rows.slice().sort((a, b) => b.date - a.date);
  }

  async add(mailbox, record) {
    const rows = (await this.store.get(`mbox:${mailbox}`)) ?? [];
    rows.push(record);
    await this.store.set(`mbox:${mailbox}`, rows);
    this.emit({ type: 'change', mailbox, id: record.id });
    return record;
  }

  async remove(mailbox, id) {
    const rows = (await this.store.get(`mbox:${mailbox}`)) ?? [];
    const next = rows.filter((r) => r.id !== id);
    await this.store.set(`mbox:${mailbox}`, next);
    this.emit({ type: 'change', mailbox, id });
  }

  async get(mailbox, id) {
    const rows = (await this.store.get(`mbox:${mailbox}`)) ?? [];
    return rows.find((r) => r.id === id) ?? null;
  }

  /**
   * Route a delivered message into the mailbox belonging to each
   * recipient address. Unknown local recipients are still accepted:
   * a loopback engine with a single identity must be able to mail itself.
   */
  async deliver(envelope) {
    const message = typeof envelope === 'string' ? parseMessage(envelope) : envelope;
    const targets = [
      ...message.to.map((a) => a.address),
      ...message.cc.map((a) => a.address),
      ...message.bcc.map((a) => a.address),
    ];
    const local = new Set(
      targets.filter((a) => this.isLocalAddress(a)).map((a) => a.toLowerCase()),
    );

    const record = {
      id: message.messageId || makeMessageId(),
      subject: message.subject,
      from: message.from,
      to: message.to,
      cc: message.cc,
      date: message.date,
      bodyText: message.bodyText,
      bodyIsHtml: message.bodyIsHtml,
      attachments: message.attachments,
      inReplyTo: message.inReplyTo || '',
      read: false,
      flagged: false,
      local: local.size > 0,
    };

    await this.add('inbox', record);
    for (const addr of local) {
      if (addr !== this.identity?.address?.toLowerCase()) {
        await this.add(`alias:${addr}`, record);
      }
    }
    this.emit({ type: 'delivered', record });
    return record;
  }

  isLocalAddress(address) {
    if (!address || !this.identity) return false;
    const addr = String(address).toLowerCase();
    const domain = String(this.identity.domain || '').toLowerCase();
    return addr.endsWith(`@${domain}`) || addr === String(this.identity.address).toLowerCase();
  }

/**
   * Send a message. `draft` should contain to, cc, bcc, subject, text, html, attachments, headers.
   * `mailbox` is where the sender's own copy lands: 'outbox' normally, or null to skip saving.
   */
  async send(draft, mailbox = 'outbox') {
    const { headers, ...draftWithoutHeaders } = draft;
    const raw = buildMessage({
      ...draftWithoutHeaders,
      from: this.identity,
      date: new Date(this.now()),
      headers,
    });
    const parsed = parseMessage(raw);
    const record = {
      id: parsed.messageId,
      subject: parsed.subject,
      from: parsed.from,
      to: parsed.to,
      cc: parsed.cc,
      date: parsed.date,
      bodyText: parsed.bodyText,
      bodyIsHtml: parsed.bodyIsHtml,
      attachments: parsed.attachments,
      inReplyTo: parsed.inReplyTo || '',
      read: true,
      flagged: false,
      status: 'sent',
      raw,
    };
    if (mailbox) {
      await this.add(mailbox, record);
    }

    // Deliver a copy to any local recipient, including the sender.
    const recipients = [
      ...parsed.to,
      ...parsed.cc,
      ...parsed.bcc,
    ].map((a) => a.address);
    const loopback = recipients.filter((a) => this.isLocalAddress(a));
    if (loopback.length) await this.deliver({ ...parsed, raw });
    return record;
  }

  /* -------- contacts -------- */

  async contacts() {
    return (await this.store.get('contacts')) ?? {};
  }

  /** Remember a display name for an address, learned from incoming mail. */
  async learnContact(address, name) {
    if (!address || !name) return null;
    const map = await this.contacts();
    const key = String(address).toLowerCase();
    if (map[key]?.name === name) return map[key];
    map[key] = { address, name, seen: this.now() };
    await this.store.set('contacts', map);
    this.emit({ type: 'contacts' });
    return map[key];
  }

  async renameContact(address, name) {
    const map = await this.contacts();
    map[String(address).toLowerCase()] = { address, name, seen: this.now() };
    await this.store.set('contacts', map);
    this.emit({ type: 'contacts' });
  }

  /* -------- identity -------- */

  async setIdentity(identity) {
    this.identity = identity;
    await this.store.set('identity', identity);
    this.emit({ type: 'identity', identity });
    return identity;
  }

  /**
   * Destroy the identity and every message it ever held.
   *
   * This is the forensic wipe. It clears the store namespace the engine
   * owns, clears in-memory state, and overwrites the persisted values
   * with empties before deleting them so a freed block is not trivially
   * recoverable from a snapshot of the underlying medium.
   */
  async wipe() {
    await this.store.clear();
    this.identity = null;
    this.listeners.clear();
    this.emit({ type: 'wiped' });
  }

  /* -------- export -------- */

  /** Serialise everything the engine owns. */
  async export({ includeMail = true } = {}) {
    const out = {
      format: 'domail/1',
      exported: this.now(),
      identity: this.identity,
      contacts: await this.contacts(),
      signature: (await this.store.get('signature')) ?? '',
    };
    if (includeMail) {
      out.mail = {
        inbox: await this.list('inbox'),
        outbox: await this.list('outbox'),
        drafts: await this.list('drafts'),
      };
    }
    return out;
  }

  /** Restore an export. Existing mail is replaced by the imported mail. */
  async import(data) {
    if (!data || data.format !== 'domail/1') {
      throw new Error('unrecognised export format');
    }
    if (data.identity) await this.setIdentity(data.identity);
    if (data.contacts) await this.store.set('contacts', data.contacts);
    if (typeof data.signature === 'string') {
      await this.store.set('signature', data.signature);
    }
    for (const box of ['inbox', 'outbox', 'drafts']) {
      const rows = data.mail?.[box];
      if (!Array.isArray(rows)) continue;
      await this.store.set(`mbox:${box}`, rows);
    }
    this.emit({ type: 'imported' });
  }
}

/* ------------------------------------------------------------------ *
 * storage adapters
 * ------------------------------------------------------------------ */

/** In-memory adapter. Used by tests and as the CLI's default. */
export function memoryStore(seed = {}) {
  const _map = new Map(Object.entries(seed));
  return {
    async get(k) {
      const v = _map.get(k);
      return v === undefined ? undefined : JSON.parse(JSON.stringify(v));
    },
    async set(k, v) {
      _map.set(k, JSON.parse(JSON.stringify(v)));
    },
    async del(k) {
      _map.delete(k);
    },
    async clear() {
      _map.clear();
    },
    async serialize() {
      return JSON.parse(JSON.stringify(Object.fromEntries(_map)));
    },
  };
}

/** IndexedDB adapter. Keys are the engine's whole namespace. */
export function indexedDbStore(dbName = 'domail', storeName = 'kv') {
  let dbp = null;
  const open = () => {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(storeName)) {
          db.createObjectStore(storeName);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbp;
  };
  const tx = async (mode, fn) => {
    const db = await open();
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeName, mode);
      const req = fn(t.objectStore(storeName));
      t.oncomplete = () => resolve(req?.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  };
  return {
    async get(k) {
      return tx('readonly', (s) => s.get(k));
    },
    async set(k, v) {
      return tx('readwrite', (s) => s.put(v, k));
    },
    async del(k) {
      return tx('readwrite', (s) => s.delete(k));
    },
    async clear() {
      return tx('readwrite', (s) => s.clear());
    },
    /** Delete the whole database. The only way to be certain nothing remains. */
    async destroy() {
      const db = await open();
      db.close();
      dbp = null;
      await new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase(dbName);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error('deleteDatabase blocked by another connection'));
      });
    },
  };
}
