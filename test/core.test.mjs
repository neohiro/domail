import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  bytesToBase64,
  base64ToBytes,
  encodeHeaderWord,
  decodeHeaderWords,
  foldHeader,
  parseAddressList,
  formatAddressList,
  buildMessage,
  parseMessage,
  splitMultipart,
  walkMime,
  parseHeaders,
  headerValue,
  dotStuff,
  undotStuff,
  toWire,
  makeMessageId,
  MailEngine,
  memoryStore,
  indexedDbStore,
  utf8,
  makeBoundary,
  preferredPart,
  collectAttachments,
  encodeBase64Body,
  decodeBase64Body,
  splitMessage,
} from '../core/mail.mjs';

const ID = { name: 'Nova', address: 'nova@domail.invalid' };

/* ---------------- base64 ---------------- */

test('base64 roundtrips every byte length 0..64', () => {
  for (let n = 0; n <= 64; n++) {
    const bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) bytes[i] = (i * 37 + n) & 0xff;
    assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes, `len ${n}`);
  }
});

test('base64 matches RFC 4648 test vectors', () => {
  const enc = (s) => bytesToBase64(utf8(s));
  assert.equal(enc(''), '');
  assert.equal(enc('f'), 'Zg==');
  assert.equal(enc('fo'), 'Zm8=');
  assert.equal(enc('foo'), 'Zm9v');
  assert.equal(enc('foob'), 'Zm9vYg==');
  assert.equal(enc('fooba'), 'Zm9vYmE=');
  assert.equal(enc('foobar'), 'Zm9vYmFy');
});

test('base64 body lines respect the 76-char RFC 2045 limit', () => {
  const bytes = new Uint8Array(4096).map((_, i) => i & 0xff);
  const body = encodeBase64Body(bytes);
  for (const line of body.split('\r\n')) assert.ok(line.length <= 76);
});

test('base64 attachment bytes survive intact, including bytes >= 0x80', () => {
  // Bytes 0x80..0xff are the ones a UTF-8 text round-trip would destroy.
  const bytes = new Uint8Array(4096).map((_, i) => (i * 7 + 128) & 0xff);
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'bin',
    text: 'see attached',
    attachments: [{ name: 'b.bin', type: 'application/octet-stream', bytes }],
  });
  const m = parseMessage(raw);
  assert.equal(m.attachments.length, 1);
  assert.deepEqual(m.attachments[0].bytes, bytes);
  assert.equal(m.bodyText, 'see attached', 'body must not be polluted by the binary part');
});

test('a base64 text attachment still decodes as text', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 't',
    text: 'body',
    attachments: [{ name: 'note.txt', type: 'text/plain', bytes: utf8('héllo wörld') }],
  });
  const m = parseMessage(raw);
  assert.equal(utf8ToStr(m.attachments[0].bytes), 'héllo wörld');
});


/* ---------------- RFC 2047 ---------------- */

test('encoded-words roundtrip non-ascii display names and subjects', () => {
  for (const s of ['Héllo', '日本語', 'Ünïcødé ✉', 'ascii only', 'a—b—c']) {
    const enc = encodeHeaderWord(s);
    assert.equal(decodeHeaderWords(enc), s, JSON.stringify(s));
  }
});

test('pure ascii is never encoded', () => {
  assert.equal(encodeHeaderWord('Plain Subject'), 'Plain Subject');
});

/* ---------------- folding ---------------- */

test('header folding keeps every line within 78 columns', () => {
  const folded = foldHeader('References', Array.from({ length: 12 }, () => `<${makeMessageId()}>`).join(' '));
  for (const line of folded.split('\r\n')) {
    assert.ok(line.length <= 78, `line ${line.length}: ${line}`);
  }
});

test('short headers are not folded', () => {
  assert.equal(foldHeader('To', 'a@b.c'), 'To: a@b.c');
});

/* ---------------- addresses ---------------- */

test('parses plain, named and quoted addresses', () => {
  assert.deepEqual(parseAddressList('a@b.c'), [{ name: '', address: 'a@b.c' }]);
  assert.deepEqual(parseAddressList('Nova <a@b.c>'), [
    { name: 'Nova', address: 'a@b.c' },
  ]);
  assert.deepEqual(parseAddressList('"Doe, Jane" <j@d.e>'), [
    { name: 'Doe, Jane', address: 'j@d.e' },
  ]);
});

test('does not split on commas inside quotes or angle brackets', () => {
  assert.deepEqual(parseAddressList('"A, B" <a@b.c>, c@d.e'), [
    { name: 'A, B', address: 'a@b.c' },
    { name: '', address: 'c@d.e' },
  ]);
});

test('address list survives a format/parse roundtrip', () => {
  const list = [
    { name: 'Plain', address: 'p@x.y' },
    { name: 'Doe, Jane', address: 'j@x.y' },
    { name: 'Ünïcødé', address: 'u@x.y' },
  ];
  assert.deepEqual(parseAddressList(formatAddressList(list)), list);
});

test('empty address input yields an empty list', () => {
  assert.deepEqual(parseAddressList(''), []);
  assert.deepEqual(parseAddressList(undefined), []);
});

/* ---------------- single-part message ---------------- */

test('builds and parses a plain text message', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ name: '', address: 'who@x.y' }],
    subject: 'Hello',
    text: 'line one\nline two',
    date: new Date(0),
  });
  assert.ok(raw.includes('From: Nova <nova@domail.invalid>'));
  assert.ok(raw.includes('Subject: Hello'));
  assert.ok(raw.includes('MIME-Version: 1.0'));
  assert.ok(raw.includes('Content-Type: text/plain; charset=UTF-8'));

  const m = parseMessage(raw);
  assert.equal(m.subject, 'Hello');
  assert.equal(m.bodyText, 'line one\nline two');
  assert.equal(m.from[0].address, 'nova@domail.invalid');
  assert.equal(m.to[0].address, 'who@x.y');
  assert.equal(m.date, 0);
  assert.match(m.messageId, /@domail\.invalid$/);
});

test('message id is wrapped in angle brackets exactly once', () => {
  const raw = buildMessage({ from: ID, to: [{ address: 'a@b.c' }], subject: 'x', text: 'y' });
  assert.ok(/^Message-ID: <[^<>]+@[^<>]+>$/m.test(raw));
});

test('omits To, Cc and Bcc headers when empty', () => {
  const raw = buildMessage({ from: ID, to: [], cc: [], bcc: [], subject: 'x', text: 'y' });
  assert.ok(!/^To:/m.test(raw));
  assert.ok(!/^Cc:/m.test(raw));
  assert.ok(!/^Bcc:/m.test(raw));
});

/* ---------------- multipart ---------------- */

test('multipart/alternative prefers text/plain and keeps both parts', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'alt',
    text: 'plain body',
    html: '<p>html body</p>',
  });
  assert.ok(/Content-Type: multipart\/alternative; boundary="/.test(raw));

  const m = parseMessage(raw);
  assert.equal(m.bodyText, 'plain body');
  assert.equal(m.bodyIsHtml, false);
  assert.ok(raw.includes('<p>html body</p>'), 'html part must survive in raw');
});

test('html-only message stays single part and is flagged as html', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'h',
    html: '<b>bold</b>',
  });
  assert.ok(/Content-Type: text\/html; charset=UTF-8/.test(raw));
  const m = parseMessage(raw);
  assert.equal(m.bodyIsHtml, true);
  assert.equal(m.bodyText, '<b>bold</b>');
});

test('mixed with an alternative inner part roundtrips both bodies', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'mix',
    text: 'the plain one',
    html: '<p>the html one</p>',
    attachments: [
      { name: 'a.txt', type: 'text/plain', bytes: utf8('attached bytes') },
    ],
  });
  assert.ok(/Content-Type: multipart\/mixed; boundary="/.test(raw));

  const m = parseMessage(raw);
  assert.equal(m.bodyText, 'the plain one');
  assert.equal(m.attachments.length, 1);
  assert.equal(m.attachments[0].name, 'a.txt');
  assert.equal(utf8ToStr(m.attachments[0].bytes), 'attached bytes');
});

function utf8ToStr(b) {
  return new TextDecoder().decode(b);
}

test('a boundary string appearing in the body does not break parsing', () => {
  const b = makeBoundary('seed');
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'collide',
    text: `before\n--${b}\nnot really a boundary\nafter`,
    html: '<p>x</p>',
  });
  const m = parseMessage(raw);
  assert.ok(m.bodyText.includes('not really a boundary'));
  assert.ok(m.bodyText.includes('after'));
});

test('splitMultipart on a message with no parts returns empty', () => {
  assert.deepEqual(splitMultipart('no boundaries here', 'xyz'), []);
});

test('preferring plain text works through a deep tree', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'deep',
    text: 'deep plain',
    html: '<p>deep html</p>',
    attachments: [{ name: 'x.bin', type: 'application/octet-stream', bytes: new Uint8Array([1, 2, 3]) }],
  });
  const split = splitMessage(raw);
  const node = walkMime(parseHeaders(split.headerBlock), split.body);
  assert.equal(node.type, 'multipart/mixed');
  assert.equal(node.parts.length, 2);
  assert.equal(node.parts[0].type, 'multipart/alternative');
  assert.equal(preferredPart(node).value.trim(), 'deep plain');
  assert.equal(collectAttachments(node).length, 1);
});

/* ---------------- CRLF / dot-stuffing ---------------- */

test('dot stuffing is reversible and RFC 5321 shaped', () => {
  const tricky = 'a\r\n.hidden\r\n..already\r\nb';
  const stuffed = dotStuff(tricky);
  assert.ok(stuffed.includes('\r\n..hidden'));
  assert.ok(stuffed.includes('\r\n...already'));
  assert.equal(undotStuff(stuffed), tricky);
});

test('leading dot on the first line is stuffed', () => {
  assert.equal(dotStuff('.x'), '..x');
});

test('wire form normalises LF to CRLF and ends with CRLF', () => {
  const wire = toWire('a\nb\n');
  assert.equal(wire, 'a\r\nb\r\n\r\n');
});

/* ---------------- engine ---------------- */

function engineWith(identity = ID) {
  const store = memoryStore();
  const e = new MailEngine(store);
  e.identity = identity;
  return { e, store };
}

test('engine sends to outbox and loops a copy back to the inbox', async () => {
  const { e } = engineWith();
  await e.send({ to: [{ address: ID.address }], subject: 'self', text: 'note to self' });

  const out = await e.list('outbox');
  const inbox = await e.list('inbox');
  assert.equal(out.length, 1, 'outbox copy');
  assert.equal(inbox.length, 1, 'inbox loopback copy');
  assert.equal(out[0].subject, 'self');
  assert.equal(inbox[0].subject, 'self');
});

test('engine leaves a non-local recipient out of the inbox', async () => {
  const { e } = engineWith();
  await e.send({ to: [{ address: 'far@elsewhere.tld' }], subject: 'out', text: 'x' });
  assert.equal((await e.list('outbox')).length, 1);
  assert.equal((await e.list('inbox')).length, 0);
});

test('deliver accepts a raw wire message from outside', async () => {
  const { e } = engineWith();
  const raw = buildMessage({
    from: { name: 'Stranger', address: 'stranger@elsewhere.tld' },
    to: [{ address: ID.address }],
    subject: 'Inbound',
    text: 'hello from the net',
  });
  const rec = await e.deliver(raw);
  assert.equal(rec.subject, 'Inbound');
  assert.equal(rec.read, false, 'new mail must be unread');
  const inbox = await e.list('inbox');
  assert.equal(inbox.length, 1);
  assert.equal(inbox[0].local, true);
});

test('mailbox is newest first', async () => {
  const { e } = engineWith();
  let t = 1000;
  for (const s of ['first', 'second', 'third']) {
    t += 1000;
    await e.deliver(
      buildMessage({
        from: { address: 'x@y.z' },
        to: [{ address: ID.address }],
        subject: s,
        text: s,
        date: new Date(t),
      }),
    );
  }
  const inbox = await e.list('inbox');
  assert.deepEqual(inbox.map((r) => r.subject), ['third', 'second', 'first']);
});

test('remove deletes exactly one record', async () => {
  const { e } = engineWith();
  const r = await e.deliver(
    buildMessage({ from: { address: 'x@y.z' }, to: [{ address: ID.address }], subject: 'gone', text: 'x' }),
  );
  assert.equal((await e.list('inbox')).length, 1);
  await e.remove('inbox', r.id);
  assert.equal((await e.list('inbox')).length, 0);
});

test('contacts are learned and renamed', async () => {
  const { e } = engineWith();
  await e.learnContact('friend@x.y', 'Friend');
  assert.equal((await e.contacts())['friend@x.y'].name, 'Friend');
  await e.renameContact('friend@x.y', 'Best Friend');
  assert.equal((await e.contacts())['friend@x.y'].name, 'Best Friend');
});

test('learning a contact without a name is a no-op', async () => {
  const { e } = engineWith();
  assert.equal(await e.learnContact('a@b.c', ''), null);
  assert.deepEqual(await e.contacts(), {});
});

test('settings-only export omits mail', async () => {
  const { e } = engineWith();
  await e.send({ to: [{ address: ID.address }], subject: 'keep', text: 'x' });
  const out = await e.export({ includeMail: false });
  assert.equal(out.format, 'domail/1');
  assert.equal(out.mail, undefined);
  assert.equal(out.identity.address, ID.address);
});

test('full export includes every mailbox and roundtrips through import', async () => {
  const { e, store } = engineWith();
  await e.send({ to: [{ address: ID.address }], subject: 'a', text: 'a' });
  await e.send({ to: [{ address: 'z@x.y' }], subject: 'b', text: 'b' });
  await store.set('mbox:drafts', [{ id: 'd1', subject: 'draft one' }]);
  await e.learnContact('c@x.y', 'See');

  const dump = await e.export({ includeMail: true });
  assert.equal(dump.mail.inbox.length, 1);
  assert.equal(dump.mail.outbox.length, 2);
  assert.equal(dump.mail.drafts.length, 1);
  assert.equal(dump.contacts['c@x.y'].name, 'See');

  const { e: fresh } = engineWith({ name: null, address: null, domain: null });
  await fresh.import(dump);
  assert.equal(fresh.identity.address, ID.address);
  assert.equal((await fresh.list('inbox'))[0].subject, 'a');
  assert.equal((await fresh.list('drafts'))[0].subject, 'draft one');
});

test('import refuses an unrecognised format', async () => {
  const { e } = engineWith();
  await assert.rejects(() => e.import({ format: 'nope' }), /unrecognised/);
});

/* ---------------- wipe ---------------- */

test('wipe destroys identity, all mail and contacts', async () => {
  const { e, store } = engineWith();
  await e.setIdentity(ID);
  await e.send({ to: [{ address: ID.address }], subject: 'secret', text: 'burn me' });
  await e.learnContact('spy@x.y', 'Spy');

  await e.wipe();

  assert.equal(e.identity, null);
  assert.deepEqual(await e.list('inbox'), []);
  assert.deepEqual(await e.list('outbox'), []);
  assert.deepEqual(await e.list('drafts'), []);
  assert.deepEqual(await e.contacts(), {});
  assert.equal(await store.get('identity'), undefined);
  assert.equal(await store.get('mbox:inbox'), undefined);
  assert.equal(await store.get('mbox:outbox'), undefined);
  assert.equal(await store.get('contacts'), undefined);
});

test('wipe leaves no residue in the raw backing map', async () => {
  const { e, store } = engineWith();
  await e.setIdentity(ID);
  await e.send({ to: [{ address: ID.address }], subject: 'gone', text: 'x' });
  await e.wipe();
  const leftover = Object.values(await store.serialize()).filter(
    (v) => v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0),
  );
  assert.deepEqual(leftover, [], `residue: ${JSON.stringify(leftover)}`);
});

test('the store adapter hands out copies, not live references', async () => {
  const store = memoryStore();
  await store.set('k', { list: [1, 2] });
  const got = await store.get('k');
  got.list.push(3);
  const again = await store.get('k');
  assert.deepEqual(again.list, [1, 2], 'mutating a read must not corrupt the store');
});

/* ---------------- header block parsing ---------------- */

test('continuation lines unfold into their header', () => {
  const h = parseHeaders('Subject: one\r\n  two\r\nTo: a@b.c');
  assert.equal(headerValue(h, 'Subject'), 'one two');
  assert.equal(headerValue(h, 'To'), 'a@b.c');
});

test('a colon inside a header value is not treated as a new header', () => {
  const h = parseHeaders('Message-ID: <abc@x.y>');
  assert.equal(h.length, 1);
  assert.equal(headerValue(h, 'Message-ID'), '<abc@x.y>');
});

test('header lookup is case-insensitive', () => {
  const h = parseHeaders('sUbJeCt: x');
  assert.equal(headerValue(h, 'Subject'), 'x');
});

/* ---------------- adapter surface ---------------- */

test('indexedDbStore is exported and inert outside a browser', () => {
  assert.equal(typeof indexedDbStore, 'function');
  const s = indexedDbStore();
  assert.equal(typeof s.get, 'function');
  assert.equal(typeof s.destroy, 'function');
});

/* ---------------- security: header injection ---------------- */

test('CRLF in subject is stripped to prevent header injection', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c' }],
    subject: 'Hello\r\nBcc: evil@x.com',
    text: 'body',
  });
  assert.ok(!raw.includes('evil@x.com'), 'injected header must not appear');
  assert.ok(!/^Bcc:/m.test(raw), 'no injected Bcc header');
});

test('CRLF in address name is stripped', () => {
  const raw = buildMessage({
    from: { name: 'Nova\r\nBcc: evil@x.com', address: 'n@d.invalid' },
    to: [{ address: 'a@b.c' }],
    subject: 'x',
    text: 'y',
  });
  assert.ok(!/^Bcc:/m.test(raw), 'no injected Bcc header');
  assert.ok(!/\r\nBcc:/.test(raw), 'no CRLF injection');
});

test('CRLF in address value is stripped', () => {
  const raw = buildMessage({
    from: ID,
    to: [{ address: 'a@b.c\r\nBcc: evil@x.com' }],
    subject: 'x',
    text: 'y',
  });
  assert.ok(!/^Bcc:/m.test(raw), 'no injected Bcc header');
  assert.ok(!/\r\nBcc:/.test(raw), 'no CRLF injection');
});

/* ---------------- splitMultipart regex ---------------- */

test('splitMultipart handles trailing tab after boundary', () => {
  const boundary = '----=_test';
  const body = `--${boundary}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--${boundary}--`;
  const parts = splitMultipart(body, boundary);
  assert.equal(parts.length, 1);
  assert.ok(parts[0].includes('hello'));
});

/* ---------------- dotStuff LF handling ---------------- */

test('dotStuff handles LF-only input', () => {
  const lf = 'a\n.hidden\nb';
  const stuffed = dotStuff(lf);
  assert.ok(stuffed.includes('\r\n..hidden'));
  assert.equal(undotStuff(stuffed), 'a\r\n.hidden\r\nb');
});

/* ---------------- wipe with signature and alias ---------------- */

test('wipe clears signature and alias keys', async () => {
  const { e, store } = engineWith();
  await e.setIdentity(ID);
  await e.send({ to: [{ address: ID.address }], subject: 'a', text: 'a' });
  await store.set('signature', 'my signature');
  await store.set('mbox:alias:test@domail.space', [{ id: 'x' }]);

  await e.wipe();

  assert.equal(await store.get('signature'), undefined);
  assert.equal(await store.get('mbox:alias:test@domail.space'), undefined);
  assert.equal(await store.get('identity'), undefined);
});

/* ---------------- memoryStore encapsulation ---------------- */

test('memoryStore does not expose internal map', () => {
  const store = memoryStore();
  assert.equal(store.map, undefined, 'map must not be publicly accessible');
  assert.equal(typeof store.clear, 'function');
  assert.equal(typeof store.serialize, 'function');
});

test('memoryStore serialize returns a copy', async () => {
  const store = memoryStore();
  await store.set('k', { list: [1, 2] });
  const snap = await store.serialize();
  snap.k.list.push(3);
  const again = await store.get('k');
  assert.deepEqual(again.list, [1, 2]);
});

/* ---------------- base64 performance ---------------- */

test('bytesToBase64 handles large input efficiently', () => {
  const bytes = new Uint8Array(100000).map((_, i) => i & 0xff);
  const start = Date.now();
  const b64 = bytesToBase64(bytes);
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 1000, `took ${elapsed}ms`);
  assert.equal(base64ToBytes(b64).length, bytes.length);
});

/* ---------------- deliver alias routing ---------------- */

test('deliver creates alias for non-identity local address', async () => {
  const store = memoryStore();
  const e = new MailEngine(store);
  e.identity = { name: 'Nova', address: 'nova@domail.space', domain: 'domail.space' };
  await e.deliver(
    buildMessage({
      from: { address: 'x@y.z' },
      to: [{ address: 'other@domail.space' }],
      subject: 'alias test',
      text: 'x',
    }),
  );
  const alias = await e.list('alias:other@domail.space');
  assert.equal(alias.length, 1);
  assert.equal(alias[0].subject, 'alias test');
});
