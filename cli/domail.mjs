#!/usr/bin/env node
/**
 * DOM Mail CLI
 *
 * A command-line interface that shares the same mail engine as the browser
 * app. Renders an ASCII inbox, allows reading and composing messages.
 *
 * Usage:
 *   node cli/domail.mjs              # interactive mode
 *   node cli/domail.mjs inbox        # list inbox
 *   node cli/domail.mjs read <id>    # read a message
 *   node cli/domail.mjs compose      # compose a new message
 *   node cli/domail.mjs send <id>    # send a draft
 *   node cli/domail.mjs wipe         # destroy all data
 */

import { MailEngine, memoryStore, buildMessage, parseMessage, makeMessageId } from '../core/mail.mjs';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_FILE = join(__dirname, '.domail-cli.json');

function loadStore() {
  if (existsSync(DATA_FILE)) {
    try {
      return memoryStore(JSON.parse(readFileSync(DATA_FILE, 'utf8')));
    } catch {}
  }
  return memoryStore();
}

function saveStore(store) {
  writeFileSync(DATA_FILE, JSON.stringify(Object.fromEntries(store.map), null, 2));
}

function createEngine() {
  const store = loadStore();
  const engine = new MailEngine(store);
  engine.save = () => saveStore(store);
  return engine;
}

function pad(str, len) {
  const s = String(str);
  return s.length >= len ? s.slice(0, len - 1) + '…' : s + ' '.repeat(len - s.length);
}

function line(width = 60) {
  return '─'.repeat(width);
}

function header(title) {
  console.log();
  console.log(`┌${line()}┐`);
  console.log(`│ ${pad(title, 58)} │`);
  console.log(`├${line()}┤`);
}

function footer() {
  console.log(`└${line()}┘`);
}

function showInbox(engine) {
  const inbox = engine._lists?.inbox || [];
  header('INBOX');
  if (!inbox.length) {
    console.log('│  (empty)                                                          │');
  } else {
    for (const m of inbox) {
      const from = m.from?.[0]?.address || 'unknown';
      const subj = m.subject || '(no subject)';
      const read = m.read ? ' ' : '●';
      console.log(`│ ${read} ${pad(from, 20)} ${pad(subj, 35)} │`);
    }
  }
  footer();
}

function showOutbox(engine) {
  const outbox = engine._lists?.outbox || [];
  header('OUTBOX');
  if (!outbox.length) {
    console.log('│  (empty)                                                          │');
  } else {
    for (const m of outbox) {
      const to = m.to?.[0]?.address || 'unknown';
      const subj = m.subject || '(no subject)';
      console.log(`│   ${pad(to, 20)} ${pad(subj, 35)} │`);
    }
  }
  footer();
}

function showMessage(engine, id) {
  const m = engine._lists?.inbox?.find((r) => r.id === id)
    || engine._lists?.outbox?.find((r) => r.id === id)
    || engine._lists?.drafts?.find((r) => r.id === id);
  if (!m) {
    console.log('Message not found.');
    return;
  }
  header(m.subject || '(no subject)');
  console.log(`│  From: ${pad(m.from?.[0]?.address || 'unknown', 51)} │`);
  console.log(`│  To:   ${pad(m.to?.[0]?.address || 'unknown', 51)} │`);
  console.log(`│  Date: ${pad(new Date(m.date).toLocaleString(), 51)} │`);
  console.log(`├${line()}┤`);
  const body = m.bodyText || '';
  for (const l of body.split('\n')) {
    console.log(`│  ${pad(l, 56)} │`);
  }
  footer();
}

async function interactive(engine) {
  const identity = engine.identity || { address: 'anonymous@domail.space', name: 'Anonymous' };
  console.log();
  console.log('  DOM Mail CLI');
  console.log(`  Identity: ${identity.address}`);
  console.log();
  console.log('  Commands: inbox, outbox, drafts, read <id>, compose, send <id>, wipe, quit');
  console.log();

  const readline = await import('node:readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

  while (true) {
    const input = await ask('domail> ');
    const [cmd, ...args] = input.trim().split(/\s+/);

    if (cmd === 'quit' || cmd === 'q') break;

    if (cmd === 'inbox') {
      const inbox = await engine.list('inbox');
      engine._lists = engine._lists || {};
      engine._lists.inbox = inbox;
      showInbox(engine);
    } else if (cmd === 'outbox') {
      const outbox = await engine.list('outbox');
      engine._lists = engine._lists || {};
      engine._lists.outbox = outbox;
      showOutbox(engine);
    } else if (cmd === 'drafts') {
      const drafts = await engine.list('drafts');
      engine._lists = engine._lists || {};
      engine._lists.drafts = drafts;
      header('DRAFTS');
      if (!drafts.length) {
        console.log('│  (empty)                                                          │');
      } else {
        for (const m of drafts) {
          console.log(`│   ${pad(m.subject || '(no subject)', 56)} │`);
        }
      }
      footer();
    } else if (cmd === 'read') {
      const id = args[0];
      if (!id) { console.log('Usage: read <id>'); continue; }
      showMessage(engine, id);
    } else if (cmd === 'compose') {
      const to = await ask('To: ');
      const subject = await ask('Subject: ');
      const body = await ask('Body (end with blank line): ');
      const msg = {
        from: identity,
        to: to.split(',').map((s) => ({ address: s.trim(), name: '' })),
        subject,
        text: body,
      };
      const raw = buildMessage(msg);
      const parsed = parseMessage(raw);
      await engine.send(msg, 'outbox');
      console.log(`Sent to ${to}`);
    } else if (cmd === 'wipe') {
      const confirm = await ask('Type "wipe" to confirm: ');
      if (confirm === 'wipe') {
        await engine.wipe();
        console.log('All data destroyed.');
      } else {
        console.log('Cancelled.');
      }
    } else {
      console.log('Unknown command.');
    }
  }

  rl.close();
}

const engine = createEngine();
const [cmd, ...args] = process.argv.slice(2);

if (!cmd || cmd === 'interactive') {
  await interactive(engine);
} else if (cmd === 'inbox') {
  const inbox = await engine.list('inbox');
  engine._lists = { inbox };
  showInbox(engine);
} else if (cmd === 'outbox') {
  const outbox = await engine.list('outbox');
  engine._lists = { outbox };
  showOutbox(engine);
} else if (cmd === 'read') {
  const id = args[0];
  if (!id) { console.error('Usage: read <id>'); process.exit(1); }
  const inbox = await engine.list('inbox');
  const outbox = await engine.list('outbox');
  const drafts = await engine.list('drafts');
  engine._lists = { inbox, outbox, drafts };
  showMessage(engine, id);
} else if (cmd === 'compose') {
  const identity = engine.identity || { address: 'anonymous@domail.space', name: 'Anonymous' };
  const to = args[0] || 'self@domail.space';
  const subject = args[1] || 'Hello from CLI';
  const msg = {
    from: identity,
    to: to.split(',').map((s) => ({ address: s.trim(), name: '' })),
    subject,
    text: 'Sent from domail CLI.',
  };
  await engine.send(msg, 'outbox');
  console.log(`Sent to ${to}`);
} else if (cmd === 'wipe') {
  await engine.wipe();
  console.log('All data destroyed.');
} else {
  console.log('Usage: node cli/domail.mjs [inbox|outbox|read <id>|compose|wipe|interactive]');
}
