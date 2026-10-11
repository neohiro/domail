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
const CONFIG_FILE = join(__dirname, '.domail-cli-config.json');

/**
 * Headless settings. Both optional networked features default to OFF, exactly
 * as in the browser build, so a CLI user gets the same local-only default.
 * Persisted beside the mail file so the choice survives restarts.
 */
const DEFAULTS = {
  pgp: false,
  pgpSign: false,
  relay: false,
  relayUrl: '',
  // Shoulder-surfing protection. Off by default so the CLI stays a usable
  // mail client, on when you are reading over someone's shoulder or sharing a
  // terminal capture.
  mask: false,
  netDirect: true,
  netTor: false,
  netI2p: false,
  netEnsIpfs: false,
  netRadicle: false,
  netYggdrasil: false,
  netNostr: false,
  netReticulum: false,
  netWebRTC: false,
  netBLE: false,
  netDNS: false,
  netSneakernet: false,
  netFederation: false,
};

/** Mask an address the same way the browser build does. */
function maskAddress(addr) {
  const raw = String(addr || '');
  if (!raw) return '';
  const at = raw.lastIndexOf('@');
  if (at <= 0) return raw;
  const local = raw.slice(0, at);
  const domain = raw.slice(at + 1);
  const dot = domain.indexOf('.');
  const head = local.length <= 1 ? '*' : local[0];
  const maskedLocal = head + '*'.repeat(Math.min(local.length - 1, 6));
  if (dot <= 0) return `${maskedLocal}@${domain[0] || '*'}${'*'.repeat(6)}`;
  const name = domain.slice(0, dot);
  const tld = domain.slice(dot + 1);
  const maskedName = (name.length <= 1 ? '*' : name[0]) + '*'.repeat(Math.min(name.length - 1, 6));
  return `${maskedLocal}@${maskedName}.${tld}`;
}

let cfgCache = null;
function config() {
  if (!cfgCache) cfgCache = loadConfig();
  return cfgCache;
}

function showAddr(addr) {
  const c = config();
  return c.mask ? maskAddress(addr) : addr;
}

function loadConfig() {
  if (!existsSync(CONFIG_FILE)) return { ...DEFAULTS };
  try {
    return { ...DEFAULTS, ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) };
  } catch {
    return { ...DEFAULTS };
  }
}

function saveConfig(cfg) {
  writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function printDisclosure(title, lines) {
  console.log();
  console.log(`  ${title}`);
  for (const l of lines) console.log(`  ${l}`);
  console.log();
}

function loadStore() {
  if (existsSync(DATA_FILE)) {
    try {
      return memoryStore(JSON.parse(readFileSync(DATA_FILE, 'utf8')));
    } catch {}
  }
  return memoryStore();
}

async function saveStore(store) {
  const data = await store.serialize();
  writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
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
      const from = showAddr(m.from?.[0]?.address || 'unknown');
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
      const to = showAddr(m.to?.[0]?.address || 'unknown');
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
  cfgCache = loadConfig();
  const cfg = cfgCache;
  console.log();
  console.log('  DOM Mail CLI');
  console.log(`  Identity: ${showAddr(identity.address)}`);
  console.log(`  Armored encryption (PGP): ${cfg.pgp ? 'ON' : 'off'}`);
  console.log(`  WebSocket relay: ${cfg.relay ? 'ON' : 'off'}`);
  console.log();
  console.log('  Commands: inbox, outbox, drafts, read <id>, compose, mask [on|off],');
  console.log('            pgp [on|off|status], relay [on|off|url|status], wipe, quit');
  console.log();

  const readline = await import('node:readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

  async function doPgp(arg) {
    cfgCache = loadConfig();
    const c = cfgCache;
    if (!arg || arg === 'status') {
      console.log(`PGP armored encryption is ${c.pgp ? 'ON' : 'off'}.`);
      if (c.pgp) printDisclosure('Metadata is still exposed:', [
        'Encrypting the body does not hide From, To, Subject, Date or size.',
        'This armor will NOT decrypt in GnuPG.',
      ]);
      return;
    }
    if (arg === 'on' || arg === 'off') {
      c.pgp = arg === 'on';
      saveConfig(c);
      console.log(`PGP armored encryption is now ${c.pgp ? 'ON' : 'off'}.`);
      if (c.pgp) printDisclosure('Before you continue:', [
        'This is OpenPGP-compatible armor around DOM Mail\'s own packet format.',
        'It will not decrypt in GnuPG.',
        'Mail will REFUSE to send if a recipient public key is unknown,',
        'rather than quietly falling back to plaintext.',
        'From/To/Subject/Date remain visible in the envelope.',
      ]);
      return;
    }
    console.log('Usage: pgp [on|off|status]');
  }

  async function doRelay(arg) {
    cfgCache = loadConfig();
    const c = cfgCache;
    if (!arg || arg === 'status') {
      console.log(`WebSocket relay is ${c.relay ? 'ON' : 'off'}${c.relayUrl ? ` (${c.relayUrl})` : ''}.`);
      if (c.relay) printDisclosure('Relay risks:', [
        'Your IP and online times are visible to the relay operator.',
        'On Tor this defeats the purpose entirely.',
        'Traffic analysis remains possible even with an encrypted body.',
        'If PGP is off, the relay reads the envelope in plaintext.',
        'A malicious relay can drop, replay, reorder or censor mail.',
        'DOM Mail stops being local-only and stops working offline.',
      ]);
      return;
    }
    if (arg === 'on' || arg === 'off') {
      c.relay = arg === 'on';
      saveConfig(c);
      console.log(`WebSocket relay is now ${c.relay ? 'ON' : 'off'}.`);
      if (c.relay) printDisclosure('Relay risks:', [
        'Your IP and online times become visible to the relay operator.',
        'On Tor this defeats the purpose entirely.',
        'A malicious relay can drop, replay, reorder or censor mail.',
      ]);
      return;
    }
    c.relayUrl = arg;
    saveConfig(c);
    console.log(`Relay URL set to ${arg}`);
  }

  async function doNetwork(net, val) {
    cfgCache = loadConfig();
    const c = cfgCache;
    const validNets = ['direct', 'tor', 'i2p', 'ens', 'radicle', 'yggdrasil', 'nostr', 'reticulum', 'webrtc', 'ble', 'dns', 'sneakernet', 'federation'];
    if (!net || net === 'status') {
      console.log('Multi-Network & Advanced Transports (13 Vectors):');
      console.log(`  Direct (80/443 TLS): ${c.netDirect !== false ? 'ON' : 'off'}`);
      console.log(`  Tor Onion Service:   ${c.netTor ? 'ON' : 'off'}`);
      console.log(`  I2P Eepsite:         ${c.netI2p ? 'ON' : 'off'}`);
      console.log(`  ENS / IPFS Gateway:  ${c.netEnsIpfs ? 'ON' : 'off'}`);
      console.log(`  Radicle P2P:         ${c.netRadicle ? 'ON' : 'off'}`);
      console.log(`  Yggdrasil Mesh:      ${c.netYggdrasil ? 'ON' : 'off'}`);
      console.log(`  Nostr Relay Sync:    ${c.netNostr ? 'ON' : 'off'}`);
      console.log(`  Reticulum / LXMF:    ${c.netReticulum ? 'ON' : 'off'}`);
      console.log(`  WebRTC P2P:          ${c.netWebRTC ? 'ON' : 'off'}`);
      console.log(`  BLE Proximity Mesh:  ${c.netBLE ? 'ON' : 'off'}`);
      console.log(`  DNS TXT Tunneling:   ${c.netDNS ? 'ON' : 'off'}`);
      console.log(`  USB/QR Sneakernet:   ${c.netSneakernet ? 'ON' : 'off'}`);
      console.log(`  Federation Gateway:  ${c.netFederation ? 'ON' : 'off'}`);
      return;
    }
    const keyMap = {
      direct: 'netDirect',
      tor: 'netTor',
      i2p: 'netI2p',
      ens: 'netEnsIpfs',
      radicle: 'netRadicle',
      yggdrasil: 'netYggdrasil',
      nostr: 'netNostr',
      reticulum: 'netReticulum',
      webrtc: 'netWebRTC',
      ble: 'netBLE',
      dns: 'netDNS',
      sneakernet: 'netSneakernet',
      federation: 'netFederation'
    };
    const key = keyMap[net.toLowerCase()];
    if (!key) {
      console.log(`Unknown network transport: ${net}. Valid: ${validNets.join(', ')}`);
      return;
    }
    if (val === 'on' || val === 'off') {
      c[key] = val === 'on';
      saveConfig(c);
      console.log(`${net} transport is now ${val.toUpperCase()}.`);
    } else {
      console.log(`${net} transport is currently ${c[key] ? 'ON' : 'off'}. Use: network ${net} [on|off]`);
    }
  }

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
    } else if (cmd === 'mask') {
      const c = loadConfig();
      const arg = args[0];
      if (!arg || arg === 'status') {
        console.log(`Address masking is ${c.mask ? 'ON' : 'off'}.`);
        if (!c.mask) console.log('  Turn on with: mask on');
      } else if (arg === 'on' || arg === 'off') {
        c.mask = arg === 'on';
        saveConfig(c);
        cfgCache = null;
        console.log(`Address masking is now ${c.mask ? 'ON' : 'off'}.`);
      } else {
        console.log('Usage: mask [on|off|status]');
      }
} else if (cmd === 'mask') {
  const c = loadConfig();
  const arg = args[0];
  if (!arg || arg === 'status') {
    console.log(`Address masking is ${c.mask ? 'ON' : 'off'}.`);
    if (!c.mask) console.log('  Turn on with: mask on');
  } else if (arg === 'on' || arg === 'off') {
    c.mask = arg === 'on';
    saveConfig(c);
    cfgCache = null;
    console.log(`Address masking is now ${c.mask ? 'ON' : 'off'}.`);
  } else {
    console.error('Usage: node cli/domail.mjs mask [on|off|status]');
    process.exit(1);
  }
    } else if (cmd === 'pgp') {
      await doPgp(args[0]);
    } else if (cmd === 'relay') {
      await doRelay(args.join(' '));
    } else if (cmd === 'network') {
      await doNetwork(args[0], args[1]);
    } else if (cmd === 'compose') {
      const to = await ask('To: ');
      const subject = await ask('Subject: ');
      const body = await ask('Body (end with blank line): ');
      const msg = {
        from: identity,
        to: to.split(/[,;]/).map((s) => ({ address: s.trim(), name: '' })).filter((a) => a.address),
        subject,
        text: body,
      };
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
} else if (cmd === 'mask') {
  const c = loadConfig();
  const arg = args[0];
  if (!arg || arg === 'status') {
    console.log(`Address masking is ${c.mask ? 'ON' : 'off'}.`);
    if (!c.mask) console.log('  Turn on with: mask on');
  } else if (arg === 'on' || arg === 'off') {
    c.mask = arg === 'on';
    saveConfig(c);
    cfgCache = null;
    console.log(`Address masking is now ${c.mask ? 'ON' : 'off'}.`);
  } else {
    console.error('Usage: node cli/domail.mjs mask [on|off|status]');
    process.exit(1);
  }
} else if (cmd === 'pgp') {
  const c = loadConfig();
  const arg = args[0];
  if (!arg || arg === 'status') {
    console.log(`PGP armored encryption is ${c.pgp ? 'ON' : 'off'}.`);
    if (c.pgp) {
      console.log('  NOTE: metadata (From/To/Subject/Date/size) is still exposed.');
      console.log('  NOTE: this armor will NOT decrypt in GnuPG.');
    }
  } else if (arg === 'on' || arg === 'off') {
    c.pgp = arg === 'on';
    saveConfig(c);
    console.log(`PGP armored encryption is now ${c.pgp ? 'ON' : 'off'}.`);
    if (c.pgp) {
      console.log('  WARNING: mail will refuse to send when a recipient key is unknown.');
      console.log('  WARNING: this armor will NOT decrypt in GnuPG.');
      console.log('  WARNING: envelope metadata is still exposed.');
    }
  } else {
    console.error('Usage: node cli/domail.mjs pgp [on|off|status]');
    process.exit(1);
  }
} else if (cmd === 'relay') {
  const c = loadConfig();
  const arg = args.join(' ');
  if (!arg || arg === 'status') {
    console.log(`WebSocket relay is ${c.relay ? 'ON' : 'off'}${c.relayUrl ? ` (${c.relayUrl})` : ''}.`);
    if (c.relay) {
      console.log('  WARNING: your IP and online times are visible to the relay operator.');
      console.log('  WARNING: on Tor this defeats the purpose entirely.');
      console.log('  WARNING: a malicious relay can drop, replay, reorder or censor mail.');
    }
  } else if (arg === 'on' || arg === 'off') {
    c.relay = arg === 'on';
    saveConfig(c);
    console.log(`WebSocket relay is now ${c.relay ? 'ON' : 'off'}.`);
  } else {
    c.relayUrl = arg;
    saveConfig(c);
    console.log(`Relay URL set to ${arg}`);
  }
} else {
  console.log('Usage: node cli/domail.mjs [inbox|outbox|read <id>|compose|wipe|mask|pgp|relay|interactive]');
}
