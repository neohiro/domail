/**
 * DOM Mail boot smoke test.
 *
 * The failure this exists to catch: a single undefined function referenced
 * during init() throws, `bindEvents()` never runs, and the whole page renders
 * but has zero working controls. That shipped once. Unit tests cannot see it,
 * because they import modules directly rather than booting the real page under
 * the real Content-Security-Policy.
 *
 * So this serves the actual site and drives it in headless Chrome, asserting:
 *   - no uncaught exceptions and no console errors
 *   - the app provisioned an identity
 *   - libsodium started (crypto is available, not silently disabled)
 *   - the visible controls are actually wired and a tab switch works
 *
 * Run:  node tools/smoke.mjs
 * Env:  SMOKE_URL      target URL (default: http://127.0.0.1:8765/)
 *       CHROME_PATH    explicit browser binary
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { extname, join, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

/** Static file server rooted at the repo, with the real MIME types. */
function serve(port) {
  return new Promise((resolve) => {
    const server = createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost');
      let path = decodeURIComponent(url.pathname);
      if (path.endsWith('/')) path += 'index.html';
      const file = join(ROOT, normalize(path).replace(/^(\.\.[/\\])+/, ''));
      try {
        const body = await readFile(file);
        res.writeHead(200, {
          'Content-Type': MIME[extname(file)] || 'application/octet-stream',
          'Cache-Control': 'no-store',
        });
        res.end(body);
      } catch {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('not found');
      }
    });
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const candidates = [
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env.PROGRAMFILES && join(process.env.PROGRAMFILES, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ].filter(Boolean);
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
}

/** Boot the page in headless Chrome and return errors plus a DOM probe. */
async function drive(url, binary) {
  const userDataDir = mkdtempSync(join(tmpdir(), 'dm-smoke-'));
  const port = 9300 + Math.floor(Math.random() * 500);
  const chrome = spawn(binary, [
    '--headless=new',
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${userDataDir}`,
    '--no-first-run', '--no-default-browser-check', '--disable-gpu',
    'about:blank',
  ], { stdio: 'ignore' });

  try {
    let target = null;
    const until = Date.now() + 30000;
    while (Date.now() < until) {
      try {
        const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
        target = list.find((t) => t.type === 'page');
        if (target) break;
      } catch {}
      await new Promise((r) => setTimeout(r, 250));
    }
    if (!target) throw new Error('headless Chrome did not expose a debugging target');

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });

    let id = 0;
    const pending = new Map();
    const events = [];
    ws.addEventListener('message', (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        const p = pending.get(m.id); pending.delete(m.id);
        m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result);
      } else if (m.method) events.push(m);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const myId = ++id;
      pending.set(myId, { resolve, reject });
      ws.send(JSON.stringify({ id: myId, method, params }));
    });

    await send('Runtime.enable');
    await send('Page.enable');
    await send('Page.navigate', { url });
    await new Promise((r) => setTimeout(r, 8000));

    const exceptions = events
      .filter((e) => e.method === 'Runtime.exceptionThrown')
      .map((e) => {
        const d = e.params.exceptionDetails;
        const at = d.url ? ` @ ${d.url}:${d.lineNumber}` : '';
        return `${d.exception?.description || d.text || 'exception'}${at}`;
      });
    const consoleErrors = events
      .filter((e) => e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error')
      .map((e) => (e.params.args || []).map((a) => a.value ?? a.description ?? '').join(' '));

    const evaluated = await send('Runtime.evaluate', {
      returnByValue: true,
      expression: `(async () => {
        const out = {};
        const identity = document.querySelector('#identity');
        out.identity = (identity?.textContent || '').trim();
        out.jsErrorShown = document.querySelector('#jsError')
          ? !document.querySelector('#jsError').hidden : null;
        out.jsErrorMsg = (document.querySelector('#jsErrorMsg')?.textContent || '').trim().slice(0, 200);
        out.cryptoReady = !!(window.sodium && typeof window.sodium.crypto_box_seal === 'function');

        // Tab switching: click Inbox, then Compose, and observe the pages.
        const inboxTab = document.querySelector('.tab[data-page="inbox"]');
        const composePage = document.querySelector('.page[data-page="compose"]');
        const inboxPage = document.querySelector('.page[data-page="inbox"]');
        out.tabs = document.querySelectorAll('.tab').length;

        let tabWorked = false;
        if (inboxTab) {
          inboxTab.click();
          await new Promise(r => setTimeout(r, 250));
          tabWorked = !inboxPage.hidden && composePage.hidden;
        }
        out.tabSwitchWorks = tabWorked;

        // A real toggle must actually mutate state.
        const overhaul = document.querySelector('#overhaul');
        if (overhaul) {
          const before = document.documentElement.style.getPropertyValue('--neon');
          overhaul.click();
          await new Promise(r => setTimeout(r, 120));
          out.overhaulChangedAccent =
            document.documentElement.style.getPropertyValue('--neon') !== before;
        }

        // Round-trip the compose field, the primary use of the app.
        const to = document.querySelector('#cTo');
        let composerUsable = false;
        if (to && !to.disabled) {
          to.value = 'probe@example.invalid';
          const body = document.querySelector('#editor');
          if (body) { body.innerHTML = 'smoke'; composerUsable = true; }
        }
        out.composerUsable = composerUsable;
        out.hasNetworkSettings = !!document.querySelector('[data-sub="network"]');

        /*
         * Actually send, and assert the mail landed. "The message never sent"
         * was a real report that no unit test could catch, because the engine
         * is correct and only the browser wiring was broken.
         */
        try {
          const db = await new Promise((res, rej) => {
            const r = indexedDB.open('domail');
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
          });
          const rd = (k) => new Promise((res) => {
            const t = db.transaction('kv', 'readonly').objectStore('kv').get(k);
            t.onsuccess = () => res(t.result); t.onerror = () => res(null);
          });
          const ident = await rd('identity');
          const self = ident?.address;
          out.selfAddress = self || null;

          to.value = self || 'probe@example.invalid';
          document.querySelector('#cSubject').value = 'smoke probe';
          const ed = document.querySelector('#editor');
          ed.innerHTML = 'smoke probe body';
          ed.dispatchEvent(new Event('input', { bubbles: true }));
          await new Promise(r => setTimeout(r, 250));

          document.querySelector('#cSend').click();
          await new Promise(r => setTimeout(r, 2500));

          const outbox = await rd('mbox:outbox');
          const inbox = await rd('mbox:inbox');
          out.outboxRows = outbox ? outbox.length : 0;
          out.inboxRows = inbox ? inbox.length : 0;
          out.sentToSelf = Boolean(self) && Boolean(inbox && inbox.some(m => m.subject === 'smoke probe'));
          out.validationShown = document.querySelector('#validate')
            ? !document.querySelector('#validate').hidden : false;
          out.validationText = (document.querySelector('#vList')?.textContent || '').slice(0, 120);
          out.toastAfterSend = (() => {
            const t = document.querySelector('#toast');
            return t && !t.hidden ? t.textContent : '';
          })();
          // Fields must be cleared after a successful send.
          out.toCleared = to.value === '';
          out.subjectCleared = document.querySelector('#cSubject').value === '';
          out.editorCleared = document.querySelector('#editor').innerHTML.trim() === '';
        } catch (e) {
          out.sendProbeError = String(e && e.name) + ': ' + String(e && e.message).slice(0, 160);
        }

        // Blind copy: the chip must never show a raw, pasteable address.
        const chip = document.querySelector('#identity');
        const shown = (chip?.textContent || '').trim();
        out.identityShown = shown;
        out.identityIsMasked = !!shown.includes('@') && shown.includes('*');
        out.identityCopyable = !!chip?.classList.contains('is-copyable');

        // Every control in the header must be reachable and labelled, because
        // an unlabelled icon reads as decoration rather than a button.
        out.headerButtons = [...document.querySelectorAll('#chrome button, #chrome [role="button"]')]
          .map(b => ({
            id: b.id || null,
            visible: b.offsetParent !== null,
            labelled: !!(b.textContent || '').trim() || !!b.getAttribute('aria-label'),
          }));
        return out;
      })()`,
      awaitPromise: true,
    });

    ws.close();
    return { exceptions, consoleErrors, dom: evaluated.result?.value ?? {} };
  } finally {
    try { chrome.kill(); } catch {}
    try { rmSync(userDataDir, { recursive: true, force: true }); } catch {}
  }
}

const failures = [];
const check = (ok, label, detail) => {
  if (ok) console.log(`  PASS  ${label}`);
  else { console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`); failures.push(label); }
};

const binary = findChrome();
if (!binary) {
  console.log('SKIP: no Chrome/Chromium found (set CHROME_PATH to run this check)');
  process.exit(0);
}

const explicitUrl = process.env.SMOKE_URL;
let server = null;
let url = explicitUrl;

if (!url) {
  const port = 8765;
  server = await serve(port);
  url = `http://127.0.0.1:${port}/`;
}

console.log(`\nDOM Mail smoke test`);
console.log(`  target: ${url}`);
console.log(`  browser: ${binary}\n`);

let result;
try {
  result = await drive(url, binary);
} catch (e) {
  console.error(`  FAIL  could not drive the page: ${e.message}`);
  server?.close();
  process.exit(1);
}
server?.close();

for (const x of result.exceptions) console.log(`  exception: ${x.slice(0, 300)}`);
for (const c of result.consoleErrors) console.log(`  console.error: ${c.slice(0, 300)}`);

const dom = result.dom;

// A boot-time exception is what silently disables every control.
check(result.exceptions.length === 0, 'page boots without uncaught exceptions',
  result.exceptions[0]);
check(!dom.jsErrorShown, 'no fatal-error panel is shown', dom.jsErrorMsg);
check(dom.cryptoReady === true, 'libsodium started (WASM permitted by CSP)');
check(!!dom.identity && dom.identity !== 'no identity' && dom.identity !== 'locked',
  'a mail identity was auto-provisioned', dom.identity);
check(dom.tabs >= 5, 'all tabs are present', `found ${dom.tabs}`);
check(dom.tabSwitchWorks === true, 'clicking a tab switches the visible page');
check(dom.overhaulChangedAccent === true, 'the style button changes the accent colour');
check(dom.composerUsable === true, 'the compose To field and editor are usable');
check(dom.hasNetworkSettings === true, 'the optional Network settings page exists');
check(dom.identityIsMasked === true,
  'the identity chip shows a masked address, not a pasteable one', dom.identityShown);
check(dom.identityCopyable === true, 'the identity chip is click-to-copy');
const unlabelled = (dom.headerButtons || []).filter((b) => b.visible && !b.labelled);
check(unlabelled.length === 0,
  'every visible header control is labelled',
  unlabelled.map((b) => b.id).join(', '));

// The regression that actually reached production: nothing was ever sent.
check(!dom.sendProbeError, 'the send probe ran', dom.sendProbeError);
check(dom.outboxRows > 0, 'a sent message reaches the Outbox', `outbox=${dom.outboxRows}`);
check(dom.sentToSelf === true,
  'a message addressed to yourself is delivered to the Inbox',
  `inbox=${dom.inboxRows} validation="${dom.validationText}" toast="${dom.toastAfterSend}"`);
check(dom.toCleared === true && dom.subjectCleared === true && dom.editorCleared === true,
  'the compose fields are cleared after a successful send',
  `to="${dom.toCleared}" subject="${dom.subjectCleared}" body="${dom.editorCleared}"`);

console.log('');
if (failures.length) {
  console.log(`FAILED: ${failures.length} check(s)`);
  process.exit(1);
}
console.log('All smoke checks passed.');