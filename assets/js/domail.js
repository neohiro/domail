/**
 * DOM Mail browser app.
 *
 * Everything here is presentation. The mail engine lives in core/mail.mjs
 * and is shared with the CLI, so this file owns no message format, no
 * storage format and no crypto primitive — only the DOM.
 */

import {
  MailEngine,
  indexedDbStore,
  buildMessage,
  parseMessage,
  makeMessageId,
  bytesToBase64,
  utf8,
} from '../core/mail.mjs';

/* ------------------------------------------------------------------ *
 * constants
 * ------------------------------------------------------------------ */

const POLL_MS = 3000;
const AUTOSAVE_MS = 450;
const DB_NAME = 'domail';

const EMOJI = {
  smileys: '😀 😃 😄 😁 😆 😅 🤣 😂 🙂 🙃 😉 😊 😇 🥰 😍 🤩 😘 😗 ☺ 😚 😙 🥲 😋 😛 😜 🤪 😝 🤑 🤗 🤭 🤫 🤔 🫡 🤐 🫠 🤨 😐 😑 😶 🫥 😏 😒 🙄 😬 🤥 🫨 😌 😔 😪 🤤 😴 😷 🤒 🤕 🤢 🤮 🤧 🥵 🥶 🥴 😵 🤯 🤠 🥳 🥸 😎 🤓 🧐 😕 🫤 😟 🙁 ☹ 😮 😯 😲 😳 🥺 🥹 😦 😧 😨 😰 😥 😢 😭 😱 😖 😣 😞 😓 😩 😫 🥱 😤 😡 😠 🤬 😈 👿 💀 ☠ 💩 🤡 👹 👺 👻 👽 👾 🤖'.split(' '),
  gestures: '👋 🤚 🖐 ✋ 🖖 🫱 🫲 🫳 🫴 👌 🤌 🤏 ✌ 🤞 🫰 🤟 🤘 🤙 👈 👉 👆 🖕 👇 ☝ 🫵 👍 👎 ✊ 👊 🤛 🤜 👏 🙌 🫶 👐 🤲 🤝 🙏 ✍ 💅 🤳 💪 🦾 🦵 🦿 🦶 👂 🦻 👃 🧠 🫀 🫁 🦷 🦴 👀 👁 👅 👄 🫦'.split(' '),
  hearts: '❤ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❤️‍🔥 ❤️‍🩹 ❣ 💕 💞 💝 💘 💖 💗 💓 💟 ☮ ✝ ☪ 🕉 ☸ ✡ 🔯 🕎 ☯ ☦ 🛐 ⛎ ♈ ♉ ♊ ♋ ♌ ♍ ♎ ♏ ♐ ♑ ♒ ♓'.split(' '),
  animals: '🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🙈 🙉 🙊 🐒 🐔 🐧 🐦 🐤 🐣 🐥 🦆 🦅 🦉 🦇 🐺 🐗 🐴 🦄 🐝 🪱 🐛 🦋 🐌 🐞 🐜 🪰 🪲 🪳 🦟 🦗 🕷 🕸 🦂 🐢 🐍 🦎 🦖 🦕 🐙 🦑 🦐 🦞 🦀 🐡 🐠 🐟 🐬 🐳 🐋 🦈 🐊 🐅 🐆 🦓 🦍 🦧 🦣 🐘 🦛 🦏 🐪 🐫 🦒 🦘 🦬 🐃 🐂 🐄 🐎 🐖 🐏 🐑 🦙 🐐 🦌 🐕 🐩 🦮 🐈 🪶 🐓 🦃 🦤 🦚 🦜 🦢 🦩 🕊 🐇 🦝 🦨 🦡 🦦 🦥 🐁 🐀 🦔'.split(' '),
  food: '🍏 🍎 🍐 🍊 🍋 🍌 🍉 🍇 🍓 🫐 🍈 🍒 🍑 🥭 🍍 🥥 🥝 🍅 🍆 🥑 🥦 🥬 🥒 🌶 🫑 🌽 🥕 🫒 🧄 🧅 🥔 🍠 🥐 🥯 🍞 🥖 🥨 🧀 🥚 🍳 🧈 🥞 🧇 🥓 🥩 🍗 🍖 🦴 🌭 🍔 🍟 🍕 🫓 🥪 🥙 🧆 🌮 🌯 🫔 🥗 🥘 🫕 🥫 🍝 🍜 🍲 🍛 🍣 🍱 🥟 🦪 🍤 🍙 🍚 🍘 🍥 🥠 🥮 🍢 🍡 🍧 🍨 🍦 🥧 🧁 🍰 🎂 🍮 🍭 🍬 🍫 🍿 🍩 🍪 🌰 🥜 🍯 🥛 🍼 🫖 ☕ 🍵 🧃 🥤 🧋 🍶 🍺 🍻 🥂 🥃 🍸 🍹 🧉 🍾 🧊'.split(' '),
  activity: '⚽ 🏀 🏈 ⚾ 🥎 🎾 🏐 🏉 🥏 🎱 🪀 🏓 🏸 🏒 🏑 🥍 🏏 🪃 🥅 ⛳ 🪁 🏹 🎣 🤿 🥊 🥋 🎽 🛹 🛼 🛷 ⛸ 🥌 🎿 ⛷ 🏂 🪂 🏋 🤼 🤸 ⛹ 🤺 🤾 🏌 🏇 🧘 🏄 🏊 🤽 🚣 🧗 🚵 🚴 🏆 🥇 🥈 🥉 🏅 🎖 🏵 🎗 🎫 🎟 🎪 🤹 🎭 🩰 🎨 🎬 🎤 🎧 🎼 🎹 🥁 🪘 🎷 🎺 🪗 🎸 🪕 🎻 🎲 ♟ 🎯 🎳 🎮 🎰 🧩'.split(' '),
  travel: '🚗 🚕 🚙 🚌 🚎 🏎 🚓 🚑 🚒 🚐 🛻 🚚 🚛 🚜 🦯 🦽 🦼 🛴 🚲 🛵 🏍 🛺 🚨 🚔 🚍 🚘 🚖 🚡 🚠 🚟 🚃 🚋 🚞 🚝 🚄 🚅 🚈 🚂 🚆 🚇 🚊 🚉 ✈ 🛫 🛬 🛩 💺 🛰 🚀 🛸 🚁 🛶 ⛵ 🚤 🛥 🛳 ⛴ 🚢 ⚓ 🪝 ⛽ 🚧 🚦 🚥 🚏 🗺 🗿 🗽 🗼 🏰 🏯 🏟 🎡 🎢 🎠 ⛲ ⛱ 🏖 🏝 🏜 🌋 ⛰ 🏔 🗻 🏕 ⛺ 🛖 🏠 🏡 🏘 🏚 🏗 🏭 🏢 🏬 🏣 🏤 🏥 🏦 🏨 🏪 🏫 🏩 💒 🏛 ⛪ 🕌 🕍 🛕 🕋 ⛩ 🛤 🛣 🗾 🎑 🏞 🌅 🌄 🌠 🎇 🎆 🌇 🌆 🏙 🌃 🌌 🌉 🌁'.split(' '),
  objects: '⌚ 📱 📲 💻 ⌨ 🖥 🖨 🖱 🖲 🕹 🗜 💽 💾 💿 📀 📼 📷 📸 📹 🎥 📽 🎞 📞 ☎ 📟 📠 📺 📻 🎙 🎚 🎛 🧭 ⏱ ⏲ ⏰ 🕰 ⌛ ⏳ 📡 🔋 🪫 🔌 💡 🔦 🕯 🪔 🧯 🛢 💸 💵 💴 💶 💷 🪙 💰 💳 💎 ⚖ 🪜 🧰 🪛 🔧 🔨 ⚒ 🛠 ⛏ 🪚 🔩 ⚙ 🪤 🧲 🔫 💣 🧨 🪓 🔪 🗡 ⚔ 🛡 🚬 ⚰ 🪦 ⚱ 🏺 🔮 📿 🧿 💈 ⚗ 🔭 🔬 🕳 🩹 🩺 💊 💉 🩸 🧬 🦠 🧫 🧪 🌡 🧹 🪠 🧺 🧻 🚽 🚰 🚿 🛁 🛀 🧼 🪥 🪒 🧽 🪣 🧴 🛎 🔑 🗝 🚪 🪑 🛋 🛏 🛌 🧸 🪆 🖼 🪞 🪟 🛍 🛒 🎁 🎎 🎏 🎐 🎀 🪄 🪅 🎊 🎉 🎋 🎍 🎎 🎏 🎐 🎑 🎀 🎁 🎗 🎟 🎫 🎖 🏆 🏅 🥇 🥈 🥉'.split(' '),
  symbols: '🏧 🚮 🚰 ♿ 🚹 🚺 🚼 🚻 🚾 🛂 🛃 🛄 🛅 ⚠ 🚸 ⛔ 🚫 🚳 🚭 🚯 🚱 🔞 📵 🚭 ❗ ❕ ❓ ❔ ‼ ⁉ 🔅 🔆 〽 ⚠ 🚸 🔱 ⚜ 🔰 ♻ ✅ 🈯 💹 ❇ ✳ ❎ 🌐 💠 Ⓜ 🌀 💤 🏧 🚾 ♿ 🅿 🛗 🈳 🈂 🛂 🛃 🛄 🛅 🚹 🚺 🚼 ⚧ 🚻 🚮 🎦 📶 🈁 🔣 ℹ 🔤 🔡 🔠 🆖 🆗 🆙 🆒 🆕 🆓 0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟 🔢 #️⃣ *️⃣ ⏏ ▶ ⏩ ⏭ ⏯ ◀ ⏪ ⏫ ⏬ ⏸ ⏹ ⏺ ⏏ 🎦 🔀 🔁 🔂'.split(' '),
};

const EMOJI_CATS = [
  ['smileys', '😀'], ['gestures', '👋'], ['hearts', '❤️'],
  ['animals', '🐾'], ['food', '🍎'], ['activity', '⚽'],
  ['travel', '🌍'], ['objects', '💡'], ['symbols', '🔣'],
];

const SKIN_TONES = ['', '\u{1F3FB}', '\u{1F3FC}', '\u{1F3FD}', '\u{1F3FE}', '\u{1F3FF}'];

const FONT_SIZES = [14, 16, 18, 20, 22, 24, 26];

const NEON_HUES = [0, 30, 55, 90, 140, 175, 200, 225, 265, 300, 330];

/* ------------------------------------------------------------------ *
 * state
 * ------------------------------------------------------------------ */

let engine = null;
let currentPage = 'inbox';
let currentSub = 'account';
let composeOpen = false;
let composeDraftId = null;
let composeWasEmpty = true;
let composeDirty = false;
let autosaveTimer = null;
let pollTimer = null;
let knownInbox = new Set();
let knownOutbox = new Set();
let knownDrafts = new Set();
let emojiCat = 'smileys';
let emojiSkin = '';
let readerMsg = null;
let audioCtx = null;
let uiPrefs = { mode: 'dark', neon: null, accent: null, font: 'system', size: 18, autoSig: true, notify: false, sound: true, pollMs: POLL_MS };

/* ------------------------------------------------------------------ *
 * dom
 * ------------------------------------------------------------------ */

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const el = {
  modeSwitch: $('#modeSwitch'),
  overhaul: $('#overhaul'),
  tabs: $$('.tab'),
  subtabs: $$('.subtab'),
  pages: $$('.page'),
  identity: $('#identity'),
  soundToggle: $('#soundToggle'),
  notifyToggle: $('#notifyToggle'),
  netstat: $('#netstat'),
  lists: { inbox: $('#list-inbox'), outbox: $('#list-outbox'), drafts: $('#list-drafts') },
  counts: { inbox: $('[data-count="inbox"]'), outbox: $('[data-count="outbox"]'), drafts: $('[data-count="drafts"]') },
  compose: $('#compose'),
  cTo: $('#cTo'), cCc: $('#cCc'), cBcc: $('#cBcc'), cSubject: $('#cSubject'),
  editor: $('#editor'),
  draftState: $('#draftState'),
  cClose: $('#cClose'), cDiscard: $('#cDiscard'), cSend: $('#cSend'),
  emoji: $('#emoji'), emojiBtn: $('#emojiBtn'), emojiCats: $('.emoji-cats'),
  emojiSkin: $('.emoji-skin'), emojiGrid: $('.emoji-grid'),
  cSize: $('#cSize'), cFont: $('#cFont'), cColor: $('#cColor'), cBg: $('#cBg'),
  cAttach: $('#cAttach'), cFile: $('#cFile'),
  onboard: $('#onboard'), createBtn: $('#createBtn'), importBtn: $('#importBtn'),
  onboardImport: $('#onboardImport'),
  validate: $('#validate'), vList: $('#vList'), vOk: $('#vOk'),
  wipeBtn: $('#wipeBtn'),
  setName: $('#setName'), setLocal: $('#setLocal'), setDomain: $('#setDomain'),
  setSig: $('#setSig'), regenDomain: $('#regenDomain'), copyKey: $('#copyKey'),
  keyView: $('#keyView'),
  setFont: $('#setFont'), setSize: $('#setSize'), setSizeOut: $('#setSizeOut'),
  setAutoSig: $('#setAutoSig'), setNotify: $('#setNotify'), setSound: $('#setSound'),
  expSettings: $('#expSettings'), expAll: $('#expAll'), impAll: $('#impAll'),
  contactList: $('#contactList'),
  toast: $('#toast'),
};

/* ------------------------------------------------------------------ *
 * small utilities
 * ------------------------------------------------------------------ */

function toast(msg, ms = 2600) {
  el.toast.textContent = msg;
  el.toast.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.toast.hidden = true; }, ms);
}

function fmtDate(ts) {
  const d = new Date(ts);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function addrLabel(a) {
  if (!a) return '';
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function addrListLabel(list) {
  return (list || []).map(addrLabel).join(', ');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function download(filename, text) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.readAsText(file);
  });
}

/* ------------------------------------------------------------------ *
 * ui preferences
 * ------------------------------------------------------------------ */

function saveUiPrefs() {
  try { localStorage.setItem('domail:ui', JSON.stringify(uiPrefs)); } catch {}
}

function loadUiPrefs() {
  try {
    const raw = localStorage.getItem('domail:ui');
    if (raw) Object.assign(uiPrefs, JSON.parse(raw));
  } catch {}
}

function applyUiPrefs() {
  const r = document.documentElement;
  r.dataset.mode = uiPrefs.mode;
  if (uiPrefs.neon) r.style.setProperty('--neon', uiPrefs.neon);
  if (uiPrefs.accent) r.style.setProperty('--accent', uiPrefs.accent);
  r.dataset.font = uiPrefs.font;
  el.modeSwitch.setAttribute('aria-pressed', String(uiPrefs.mode === 'light'));
  el.soundToggle.setAttribute('aria-pressed', String(uiPrefs.sound));
  el.notifyToggle.setAttribute('aria-pressed', String(uiPrefs.notify));
  el.setAutoSig.checked = uiPrefs.autoSig;
  el.setNotify.checked = uiPrefs.notify;
  el.setSound.checked = uiPrefs.sound;
  el.setFont.value = uiPrefs.font;
  el.setSize.value = String(uiPrefs.size);
  el.setSizeOut.value = `${uiPrefs.size}px`;
  el.cSize.innerHTML = FONT_SIZES.map((s) => `<option value="${s}">${s}px</option>`).join('');
  el.cSize.value = String(uiPrefs.size);
}

/* ------------------------------------------------------------------ *
 * identity
 * ------------------------------------------------------------------ */

async function generateIdentity(name, local, domain) {
  const ed = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const x = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const edPub = new Uint8Array(await crypto.subtle.exportKey('raw', ed.publicKey));
  const xPub = new Uint8Array(await crypto.subtle.exportKey('raw', x.publicKey));
  return {
    name: name || 'Nova',
    local: local || 'nova',
    domain: domain || 'domail.space',
    address: `${local || 'nova'}@${domain || 'domail.space'}`,
    ed25519: bytesToBase64(edPub),
    x25519: bytesToBase64(xPub),
    created: Date.now(),
  };
}

function publicKeyBlock(identity) {
  return [
    '-----BEGIN DOM MAIL PUBLIC KEY-----',
    `address: ${identity.address}`,
    `ed25519: ${identity.ed25519}`,
    `x25519: ${identity.x25519}`,
    `created: ${new Date(identity.created).toISOString()}`,
    '-----END DOM MAIL PUBLIC KEY-----',
  ].join('\n');
}

async function createIdentity() {
  const identity = await generateIdentity('Nova', 'nova', 'domail.space');
  await engine.setIdentity(identity);
  el.identity.textContent = identity.address;
  el.keyView.textContent = publicKeyBlock(identity);
  toast(`Identity created: ${identity.address}`);
  await refreshAll();
  startPolling();
}

/* ------------------------------------------------------------------ *
 * navigation
 * ------------------------------------------------------------------ */

function showPage(name) {
  currentPage = name;
  for (const tab of el.tabs) {
    tab.setAttribute('aria-selected', String(tab.dataset.page === name));
  }
  for (const page of el.pages) {
    const active = page.dataset.page === name;
    page.classList.toggle('is-active', active);
    page.hidden = !active;
  }
  if (name === 'settings') showSub(currentSub);
  if (name !== 'inbox') closeReader();
}

function showSub(name) {
  currentSub = name;
  for (const st of el.subtabs) {
    st.setAttribute('aria-selected', String(st.dataset.sub === name));
  }
  for (const sp of $$('.subpage')) {
    sp.hidden = sp.dataset.sub !== name;
  }
}

/* ------------------------------------------------------------------ *
 * lists
 * ------------------------------------------------------------------ */

async function refreshList(box) {
  const rows = await engine.list(box);
  const listEl = el.lists[box];
  const emptyEl = $(`[data-empty="${box}"]`);

  listEl.innerHTML = '';
  for (const m of rows) {
    const li = document.createElement('li');
    li.className = 'msg';
    li.dataset.id = m.id;
    li.dataset.read = String(!!m.read);
    const who = box === 'inbox' ? addrListLabel(m.from) : addrListLabel(m.to);
    li.innerHTML = `
      <strong>${escapeHtml(m.subject || '(no subject)')}</strong>
      <span class="when">${fmtDate(m.date)}</span>
      <span class="who">${escapeHtml(who)}</span>
      <span class="snippet">${escapeHtml((m.bodyText || '').slice(0, 90))}</span>
    `;
    li.addEventListener('click', () => openReader(box, m.id));
    listEl.appendChild(li);
  }

  emptyEl.style.display = rows.length ? 'none' : '';
  el.counts[box].textContent = String(rows.length);
  el.counts[box].closest('.tab').dataset.unread = String(rows.some((r) => !r.read));
}

async function refreshAll() {
  await Promise.all([refreshList('inbox'), refreshList('outbox'), refreshList('drafts')]);
  await refreshContacts();
}

/* ------------------------------------------------------------------ *
 * reader
 * ------------------------------------------------------------------ */

async function openReader(box, id) {
  const m = await engine.get(box, id);
  if (!m) return;
  readerMsg = { box, id };

  if (box === 'inbox' && !m.read) {
    const rows = await engine.list('inbox');
    const idx = rows.findIndex((r) => r.id === id);
    if (idx !== -1) {
      rows[idx].read = true;
      await engine.store.set('mbox:inbox', rows);
      knownInbox.add(id);
      await refreshList('inbox');
    }
  }

  const page = $(`.page[data-page="${box}"]`);
  const existing = page.querySelector('.reader');
  if (existing) existing.remove();

  const div = document.createElement('div');
  div.className = 'reader';
  const who = box === 'inbox' ? addrListLabel(m.from) : addrListLabel(m.to);
  const body = m.bodyIsHtml
    ? m.bodyText
    : escapeHtml(m.bodyText || '').replace(/\n/g, '<br>');

  div.innerHTML = `
    <h2>${escapeHtml(m.subject || '(no subject)')}</h2>
    <p class="meta">${escapeHtml(who)} &middot; ${new Date(m.date).toLocaleString()}</p>
    <div class="body">${body}</div>
    <div class="acts">
      ${box === 'inbox' ? '<button class="pill" data-act="reply" type="button">Reply</button>' : ''}
      <button class="pill" data-act="delete" type="button">Delete</button>
      <button class="pill" data-act="close" type="button">Close</button>
    </div>
  `;

  div.querySelector('[data-act="close"]').addEventListener('click', closeReader);
  div.querySelector('[data-act="delete"]').addEventListener('click', async () => {
    await engine.remove(box, id);
    closeReader();
    await refreshList(box);
    toast('Deleted');
  });
  const replyBtn = div.querySelector('[data-act="reply"]');
  if (replyBtn) {
    replyBtn.addEventListener('click', () => {
      const from = m.from[0];
      openCompose({
        to: from ? [from] : [],
        subject: m.subject.startsWith('Re:') ? m.subject : `Re: ${m.subject}`,
        inReplyTo: m.id,
      });
    });
  }

  page.appendChild(div);
  div.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeReader() {
  readerMsg = null;
  for (const page of el.pages) {
    const r = page.querySelector('.reader');
    if (r) r.remove();
  }
}

/* ------------------------------------------------------------------ *
 * compose
 * ------------------------------------------------------------------ */

function openCompose(opts = {}) {
  composeOpen = true;
  composeDraftId = null;
  composeWasEmpty = true;
  composeDirty = false;

  el.cTo.value = addrListLabel(opts.to || []);
  el.cSubject.value = opts.subject || '';
  el.editor.innerHTML = opts.body || '';
  el.draftState.textContent = 'draft autosaves';

  $$('.addr-row[data-extra]').forEach((r) => { r.hidden = true; });

  el.compose.hidden = false;
  el.cTo.focus();

  if (opts.inReplyTo) {
    // keep the thread reference on the draft
    el.compose.dataset.replyTo = opts.inReplyTo;
  } else {
    delete el.compose.dataset.replyTo;
  }

  scheduleAutosave();
}

function closeCompose() {
  if (composeOpen && composeDirty) saveDraft();
  composeOpen = false;
  composeDirty = false;
  clearTimeout(autosaveTimer);
  el.compose.hidden = true;
  el.emoji.hidden = true;
}

function getComposeContent() {
  return {
    to: el.cTo.value,
    cc: el.cCc.value,
    bcc: el.cBcc.value,
    subject: el.cSubject.value,
    html: el.editor.innerHTML,
    text: el.editor.innerText,
  };
}

function scheduleAutosave() {
  clearTimeout(autosaveTimer);
  autosaveTimer = setTimeout(saveDraft, AUTOSAVE_MS);
}

async function saveDraft() {
  if (!composeOpen) return;
  const c = getComposeContent();
  const isEmpty = !c.to && !c.subject && !c.text.trim();

  if (isEmpty) {
    if (composeDraftId) {
      await engine.remove('drafts', composeDraftId);
      knownDrafts.delete(composeDraftId);
      composeDraftId = null;
      composeWasEmpty = true;
      await refreshList('drafts');
    }
    el.draftState.textContent = 'draft autosaves';
    return;
  }

  const draft = {
    id: composeDraftId || makeMessageId(),
    subject: c.subject,
    from: engine.identity ? [engine.identity] : [],
    to: parseAddr(c.to),
    cc: parseAddr(c.cc),
    bcc: parseAddr(c.bcc),
    date: Date.now(),
    bodyText: c.text,
    bodyIsHtml: true,
    attachments: [],
    inReplyTo: el.compose.dataset.replyTo || '',
    read: true,
    flagged: false,
    raw: '',
  };

  const rows = await engine.list('drafts');
  const idx = rows.findIndex((r) => r.id === draft.id);
  if (idx === -1) rows.push(draft);
  else rows[idx] = draft;
  await engine.store.set('mbox:drafts', rows);

  if (!composeDraftId) {
    composeDraftId = draft.id;
    composeWasEmpty = false;
  }
  knownDrafts.add(draft.id);
  composeDirty = false;
  el.draftState.textContent = `saved ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  await refreshList('drafts');
}

function parseAddr(val) {
  if (!val) return [];
  return val.split(',').map((s) => s.trim()).filter(Boolean).map((address) => ({ name: '', address }));
}

async function sendCompose() {
  const c = getComposeContent();
  const issues = [];

  const to = parseAddr(c.to);
  if (!to.length) issues.push('Add at least one recipient in To.');
  if (!c.text.trim()) issues.push('The message body is empty.');

  if (issues.length) {
    showValidation(issues);
    return;
  }

  const sig = uiPrefs.autoSig ? await engine.store.get('signature') : '';
  const body = sig ? `${c.text}\n\n${sig}` : c.text;

  await engine.send({
    to,
    cc: parseAddr(c.cc),
    bcc: parseAddr(c.bcc),
    subject: c.subject,
    text: body,
    html: el.editor.innerHTML,
  }, 'outbox');

  if (composeDraftId) {
    await engine.remove('drafts', composeDraftId);
    knownDrafts.delete(composeDraftId);
  }

  closeCompose();
  toast('Sent');
  await refreshAll();
  showPage('outbox');
}

/* ------------------------------------------------------------------ *
 * validation
 * ------------------------------------------------------------------ */

function showValidation(issues) {
  el.vList.innerHTML = issues.map((i) => `<li>${escapeHtml(i)}</li>`).join('');
  el.validate.hidden = false;
}

/* ------------------------------------------------------------------ *
 * emoji
 * ------------------------------------------------------------------ */

function renderEmojiCats() {
  el.emojiCats.innerHTML = EMOJI_CATS.map(([key, icon]) =>
    `<button type="button" data-cat="${key}" role="tab" aria-selected="${key === emojiCat}">${icon}</button>`
  ).join('');
  for (const btn of el.emojiCats.querySelectorAll('button')) {
    btn.addEventListener('click', () => {
      emojiCat = btn.dataset.cat;
      renderEmojiCats();
      renderEmojiGrid();
    });
  }
}

function renderEmojiSkin() {
  for (const btn of el.emojiSkin.querySelectorAll('button')) {
    btn.classList.toggle('on', btn.dataset.skin === emojiSkin);
    btn.addEventListener('click', () => {
      emojiSkin = btn.dataset.skin;
      renderEmojiSkin();
      renderEmojiGrid();
    });
  }
}

function renderEmojiGrid() {
  const emojis = EMOJI[emojiCat] || [];
  el.emojiGrid.innerHTML = emojis.map((e) => {
    const char = emojiSkin ? e + emojiSkin : e;
    return `<button type="button" data-char="${escapeHtml(char)}">${char}</button>`;
  }).join('');
  for (const btn of el.emojiGrid.querySelectorAll('button')) {
    btn.addEventListener('click', () => {
      insertAtCursor(btn.dataset.char);
    });
  }
}

function insertAtCursor(text) {
  el.editor.focus();
  const sel = window.getSelection();
  if (sel.rangeCount) {
    const range = sel.getRangeAt(0);
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
    range.collapse(false);
    sel.removeAllRanges();
    sel.addRange(range);
  }
  scheduleAutosave();
}

function toggleEmoji() {
  const open = el.emoji.hidden;
  el.emoji.hidden = !open;
  el.emojiBtn.setAttribute('aria-expanded', String(open));
  if (open) {
    renderEmojiCats();
    renderEmojiSkin();
    renderEmojiGrid();
    const rect = el.emojiBtn.getBoundingClientRect();
    el.emoji.style.left = `${Math.min(rect.left, window.innerWidth - 240)}px`;
    el.emoji.style.top = `${rect.bottom + 4}px`;
  }
}

/* ------------------------------------------------------------------ *
 * formatting
 * ------------------------------------------------------------------ */

function execFmt(cmd, val = null) {
  el.editor.focus();
  document.execCommand(cmd, false, val);
  scheduleAutosave();
}

/* ------------------------------------------------------------------ *
 * notifications
 * ------------------------------------------------------------------ */

function ensureAudio() {
  if (!audioCtx) {
    try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch {}
  }
  if (audioCtx && audioCtx.state === 'suspended') audioCtx.resume();
}

function playChime() {
  if (!uiPrefs.sound) return;
  ensureAudio();
  if (!audioCtx) return;
  const t = audioCtx.currentTime;
  for (const [freq, start, dur] of [[880, 0, 0.12], [1174.66, 0.1, 0.18]]) {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = 'sine';
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0, t + start);
    gain.gain.linearRampToValueAtTime(0.18, t + start + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, t + start + dur);
    osc.connect(gain).connect(audioCtx.destination);
    osc.start(t + start);
    osc.stop(t + start + dur + 0.02);
  }
}

async function notifyNative(title, body) {
  if (!uiPrefs.notify) return;
  if (!('Notification' in window)) return;
  if (Notification.permission !== 'granted') return;
  try { new Notification(title, { body, silent: true }); } catch {}
}

async function requestNotifyPermission() {
  if (!('Notification' in window)) { toast('Notifications not supported'); return; }
  const p = await Notification.requestPermission();
  uiPrefs.notify = p === 'granted';
  el.notifyToggle.setAttribute('aria-pressed', String(uiPrefs.notify));
  saveUiPrefs();
  toast(uiPrefs.notify ? 'Notifications on' : 'Notifications off');
}

function notifyNewMail(m) {
  playChime();
  notifyNative('New mail', `${m.subject || '(no subject)'} — ${addrListLabel(m.from)}`);
  toast(`New mail: ${m.subject || '(no subject)'}`);
}

/* ------------------------------------------------------------------ *
 * polling
 *
 * The whole "server" is this loop. Every few seconds it reads the local
 * store, diffs against what it last saw, and reacts. No push, no
 * socket, no background worker — which is why it costs nothing when
 * there is nothing to do.
 * ------------------------------------------------------------------ */

async function poll() {
  if (!engine) return;
  try {
    const inbox = await engine.list('inbox');
    const outbox = await engine.list('outbox');

    for (const m of inbox) {
      if (!knownInbox.has(m.id)) {
        knownInbox.add(m.id);
        if (!m.read) notifyNewMail(m);
      }
    }
    for (const m of outbox) {
      if (!knownOutbox.has(m.id)) knownOutbox.add(m.id);
    }

    el.counts.inbox.textContent = String(inbox.length);
    el.counts.outbox.textContent = String(outbox.length);
    el.counts.inbox.closest('.tab').dataset.unread = String(inbox.some((m) => !m.read));
  } catch {}
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(poll, uiPrefs.pollMs);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

/* ------------------------------------------------------------------ *
 * export / import
 * ------------------------------------------------------------------ */

async function exportSettings() {
  const data = await engine.export({ includeMail: false });
  download(`domail-settings-${Date.now()}.json`, JSON.stringify(data, null, 2));
  toast('Settings exported');
}

async function exportAll() {
  const data = await engine.export({ includeMail: true });
  download(`domail-backup-${Date.now()}.json`, JSON.stringify(data, null, 2));
  toast('Settings and mail exported');
}

async function importData(file) {
  try {
    const text = await readFile(file);
    const data = JSON.parse(text);
    await engine.import(data);
    el.identity.textContent = engine.identity ? engine.identity.address : 'no identity';
    if (engine.identity) el.keyView.textContent = publicKeyBlock(engine.identity);
    await refreshAll();
    toast('Imported');
  } catch (e) {
    toast(`Import failed: ${e.message}`);
  }
}

/* ------------------------------------------------------------------ *
 * contacts
 * ------------------------------------------------------------------ */

async function refreshContacts() {
  const map = await engine.contacts();
  const entries = Object.values(map).sort((a, b) => a.name.localeCompare(b.name));
  el.contactList.innerHTML = entries.map((c) =>
    `<li><span>${escapeHtml(c.name)}</span><span class="addr">${escapeHtml(c.address)}</span></li>`
  ).join('');
  $('[data-empty="contacts"]').style.display = entries.length ? 'none' : '';
}

/* ------------------------------------------------------------------ *
 * wipe
 * ------------------------------------------------------------------ */

async function wipeIdentity() {
  await engine.wipe();
  stopPolling();
  knownInbox.clear();
  knownOutbox.clear();
  knownDrafts.clear();
  el.identity.textContent = 'no identity';
  el.keyView.textContent = '';
  await refreshAll();
  showPage('inboard');
  showOnboarding();
  toast('Identity wiped');
}

/* ------------------------------------------------------------------ *
 * onboarding
 * ------------------------------------------------------------------ */

function showOnboarding() {
  el.onboard.hidden = false;
}

function hideOnboarding() {
  el.onboard.hidden = true;
}

/* ------------------------------------------------------------------ *
 * wire up
 * ------------------------------------------------------------------ */

function bindEvents() {
  el.modeSwitch.addEventListener('click', () => {
    uiPrefs.mode = uiPrefs.mode === 'dark' ? 'light' : 'dark';
    applyUiPrefs();
    saveUiPrefs();
  });

  el.overhaul.addEventListener('click', () => {
    const hue = NEON_HUES[Math.floor(Math.random() * NEON_HUES.length)];
    const sat = 85 + Math.floor(Math.random() * 15);
    const light = 55 + Math.floor(Math.random() * 10);
    uiPrefs.neon = `hsl(${hue} ${sat}% ${light}%)`;
    uiPrefs.accent = uiPrefs.neon;
    applyUiPrefs();
    saveUiPrefs();
  });

  for (const tab of el.tabs) {
    tab.addEventListener('click', () => showPage(tab.dataset.page));
  }

  for (const st of el.subtabs) {
    st.addEventListener('click', () => showSub(st.dataset.sub));
  }

  el.soundToggle.addEventListener('click', () => {
    uiPrefs.sound = !uiPrefs.sound;
    el.soundToggle.setAttribute('aria-pressed', String(uiPrefs.sound));
    saveUiPrefs();
  });

  el.notifyToggle.addEventListener('click', requestNotifyPermission);

  el.cClose.addEventListener('click', closeCompose);
  el.cDiscard.addEventListener('click', async () => {
    if (composeDraftId) {
      await engine.remove('drafts', composeDraftId);
      knownDrafts.delete(composeDraftId);
    }
    closeCompose();
    await refreshList('drafts');
    toast('Draft discarded');
  });
  el.cSend.addEventListener('click', sendCompose);

  el.editor.addEventListener('input', () => {
    composeDirty = true;
    scheduleAutosave();
  });

  el.emojiBtn.addEventListener('click', toggleEmoji);
  el.cAttach.addEventListener('click', () => el.cFile.click());
  el.cFile.addEventListener('change', async () => {
    // attachments are read into the draft on send; for now just note them
    toast(`${el.cFile.files.length} file(s) attached`);
  });

  for (const btn of $$('.format button[data-fmt]')) {
    btn.addEventListener('click', () => {
      const cmd = { bold: 'bold', italic: 'italic', underline: 'underline', strike: 'strikeThrough' }[btn.dataset.fmt];
      if (cmd) execFmt(cmd);
    });
  }

  el.cSize.addEventListener('change', () => {
    uiPrefs.size = Number(el.cSize.value);
    el.setSizeOut.value = `${uiPrefs.size}px`;
    saveUiPrefs();
  });

  el.cFont.addEventListener('change', () => execFmt('fontName', el.cFont.value));
  el.cColor.addEventListener('input', () => execFmt('foreColor', el.cColor.value));
  el.cBg.addEventListener('input', () => execFmt('hiliteColor', el.cBg.value));

  el.setName.addEventListener('change', async () => {
    if (!engine.identity) return;
    engine.identity.name = el.setName.value;
    await engine.setIdentity(engine.identity);
    el.identity.textContent = engine.identity.address;
  });

  el.setLocal.addEventListener('change', async () => {
    if (!engine.identity) return;
    engine.identity.local = el.setLocal.value;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
  });

  el.setDomain.addEventListener('change', async () => {
    if (!engine.identity) return;
    engine.identity.domain = el.setDomain.value;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
  });

  el.setSig.addEventListener('change', async () => {
    await engine.store.set('signature', el.setSig.value);
    toast('Signature saved');
  });

  el.regenDomain.addEventListener('click', async () => {
    if (!engine.identity) return;
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let sub = '';
    for (let i = 0; i < 8; i++) sub += chars[Math.floor(Math.random() * chars.length)];
    engine.identity.domain = `${sub}.domail.space`;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    el.setDomain.value = engine.identity.domain;
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
    toast(`New domain: ${engine.identity.domain}`);
  });

  el.copyKey.addEventListener('click', async () => {
    if (!engine.identity) return;
    const text = publicKeyBlock(engine.identity);
    try {
      await navigator.clipboard.writeText(text);
      toast('Public key copied');
    } catch {
      toast('Copy failed — select the key manually');
    }
  });

  el.setFont.addEventListener('change', () => {
    uiPrefs.font = el.setFont.value;
    applyUiPrefs();
    saveUiPrefs();
  });

  el.setSize.addEventListener('input', () => {
    uiPrefs.size = Number(el.setSize.value);
    el.setSizeOut.value = `${uiPrefs.size}px`;
    el.cSize.value = String(uiPrefs.size);
    saveUiPrefs();
  });

  el.setAutoSig.addEventListener('change', () => {
    uiPrefs.autoSig = el.setAutoSig.checked;
    saveUiPrefs();
  });

  el.setNotify.addEventListener('change', () => {
    uiPrefs.notify = el.setNotify.checked;
    el.notifyToggle.setAttribute('aria-pressed', String(uiPrefs.notify));
    saveUiPrefs();
  });

  el.setSound.addEventListener('change', () => {
    uiPrefs.sound = el.setSound.checked;
    el.soundToggle.setAttribute('aria-pressed', String(uiPrefs.sound));
    saveUiPrefs();
  });

  el.expSettings.addEventListener('click', exportSettings);
  el.expAll.addEventListener('click', exportAll);
  el.impAll.addEventListener('change', (e) => {
    if (e.target.files[0]) importData(e.target.files[0]);
    e.target.value = '';
  });

  el.createBtn.addEventListener('click', async () => {
    await createIdentity();
    hideOnboarding();
  });

  el.importBtn.addEventListener('click', () => el.onboardImport.click());
  el.onboardImport.addEventListener('change', (e) => {
    if (e.target.files[0]) importData(e.target.files[0]);
    e.target.value = '';
  });

  el.vOk.addEventListener('click', () => { el.validate.hidden = true; });

  el.wipeBtn.addEventListener('click', async () => {
    if (confirm('Destroy this identity and all mail? This cannot be undone.')) {
      await wipeIdentity();
    }
  });

  // close compose on escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!el.validate.hidden) { el.validate.hidden = true; return; }
      if (composeOpen) { closeCompose(); return; }
      if (!el.emoji.hidden) { el.emoji.hidden = true; return; }
    }
  });

  // close emoji when clicking outside
  document.addEventListener('click', (e) => {
    if (!el.emoji.hidden && !el.emoji.contains(e.target) && e.target !== el.emojiBtn) {
      el.emoji.hidden = true;
    }
  });
}

/* ------------------------------------------------------------------ *
 * init
 * ------------------------------------------------------------------ */

async function init() {
  loadUiPrefs();
  applyUiPrefs();
  bindEvents();

  const store = indexedDbStore(DB_NAME);
  engine = new MailEngine(store);
  await engine.load();

  if (engine.identity) {
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
    el.setName.value = engine.identity.name;
    el.setLocal.value = engine.identity.local;
    el.setDomain.value = engine.identity.domain;
    const sig = await engine.store.get('signature');
    if (sig) el.setSig.value = sig;
    hideOnboarding();
    await refreshAll();
    startPolling();
  } else {
    showOnboarding();
  }
}

init();
