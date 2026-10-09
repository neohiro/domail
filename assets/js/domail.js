/**
 * DOM Mail browser app - Enhanced with military-grade security.
 *
 * Everything here is presentation. The mail engine lives in core/mail.mjs
 * and is shared with the CLI, so this file owns no message format, no
 * storage format and no crypto primitive — only the DOM.
 * 
 * Security features:
 * - End-to-end encrypted storage (Argon2id + XChaCha20-Poly1305)
 * - Anti-keylogger engine (virtual keyboard, input masking, timing noise)
 * - Screen theft protection (PII obfuscation, canvas fingerprinting resistance)
 * - Zero fingerprinting (canvas, WebGL, audio, fonts, battery, WebRTC, etc.)
 * - Tor/I2P ready (offline-first Service Worker)
 * - Professional/hacker culture domain generator
 * - Legal warning banner with dismiss persistence
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

import {
  EncryptedStore,
  createMailEngineWithEncryption,
  unlockMailEngine,
} from '../core/encrypted-store.mjs';

import {
  createAntiKeylogger,
} from '../core/antikeylogger.mjs';

import {
  createScreenProtection,
} from '../core/screenprotection.mjs';

import {
  createFingerprintProtection,
} from '../core/fingerprinting.mjs';

import {
  createDomainGenerator,
  DOMAIN_CULTURES,
} from '../core/domains.mjs';

/* ------------------------------------------------------------------ *
 * constants
 * ------------------------------------------------------------------ */

const POLL_MS = 3000;
const AUTOSAVE_MS = 450;
const DB_NAME = 'domail';
const LEGAL_BANNER_DISMISSED_KEY = 'domail:legal:dismissed';

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
let composeDirty = false;
let composeAttachments = [];
let autosaveTimer = null;
let pollTimer = null;
let knownInbox = new Set();
let knownOutbox = new Set();
let knownDrafts = new Set();
let emojiCat = 'smileys';
let emojiSkin = '';
let audioCtx = null;

let antiKeylogger = null;
let screenProtection = null;
let fingerprintProtection = null;
let domainGenerator = null;

let uiPrefs = { 
  mode: 'dark', 
  neon: null, 
  accent: null, 
  font: 'system', 
  size: 18, 
  autoSig: true, 
  notify: false, 
  sound: true, 
  pollMs: POLL_MS,
  antiKeylogger: true,
  screenProtection: true,
  fingerprintProtection: true,
  passphrase: '',
  domainCulture: 'mixed',
  offlineMode: true,
  blockDevTools: false,
  torNotice: false,
  reqSentConfirm: false,
  autoReceive: true,
  saveSent: true,
  sigRich: true,
  sigAbove: false,
};

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
  securityToggle: $('#securityToggle'),
  netstat: $('#netstat'),
  legalBanner: $('#legalBanner'),
  legalDismiss: $('#legalDismiss'),
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
  passphraseModal: $('#passphraseModal'),
  unlockPassphrase: $('#unlockPassphrase'),
  unlockBtn: $('#unlockBtn'),
  cancelUnlockBtn: $('#cancelUnlockBtn'),
  wipeFromLock: $('#wipeFromLock'),
  setPassphrase: $('#setPassphrase'),
  confirmPassphrase: $('#confirmPassphrase'),
  setPassphraseBtn: $('#setPassphraseBtn'),
  lockMailboxBtn: $('#lockMailboxBtn'),
  encryptionStatus: $('#encryptionStatus'),
  setAntiKeylogger: $('#setAntiKeylogger'),
  setScreenProtection: $('#setScreenProtection'),
  setFingerprintProtection: $('#setFingerprintProtection'),
  setDevToolsBlock: $('#setDevToolsBlock'),
  setOfflineMode: $('#setOfflineMode'),
  setTorNotice: $('#setTorNotice'),
  setDomainCulture: $('#setDomainCulture'),
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
  // New compose settings
  setSigCompose: $('#setSigCompose'),
  setSigRich: $('#setSigRich'),
  setSigAbove: $('#setSigAbove'),
  setPollInterval: $('#setPollInterval'),
  setReqSentConfirm: $('#setReqSentConfirm'),
  setAutoReceive: $('#setAutoReceive'),
  setSaveSent: $('#setSaveSent'),
  manualPollBtn: $('#manualPollBtn'),
  flushOutboxBtn: $('#flushOutboxBtn'),
};

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

function sanitizeHtml(html) {
  try {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script, iframe, object, embed, link, meta, style').forEach((el) => el.remove());
    doc.querySelectorAll('*').forEach((el) => {
      for (const attr of [...el.attributes]) {
        if (attr.name.startsWith('on')) el.removeAttribute(attr.name);
        if ((attr.name === 'href' || attr.name === 'src') && /^\s*javascript:/i.test(attr.value)) {
          el.removeAttribute(attr.name);
        }
      }
    });
    return doc.body.innerHTML;
  } catch {
    return escapeHtml(html);
  }
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

function saveUiPrefs() {
  try {
    const { passphrase, ...safePrefs } = uiPrefs;
    localStorage.setItem('domail:ui', JSON.stringify(safePrefs));
  } catch {}
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

  el.setAntiKeylogger.checked = uiPrefs.antiKeylogger;
  el.setScreenProtection.checked = uiPrefs.screenProtection;
  el.setFingerprintProtection.checked = uiPrefs.fingerprintProtection;
  el.setDevToolsBlock.checked = uiPrefs.blockDevTools;
  el.setOfflineMode.checked = uiPrefs.offlineMode;
  el.setTorNotice.checked = uiPrefs.torNotice;
  el.setDomainCulture.value = uiPrefs.domainCulture;

  // New compose settings
  if (el.setSigCompose) el.setSigCompose.value = uiPrefs.signature || '';
  el.setSigRich.checked = uiPrefs.sigRich;
  el.setSigAbove.checked = uiPrefs.sigAbove;
  el.setPollInterval.value = String(uiPrefs.pollMs);
  el.setReqSentConfirm.checked = uiPrefs.reqSentConfirm;
  el.setAutoReceive.checked = uiPrefs.autoReceive;
  el.setSaveSent.checked = uiPrefs.saveSent;

  if (checkLegalBannerDismissed() && el.legalBanner) {
    el.legalBanner.hidden = true;
  }
}

async function initSecuritySystems() {
  if (uiPrefs.antiKeylogger) {
    antiKeylogger = createAntiKeylogger();
    await antiKeylogger.init();
    document.querySelectorAll('input[type="text"], input[type="password"], textarea, [contenteditable="true"]').forEach(field => {
      antiKeylogger.protectField(field);
    });
  }

  if (uiPrefs.screenProtection) {
    screenProtection = createScreenProtection();
    await screenProtection.init();
  }

  if (uiPrefs.fingerprintProtection) {
    fingerprintProtection = createFingerprintProtection();
    await fingerprintProtection.init();
  }

  domainGenerator = createDomainGenerator({ culture: uiPrefs.domainCulture });
}

async function generateIdentity(name, local, domain) {
  if (!crypto.subtle) {
    throw new Error('WebCrypto not available — use HTTPS or localhost');
  }
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
  const local = domainGenerator ? domainGenerator.generateLocalPart(uiPrefs.domainCulture) : 'nova';
  const domain = domainGenerator ? domainGenerator.generateDomain(uiPrefs.domainCulture) : 'domail.space';
  const identity = await generateIdentity('Nova', local, domain);
  await engine.setIdentity(identity);
  el.identity.textContent = identity.address;
  el.keyView.textContent = publicKeyBlock(identity);
  toast(`Identity created: ${identity.address}`);
  await refreshAll();
  startPolling();
}

function showPage(name) {
  const validPages = ['inbox', 'outbox', 'drafts', 'settings', 'wipe'];
  if (!validPages.includes(name)) return;
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

async function refreshList(box) {
  if (!engine) return;
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

async function openReader(box, id) {
  if (!engine) return;
  const m = await engine.get(box, id);
  if (!m) {
    toast('Message not found');
    return;
  }

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
    ? sanitizeHtml(m.bodyText)
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
  for (const page of el.pages) {
    const r = page.querySelector('.reader');
    if (r) r.remove();
  }
}

function openCompose(opts = {}) {
  composeOpen = true;
  composeDraftId = null;
  composeDirty = false;
  composeAttachments = [];

  el.cTo.value = addrListLabel(opts.to || []);
  el.cSubject.value = opts.subject || '';
  el.editor.innerHTML = opts.body || '';
  el.draftState.textContent = 'draft autosaves';

  $$('.addr-row[data-extra]').forEach((r) => { r.hidden = true; });

  el.compose.hidden = false;
  el.cTo.focus();

  if (opts.inReplyTo) {
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
  if (!composeOpen || !engine) return;
  try {
    const c = getComposeContent();
    const isEmpty = !c.to && !c.subject && !c.text.trim();

    if (isEmpty) {
      if (composeDraftId) {
        await engine.remove('drafts', composeDraftId);
        knownDrafts.delete(composeDraftId);
        composeDraftId = null;
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
    }
    knownDrafts.add(draft.id);
    composeDirty = false;
    el.draftState.textContent = `saved ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    await refreshList('drafts');
  } catch (e) {
    el.draftState.textContent = 'draft save failed';
    console.error('saveDraft error:', e);
  }
}

function parseAddr(val) {
  if (!val) return [];
  return val.split(',').map((s) => s.trim()).filter(Boolean).map((address) => {
    const nameMatch = address.match(/^"([^"]+)"\s*<(.+)>$/) || address.match(/^([^<]+)\s*<(.+)>$/);
    if (nameMatch) {
      return { name: nameMatch[1].trim(), address: nameMatch[2].trim() };
    }
    const clean = address.replace(/[<>"']/g, '').trim();
    if (!clean) return null;
    return { name: '', address: clean };
  }).filter(Boolean);
}

async function sendCompose() {
  if (!engine) return;
  const c = getComposeContent();
  const issues = [];

  const to = parseAddr(c.to);
  if (!to.length) issues.push('Add at least one recipient in To.');
  if (!c.text.trim()) issues.push('The message body is empty.');

  if (issues.length) {
    showValidation(issues);
    return;
  }

  try {
    const sig = uiPrefs.autoSig ? await engine.store.get('signature') : '';
    const body = sig ? `${c.text}\n\n${sig}` : c.text;

    const headers = {};
    if (uiPrefs.reqSentConfirm && engine.identity) {
      headers['Disposition-Notification-To'] = engine.identity.address;
    }

    await engine.send({
      to,
      cc: parseAddr(c.cc),
      bcc: parseAddr(c.bcc),
      subject: c.subject,
      text: body,
      html: el.editor.innerHTML,
      attachments: composeAttachments,
      headers,
    }, uiPrefs.saveSent ? 'outbox' : null);

    if (composeDraftId) {
      await engine.remove('drafts', composeDraftId);
      knownDrafts.delete(composeDraftId);
    }

    closeCompose();
    toast(uiPrefs.saveSent ? 'Sent (saved to Outbox)' : 'Sent (not saved)');
    await refreshAll();
    showPage('outbox');
  } catch (e) {
    toast(`Send failed: ${e.message}`);
  }
}

function showValidation(issues) {
  el.vList.innerHTML = issues.map((i) => `<li>${escapeHtml(i)}</li>`).join('');
  el.validate.hidden = false;
}

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

function execFmt(cmd, val = null) {
  el.editor.focus();
  document.execCommand(cmd, false, val);
  scheduleAutosave();
}

function ensureAudio() {
  if (!audioCtx) {
    try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch {}
  }
  if (audioCtx && audioCtx.state === 'suspended') audioCtx.resume();
}

function playChime() {
  if (!uiPrefs.sound) return;
  try {
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
  } catch (e) {
    console.error('playChime error:', e);
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

    const totalBytes = JSON.stringify({ inbox, outbox }).length;
    el.netstat.textContent = `${(totalBytes / 1024).toFixed(1)} KB · local`;
  } catch (e) {
    console.error('poll error:', e);
  }
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(poll, uiPrefs.pollMs);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

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
    if (!data || data.format !== 'domail/1') {
      throw new Error('Not a DOM Mail export file');
    }
    await engine.import(data);
    el.identity.textContent = engine.identity ? engine.identity.address : 'no identity';
    if (engine.identity) el.keyView.textContent = publicKeyBlock(engine.identity);
    await refreshAll();
    toast('Imported');
  } catch (e) {
    toast(`Import failed: ${e.message}`);
  }
}

async function refreshContacts() {
  if (!engine) return;
  const map = await engine.contacts();
  const entries = Object.values(map).sort((a, b) => a.name.localeCompare(b.name));
  el.contactList.innerHTML = entries.map((c) =>
    `<li><span>${escapeHtml(c.name)}</span><span class="addr">${escapeHtml(c.address)}</span></li>`
  ).join('');
  $('[data-empty="contacts"]').style.display = entries.length ? 'none' : '';
}

async function wipeIdentity() {
  try {
    if (engine && engine.store && typeof engine.store.destroy === 'function') {
      await engine.store.destroy();
    } else if (engine) {
      await engine.wipe();
    }
    stopPolling();
    knownInbox.clear();
    knownOutbox.clear();
    knownDrafts.clear();
    el.identity.textContent = 'no identity';
    el.keyView.textContent = '';
    await refreshAll();
    showPage('inbox');
    if (el.passphraseModal) el.passphraseModal.hidden = true;
    showOnboarding();
    toast('Identity wiped');
  } catch (e) {
    toast(`Wipe failed: ${e.message}`);
  }
}

function showOnboarding() {
  el.onboard.hidden = false;
}

function hideOnboarding() {
  el.onboard.hidden = true;
}

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
    const files = [...el.cFile.files];
    if (!files.length) return;
    const attachments = [];
    for (const file of files) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      attachments.push({ name: file.name, type: file.type || 'application/octet-stream', bytes });
    }
    composeAttachments.push(...attachments);
    toast(`${attachments.length} file(s) attached`);
    el.cFile.value = '';
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
    if (!engine || !engine.identity) return;
    engine.identity.name = el.setName.value;
    await engine.setIdentity(engine.identity);
    el.identity.textContent = engine.identity.address;
  });

  el.setLocal.addEventListener('change', async () => {
    if (!engine || !engine.identity) return;
    engine.identity.local = el.setLocal.value;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
  });

  el.setDomain.addEventListener('change', async () => {
    if (!engine || !engine.identity) return;
    engine.identity.domain = el.setDomain.value;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
  });

  el.setSig.addEventListener('change', async () => {
    if (!engine) return;
    await engine.store.set('signature', el.setSig.value);
    toast('Signature saved');
  });

  el.regenDomain.addEventListener('click', async () => {
    if (!engine || !engine.identity) return;
    const newDomain = domainGenerator ? domainGenerator.generateDomain(uiPrefs.domainCulture) : `${Math.random().toString(36).slice(2, 10)}.domail.space`;
    engine.identity.domain = newDomain;
    engine.identity.address = `${engine.identity.local}@${newDomain}`;
    await engine.setIdentity(engine.identity);
    el.setDomain.value = engine.identity.domain;
    el.identity.textContent = engine.identity.address;
    el.keyView.textContent = publicKeyBlock(engine.identity);
    toast(`New domain: ${engine.identity.domain}`);
  });

  el.copyKey.addEventListener('click', async () => {
    if (!engine || !engine.identity) return;
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

  // New compose settings
  el.setSigCompose.addEventListener('change', async () => {
    if (!engine) return;
    await engine.store.set('signature', el.setSigCompose.value);
    uiPrefs.signature = el.setSigCompose.value;
    saveUiPrefs();
    toast('Signature saved');
  });

  el.setSigRich.addEventListener('change', () => {
    uiPrefs.sigRich = el.setSigRich.checked;
    saveUiPrefs();
  });

  el.setSigAbove.addEventListener('change', () => {
    uiPrefs.sigAbove = el.setSigAbove.checked;
    saveUiPrefs();
  });

  el.setPollInterval.addEventListener('change', () => {
    const val = Number(el.setPollInterval.value);
    if (!Number.isFinite(val) || val < 0) {
      toast('Invalid polling interval');
      el.setPollInterval.value = String(uiPrefs.pollMs);
      return;
    }
    uiPrefs.pollMs = val;
    saveUiPrefs();
    if (uiPrefs.pollMs > 0) {
      startPolling();
    } else {
      stopPolling();
    }
    toast(uiPrefs.pollMs > 0 ? `Polling set to ${uiPrefs.pollMs / 1000}s` : 'Polling disabled (manual only)');
  });

  el.setReqSentConfirm.addEventListener('change', () => {
    uiPrefs.reqSentConfirm = el.setReqSentConfirm.checked;
    saveUiPrefs();
  });

  el.setAutoReceive.addEventListener('change', () => {
    uiPrefs.autoReceive = el.setAutoReceive.checked;
    saveUiPrefs();
  });

  el.setSaveSent.addEventListener('change', () => {
    uiPrefs.saveSent = el.setSaveSent.checked;
    saveUiPrefs();
  });

  el.manualPollBtn.addEventListener('click', () => {
    poll();
    toast('Checking for new mail...');
  });

  el.flushOutboxBtn.addEventListener('click', async () => {
    if (!engine) return;
    const outbox = await engine.list('outbox');
    let sent = 0;
    for (const m of outbox) {
      // Only attempt to resend messages that don't have 'sent' status
      // (e.g., failed/queued messages) or messages without status field
      if (!m.status || m.status === 'queued' || m.status === 'sending') {
        try {
          await engine.send(m, 'outbox');
          sent++;
        } catch (e) {
          console.error('Flush failed for message:', e);
        }
      }
    }
    await refreshAll();
    toast(`Flushed ${sent} message(s) from outbox`);
  });

  // Security toggles
  el.setAntiKeylogger.addEventListener('change', () => {
    uiPrefs.antiKeylogger = el.setAntiKeylogger.checked;
    saveUiPrefs();
    toast(uiPrefs.antiKeylogger ? 'Anti-keylogger enabled (reload to apply)' : 'Anti-keylogger disabled');
  });

  el.setScreenProtection.addEventListener('change', () => {
    uiPrefs.screenProtection = el.setScreenProtection.checked;
    saveUiPrefs();
    if (screenProtection) {
      if (uiPrefs.screenProtection) screenProtection.enable();
      else screenProtection.disable();
    }
    toast(uiPrefs.screenProtection ? 'Screen protection enabled' : 'Screen protection disabled');
  });

  el.setFingerprintProtection.addEventListener('change', () => {
    uiPrefs.fingerprintProtection = el.setFingerprintProtection.checked;
    saveUiPrefs();
    toast(uiPrefs.fingerprintProtection ? 'Zero fingerprinting enabled (reload to apply)' : 'Zero fingerprinting disabled');
  });

  el.setDomainCulture.addEventListener('change', () => {
    uiPrefs.domainCulture = el.setDomainCulture.value;
    if (domainGenerator) domainGenerator.culture = uiPrefs.domainCulture;
    saveUiPrefs();
    toast(`Domain culture set to ${uiPrefs.domainCulture}`);
  });

  // Passphrase management
  el.setPassphraseBtn.addEventListener('click', async () => {
    const pw = el.setPassphrase.value;
    const confirm = el.confirmPassphrase.value;
    if (!pw) {
      toast('Passphrase cannot be empty');
      return;
    }
    if (pw !== confirm) {
      toast('Passphrases do not match');
      return;
    }
    try {
      await initializeEncryptedStorage(pw);
      el.encryptionStatus.textContent = 'Storage: Encrypted (Argon2id + XChaCha20)';
      toast('Encryption enabled successfully');
      el.setPassphrase.value = '';
      el.confirmPassphrase.value = '';
    } catch (e) {
      toast(`Encryption setup failed: ${e.message}`);
    }
  });

  el.lockMailboxBtn.addEventListener('click', async () => {
    if (engine && engine.store && typeof engine.store.lock === 'function') {
      await engine.store.lock();
      stopPolling();
      el.identity.textContent = 'locked';
      if (el.passphraseModal) el.passphraseModal.hidden = false;
      toast('Mailbox locked');
    } else {
      toast('Mailbox not using encrypted storage');
    }
  });

  el.unlockBtn.addEventListener('click', async () => {
    const pw = el.unlockPassphrase.value;
    if (!pw) {
      toast('Enter passphrase');
      return;
    }
    try {
      await unlockExistingStorage(pw);
      el.passphraseModal.hidden = true;
      el.unlockPassphrase.value = '';
      el.encryptionStatus.textContent = 'Storage: Encrypted & Unlocked';
      el.identity.textContent = engine.identity ? engine.identity.address : 'no identity';
      if (engine.identity) {
        el.keyView.textContent = publicKeyBlock(engine.identity);
        el.setName.value = engine.identity.name;
        el.setLocal.value = engine.identity.local;
        el.setDomain.value = engine.identity.domain;
        hideOnboarding();
        await refreshAll();
        startPolling();
      }
      toast('Mailbox unlocked');
    } catch (e) {
      toast(`Unlock failed: ${e.message}`);
    }
  });

  el.cancelUnlockBtn.addEventListener('click', () => {
    if (el.passphraseModal) el.passphraseModal.hidden = true;
  });

  el.wipeFromLock.addEventListener('click', async () => {
    if (confirm('Destroy this identity and all encrypted mail? This cannot be undone.')) {
      if (el.passphraseModal) el.passphraseModal.hidden = true;
      await wipeIdentity();
    }
  });

  // Legal banner dismiss
  if (el.legalDismiss) {
    el.legalDismiss.addEventListener('click', () => {
      saveLegalBannerDismissed();
      if (el.legalBanner) el.legalBanner.hidden = true;
      toast('Warning acknowledged');
    });
  }

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

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!el.validate.hidden) { el.validate.hidden = true; return; }
      if (composeOpen) { closeCompose(); return; }
      if (!el.emoji.hidden) { el.emoji.hidden = true; return; }
      if (el.passphraseModal && !el.passphraseModal.hidden) { return; }
    }
  });

  document.addEventListener('click', (e) => {
    if (!el.emoji.hidden && !el.emoji.contains(e.target) && e.target !== el.emojiBtn) {
      el.emoji.hidden = true;
    }
  });
}

async function init() {
  loadUiPrefs();
  applyUiPrefs();
  bindEvents();
  await initSecuritySystems();

  try {
    const store = indexedDbStore(DB_NAME);
    const encryptedStore = new EncryptedStore(store);
    await encryptedStore._ensureInit();

    // Check if salt exists (meaning storage is encrypted)
    const salt = await store.get('__salt__');
    if (salt) {
      // Prompt for passphrase
      if (el.passphraseModal) el.passphraseModal.hidden = false;
      return;
    }

    engine = new MailEngine(store);
    await engine.load();

    if (engine.identity) {
      el.identity.textContent = engine.identity.address;
      el.keyView.textContent = publicKeyBlock(engine.identity);
      el.setName.value = engine.identity.name;
      el.setLocal.value = engine.identity.local;
      el.setDomain.value = engine.identity.domain;
      const sig = await store.get('signature');
      if (sig) el.setSig.value = sig;
      hideOnboarding();
      await refreshAll();
      startPolling();
    } else {
      showOnboarding();
    }
  } catch (e) {
    console.error('Init error:', e);
    showOnboarding();
  }
}

init();
