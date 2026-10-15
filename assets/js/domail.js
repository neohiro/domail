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
  makeMessageId,
  bytesToBase64,
} from '../../core/mail.mjs';

import {
  EncryptedStore,
  unlockMailEngine,
} from '../../core/encrypted-store.mjs';

import {
  createAntiKeylogger,
} from '../../core/antikeylogger.mjs';

import {
  createScreenProtection,
} from '../../core/screenprotection.mjs';

import {
  createFingerprintProtection,
} from '../../core/fingerprinting.mjs';

import {
  createDomainGenerator,
} from '../../core/domains.mjs';

import {
  encryptMessage,
  decryptMessage,
  encryptWithPassphrase,
  decryptWithPassphrase,
  isPassphraseMessage,
  PGP,
} from '../../core/pgp.mjs';

import {
  createRelayClient,
} from '../../core/relay.mjs';

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
/** Message-ID this draft replies to. Plain state, not a DOM data attribute. */
let composeReplyTo = '';
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

/**
 * Relay client. Constructed lazily and only when the user has opted in, so
 * importing this module never touches the network.
 */
let relay = null;

/**
 * PGP keyring: address (lowercased) -> base64 X25519 public key.
 * Populated from identities DOM Mail has already met, so there is no key
 * server and nothing is fetched to learn a key.
 */
let pgpKeyring = {};

/** base64 -> Uint8Array, tolerating the plain-ASCII default alphabet. */
function fromBase64(b64) {
  const bin = atob(String(b64));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Learn (or refresh) a peer's X25519 public key from a DOM Mail identity. */
function rememberPgpKey(identity) {
  if (!identity?.address || !identity.x25519) return;
  pgpKeyring[String(identity.address).toLowerCase()] = identity.x25519;
}

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
  pgpPassphrase: '',
  showFullIdentity: false,
  suggestContacts: true,
  // Optional networked features (off by default)
  gpgEnabled: false,
  gpgPath: 'gpg',
  // Body text PII obfuscation
  bodyObfuscate: true,
  bodyObfuscateHoverReveal: true,
  // Multi-network transports
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
  vpnEnabled: false,
  vpnEndpoint: '',
  vpnConfigName: '',
  vpnConfigBody: '',
  // SMTP relay (for sending to external email addresses via WebSocket relay)
  smtpRelayEnabled: false,
  smtpRelayUrl: '',
  smtpRelayHost: '',
  smtpRelayPort: 587,
  smtpRelaySecure: false,
  smtpRelayUser: '',
  smtpRelayPass: '',
  // Local MX Node (run own mail server in browser)
  localMxEnabled: false,
  localMxHostname: '',
  localMxCert: '',
  localMxKey: '',
};

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const el = {
  overhaul: $('#overhaul'),
  resetAccent: $('#resetAccent'),
  accentSwatches: $('#accentSwatches'),
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
  mobileBottomNav: $('.mobile-bottom-nav'),
  mobileTabs: $$('.mobile-bottom-nav .tab'),
  lists: { inbox: $('#list-inbox'), outbox: $('#list-outbox'), drafts: $('#list-drafts') },
  counts: { inbox: $('[data-count="inbox"]'), outbox: $('[data-count="outbox"]'), drafts: $('[data-count="drafts"]') },
  cTo: $('#cTo'), cCc: $('#cCc'), cBcc: $('#cBcc'), cSubject: $('#cSubject'),
  editor: $('#editor'),
  draftState: $('#draftState'),
  cDiscard: $('#cDiscard'), cSend: $('#cSend'),
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
  setShowFullAddr: $('#setShowFullAddr'), setSuggestContacts: $('#setSuggestContacts'),
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
  // Optional networked features (off by default)
setPgp: $('#setPgp'),
  setPgpSign: $('#setPgpSign'),
  setPgpPass: $('#setPgpPass'),
  pgpState: $('#pgpState'),
  optPgp: $('#optPgp'),
  setRelay: $('#setRelay'),
  setRelayUrl: $('#setRelayUrl'),
  relayState: $('#relayState'),
  relayStatus: $('#relayStatus'),
  optRelay: $('#optRelay'),
  relayConnectBtn: $('#relayConnectBtn'),
  relayDisconnectBtn: $('#relayDisconnectBtn'),
  // Multi-network transport elements
  netDirect: $('#netDirect'),
  netTor: $('#netTor'),
  netI2p: $('#netI2p'),
  netEnsIpfs: $('#netEnsIpfs'),
  netRadicle: $('#netRadicle'),
  netYggdrasil: $('#netYggdrasil'),
  netNostr: $('#netNostr'),
  netReticulum: $('#netReticulum'),
  netWebRTC: $('#netWebRTC'),
  netBLE: $('#netBLE'),
  netDNS: $('#netDNS'),
  netSneakernet: $('#netSneakernet'),
  netFederation: $('#netFederation'),
  // Compose-time dispatch network elements
  sendNetDirect: $('#sendNetDirect'),
  sendNetTor: $('#sendNetTor'),
  sendNetI2p: $('#sendNetI2p'),
  sendNetEnsIpfs: $('#sendNetEnsIpfs'),
  sendNetRadicle: $('#sendNetRadicle'),
  sendNetYggdrasil: $('#sendNetYggdrasil'),
  sendNetNostr: $('#sendNetNostr'),
  sendNetReticulum: $('#sendNetReticulum'),
  sendNetWebRTC: $('#sendNetWebRTC'),
  sendNetBLE: $('#sendNetBLE'),
  sendNetDNS: $('#sendNetDNS'),
  sendNetSneakernet: $('#sendNetSneakernet'),
  sendNetFederation: $('#sendNetFederation'),
  // VPN Gateway elements
  setVpn: $('#setVpn'),
  vpnState: $('#vpnState'),
  setVpnEndpoint: $('#setVpnEndpoint'),
  setVpnFile: $('#setVpnFile'),
  vpnFileStatus: $('#vpnFileStatus'),
  // SMTP Relay elements
  setSmtpRelay: $('#setSmtpRelay'),
  smtpRelayState: $('#smtpRelayState'),
  setSmtpRelayUrl: $('#setSmtpRelayUrl'),
  setSmtpRelayHost: $('#setSmtpRelayHost'),
  setSmtpRelayPort: $('#setSmtpRelayPort'),
  setSmtpRelaySecure: $('#setSmtpRelaySecure'),
  setSmtpRelayUser: $('#setSmtpRelayUser'),
  setSmtpRelayPass: $('#setSmtpRelayPass'),
  smtpRelayConnectBtn: $('#smtpRelayConnectBtn'),
  smtpRelayDisconnectBtn: $('#smtpRelayDisconnectBtn'),
  smtpRelayTestBtn: $('#smtpRelayTestBtn'),
  smtpRelayStatus: $('#smtpRelayStatus'),
  optSmtpRelay: $('#optSmtpRelay'),
  // Local MX Node elements
  setLocalMx: $('#setLocalMx'),
  localMxState: $('#localMxState'),
  setLocalMxHostname: $('#setLocalMxHostname'),
  setLocalMxCert: $('#setLocalMxCert'),
  setLocalMxKey: $('#setLocalMxKey'),
  localMxCertStatus: $('#localMxCertStatus'),
  localMxStartBtn: $('#localMxStartBtn'),
  localMxStopBtn: $('#localMxStopBtn'),
  localMxTestBtn: $('#localMxTestBtn'),
  localMxStatus: $('#localMxStatus'),
  optLocalMx: $('#optLocalMx'),
};

/*
 * Legal-banner dismissal.
 *
 * Both helpers used to be referenced from applyUiPrefs() and the dismiss
 * handler but were never defined, which threw during init and left every
 * control on the page unwired. They must not be able to throw: storage can be
 * unavailable (private mode, blocked cookies), and a banner is cosmetic.
 */
function checkLegalBannerDismissed() {
  try {
    return localStorage.getItem(LEGAL_BANNER_DISMISSED_KEY) === '1';
  } catch {
    return false;
  }
}

function saveLegalBannerDismissed() {
  try {
    localStorage.setItem(LEGAL_BANNER_DISMISSED_KEY, '1');
  } catch {}
}

/**
 * Render the transport-level metadata carried by a message, so the user can
 * see exactly what arrived alongside the body. Addresses are masked here too.
 */
function headerRows(m) {
  const rows = [
    ['From', displayAddrList(m.from)],
    ['To', displayAddrList(m.to)],
  ];
  if (m.cc?.length) rows.push(['Cc', displayAddrList(m.cc)]);
  if (m.bcc?.length) rows.push(['Bcc', displayAddrList(m.bcc)]);
  rows.push(['Date', new Date(m.date).toLocaleString()]);
  if (m.inReplyTo) rows.push(['In-Reply-To', `<${escapeHtml(m.inReplyTo)}>`]);

  // Anything the raw message carried that we do not model explicitly.
  const seen = new Set(rows.map((r) => r[0].toLowerCase()));
  for (const line of String(m.raw || '').split(/\r?\n/)) {
    if (!line.trim()) break;
    const i = line.indexOf(':');
    if (i < 1) continue;
    const name = line.slice(0, i).trim();
    if (seen.has(name.toLowerCase())) continue;
    if (/^(content-type|content-transfer-encoding|mime-version)$/i.test(name)) continue;
    seen.add(name.toLowerCase());
    const value = line.slice(i + 1).trim();
    // A header value is attacker-controlled: never mark it up.
    rows.push([name, escapeHtml(maskHeaderValue(value))]);
  }
  if (m.attachments?.length) {
    rows.push(['Attachments', m.attachments.map((a) => `${a.name} (${a.bytes?.length ?? 0} B)`).join(', ')]);
  }
  if (m.decrypted) rows.push(['Body', 'decrypted at read time, not stored in clear']);
  if (m.signed) rows.push(['Signature', m.signatureValid ? 'valid' : 'INVALID']);
  return rows.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`).join('');
}

/** Mask an email address inside a free-form header value. */
function maskHeaderValue(value) {
  return String(value).replace(
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    (m2) => (uiPrefs.showFullIdentity ? m2 : maskAddress(m2)),
  );
}

/**
 * Blind-copy display for a mail address.
 *
 * The address is never rendered in full on screen. Clicking the element copies
 * the real address to the clipboard and briefly confirms it, so an onlooker
 * (or a screenshot) never captures a usable address while the user can still
 * paste it into a recipient field. Set showFullIdentity to opt out.
 */
function maskAddress(addr) {
  const raw = String(addr ?? '');
  if (!raw) return '';
  if (uiPrefs.showFullIdentity) return raw;
  if (raw === 'no identity' || raw === 'locked' || raw.startsWith('emergency_')) return raw;

  const at = raw.lastIndexOf('@');
  if (at <= 0) return raw;
  const local = raw.slice(0, at);
  const domain = raw.slice(at + 1);
  const dot = domain.indexOf('.');

  const head = local.length <= 1 ? '*' : local[0];
  const maskedLocal = `${head}${'*'.repeat(Math.min(local.length - 1, 6))}`;

  if (dot <= 0) return `${maskedLocal}@${domain[0] || '*'}${'*'.repeat(6)}`;
  const name = domain.slice(0, dot);
  const tld = domain.slice(dot + 1);
  const maskedName = `${name.length <= 1 ? '*' : name[0]}${'*'.repeat(Math.min(name.length - 1, 6))}`;
return `${maskedLocal}@${maskedName}.${tld}`;
}

/**
 * Mask PII (emails, phone numbers) in text content.
 * Returns a version with emails/phones masked, or original if showFullIdentity is true.
 */
function obfuscateBodyPII(element) {
  if (uiPrefs.showFullIdentity || !uiPrefs.bodyObfuscate) return;
  const htmlContent = element.innerHTML;
  // Mask emails
  let maskedHtml = element.innerHTML.replace(
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    (m) => `<span class="pii-masked" data-original="${escapeHtml(m)}">${maskAddress(m)}</span>`
  );
  // Mask phone numbers (basic pattern)
  maskedHtml = maskedHtml.replace(
    /(\+?\d[\d\s\-]{7,}\d)/g,
    (m) => `<span class="pii-masked" data-original="${escapeHtml(m)}">${maskPhone(m)}</span>`
  );

  element.innerHTML = maskedHtml;
  // Store original for hover reveal
  element.dataset.raw = element.innerHTML;
}

function maskPhone(phone) {
  const digits = phone.replace(/\D/g, '');
  if (digits.length < 7) return phone;
  const visible = digits.slice(-4);
  return '*'.repeat(Math.max(0, digits.length - 4)) + visible;
}

/**
 * Restore original content on hover/focus
 */
function revealBodyPII(element) {
  if (element.dataset.raw) {
    element.innerHTML = element.dataset.raw;
    delete element.dataset.raw;
  }
}

/** Paint the identity chip with a masked address (see maskAddress). */
function renderIdentity() {
  if (!el.identity) return;
  if (!engine?.identity) {
    el.identity.textContent = 'no identity';
    el.identity.classList.remove('is-copyable', 'is-copied');
    el.identity.title = 'No identity yet';
    return;
  }
  el.identity.textContent = maskAddress(engine.identity.address);
  el.identity.title = 'Click to copy the full address';
  el.identity.classList.add('is-copyable');
}

let identityCopyTimer = null;
async function copyFullAddress() {
  const addr = engine?.identity?.address;
  if (!addr) return;
  try {
    await navigator.clipboard.writeText(addr);
    el.identity.textContent = 'Copied!';
    el.identity.classList.add('is-copied');
    clearTimeout(identityCopyTimer);
    identityCopyTimer = setTimeout(() => {
      el.identity.classList.remove('is-copied');
      renderIdentity();
    }, 1400);
  } catch {
    toast('Could not copy — your browser blocked clipboard access');
  }
}

/* ------------------------------------------------------------------ *
 * contact suggestions for the address fields
 *
 * Non-obtrusive by design: the list only appears while the field has focus,
 * filters as you type, and any keystroke that isn't choosing a suggestion
 * simply types through, so a new address is never blocked. Escape, blur or
 * clicking away dismisses it.
 * ------------------------------------------------------------------ */

const ADDR_FIELDS = ['#cTo', '#cCc', '#cBcc'];
let suggestBox = null;
let suggestIndex = -1;
let suggestItems = [];

function ensureSuggestBox() {
  if (suggestBox) return suggestBox;
  suggestBox = document.createElement('div');
  suggestBox.className = 'addr-suggest';
  suggestBox.setAttribute('role', 'listbox');
  suggestBox.hidden = true;
  document.body.appendChild(suggestBox);
  return suggestBox;
}

function hideContactSuggest() {
  if (!suggestBox) return;
  suggestBox.hidden = true;
  suggestBox.innerHTML = '';
  suggestIndex = -1;
  suggestItems = [];
}

/** Split an address field into completed entries plus the token being typed. */
function splitAddrField(value) {
  const raw = String(value || '');
  const parts = raw.split(/[,;]/);
  const token = parts[parts.length - 1].replace(/^\s+/, '');
  const head = parts.slice(0, -1);
  const prefix = head.length
    ? head.map((p) => `${p.trim()}, `).join('')
    : '';
  return { prefix, token };
}

/** Insert a chosen contact, preserving whatever the user already typed. */
function acceptSuggestion(address, field) {
  const { prefix } = splitAddrField(field.value);
  field.value = `${prefix}${address}, `;
  field.focus();
  field.setSelectionRange(field.value.length, field.value.length);
  hideContactSuggest();
  markComposeDirty();
}

function renderContactSuggest(field) {
  if (!uiPrefs.suggestContacts) return hideContactSuggest();
  const { token } = splitAddrField(field.value);
  const needle = token.trim().toLowerCase();

  // Get user's own address to exclude from suggestions
  const ownAddress = engine?.identity?.address?.toLowerCase() || '';

  // Merge learned contacts with identities we have keys for, de-duplicated.
  const seen = new Set();
  const all = [];
  const push = (address, name) => {
    const a = String(address || '').toLowerCase();
    if (!a || seen.has(a)) return;
    // Exclude user's own address from suggestions
    if (a === ownAddress) return;
    seen.add(a);
    all.push({ address: a, name: name || '' });
  };
  for (const [addr, meta] of Object.entries(pgpContacts || {})) push(addr, meta?.name);
  for (const [addr, key] of Object.entries(pgpKeyring || {})) push(addr, '');

  const matches = all
    .filter((c) => !needle
      || c.address.includes(needle)
      || (c.name && c.name.toLowerCase().includes(needle)))
    .sort((a, b) => {
      // Prefix matches first: typing "no" should rank "nova@…" above "xnova@…".
      const ap = a.address.startsWith(needle) || a.name.toLowerCase().startsWith(needle);
      const bp = b.address.startsWith(needle) || b.name.toLowerCase().startsWith(needle);
      if (ap !== bp) return ap ? -1 : 1;
      return a.address.localeCompare(b.address);
    })
    .slice(0, 8);

  suggestItems = matches;
  suggestIndex = matches.length ? 0 : -1;

  const box = ensureSuggestBox();
  if (!matches.length) return hideContactSuggest();

  box.innerHTML = matches.map((c, i) => `
    <div class="addr-suggest__row${i === 0 ? ' is-active' : ''}" role="option"
         aria-selected="${i === 0}" data-addr="${escapeHtml(c.address)}">
      ${c.name ? `<span class="addr-suggest__name">${escapeHtml(c.name)}</span>` : ''}
      <span class="addr-suggest__addr">${escapeHtml(c.address)}</span>
    </div>`).join('');

  const r = field.getBoundingClientRect();
  box.style.left = `${Math.min(r.left, window.innerWidth - 300)}px`;
  box.style.top = `${Math.min(r.bottom, window.innerHeight - box.offsetHeight - 8)}px`;
  box.hidden = false;

  for (const row of box.querySelectorAll('.addr-suggest__row')) {
    row.addEventListener('mousedown', (e) => {
      e.preventDefault();
      acceptSuggestion(row.dataset.addr, field);
    });
  }
}

function markContactSuggest(keyIndex) {
  const rows = suggestBox?.querySelectorAll('.addr-suggest__row') || [];
  suggestIndex = keyIndex;
  rows.forEach((row, i) => {
    row.classList.toggle('is-active', i === keyIndex);
    row.setAttribute('aria-selected', String(i === keyIndex));
  });
}

function bindContactSuggest() {
  for (const sel of ADDR_FIELDS) {
    const field = $(sel);
    if (!field) continue;
    field.setAttribute('autocomplete', 'off');
    field.setAttribute('aria-autocomplete', 'list');

    field.addEventListener('focus', () => refreshContactSuggest(field));
    field.addEventListener('input', () => {
      markComposeDirty();
      renderContactSuggest(field);
    });
    // A short grace period so clicking a row lands before blur hides it.
    field.addEventListener('blur', () => {
      setTimeout(hideContactSuggest, 120);
    });
    field.addEventListener('keydown', (e) => {
      if (suggestBox?.hidden || !suggestItems.length) return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        markContactSuggest((suggestIndex + 1) % suggestItems.length);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        markContactSuggest((suggestIndex - 1 + suggestItems.length) % suggestItems.length);
      } else if (e.key === 'Enter' || e.key === 'Tab') {
        if (suggestIndex >= 0 && suggestItems[suggestIndex]) {
          e.preventDefault();
          acceptSuggestion(suggestItems[suggestIndex].address, field);
        }
      } else if (e.key === 'Escape') {
        // First Escape closes the list; it never blocks typing afterwards.
        e.stopPropagation();
        hideContactSuggest();
      }
    });
  }
}

/** Re-read the contact book, then repaint whichever field has focus. */
async function refreshContactSuggest(field) {
  try {
    if (engine) pgpContacts = (await engine.contacts()) || {};
  } catch { /* contacts are optional; suggestions simply stay empty */ }
  renderContactSuggest(field);
}

/** Mark the composer dirty and schedule the draft autosave. */
function markComposeDirty() {
  if (!composeOpen) {
    composeOpen = true;
    composeReplyTo = composeReplyTo || '';
  }
  composeDirty = true;
  scheduleAutosave();
}

let pgpContacts = {};

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

/**
 * Address rendering for message lists and headers. Masked unless the user has
 * explicitly opted in via Settings > Privacy, so a screenshot or a passing
 * glance cannot harvest a contact list.
 */
function displayAddrList(list) {
  if (uiPrefs.showFullIdentity) return addrListLabel(list);
  return (list || [])
    .map((a) => (a.name ? `${a.name} <${maskAddress(a.address)}>` : maskAddress(a.address)))
    .join(', ');
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

/**
 * Secrets are deliberately never persisted: the mailbox passphrase and the
 * shared PGP passphrase are stripped before the preference blob is written.
 * The PGP passphrase therefore lasts for the current session only and must be
 * re-entered after a reload, which is the lesser evil versus leaving a reusable
 * secret sitting in localStorage.
 */
function saveUiPrefs() {
  try {
    const { passphrase, pgpPassphrase, ...safePrefs } = uiPrefs;
    localStorage.setItem('domail:ui', JSON.stringify(safePrefs));
  } catch {}
}

function loadUiPrefs() {
  try {
    const raw = localStorage.getItem('domail:ui');
    if (raw) {
      const stored = JSON.parse(raw);
      // Never trust a stored secret, even from an older build.
      delete stored.pgpPassphrase;
      delete stored.passphrase;
      Object.assign(uiPrefs, stored);
    }
  } catch {}
  uiPrefs.passphrase = '';
  uiPrefs.pgpPassphrase = '';
}

function applyUiPrefs() {
  const r = document.documentElement;
  r.dataset.mode = uiPrefs.mode;
  if (uiPrefs.neon) r.style.setProperty('--neon', uiPrefs.neon);
  else r.style.removeProperty('--neon');
  if (uiPrefs.accent) r.style.setProperty('--accent', uiPrefs.accent);
  r.dataset.font = uiPrefs.font;
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

  // Body obfuscation settings
  if (el.setBodyObfuscate) el.setBodyObfuscate.checked = uiPrefs.bodyObfuscate;
  if (el.setBodyObfuscateHover) el.setBodyObfuscateHover.checked = uiPrefs.bodyObfuscateHoverReveal;

  // GnuPG settings
  if (el.setGpg) {
    el.setGpg.checked = uiPrefs.gpgEnabled;
    el.setGpgPath.value = uiPrefs.gpgPath || 'gpg';
    el.setGpgPath.disabled = !uiPrefs.gpgEnabled;
    el.gpgState.textContent = uiPrefs.gpgEnabled ? 'On' : 'Off';
    el.optGpg.classList.toggle('is-on', uiPrefs.gpgEnabled);
  }

  paintOptionalPrefs();
  paintThemeControl();
  el.setShowFullAddr.checked = uiPrefs.showFullIdentity;
  el.setSuggestContacts.checked = uiPrefs.suggestContacts;

  if (checkLegalBannerDismissed() && el.legalBanner) {
    el.legalBanner.hidden = true;
  }
}

/** Reflect the theme preference in the Settings segmented control. */
function paintThemeControl() {
  for (const btn of $$('.seg__btn[data-theme]')) {
    const on = btn.dataset.theme === uiPrefs.mode;
    btn.setAttribute('aria-checked', String(on));
    btn.classList.toggle('is-on', on);
  }
}

/** Reflect the optional-feature prefs into the switches and panels. */
function paintOptionalPrefs() {
if (el.setPgp) {
    el.setPgp.checked = uiPrefs.pgp;
    el.setPgpSign.checked = uiPrefs.pgpSign;
    el.setPgpSign.disabled = !uiPrefs.pgp;
    if (el.setPgpPass) {
      el.setPgpPass.disabled = !uiPrefs.pgp;
      el.setPgpPass.value = uiPrefs.pgpPassphrase || '';
    }
    el.pgpState.textContent = uiPrefs.pgp ? 'On' : 'Off';
    el.optPgp.classList.toggle('is-on', uiPrefs.pgp);
  }
if (el.setRelay) {
    el.setRelay.checked = uiPrefs.relay;
    el.setRelayUrl.value = uiPrefs.relayUrl || '';
    el.setRelayUrl.disabled = !uiPrefs.relay;
    el.relayState.textContent = uiPrefs.relay ? 'On' : 'Off';
    el.optRelay.classList.toggle('is-on', uiPrefs.relay);
    const live = relay?.status || 'disabled';
    el.relayConnectBtn.disabled = !uiPrefs.relay;
    el.relayDisconnectBtn.disabled = !uiPrefs.relay;
    if (live !== 'connected' && live !== 'connecting') el.relayConnectBtn.disabled = false;
  }

  // SMTP Relay (External Email Delivery)
  if (el.setSmtpRelay) {
    el.setSmtpRelay.checked = uiPrefs.smtpRelayEnabled;
    if (el.smtpRelayState) el.smtpRelayState.textContent = uiPrefs.smtpRelayEnabled ? 'On' : 'Off';
    const smtpLive = smtpRelay?.status || 'disabled';
    const smtpSec = document.getElementById('optSmtpRelay');
    if (smtpSec) smtpSec.classList.toggle('is-on', !!uiPrefs.smtpRelayEnabled);
    el.setSmtpRelayUrl.value = uiPrefs.smtpRelayUrl || '';
    el.setSmtpRelayUrl.disabled = !uiPrefs.smtpRelayEnabled;
    el.setSmtpRelayHost.value = uiPrefs.smtpRelayHost || '';
    el.setSmtpRelayHost.disabled = !uiPrefs.smtpRelayEnabled;
    el.setSmtpRelayPort.value = uiPrefs.smtpRelayPort || 587;
    el.setSmtpRelayPort.disabled = !uiPrefs.smtpRelayEnabled;
    el.setSmtpRelaySecure.value = uiPrefs.smtpRelaySecure || 'starttls';
    el.setSmtpRelaySecure.disabled = !uiPrefs.smtpRelayEnabled;
    el.setSmtpRelayUser.value = uiPrefs.smtpRelayUser || '';
    el.setSmtpRelayUser.disabled = !uiPrefs.smtpRelayEnabled;
    el.setSmtpRelayPass.value = ''; // Never restore password
    el.setSmtpRelayPass.disabled = !uiPrefs.smtpRelayEnabled;
    el.smtpRelayConnectBtn.disabled = !uiPrefs.smtpRelayEnabled || smtpLive === 'connected' || smtpLive === 'connecting';
    el.smtpRelayDisconnectBtn.disabled = !uiPrefs.smtpRelayEnabled || smtpLive === 'disabled';
    el.smtpRelayTestBtn.disabled = smtpLive !== 'connected';
  }

  // GnuPG settings
  if (el.setGpg) {
    el.setGpg.checked = uiPrefs.gpgEnabled;
    el.setGpgPath.value = uiPrefs.gpgPath || 'gpg';
    el.setGpgPath.disabled = !uiPrefs.gpgEnabled;
    el.gpgState.textContent = uiPrefs.gpgEnabled ? 'On' : 'Off';
    el.optGpg.classList.toggle('is-on', uiPrefs.gpgEnabled);
  }

  // Multi-network transports
  if (el.netDirect) el.netDirect.checked = uiPrefs.netDirect !== false;
  if (el.netTor) el.netTor.checked = !!uiPrefs.netTor;
  if (el.netI2p) el.netI2p.checked = !!uiPrefs.netI2p;
  if (el.netEnsIpfs) el.netEnsIpfs.checked = !!uiPrefs.netEnsIpfs;
  if (el.netRadicle) el.netRadicle.checked = !!uiPrefs.netRadicle;
  if (el.netYggdrasil) el.netYggdrasil.checked = !!uiPrefs.netYggdrasil;
  if (el.netNostr) el.netNostr.checked = !!uiPrefs.netNostr;
  if (el.netReticulum) el.netReticulum.checked = !!uiPrefs.netReticulum;
  if (el.netWebRTC) el.netWebRTC.checked = !!uiPrefs.netWebRTC;
  if (el.netBLE) el.netBLE.checked = !!uiPrefs.netBLE;
  if (el.netDNS) el.netDNS.checked = !!uiPrefs.netDNS;
  if (el.netSneakernet) el.netSneakernet.checked = !!uiPrefs.netSneakernet;
  if (el.netFederation) el.netFederation.checked = !!uiPrefs.netFederation;

  // Environment auto-detection and smart greying out
  const host = typeof window !== 'undefined' ? window.location.hostname || '' : '';
  const isTor = host.endsWith('.onion');
  const isI2p = host.endsWith('.i2p');
  const isEnsIpfs = host.endsWith('.eth') || host.includes('ipfs') || host.includes('limo');
  const isYgg = host.includes(':') && !host.startsWith('127.');
  const hasSpecificEnv = isTor || isI2p || isEnsIpfs || isYgg;

  if (hasSpecificEnv) {
    if (el.netTor) el.netTor.closest('label').style.opacity = isTor ? '1' : '0.4';
    if (el.netI2p) el.netI2p.closest('label').style.opacity = isI2p ? '1' : '0.4';
    if (el.netEnsIpfs) el.netEnsIpfs.closest('label').style.opacity = isEnsIpfs ? '1' : '0.4';
    if (el.netYggdrasil) el.netYggdrasil.closest('label').style.opacity = isYgg ? '1' : '0.4';
  } else {
    const multiSec = document.getElementById('optMultiNetwork');
    if (multiSec) {
      multiSec.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        const lbl = cb.closest('label');
        if (lbl) lbl.style.opacity = '1';
      });
    }
  }

  // VPN gateway / clearnet masking
  if (el.setVpn) {
    el.setVpn.checked = !!uiPrefs.vpnEnabled;
    if (el.vpnState) el.vpnState.textContent = uiPrefs.vpnEnabled ? 'On' : 'Off';
    const vpnSec = document.getElementById('optVpn');
    if (vpnSec) vpnSec.classList.toggle('is-on', !!uiPrefs.vpnEnabled);
  }
  if (el.setVpnEndpoint) {
    el.setVpnEndpoint.value = uiPrefs.vpnEndpoint || '';
    el.setVpnEndpoint.disabled = !uiPrefs.vpnEnabled;
  }
  if (el.vpnFileStatus) {
    el.vpnFileStatus.textContent = uiPrefs.vpnConfigName
      ? `Loaded: ${uiPrefs.vpnConfigName}`
      : 'No config loaded';
  }

  // Local MX Node
  if (el.setLocalMx) {
    el.setLocalMx.checked = !!uiPrefs.localMxEnabled;
    if (el.localMxState) el.localMxState.textContent = uiPrefs.localMxEnabled ? 'On' : 'Off';
    const localMxSec = document.getElementById('optLocalMx');
    if (localMxSec) localMxSec.classList.toggle('is-on', !!uiPrefs.localMxEnabled);
  }
  if (el.setLocalMxHostname) {
    el.setLocalMxHostname.value = uiPrefs.localMxHostname || '';
    el.setLocalMxHostname.disabled = !uiPrefs.localMxEnabled;
  }
  if (el.setLocalMxCert) {
    el.setLocalMxCert.disabled = !uiPrefs.localMxEnabled;
  }
  if (el.setLocalMxKey) {
    el.setLocalMxKey.disabled = !uiPrefs.localMxEnabled;
  }
  if (el.localMxCertStatus) {
    const hasCert = uiPrefs.localMxCert && uiPrefs.localMxKey;
    el.localMxCertStatus.textContent = hasCert ? 'Certificate & key loaded' : 'Not loaded';
  }
  if (el.localMxStartBtn) {
    el.localMxStartBtn.disabled = !uiPrefs.localMxEnabled || !uiPrefs.localMxHostname || !uiPrefs.localMxCert || !uiPrefs.localMxKey;
  }
  if (el.localMxStopBtn) {
    el.localMxStopBtn.disabled = !uiPrefs.localMxEnabled;
  }
  if (el.localMxTestBtn) {
    el.localMxTestBtn.disabled = !uiPrefs.localMxEnabled;
  }
  if (el.localMxStatus) {
    el.localMxStatus.textContent = uiPrefs.localMxEnabled ? 'running' : 'disabled';
  }
}

function bindOptionalEvents() {
  const netInputs = [
    ['netDirect', 'Direct / Plain WWW (80/443 TLS)'],
    ['netTor', 'Tor Onion Service'],
    ['netI2p', 'I2P Eepsite'],
    ['netEnsIpfs', 'Ethereum ENS / IPFS'],
    ['netRadicle', 'Radicle P2P'],
    ['netYggdrasil', 'Yggdrasil Mesh'],
    ['netNostr', 'Nostr Relay'],
    ['netReticulum', 'Reticulum / LXMF'],
    ['netWebRTC', 'WebRTC P2P Data Channels'],
    ['netBLE', 'Bluetooth Low Energy (BLE) Mesh'],
    ['netDNS', 'DNS TXT / CNAME Censorship Tunneling'],
    ['netSneakernet', 'USB / QR-Code Air-Gapped Sneakernet'],
    ['netFederation', 'ActivityPub / Matrix / XMPP Gateway'],
  ];
  for (const [key, label] of netInputs) {
    if (el[key]) {
      el[key].addEventListener('change', () => {
        uiPrefs[key] = el[key].checked;
        saveUiPrefs();
        toast(`${label} transport ${uiPrefs[key] ? 'ENABLED' : 'DISABLED'}`);
      });
    }
  }

  // VPN gateway / clearnet masking events
  if (el.setVpn) {
    el.setVpn.addEventListener('change', () => {
      uiPrefs.vpnEnabled = el.setVpn.checked;
      saveUiPrefs();
      paintOptionalPrefs();
      toast(uiPrefs.vpnEnabled
        ? 'VPN gateway ON — public clearnet mail will egress via your proxy IP'
        : 'VPN gateway off — public clearnet mail uses your real IP');
    });
  }
  if (el.setVpnEndpoint) {
    el.setVpnEndpoint.addEventListener('change', () => {
      uiPrefs.vpnEndpoint = el.setVpnEndpoint.value.trim();
      saveUiPrefs();
      toast(uiPrefs.vpnEndpoint ? 'VPN endpoint saved' : 'VPN endpoint cleared');
    });
  }
  if (el.setVpnFile) {
    el.setVpnFile.addEventListener('change', () => {
      const file = el.setVpnFile.files && el.setVpnFile.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        uiPrefs.vpnConfigName = file.name;
        uiPrefs.vpnConfigBody = String(reader.result || '').slice(0, 65536);
        saveUiPrefs();
        paintOptionalPrefs();
        toast(`VPN config "${file.name}" loaded locally (never uploaded)`);
      };
      reader.readAsText(file);
    });
  }

  if (el.setPgp) {
    el.setPgp.addEventListener('change', () => {
      uiPrefs.pgp = el.setPgp.checked;
      saveUiPrefs();
      paintOptionalPrefs();
      toast(uiPrefs.pgp
        ? 'Armored encryption ON — mail will refuse to send without recipient keys'
        : 'Armored encryption off — mail is sent unencrypted');
    });
el.setPgpSign.addEventListener('change', () => {
      uiPrefs.pgpSign = el.setPgpSign.checked;
      saveUiPrefs();
    });
    el.setPgpPass.addEventListener('change', () => {
      uiPrefs.pgpPassphrase = el.setPgpPass.value;
      saveUiPrefs();
    });
  }

  if (el.setRelay) {
    el.setRelay.addEventListener('change', () => {
      uiPrefs.relay = el.setRelay.checked;
      saveUiPrefs();
      paintOptionalPrefs();
      if (!uiPrefs.relay) {
        relay?.shutdown();
        relay = null;
        paintRelayStatus('disabled');
        toast('Relay off — DOM Mail is local only');
      } else {
        syncRelay();
        toast('Relay enabled — start it when you are ready');
      }
    });

    el.setRelayUrl.addEventListener('change', () => {
      uiPrefs.relayUrl = el.setRelayUrl.value.trim();
      saveUiPrefs();
      if (relay) relay.url = uiPrefs.relayUrl;
      if (uiPrefs.relay) syncRelay();
    });

    el.relayConnectBtn.addEventListener('click', () => {
      uiPrefs.relayUrl = el.setRelayUrl.value.trim();
      uiPrefs.relay = true;
      saveUiPrefs();
      el.setRelay.checked = true;
      paintOptionalPrefs();
      syncRelay();
      if (!relay?.connect()) {
        toast('Relay could not start — check the URL');
      }
    });

el.relayDisconnectBtn.addEventListener('click', () => {
      relay?.disconnect('stopped by you');
      paintOptionalPrefs();
      toast('Relay disconnected');
    });
  }

  /** OS-agnostic MX Node Setup Assistant */
  function openMxSetupAssistant() {
    const isAndroid = /Android/i.test(navigator.userAgent);
    const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
    const isMobile = isAndroid || isIOS;
    const isWindows = navigator.platform.toLowerCase().includes('win');
    const isMac = navigator.platform.toLowerCase().includes('mac');
    const isLinux = navigator.platform.toLowerCase().includes('linux');

    let instructions = '=== DOM Mail MX Node Setup Assistant ===\n\n';
    instructions += 'This guide helps you run your own local MX node.\n';
    instructions += 'Choose your platform below for tailored instructions.\n\n';
    instructions += '===========================================\n\n';

    if (isMobile) {
      instructions += '📱 MOBILE DEVICE DETECTED\n';
      instructions += 'Running an MX node directly on mobile is not recommended due to:\n';
      instructions += '  • Battery drain from persistent network services\n';
      instructions += '  • OS background execution limits\n';
      instructions += '  • Lack of static IP / port forwarding\n\n';
      instructions += 'RECOMMENDED: Run the MX node on a desktop/server and connect from mobile.\n\n';
      instructions += '--- Desktop Setup (run on your computer) ---\n\n';
    }

    instructions += '🖥️  PLATFORM-SPECIFIC INSTRUCTIONS\n\n';

    if (isWindows || navigator.userAgent.includes('Windows')) {
      instructions += '>>> WINDOWS (Docker Desktop) <<<\n\n';
      instructions += '1. Install Docker Desktop:\n';
      instructions += '   Download: https://www.docker.com/products/docker-desktop/\n\n';
      instructions += '2. Open PowerShell as Administrator and run:\n';
      instructions += '   git clone https://github.com/neohiro/domail.git\n';
      instructions += '   cd domail\n';
      instructions += '   docker compose up -d\n\n';
      instructions += '3. Verify it\'s running:\n';
      instructions += '   docker compose logs -f\n\n';
      instructions += '4. In DOM Mail settings, set Relay WebSocket URL to:\n';
      instructions += '   ws://localhost:8765/relay\n\n';
    } else if (isMac) {
      instructions += '>>> macOS (Docker Desktop or Colima) <<<\n\n';
      instructions += 'Option A: Docker Desktop (easiest)\n';
      instructions += '   Download: https://www.docker.com/products/docker-desktop/\n\n';
      instructions += 'Option B: Colima (lightweight, CLI-only)\n';
      instructions += '   brew install colima docker docker-compose\n';
      instructions += '   colima start\n\n';
      instructions += 'Then for either option:\n';
      instructions += '   git clone https://github.com/neohiro/domail.git\n';
      instructions += '   cd domail\n';
      instructions += '   docker compose up -d\n\n';
      instructions += '4. In DOM Mail settings, set Relay WebSocket URL to:\n';
      instructions += '   ws://localhost:8765/relay\n\n';
    } else if (isLinux) {
      instructions += '>>> LINUX (Docker Engine or Podman) <<<\n\n';
      instructions += 'Option A: Docker Engine\n';
      instructions += '   sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin\n\n';
      instructions += 'Option B: Podman (rootless, daemonless)\n';
      instructions += '   sudo apt-get install -y podman podman-compose\n\n';
      instructions += 'Then for either option:\n';
      instructions += '   git clone https://github.com/neohiro/domail.git\n';
      instructions += '   cd domail\n';
      instructions += '   docker compose up -d\n';
      instructions += '   # Or with Podman: podman-compose up -d\n\n';
      instructions += '4. In DOM Mail settings, set Relay WebSocket URL to:\n';
      instructions += '   ws://localhost:8765/relay\n\n';
    } else {
      instructions += '>>> GENERIC / UNKNOWN PLATFORM <<<\n\n';
      instructions += '1. Install Docker: https://docs.docker.com/get-docker/\n';
      instructions += '2. Clone and run:\n';
      instructions += '   git clone https://github.com/neohiro/domail.git\n';
      instructions += '   cd domail\n';
      instructions += '   docker compose up -d\n\n';
      instructions += '3. In DOM Mail settings, set Relay WebSocket URL to:\n';
      instructions += '   ws://localhost:8765/relay\n\n';
    }

    instructions += '===========================================\n';
    instructions += '📋 ALTERNATIVE: CLI SMTP Bridge (no Docker)\n\n';
    instructions += 'If you prefer not to use Docker, run the built-in bridge:\n\n';
    instructions += '   node tools/smtp-bridge.mjs \\\n';
    instructions += '     --server smtp.yourprovider.com \\\n';
    instructions += '     --port 587 \\\n';
    instructions += '     --mode starttls \\\n';
    instructions += '     --from your@email.com \\\n';
    instructions += '     --user your@email.com \\\n';
    instructions += '     --pass "your-app-password"\n\n';
    instructions += 'This connects directly to your SMTP provider without a full MX node.\n\n';

    instructions += '===========================================\n';
    instructions += '🔗 PORT FORWARDING (for inbound mail)\n\n';
    instructions += 'To receive external email, forward port 25 on your router to the\n';
    instructions += 'machine running the MX node. See your router\'s manual for instructions.\n\n';

    instructions += '===========================================\n';
    instructions += '📚 FULL DOCUMENTATION\n\n';
    instructions += '• GitHub: https://github.com/neohiro/domail\n';
    instructions += '• NETWORKS.md for Tor/I2P/Yggdrasil deployments\n';
    instructions += '• README.md for complete setup guide\n\n';

    // Create a modal dialog with the instructions
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
      position: fixed; inset: 0; background: rgba(0,0,0,0.7);
      display: flex; align-items: center; justify-content: center;
      z-index: 10000; padding: 1rem; overflow: auto;
    `;
    modal.innerHTML = `
      <div style="background: var(--bg-elevated, #1e1e1e); color: var(--fg, #fff);
                  max-width: 700px; max-height: 90vh; width: 90%;
                  border-radius: 8px; padding: 1.5rem; overflow: auto;
                  font-family: monospace; white-space: pre-wrap;
                  border: 1px solid var(--border, #333);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h2 style="margin: 0;">MX Node Setup Assistant</h2>
          <button id="mxSetupClose" style="background: none; border: none; color: var(--fg, #fff); font-size: 1.5rem; cursor: pointer;">&times;</button>
        </div>
        <pre style="margin: 0; overflow: auto; max-height: 70vh;">${instructions}</pre>
        <div style="margin-top: 1rem; display: flex; gap: 0.5rem; justify-content: flex-end;">
          <button id="mxSetupCopy" class="pill">Copy to Clipboard</button>
          <button id="mxSetupGitHub" class="pill">Open GitHub</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelector('#mxSetupClose').addEventListener('click', () => modal.remove());
    modal.querySelector('#mxSetupCopy').addEventListener('click', () => {
      navigator.clipboard.writeText(instructions).then(() => {
        toast('Instructions copied to clipboard');
      });
    });
    modal.querySelector('#mxSetupGitHub').addEventListener('click', () => {
      window.open('https://github.com/neohiro/domail', '_blank');
    });

    // Close on overlay click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });

    // Add script download buttons after modal is in DOM
    const buttonContainer = modal.querySelector('div[style*="justify-content: flex-end"]');
    if (buttonContainer) {
      const scriptButtons = document.createElement('div');
      scriptButtons.style.cssText = 'margin-top: 0.5rem; display: flex; gap: 0.5rem; justify-content: flex-end; flex-wrap: wrap;';
      
      // Generate and add platform-specific script download buttons
      const platformScripts = generatePlatformScripts(isWindows, isMac, isLinux, isMobile);
      for (const [label, script, filename, mimeType] of platformScripts) {
        const btn = document.createElement('button');
        btn.className = 'pill';
        btn.textContent = `Download ${label}`;
        btn.addEventListener('click', () => {
          const blob = new Blob([script], { type: mimeType });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          a.click();
          URL.revokeObjectURL(url);
          toast(`${label} downloaded`);
        });
        scriptButtons.appendChild(btn);
      }
      buttonContainer.appendChild(scriptButtons);
    }

    // Add Port 25 Reachability Test section
    const testSection = document.createElement('div');
    testSection.style.cssText = 'margin-top: 1rem; padding: 1rem; background: var(--bg, #111); border-radius: 4px; border: 1px solid var(--border, #333);';
    testSection.innerHTML = `
      <h3 style="margin: 0 0 0.5rem 0;">🔍 Port 25 Reachability Test</h3>
      <p style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: var(--fg-muted, #888);">
        Test if your public IP can receive inbound SMTP on port 25. Requires a connected relay with port-check capability.
      </p>
      <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
        <button id="mxPort25Test" class="pill" disabled>Test Port 25</button>
        <span id="mxPort25Result" style="align-self: center; font-size: 0.9rem;"></span>
      </div>
    `;
    modal.querySelector('div[style*="max-height: 90vh"]').appendChild(testSection);

    const port25Btn = modal.querySelector('#mxPort25Test');
    const port25Result = modal.querySelector('#mxPort25Result');
    
    // Enable test button if relay is connected
    if (smtpRelay && smtpRelay.status === 'connected') {
      port25Btn.disabled = false;
    }
    
    port25Btn.addEventListener('click', async () => {
      port25Btn.disabled = true;
      port25Btn.textContent = 'Testing...';
      port25Result.textContent = '';
      
      try {
        const result = await testPort25Reachability();
        if (result.reachable) {
          port25Result.textContent = `✅ Port 25 reachable! (latency: ${result.latency}ms)`;
          port25Result.style.color = 'var(--success, #4caf50)';
        } else {
          port25Result.textContent = `❌ Port 25 not reachable: ${result.error || 'Connection refused or timeout'}`;
          port25Result.style.color = 'var(--error, #f44336)';
        }
      } catch (e) {
        port25Result.textContent = `❌ Test failed: ${e.message}`;
        port25Result.style.color = 'var(--error, #f44336)';
      } finally {
        port25Btn.disabled = false;
        port25Btn.textContent = 'Test Port 25';
      }
    });

    // Listen for relay connection changes to enable/disable test button
    const relayStatusHandler = (status) => {
      if (port25Btn) {
        port25Btn.disabled = status !== 'connected';
      }
    };
    if (smtpRelay) {
      smtpRelay.addStatusListener?.(relayStatusHandler);
      // Clean up listener when modal closes
      const originalClose = modal.querySelector('#mxSetupClose').onclick;
      modal.querySelector('#mxSetupClose').onclick = () => {
        if (smtpRelay) smtpRelay.removeStatusListener?.(relayStatusHandler);
        modal.remove();
      };
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          if (smtpRelay) smtpRelay.removeStatusListener?.(relayStatusHandler);
          modal.remove();
        }
      });
    }
  }
  function generatePlatformScripts(isWindows, isMac, isLinux, isMobile) {
    const scripts = [];
    const baseCommands = {
      clone: 'git clone https://github.com/neohiro/domail.git',
      cd: 'cd domail',
      up: 'docker compose up -d',
      logs: 'docker compose logs -f',
    };

    if (isWindows) {
      const ps1 = `# DOM Mail MX Node Setup Script for Windows (PowerShell)
# Run as Administrator

Write-Host "=== DOM Mail MX Node Setup for Windows ===" -ForegroundColor Cyan

# Check for Docker Desktop
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Warning "Docker not found. Please install Docker Desktop first:"
    Write-Host "  https://www.docker.com/products/docker-desktop/"
    exit 1
}

Write-Host "Cloning DOM Mail repository..." -ForegroundColor Green
${baseCommands.clone}
${baseCommands.cd}

Write-Host "Starting MX node with Docker Compose..." -ForegroundColor Green
${baseCommands.up}

Write-Host "Waiting for services to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "Checking service status..." -ForegroundColor Green
${baseCommands.logs}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "In DOM Mail settings, set Relay WebSocket URL to:"
Write-Host "  ws://localhost:8765/relay"
Write-Host ""
Write-Host "For inbound mail, forward port 25 on your router to this machine."
`;
      scripts.push(['PowerShell Script', ps1, 'mx-setup.ps1', 'text/plain']);
    } else if (isMac) {
      const sh = `#!/bin/bash
# DOM Mail MX Node Setup Script for macOS

echo "=== DOM Mail MX Node Setup for macOS ==="

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Install Docker Desktop or Colima:"
    echo "  Docker Desktop: https://www.docker.com/products/docker-desktop/"
    echo "  Colima: brew install colima docker docker-compose && colima start"
    exit 1
fi

echo "Cloning DOM Mail repository..."
${baseCommands.clone}
${baseCommands.cd}

echo "Starting MX node with Docker Compose..."
${baseCommands.up}

echo "Waiting for services to start..."
sleep 5

echo "Checking service status..."
${baseCommands.logs}

echo ""
echo "=== Setup Complete ==="
echo "In DOM Mail settings, set Relay WebSocket URL to:"
echo "  ws://localhost:8765/relay"
echo ""
echo "For inbound mail, forward port 25 on your router to this machine."
`;
      scripts.push(['macOS Shell Script', sh, 'mx-setup.sh', 'text/x-sh']);
    } else if (isLinux) {
      const sh = `#!/bin/bash
# DOM Mail MX Node Setup Script for Linux

echo "=== DOM Mail MX Node Setup for Linux ==="

# Check for Docker or Podman
if command -v docker &> /dev/null; then
    DOCKER_CMD="docker compose"
elif command -v podman &> /dev/null; then
    DOCKER_CMD="podman-compose"
    echo "Using Podman..."
else
    echo "Neither Docker nor Podman found. Install one:"
    echo "  Docker: sudo apt-get install -y docker.io docker-compose-plugin"
    echo "  Podman: sudo apt-get install -y podman podman-compose"
    exit 1
fi

echo "Cloning DOM Mail repository..."
${baseCommands.clone}
${baseCommands.cd}

echo "Starting MX node with \${DOCKER_CMD}..."
\${DOCKER_CMD} up -d

echo "Waiting for services to start..."
sleep 5

echo "Checking service status..."
\${DOCKER_CMD} logs -f

echo ""
echo "=== Setup Complete ==="
echo "In DOM Mail settings, set Relay WebSocket URL to:"
echo "  ws://localhost:8765/relay"
echo ""
echo "For inbound mail, forward port 25 on your router to this machine."
`;
      scripts.push(['Linux Shell Script', sh, 'mx-setup.sh', 'text/x-sh']);
    } else {
      const sh = `#!/bin/bash
# DOM Mail MX Node Setup Script (Generic)

echo "=== DOM Mail MX Node Setup ==="

if ! command -v docker &> /dev/null; then
    echo "Docker not found. Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "Cloning DOM Mail repository..."
${baseCommands.clone}
${baseCommands.cd}

echo "Starting MX node with Docker Compose..."
${baseCommands.up}

echo "Waiting for services to start..."
sleep 5

echo "Checking service status..."
${baseCommands.logs}

echo ""
echo "=== Setup Complete ==="
echo "In DOM Mail settings, set Relay WebSocket URL to:"
echo "  ws://localhost:8765/relay"
echo ""
echo "For inbound mail, forward port 25 on your router to this machine."
`;
      scripts.push(['Generic Shell Script', sh, 'mx-setup.sh', 'text/x-sh']);
    }

    // Always include CLI bridge script as alternative
    const bridgeSh = `#!/bin/bash
# DOM Mail CLI SMTP Bridge - Alternative to full MX node
# Usage: ./smtp-bridge.sh <server> <port> <mode> <from> <user> <pass>

set -e

SERVER="\${1:-smtp.yourprovider.com}"
PORT="\${2:-587}"
MODE="\${3:-starttls}"
FROM="\${4:-your@email.com}"
USER="\${5:-\$FROM}"
PASS="\${6}"

if [ -z "\$PASS" ]; then
    echo "Usage: \$0 <server> <port> <mode> <from> <user> <pass>"
    echo "Example: \$0 smtp.gmail.com 587 starttls you@gmail.com you@gmail.com 'app-password'"
    exit 1
fi

echo "Starting SMTP bridge to \$SERVER:\$PORT (\$MODE)..."
node tools/smtp-bridge.mjs \\
  --server "\$SERVER" \\
  --port "\$PORT" \\
  --mode "\$MODE" \\
  --from "\$FROM" \\
  --user "\$USER" \\
  --pass "\$PASS"
`;
    scripts.push(['CLI Bridge Script', bridgeSh, 'smtp-bridge.sh', 'text/x-sh']);

    return scripts;
  }

  /** Test if port 25 is reachable from the public internet via relay */
  async function testPort25Reachability() {
    if (!smtpRelay || smtpRelay.status !== 'connected') {
      throw new Error('No relay connected. Start the relay first to test port 25.');
    }
    
    return new Promise((resolve, reject) => {
      const timeout = 10000;
      const timer = setTimeout(() => {
        reject(new Error('Port 25 test timeout'));
      }, timeout);
      
      const subId = 'port25_test_' + Math.random().toString(36).slice(2, 8);
      const start = Date.now();
      
      const handler = (frame) => {
        if (frame && frame.type === 'port25_result' && frame.id === subId) {
          clearTimeout(timer);
          smtpRelay.removeMessageListener(handler);
          const latency = Date.now() - start;
          if (frame.reachable) {
            resolve({ reachable: true, latency });
          } else {
            resolve({ reachable: false, latency, error: frame.error });
          }
        }
      };
      
      smtpRelay.addMessageListener(handler);
      
      smtpRelay.socket?.send(JSON.stringify({
        type: 'port25_test',
        id: subId,
      }));
    });
  }

  // SMTP Relay (external email delivery)
  if (el.setSmtpRelay) {
    el.setSmtpRelay.addEventListener('change', () => {
      uiPrefs.smtpRelayEnabled = el.setSmtpRelay.checked;
      saveUiPrefs();
      paintOptionalPrefs();
      if (!uiPrefs.smtpRelayEnabled) {
        smtpRelay?.shutdown?.();
        smtpRelay = null;
        // Clear password from memory
        uiPrefs.smtpRelayPass = '';
        if (el.setSmtpRelayPass) el.setSmtpRelayPass.value = '';
        paintSmtpRelayStatus('disabled');
        toast('SMTP relay off — external delivery disabled');
      } else {
        const useOwn = confirm(
          'External Email Delivery Notice:\n\n' +
          'Using an online external relay shares delivery metadata with that operator.\n' +
          'We strongly recommend running your own local MX node for complete privacy.\n\n' +
          'Click OK to open the OS-agnostic MX Setup Assistant, or Cancel to use Nostr decentralized relay discovery.'
        );
        if (useOwn) {
          openMxSetupAssistant();
          uiPrefs.smtpRelayEnabled = false;
          el.setSmtpRelay.checked = false;
          saveUiPrefs();
          paintOptionalPrefs();
          return;
        } else {
          toast('Using Nostr decentralized relay discovery for SMTP bridging...');
        }
        syncSmtpRelay();
        toast('SMTP relay enabled — configure and connect');
      }
    });

    el.setSmtpRelayUrl.addEventListener('change', () => {
      uiPrefs.smtpRelayUrl = el.setSmtpRelayUrl.value.trim();
      saveUiPrefs();
      if (smtpRelay) smtpRelay.url = uiPrefs.smtpRelayUrl;
      if (uiPrefs.smtpRelayEnabled) syncSmtpRelay();
    });

    el.setSmtpRelayHost.addEventListener('change', () => {
      uiPrefs.smtpRelayHost = el.setSmtpRelayHost.value.trim();
      saveUiPrefs();
    });
    el.setSmtpRelayPort.addEventListener('change', () => {
      uiPrefs.smtpRelayPort = parseInt(el.setSmtpRelayPort.value) || 587;
      saveUiPrefs();
    });
    el.setSmtpRelaySecure.addEventListener('change', () => {
      uiPrefs.smtpRelaySecure = el.setSmtpRelaySecure.value;
      saveUiPrefs();
    });
    el.setSmtpRelayUser.addEventListener('change', () => {
      uiPrefs.smtpRelayUser = el.setSmtpRelayUser.value.trim();
      saveUiPrefs();
    });
    el.setSmtpRelayPass.addEventListener('change', () => {
      // Password only kept in memory, not saved to localStorage
      uiPrefs.smtpRelayPass = el.setSmtpRelayPass.value;
    });

    el.smtpRelayConnectBtn.addEventListener('click', () => {
      uiPrefs.smtpRelayUrl = el.setSmtpRelayUrl.value.trim();
      uiPrefs.smtpRelayEnabled = true;
      saveUiPrefs();
      el.setSmtpRelay.checked = true;
      paintOptionalPrefs();
      syncSmtpRelay();
      if (!smtpRelay?.connect()) {
        toast('SMTP relay could not start — check the URL');
      }
    });

    el.smtpRelayDisconnectBtn.addEventListener('click', () => {
      smtpRelay?.disconnect?.('stopped by you');
      // Clear password from memory
      uiPrefs.smtpRelayPass = '';
      el.setSmtpRelayPass.value = '';
      paintOptionalPrefs();
      toast('SMTP relay disconnected');
    });

    el.smtpRelayTestBtn.addEventListener('click', async () => {
      if (!smtpRelay || smtpRelay.status !== 'connected') {
        toast('SMTP relay not connected');
        return;
      }
      // Send a test config frame to verify SMTP credentials
      const testConfig = buildSmtpRelayConfig();
      if (!testConfig) {
        toast('Incomplete SMTP configuration');
        return;
      }
      try {
        smtpRelay.socket?.send(JSON.stringify({ type: 'config', config: testConfig }));
        toast('Test config sent to relay');
      } catch (e) {
        toast(`Test failed: ${e.message}`);
      }
    });
  }

  // Local MX Node events
  if (el.setLocalMx) {
    el.setLocalMx.addEventListener('change', () => {
      uiPrefs.localMxEnabled = el.setLocalMx.checked;
      saveUiPrefs();
      paintOptionalPrefs();
      toast(uiPrefs.localMxEnabled
        ? 'Local MX Node enabled — configure hostname and certificates'
        : 'Local MX Node disabled');
    });
  }
  if (el.setLocalMxHostname) {
    el.setLocalMxHostname.addEventListener('change', () => {
      uiPrefs.localMxHostname = el.setLocalMxHostname.value.trim();
      saveUiPrefs();
      paintOptionalPrefs();
    });
  }
  if (el.setLocalMxCert) {
    el.setLocalMxCert.addEventListener('change', () => {
      const file = el.setLocalMxCert.files && el.setLocalMxCert.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        uiPrefs.localMxCert = String(reader.result || '').slice(0, 65536);
        saveUiPrefs();
        paintOptionalPrefs();
        toast('TLS certificate loaded (memory only)');
      };
      reader.readAsText(file);
    });
  }
  if (el.setLocalMxKey) {
    el.setLocalMxKey.addEventListener('change', () => {
      const file = el.setLocalMxKey.files && el.setLocalMxKey.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        uiPrefs.localMxKey = String(reader.result || '').slice(0, 65536);
        saveUiPrefs();
        paintOptionalPrefs();
        toast('TLS private key loaded (memory only)');
      };
      reader.readAsText(file);
    });
  }
  if (el.localMxStartBtn) {
    el.localMxStartBtn.addEventListener('click', async () => {
      if (!uiPrefs.localMxHostname || !uiPrefs.localMxCert || !uiPrefs.localMxKey) {
        toast('Configure hostname, certificate, and key first');
        return;
      }
      uiPrefs.localMxEnabled = true;
      saveUiPrefs();
      paintOptionalPrefs();
      await startLocalMxNode();
    });
  }
  if (el.localMxStopBtn) {
    el.localMxStopBtn.addEventListener('click', async () => {
      await stopLocalMxNode();
      uiPrefs.localMxEnabled = false;
      saveUiPrefs();
      paintOptionalPrefs();
      toast('Local MX Node stopped');
    });
  }
  if (el.localMxTestBtn) {
    el.localMxTestBtn.addEventListener('click', async () => {
      await testLocalMxConnectivity();
    });
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
    screenProtection = createScreenProtection({ 
      respectShowFullIdentity: true,
      getShowFullIdentity: () => uiPrefs.showFullIdentity
    });
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
  renderIdentity();
  el.keyView.textContent = publicKeyBlock(identity);
  toast(`Identity created: ${maskAddress(identity.address)}`);
  await refreshAll();
  startPolling();
}

function showPage(name) {
  const validPages = ['compose', 'inbox', 'outbox', 'drafts', 'settings', 'wipe'];
  if (!validPages.includes(name)) return;
  currentPage = name;
  for (const tab of el.tabs) {
    tab.setAttribute('aria-selected', String(tab.dataset.page === name));
  }
  // Mobile bottom nav sync
  if (el.mobileTabs) {
    for (const tab of el.mobileTabs) {
      tab.setAttribute('aria-selected', String(tab.dataset.page === name));
    }
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
    li.dataset.flagged = String(!!m.flagged);
    const who = displayAddrList(box === 'inbox' ? m.from : m.to);
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

  // Learn the sender's key from any DOM Mail identity block they sent, so we
  // can reply to them encrypted later. No key server involved.
  for (const a of m.from || []) rememberPgpKey(a);

  const crypto = await tryDecryptRecord(m);

  const div = document.createElement('div');
  div.className = 'reader';
  const who = displayAddrList(box === 'inbox' ? m.from : m.to);
  const body = m.bodyIsHtml
    ? sanitizeHtml(m.bodyText)
    : escapeHtml(m.bodyText || '').replace(/\n/g, '<br>');

div.innerHTML = `
    <h2>${escapeHtml(m.subject || '(no subject)')}</h2>
    <p class="meta">${escapeHtml(who)} &middot; ${new Date(m.date).toLocaleString()}</p>
    ${crypto ? `<p class="crypto-tag${/INVALID|no key|WRONG|needed/.test(crypto) ? ' crypto-tag--bad' : ''}">${escapeHtml(crypto)}</p>` : ''}
    <details class="hdr">
      <summary>Message details</summary>
      <dl class="hdr-list">
        ${headerRows(m)}
      </dl>
    </details>
    <div class="body">${body}</div>
    <div class="acts">
      ${box === 'inbox' ? '<button class="pill" data-act="reply" type="button">Reply</button>' : ''}
      <button class="pill" data-act="flag" type="button">${m.flagged ? 'Unflag' : 'Flag'}</button>
      <button class="pill" data-act="toggle-read" type="button">${m.read ? 'Mark unread' : 'Mark read'}</button>
      ${box !== 'inbox' ? '<button class="pill" data-act="reply" type="button">Reply</button>' : ''}
      <button class="pill" data-act="delete" type="button">Delete</button>
      <button class="pill" data-act="close" type="button">Close</button>
    </div>
  `;

  // Persist a per-message flag/read change back into the mailbox.
  const patchRecord = async (changes) => {
    const rows = await engine.list(box);
    const i = rows.findIndex((r) => r.id === id);
    if (i === -1) return;
    Object.assign(rows[i], changes);
    await engine.store.set(`mbox:${box}`, rows);
    await refreshList(box);
  };

  div.querySelector('[data-act="flag"]').addEventListener('click', async () => {
    await patchRecord({ flagged: !m.flagged });
    closeReader();
    toast(m.flagged ? 'Flag removed' : 'Flagged');
  });

  div.querySelector('[data-act="toggle-read"]').addEventListener('click', async () => {
    await patchRecord({ read: !m.read });
    closeReader();
    toast(m.read ? 'Marked unread' : 'Marked read');
  });

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

/*
 * Compose is a page, not a modal (the legacy modal was removed: it duplicated
 * every element ID, so querySelector silently bound the app to a hidden copy).
 * Reply threading therefore lives in a variable rather than a data attribute.
 */
function openCompose(opts = {}) {
  composeOpen = true;
  composeDraftId = opts.draftId ?? null;
  composeDirty = false;
  composeAttachments = [];
  composeReplyTo = opts.inReplyTo || '';

  el.cTo.value = addrListLabel(opts.to || []);
  el.cCc.value = opts.cc || '';
  el.cBcc.value = opts.bcc || '';
  el.cSubject.value = opts.subject || '';
  // Sanitize draft body to prevent XSS from imported drafts
  el.editor.innerHTML = opts.body ? sanitizeHtml(opts.body) : '';
  el.draftState.textContent = composeDraftId ? 'editing saved draft' : 'draft autosaves';

  if (el.sendNetDirect) el.sendNetDirect.checked = uiPrefs.netDirect !== false;
  if (el.sendNetTor) el.sendNetTor.checked = !!uiPrefs.netTor;
  if (el.sendNetI2p) el.sendNetI2p.checked = !!uiPrefs.netI2p;
  if (el.sendNetEnsIpfs) el.sendNetEnsIpfs.checked = !!uiPrefs.netEnsIpfs;
  if (el.sendNetRadicle) el.sendNetRadicle.checked = !!uiPrefs.netRadicle;
  if (el.sendNetYggdrasil) el.sendNetYggdrasil.checked = !!uiPrefs.netYggdrasil;
  if (el.sendNetNostr) el.sendNetNostr.checked = !!uiPrefs.netNostr;
  if (el.sendNetReticulum) el.sendNetReticulum.checked = !!uiPrefs.netReticulum;
  if (el.sendNetWebRTC) el.sendNetWebRTC.checked = !!uiPrefs.netWebRTC;
  if (el.sendNetBLE) el.sendNetBLE.checked = !!uiPrefs.netBLE;
  if (el.sendNetDNS) el.sendNetDNS.checked = !!uiPrefs.netDNS;
  if (el.sendNetSneakernet) el.sendNetSneakernet.checked = !!uiPrefs.netSneakernet;
  if (el.sendNetFederation) el.sendNetFederation.checked = !!uiPrefs.netFederation;

  showPage('compose');
  el.cTo.focus();
  scheduleAutosave();
}

/** Clear the composer so the next message never inherits the previous one. */
function resetComposeFields() {
  el.cTo.value = '';
  el.cCc.value = '';
  el.cBcc.value = '';
  el.cSubject.value = '';
  el.editor.innerHTML = '';
  el.draftState.textContent = 'draft autosaves';
  composeAttachments = [];
  composeReplyTo = '';
  hideContactSuggest();
  if (el.emoji) el.emoji.hidden = true;
}

function closeCompose() {
  if (composeOpen && composeDirty) saveDraft();
  composeOpen = false;
  composeDirty = false;
  composeDraftId = null;
  clearTimeout(autosaveTimer);
  resetComposeFields();
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
      inReplyTo: composeReplyTo,
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

/* ------------------------------------------------------------------ *
 * optional: armored encryption (PGP) and WebSocket relay
 *
 * Both are opt-in and default OFF. The relay is constructed lazily so that
 * simply loading the app performs no network activity whatsoever.
 * ------------------------------------------------------------------ */

/**
 * If a received body is one of our armored messages and we hold the key,
 * decrypt it in place. Returns a short label for the UI, or null.
 */
async function tryDecryptRecord(record) {
  if (!record?.bodyText || !/-----BEGIN PGP MESSAGE-----/.test(record.bodyText)) return null;

  // Passphrase mode: ask for the shared secret, then open.
  if (isPassphraseMessage(record.bodyText)) {
    const pass = window.prompt('This message is passphrase-protected.\nEnter the passphrase:');
    if (!pass) return 'encrypted · passphrase needed';
    try {
      const { text } = await decryptWithPassphrase(record.bodyText, pass);
      record.bodyText = text;
      record.bodyIsHtml = false;
      record.decrypted = true;
      return 'encrypted · passphrase accepted';
    } catch {
      return 'encrypted · WRONG PASSPHRASE';
    }
  }

  if (!engine?.identity?.x25519) return 'encrypted · no local key';
  try {
    const { text, signed, signatureValid } = await decryptMessage(
      record.bodyText,
      fromBase64(engine.identity.x25519),
      fromBase64(engine.identity.x25519),
    );
    record.bodyText = text;
    record.bodyIsHtml = false;
    record.decrypted = true;
    record.signed = signed;
    record.signatureValid = signatureValid;
    return signed
      ? (signatureValid ? 'encrypted · signature verified' : 'encrypted · SIGNATURE INVALID')
      : 'encrypted · decrypted';
  } catch {
    return 'encrypted · no key for this message';
  }
}

/** Build (or tear down) the relay client to match the current prefs. */
function syncRelay() {
  if (!uiPrefs.relay) {
    if (relay) {
      relay.shutdown();
      relay = null;
    }
    paintRelayStatus('disabled');
    return;
  }
  if (!relay) {
    relay = createRelayClient({
      enabled: true,
      url: uiPrefs.relayUrl,
      onStatus: (status, detail) => {
        paintRelayStatus(status, detail);
        if (status === 'connected' && engine?.identity) {
          relay?.setIdentity(engine.identity);
          relay?.connect(); // completes the hello with the address
        }
      },
      onMessage: (frame) => { void ingestRelayMail(frame); },
      onError: (err) => {
        paintRelayStatus('error', err?.message);
        toast(`Relay: ${err.message}`);
      },
    });
  }
  relay.enabled = true;
  relay.url = uiPrefs.relayUrl;
  if (engine?.identity) relay.setIdentity(engine.identity);
}

function paintRelayStatus(status, detail) {
  if (!el.relayStatus) return;
  el.relayStatus.dataset.state = status;
  el.relayStatus.textContent = detail ? `${status} — ${detail}` : status;
  el.relayStatus.title = detail || '';
}

/** Deliver a mail frame pushed by the relay into the inbox. */
async function ingestRelayMail(frame) {
  if (!engine || !frame?.mail?.raw) return;
  try {
    await engine.deliver(frame.mail.raw);
    await refreshAll();
    toast(`Relay: received “${frame.mail.subject || '(no subject)'}”`);
  } catch (e) {
    console.error('relay ingest failed:', e);
    toast('Relay: could not deliver the message');
  }
}

/** Push a sent message to the relay, if enabled. Never blocks the send path. */
function publishToRelay(record) {
  if (!record?.raw) return;
  // WebSocket relay (for domail-to-domail)
  if (uiPrefs.relay && relay) {
    const res = relay.publish({
      subject: record.subject || '',
      from: record.from?.[0]?.address || null,
      to: (record.to || []).map((a) => a.address),
      raw: record.raw,
    });
    if (res.queued) toast(`Relay offline — ${res.depth} message(s) queued`);
  }
  // SMTP relay (for external email delivery)
  if (uiPrefs.smtpRelayEnabled && smtpRelay) {
    const res = smtpRelay.publish({
      subject: record.subject || '',
      from: record.from?.[0]?.address || null,
      to: [
        ...(record.to || []).map((a) => a.address),
        ...(record.cc || []).map((a) => a.address),
        ...(record.bcc || []).map((a) => a.address),
      ],
      raw: record.raw,
    });
    if (res.queued) toast(`SMTP relay offline — ${res.depth} message(s) queued`);
  }
}

/* -------------------- SMTP Relay (External Email) -------------------- */

let smtpRelay = null;

/** Build SMTP relay config from current prefs. */
function buildSmtpRelayConfig() {
  if (!uiPrefs.smtpRelayEnabled) return null;
  if (!uiPrefs.smtpRelayUrl) return null;
  if (!uiPrefs.smtpRelayHost) return null;
  if (!uiPrefs.smtpRelayUser) return null;
  if (!uiPrefs.smtpRelayPass) return null;
  const port = Number(uiPrefs.smtpRelayPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return {
    smtp: {
      host: uiPrefs.smtpRelayHost,
      port,
      secure: uiPrefs.smtpRelaySecure === 'implicit',
      starttls: uiPrefs.smtpRelaySecure === 'starttls',
      user: uiPrefs.smtpRelayUser,
      pass: uiPrefs.smtpRelayPass,
    },
  };
}

/** Build (or tear down) the SMTP relay client. */
function syncSmtpRelay() {
  if (!uiPrefs.smtpRelayEnabled) {
    if (smtpRelay) {
      smtpRelay.shutdown?.();
      smtpRelay = null;
      // Clear password from memory
      uiPrefs.smtpRelayPass = '';
      if (el.setSmtpRelayPass) el.setSmtpRelayPass.value = '';
    }
    paintSmtpRelayStatus('disabled');
    return;
  }
  if (!uiPrefs.smtpRelayUrl) {
    paintSmtpRelayStatus('error', 'no relay URL');
    return;
  }
if (!smtpRelay) {
    smtpRelay = createRelayClient({
      enabled: true,
      url: uiPrefs.smtpRelayUrl,
      onStatus: (status, detail) => {
        paintSmtpRelayStatus(status, detail);
        if (status === 'connected' && engine?.identity) {
          smtpRelay?.setIdentity(engine.identity);
          // Send SMTP config to relay after connection
          const config = buildSmtpRelayConfig();
          if (config) {
            smtpRelay?.socket?.send(JSON.stringify({ type: 'config', config }));
          }
        }
      },
      onMessage: (frame) => { void ingestRelayMail(frame); },
      onError: (err) => {
        paintSmtpRelayStatus('error', err?.message);
        toast(`SMTP Relay: ${err.message}`);
      },
    });
  }
  smtpRelay.enabled = true;
  smtpRelay.url = uiPrefs.smtpRelayUrl;
  if (engine?.identity) smtpRelay.setIdentity(engine.identity);
  // Initiate connection
  smtpRelay.connect();
}

function paintSmtpRelayStatus(status, detail) {
  if (!el.smtpRelayStatus) return;
  el.smtpRelayStatus.dataset.state = status;
  el.smtpRelayStatus.textContent = detail ? `${status} — ${detail}` : status;
  el.smtpRelayStatus.title = detail || '';
  // Update button states
  if (el.smtpRelayConnectBtn) el.smtpRelayConnectBtn.disabled = status === 'connected' || status === 'connecting';
  if (el.smtpRelayDisconnectBtn) el.smtpRelayDisconnectBtn.disabled = status === 'disabled' || status === 'error';
if (el.smtpRelayTestBtn) el.smtpRelayTestBtn.disabled = status !== 'connected';
}

/* -------------------- Local MX Node (In-Browser Mail Server) -------------------- */

let localMxNode = null;

/** Start the local MX node using WebAssembly SMTP/IMAP server. */
async function startLocalMxNode() {
  if (!uiPrefs.localMxEnabled) return;
  if (!uiPrefs.localMxHostname || !uiPrefs.localMxCert || !uiPrefs.localMxKey) {
    toast('Missing hostname, certificate, or key');
    return;
  }

  // Validate PEM format before attempting to start
  const certValid = uiPrefs.localMxCert.includes('-----BEGIN CERTIFICATE-----') && uiPrefs.localMxCert.includes('-----END CERTIFICATE-----');
  const keyValid = uiPrefs.localMxKey.includes('-----BEGIN PRIVATE KEY-----') || uiPrefs.localMxKey.includes('-----BEGIN RSA PRIVATE KEY-----');
  if (!certValid || !keyValid) {
    toast('Invalid certificate or key format (must be PEM)');
    return;
  }

  try {
    el.localMxStatus.textContent = 'starting…';
    el.localMxStartBtn.disabled = true;

    // Dynamic import of the WASM MX node module
    const { createLocalMxNode } = await import('../../core/local-mx.mjs');
    
    localMxNode = createLocalMxNode({
      hostname: uiPrefs.localMxHostname,
      certPem: uiPrefs.localMxCert,
      keyPem: uiPrefs.localMxKey,
      identity: engine?.identity,
      onStatus: (status, detail) => {
        paintLocalMxStatus(status, detail);
      },
      onInboundMail: async (rawMessage) => {
        if (engine) {
          await engine.deliver(rawMessage);
          await refreshAll();
          toast(`MX Node: received new mail`);
        }
      },
      onError: (err) => {
        paintLocalMxStatus('error', err?.message);
        toast(`MX Node error: ${err.message}`);
      },
    });

    await localMxNode.start();
    paintLocalMxStatus('running', 'MX node active on ports 25/587/993');
    toast('Local MX Node started — ready to send/receive mail worldwide');
  } catch (e) {
    paintLocalMxStatus('error', e?.message);
    toast(`Failed to start MX Node: ${e.message}`);
    el.localMxStartBtn.disabled = false;
  }
}

/** Stop the local MX node. */
async function stopLocalMxNode() {
  if (localMxNode) {
    await localMxNode.stop();
    localMxNode = null;
    paintLocalMxStatus('disabled', 'MX node stopped');
  }
}

/** Test MX node connectivity (port 25 reachability, TLS, etc.). */
async function testLocalMxConnectivity() {
  if (!localMxNode) {
    toast('MX Node not running');
    return;
  }
  
  try {
    el.localMxTestBtn.disabled = true;
    el.localMxTestBtn.textContent = 'Testing…';
    
    const result = await localMxNode.testConnectivity();
    
    if (result.port25Reachable) {
      toast(`✅ Port 25 reachable (latency: ${result.latency}ms)`);
    } else {
      toast(`❌ Port 25 not reachable: ${result.error || 'Connection refused'}`);
    }
    
    if (result.tlsValid) {
      toast(`✅ TLS certificate valid`);
    } else {
      toast(`❌ TLS issue: ${result.tlsError || 'Invalid certificate'}`);
    }
  } catch (e) {
    toast(`Test failed: ${e.message}`);
  } finally {
    el.localMxTestBtn.disabled = false;
    el.localMxTestBtn.textContent = 'Test Connectivity';
  }
}

function paintLocalMxStatus(status, detail) {
  if (!el.localMxStatus) return;
  el.localMxStatus.dataset.state = status;
  el.localMxStatus.textContent = detail ? `${status} — ${detail}` : status;
  el.localMxStatus.title = detail || '';
  
  if (el.localMxStartBtn) el.localMxStartBtn.disabled = status === 'running' || status === 'starting';
  if (el.localMxStopBtn) el.localMxStopBtn.disabled = status === 'disabled' || status === 'error';
  if (el.localMxTestBtn) el.localMxTestBtn.disabled = status !== 'running';
}

/**
 * Load the X25519 public keys we know for a set of recipient addresses.
 * DOM Mail only has keys for identities we have seen; anything else is
 * reported so the user is never silently sent in the clear.
 */
function keyringFor(addresses) {
  const ring = pgpKeyring;
  const found = [];
  const missing = [];
  for (const addr of addresses) {
    const key = ring[String(addr).toLowerCase()];
    if (key) found.push({ address: addr, publicKey: fromBase64(key) });
    else missing.push(addr);
  }
  return { found, missing };
}

/** Recipient addresses in scope for PGP: To, Cc and Bcc. */
function pgpRecipients(c) {
  return [...c.to, ...c.cc, ...c.bcc].map((a) => a.address);
}

function parseAddr(val) {
  if (!val) return [];
  return val.split(/[,;]/).map((s) => s.trim()).filter(Boolean).map((address) => {
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

  const cc = parseAddr(c.cc);
  const bcc = parseAddr(c.bcc);

  try {
    const sig = uiPrefs.autoSig ? await engine.store.get('signature') : '';
    let body = sig ? `${c.text}\n\n${sig}` : c.text;
    let html = el.editor.innerHTML;

    const headers = {};
    if (uiPrefs.reqSentConfirm && engine.identity) {
      headers['Disposition-Notification-To'] = engine.identity.address;
    }

    /*
     * PGP is applied per-recipient over the body. If we do not hold a public
     * key for every recipient we refuse rather than quietly sending part of
     * the mail in the clear: a silent downgrade is worse than a hard failure.
     */
let encryptedFor = 0;
    let encryptedMode = null;
    if (uiPrefs.pgp) {
      const pass = uiPrefs.pgpPassphrase;
      let armored;
      if (pass) {
        /*
         * Passphrase mode needs no keys, so any recipient can open it. This is
         * the only mode that reaches peers outside DOM Mail.
         */
        armored = await encryptWithPassphrase(body, pass);
        encryptedMode = 'passphrase';
        encryptedFor = [...to, ...cc, ...bcc].length;
      } else {
        const all = [...to, ...cc, ...bcc].map((a) => a.address);
        const { found, missing } = keyringFor(all);
        if (missing.length) {
          showValidation([
            `No public key known for: ${missing.join(', ')}.`,
            'DOM Mail will not send in the clear while armored encryption is on.',
            'Set a shared passphrase to reach recipients you hold no key for, or turn PGP off.',
          ]);
          return;
        }
        armored = await encryptMessage(body, found, {
          sign: uiPrefs.pgpSign && engine.identity,
          signer: engine.identity
            ? { privateKey: fromBase64(engine.identity.ed25519), publicKey: fromBase64(engine.identity.x25519) }
            : undefined,
        });
        encryptedMode = 'key';
        encryptedFor = found.length;
      }
      headers['X-DOM-Mail-Encryption'] = encryptedMode === 'passphrase'
        ? `${PGP.ARMOR_TYPE}; mode=passphrase`
        : `${PGP.ARMOR_TYPE}; mode=key`;
      body = armored;
      // The HTML alternative would leak the plaintext, so drop it.
      html = '';
    }

const record = await engine.send({
      to,
      cc,
      bcc,
      subject: c.subject,
      text: body,
      html,
      attachments: composeAttachments,
      headers,
    }, uiPrefs.saveSent ? 'outbox' : null);

    publishToRelay(record);

    if (composeDraftId) {
      await engine.remove('drafts', composeDraftId);
      knownDrafts.delete(composeDraftId);
    }

    /*
     * Only clear after send() has actually resolved. A failed send must leave
     * the draft intact so nothing is lost. resetComposeFields() also drops the
     * draft id, so the composer's state cannot bleed into the next message.
     */
    closeCompose();
    resetComposeFields();

    const selectedNetworks = [];
    if (el.sendNetDirect?.checked) selectedNetworks.push('Direct');
    if (el.sendNetTor?.checked) selectedNetworks.push('Tor');
    if (el.sendNetI2p?.checked) selectedNetworks.push('I2P');
    if (el.sendNetEnsIpfs?.checked) selectedNetworks.push('ENS/IPFS');
    if (el.sendNetRadicle?.checked) selectedNetworks.push('Radicle');
    if (el.sendNetYggdrasil?.checked) selectedNetworks.push('Yggdrasil');
    if (el.sendNetNostr?.checked) selectedNetworks.push('Nostr');
    if (el.sendNetReticulum?.checked) selectedNetworks.push('Reticulum');
    if (el.sendNetWebRTC?.checked) selectedNetworks.push('WebRTC');
    if (el.sendNetBLE?.checked) selectedNetworks.push('BLE');
    if (el.sendNetDNS?.checked) selectedNetworks.push('DNS');
    if (el.sendNetSneakernet?.checked) selectedNetworks.push('Sneakernet');
    if (el.sendNetFederation?.checked) selectedNetworks.push('Federation');

    const bits = [];
    bits.push(uiPrefs.saveSent ? 'Saved to Outbox' : 'Not saved');
    if (encryptedFor) {
      bits.push(encryptedMode === 'passphrase'
        ? `passphrase-encrypted for ${encryptedFor} recipient(s)`
        : `key-encrypted for ${encryptedFor} recipient(s)`);
    }
    if (selectedNetworks.length) {
      bits.push(`dispatched via [${selectedNetworks.join(', ')}]`);
    }
    toast(`Sent — ${bits.join(' · ')}`);
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
  /*
   * Native notifications render on the lock screen and in the OS notification
   * centre, outside anything this page can protect. The address is therefore
   * never handed to the operating system.
   */
  notifyNative('New mail', `${m.subject || '(no subject)'} — sender masked`);
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
    renderIdentity();
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
    // Stop local MX node if running
    if (localMxNode) {
      await localMxNode.stop();
      localMxNode = null;
    }
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
  // Theme is a two-way segmented control in Settings; dark is the default.
  for (const btn of $$('.seg__btn[data-theme]')) {
    btn.addEventListener('click', () => {
      uiPrefs.mode = btn.dataset.theme === 'light' ? 'light' : 'dark';
      applyUiPrefs();
      saveUiPrefs();
    });
  }

  el.overhaul.addEventListener('click', () => {
    const hue = NEON_HUES[Math.floor(Math.random() * NEON_HUES.length)];
    const sat = 85 + Math.floor(Math.random() * 15);
    const light = 55 + Math.floor(Math.random() * 10);
uiPrefs.neon = `hsl(${hue} ${sat}% ${light}%)`;
    uiPrefs.accent = uiPrefs.neon;
    applyUiPrefs();
    saveUiPrefs();
  });

  el.resetAccent.addEventListener('click', () => {
    uiPrefs.neon = null;
    uiPrefs.accent = null;
    applyUiPrefs();
    saveUiPrefs();
    toast('Accent reset to the default');
  });

  // Direct-pick swatches, so choosing a colour does not require a dice roll.
  el.accentSwatches.innerHTML = NEON_HUES.map((h) => `
    <button type="button" class="swatch" data-hue="${h}"
            style="--c:hsl(${h} 90% 58%)"
            aria-label="Use accent hue ${h}"></button>`).join('');
  for (const sw of el.accentSwatches.querySelectorAll('.swatch')) {
    sw.addEventListener('click', () => {
      const h = sw.dataset.hue;
      uiPrefs.neon = `hsl(${h} 90% 58%)`;
      uiPrefs.accent = uiPrefs.neon;
      applyUiPrefs();
      saveUiPrefs();
    });
  }

  // Bulletproof tab & subtab event delegation
  document.addEventListener('click', (e) => {
    const tabBtn = e.target.closest('.tab');
    if (tabBtn && tabBtn.dataset.page) {
      showPage(tabBtn.dataset.page);
    }
    const subBtn = e.target.closest('.subtab');
    if (subBtn && subBtn.dataset.sub) {
      showSub(subBtn.dataset.sub);
    }
  });

  el.soundToggle.addEventListener('click', () => {
    uiPrefs.sound = !uiPrefs.sound;
    el.soundToggle.setAttribute('aria-pressed', String(uiPrefs.sound));
    saveUiPrefs();
  });

  el.notifyToggle.addEventListener('click', requestNotifyPermission);

  // Blind copy: the address on screen is masked; clicking copies the real one.
  el.identity.addEventListener('click', copyFullAddress);
  el.identity.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      copyFullAddress();
    }
  });

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
    renderIdentity();
  });

  el.setLocal.addEventListener('change', async () => {
    if (!engine || !engine.identity) return;
    engine.identity.local = el.setLocal.value;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    renderIdentity();
    el.keyView.textContent = publicKeyBlock(engine.identity);
  });

  el.setDomain.addEventListener('change', async () => {
    if (!engine || !engine.identity) return;
    engine.identity.domain = el.setDomain.value;
    engine.identity.address = `${engine.identity.local}@${engine.identity.domain}`;
    await engine.setIdentity(engine.identity);
    renderIdentity();
    el.keyView.textContent = publicKeyBlock(engine.identity);
  });

el.setSig.addEventListener('change', async () => {
    if (!engine) return;
    await engine.store.set('signature', el.setSig.value);
    toast('Signature saved');
  });

  el.setShowFullAddr.addEventListener('change', () => {
    uiPrefs.showFullIdentity = el.setShowFullAddr.checked;
    saveUiPrefs();
    renderIdentity();
    toast(uiPrefs.showFullIdentity
      ? 'Addresses will be shown in full — screen privacy reduced'
      : 'Addresses will be masked on screen');
    void refreshAll();
  });

  el.setSuggestContacts.addEventListener('change', () => {
    uiPrefs.suggestContacts = el.setSuggestContacts.checked;
    saveUiPrefs();
    if (!uiPrefs.suggestContacts) hideContactSuggest();
  });

  el.regenDomain.addEventListener('click', async () => {
    if (!engine || !engine.identity) return;
    const newDomain = domainGenerator ? domainGenerator.generateDomain(uiPrefs.domainCulture) : `${Math.random().toString(36).slice(2, 10)}.domail.space`;
    engine.identity.domain = newDomain;
    engine.identity.address = `${engine.identity.local}@${newDomain}`;
    await engine.setIdentity(engine.identity);
    el.setDomain.value = engine.identity.domain;
    renderIdentity();
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

  // GnuPG settings
  if (el.setGpg) {
    el.setGpg.addEventListener('change', () => {
      uiPrefs.gpgEnabled = el.setGpg.checked;
      saveUiPrefs();
      paintOptionalPrefs();
      toast(uiPrefs.gpgEnabled
        ? 'GnuPG integration ON — using local gpg binary'
        : 'GnuPG integration off');
    });

    el.setGpgPath.addEventListener('change', () => {
      uiPrefs.gpgPath = el.setGpgPath.value.trim() || 'gpg';
      saveUiPrefs();
    });
  }

  // Body obfuscation settings
if (el.setBodyObfuscate) {
    el.setBodyObfuscate.addEventListener('change', () => {
      uiPrefs.bodyObfuscate = el.setBodyObfuscate.checked;
      saveUiPrefs();
      toast(uiPrefs.bodyObfuscate
        ? 'Body PII obfuscation ON — PII will be masked when not hovering'
        : 'Body PII obfuscation OFF');
      // Re-render current message if viewing one
      const box = document.querySelector('.page.is-active')?.dataset.page;
      if (box) refreshList(box);
    });
  }

  if (el.setBodyObfuscateHover) {
    el.setBodyObfuscateHover.addEventListener('change', () => {
      uiPrefs.bodyObfuscateHoverReveal = el.setBodyObfuscateHover.checked;
      saveUiPrefs();
    });
  }

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
      // Use the imported unlockMailEngine function
      await unlockMailEngine(engine, pw);
      el.passphraseModal.hidden = true;
      el.unlockPassphrase.value = '';
      el.encryptionStatus.textContent = 'Storage: Encrypted & Unlocked';
      renderIdentity();
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
    
    // Cross-tab navigation links (e.g., from Security to Account)
    if (e.target.matches('[data-sub-link]')) {
      e.preventDefault();
      const targetSub = e.target.dataset.subLink;
      if (targetSub) {
        showPage('settings');
        showSub(targetSub);
      }
    }
  });

  // Mobile bottom nav: show/hide based on screen size
  let mobileNavResizeTimer = null;
  function updateMobileNav() {
    const isMobile = window.innerWidth <= 720;
    if (el.mobileBottomNav) {
      el.mobileBottomNav.hidden = !isMobile;
    }
    if (el.tabs) {
      const tabsContainer = el.tabs[0]?.closest('.tabs');
      if (tabsContainer) {
        tabsContainer.style.display = isMobile ? 'none' : 'flex';
      }
    }
    // Adjust view height
    const view = $('#view');
    if (view) {
      if (isMobile) {
        view.style.height = 'calc(100dvh - 60px - 56px)';
      } else {
        view.style.height = 'calc(100dvh - var(--chrome-h))';
      }
    }
  }
  
  // Initial check
  updateMobileNav();
  // Listen for resize with debounce
  window.addEventListener('resize', () => {
    if (mobileNavResizeTimer) clearTimeout(mobileNavResizeTimer);
    mobileNavResizeTimer = setTimeout(updateMobileNav, 100);
  });
  
  // Mobile bottom nav click handling
  if (el.mobileTabs) {
    for (const tab of el.mobileTabs) {
      tab.addEventListener('click', () => {
        if (tab.dataset.page) showPage(tab.dataset.page);
      });
    }
  }
}

async function init() {
  loadUiPrefs();
  applyUiPrefs();
  bindEvents();
  bindOptionalEvents();
  bindContactSuggest();

  // Initialize security systems with timeout and graceful degradation
  try {
    await Promise.race([
      initSecuritySystems(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Security systems init timeout')), 5000))
    ]);
  } catch (e) {
    console.warn('Security systems init failed, continuing without:', e);
    toast('Some security features unavailable');
  }

  // Initialize main app with robust error handling
  await initMainApp();
}

async function initMainApp() {
  let store;
  let encryptedStore;
  let useMemoryStore = false;

  // Try to initialize IndexedDB store with timeout
  try {
    await Promise.race([
      (async () => {
        store = indexedDbStore(DB_NAME);
        encryptedStore = new EncryptedStore(store);
        await Promise.race([
          encryptedStore._ensureInit(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('EncryptedStore init timeout')), 5000))
        ]);
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Store init timeout')), 5000))
    ]);
  } catch (e) {
    console.warn('IndexedDB/EncryptedStore unavailable, falling back to memory store:', e);
    useMemoryStore = true;
    const { memoryStore } = await import('../../core/mail.mjs');
    store = memoryStore();
    toast('Running in memory-only mode (data not persisted)');
  }

  // Check if storage is encrypted (has salt)
  let isEncrypted = false;
  try {
    if (!useMemoryStore) {
      const salt = await Promise.race([
        store.get('__salt__'),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Salt check timeout')), 3000))
      ]);
      isEncrypted = !!salt;
    }
  } catch (e) {
    console.warn('Salt check failed:', e);
  }

if (isEncrypted) {
    if (el.passphraseModal) el.passphraseModal.hidden = false;
    return;
  }

// Initialize mail engine
  const { MailEngine } = await import('../../core/mail.mjs');
  engine = new MailEngine(store);
  
  let loadSucceeded = false;
  try {
    await Promise.race([
      engine.load(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Engine load timeout')), 5000))
    ]);
    loadSucceeded = true;
    console.log('[domail] Engine loaded, identity:', engine.identity?.address || 'none');
  } catch (e) {
    console.warn('Engine load failed:', e);
  }

  // Auto-provision identity ONLY if load succeeded but no identity exists.
  // If load failed, don't create a new identity - show onboarding instead.
  if (loadSucceeded && !engine.identity) {
    try {
      const local = domainGenerator ? domainGenerator.generateLocalPart(uiPrefs.domainCulture) : 'nova';
      const domain = domainGenerator ? domainGenerator.generateDomain(uiPrefs.domainCulture) : 'domail.space';
      let identity;
      try {
        identity = await Promise.race([
          generateIdentity('Nova', local, domain),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Crypto timeout')), 4000))
        ]);
      } catch {
        identity = {
          name: 'Nova',
          local,
          domain,
          address: `${local}@${domain}`,
          ed25519: 'fallback_ed25519',
          x25519: 'fallback_x25519',
          created: Date.now(),
        };
      }
      await engine.setIdentity(identity);
    } catch (e) {
      console.error('Identity generation failed, using emergency fallback:', e);
      const identity = {
        name: 'Nova',
        local: 'nova',
        domain: 'domail.space',
        address: 'nova@domail.space',
        ed25519: 'emergency_ed25519',
        x25519: 'emergency_x25519',
        created: Date.now(),
      };
      await engine.setIdentity(identity);
    }
  }

if (engine.identity) {
    renderIdentity();
    el.keyView.textContent = publicKeyBlock(engine.identity);
    el.setName.value = engine.identity.name;
    el.setLocal.value = engine.identity.local;
    el.setDomain.value = engine.identity.domain;
    const sig = await store.get('signature');
    if (sig) el.setSig.value = sig;
    rememberPgpKey(engine.identity);
    hideOnboarding();
    await refreshAll();
    startPolling();
    showPage('compose');
    // Connect the relay only if the user previously opted in.
    if (uiPrefs.relay) syncRelay();
    // Connect the SMTP relay if enabled.
    if (uiPrefs.smtpRelayEnabled) syncSmtpRelay();
  } else {
    // No identity loaded (either load failed or store is empty)
    showOnboarding();
}
}

/* ============================ MX Node Install Wizard ============================ */

let mxWizardState = {
  currentStep: 1,
  config: {
    domain: '',
    useLetsEncrypt: true,
    certPem: '',
    keyPem: '',
    transports: ['direct'],
    security: {
      tls13Only: true,
      certPinning: true,
      dane: true,
      mtaSts: true,
      rateLimit: 100,
    }
  },
  prereqs: {
    wasm: false,
    crypto: false,
    https: false,
    port25: false,
    dns: false,
  }
};

function openMxWizard() {
  const wizard = $('#mxWizard');
  if (!wizard) return;
  wizard.hidden = false;
  mxWizardState.currentStep = 1;
  showMxWizardStep(1);
  runPrereqChecks();
}

function closeMxWizard() {
  const wizard = $('#mxWizard');
  if (wizard) wizard.hidden = true;
}

function showMxWizardStep(step) {
  mxWizardState.currentStep = step;
  $$('.mx-wizard-step').forEach(el => el.hidden = el.dataset.step != String(step));
  updateMxWizardNav();
}

function updateMxWizardNav() {
  // Navigation is handled by step buttons
}

async function runPrereqChecks() {
  const list = $('#mxPrereqList');
  if (!list) return;
  list.innerHTML = '<div class="minor">Checking...</div>';
  
  const checks = [
    { id: 'wasm', name: 'WebAssembly Support', check: () => typeof WebAssembly !== 'undefined' && typeof WebAssembly.instantiate === 'function' },
    { id: 'crypto', name: 'WebCrypto API', check: () => window.crypto && window.crypto.subtle },
    { id: 'https', name: 'HTTPS / Secure Context', check: () => window.isSecureContext },
    { id: 'port25', name: 'Port 25 Reachability (test)', check: async () => { try { const r = await fetch('/api/check-port25'); return r.ok; } catch { return false; } } },
    { id: 'dns', name: 'DNS Resolution', check: async () => { try { await fetch('/api/check-dns'); return true; } catch { return false; } } },
  ];
  
  let html = '';
  for (const c of checks) {
    html += `<div style="display:flex;align-items:center;gap:0.5rem;padding:0.5rem;margin:0.25rem 0;background:var(--bg);border-radius:var(--radius-sm);">
      <span class="mx-prereq-icon" data-id="${c.id}" style="font-size:1.2rem;">⏳</span>
      <span>${c.name}</span>
    </div>`;
  }
  $('#mxPrereqList').innerHTML = html;
  
  let passed = 0;
  for (const c of checks) {
    try {
      const result = await c.check();
      mxWizardState.prereqs[c.id] = result;
      const icon = $(`.mx-prereq-icon[data-id="${c.id}"]`);
      if (icon) {
        icon.textContent = result ? '✅' : '❌';
        icon.style.color = result ? 'var(--neon)' : '#ff5a5a';
      }
      if (result) passed++;
    } catch (e) {
      mxWizardState.prereqs[c.id] = false;
      const icon = $(`.mx-prereq-icon[data-id="${c.id}"]`);
      if (icon) {
        icon.textContent = '❌';
        icon.style.color = '#ff5a5a';
      }
    }
  }
  
  if (passed >= 3) {
    $('#mxWizardNext1').disabled = false;
  }
  
  updateDnsRecordsDisplay();
}

function updateDnsRecordsDisplay() {
  const domain = mxWizardState.config.domain || 'yourdomain.tld';
  const dnsEl = $('#mxDnsRecords');
  if (!dnsEl) return;
  
  dnsEl.innerHTML = `
    <div style="margin:0.5rem 0;font-family:var(--mono);font-size:0.75rem;">
      <div><strong>MX Record:</strong> ${domain} IN MX 10 ${domain}</div>
      <div><strong>A Record:</strong> ${domain} IN A YOUR_PUBLIC_IP</div>
      <div><strong>AAAA Record:</strong> ${domain} IN AAAA YOUR_IPV6</div>
      <div style="margin-top:0.5rem;"><strong>SPF:</strong> ${domain} IN TXT "v=spf1 mx ~all"</div>
      <div><strong>DMARC:</strong> _dmarc.${domain} IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@${domain}"</div>
      <div><strong>MTA-STS:</strong> _mta-sts.${domain} IN TXT "v=STSv1; id=1"</div>
      <div><strong>TLS-RPT:</strong> _smtp._tls.${domain} IN TXT "v=TLSRPTv1; rua=mailto:tls@${domain}"</div>
    </div>
  `;
}

async function checkDnsRecords() {
  const domain = mxWizardState.config.domain;
  if (!domain) {
    toast('Enter a domain first');
    return;
  }
  
  const btn = $('#mxWizardCheckDnsBtn');
  btn.textContent = 'Checking...';
  btn.disabled = true;
  
  try {
    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
    const data = await response.json();
    
    if (data.Answer && data.Answer.length > 0) {
      toast(`✅ DNS records found for ${domain}`);
      mxWizardState.prereqs.dns = true;
      $('#mxWizardNext2').disabled = false;
    } else {
      toast(`⚠️ No MX records found for ${domain}`);
    }
  } catch (e) {
    toast(`❌ DNS check failed: ${e.message}`);
  } finally {
    btn.textContent = 'Check DNS';
    btn.disabled = false;
  }
}

function populateTransports() {
  const container = $('#mxWizardTransports');
  if (!container) return;
  
  const transports = [
    { id: 'direct', name: 'Direct (TLS 1.3)', desc: 'Standard TLS delivery', required: true },
    { id: 'tor', name: 'Tor Onion Service', desc: 'Anonymous delivery via Tor', required: false },
    { id: 'i2p', name: 'I2P Eepsite', desc: 'Anonymous delivery via I2P', required: false },
    { id: 'nostr', name: 'Nostr Relays', desc: 'Decentralized relay via Nostr', required: false },
    { id: 'dns', name: 'DNS TXT Tunneling', desc: 'Censorship-resistant delivery', required: false },
    { id: 'sneakernet', name: 'Sneakernet (QR/USB)', desc: 'Air-gapped physical delivery', required: false },
  ];
  
  container.innerHTML = transports.map(t => `
    <label class="check" style="padding:0.75rem;background:var(--bg);border-radius:var(--radius-sm);border:1px solid var(--line);">
      <input type="checkbox" data-transport="${t.id}" ${t.required ? 'checked disabled' : ''}>
      <div>
        <strong>${t.name}</strong>
        <div class="minor">${t.desc}</div>
      </div>
    </label>
  `).join('');
  
  $$('[data-transport]').forEach(cb => {
    if (!cb.disabled) {
      cb.checked = mxWizardState.config.transports.includes(cb.dataset.transport);
      cb.addEventListener('change', () => {
        if (cb.checked) {
          mxWizardState.config.transports.push(cb.dataset.transport);
        } else {
          mxWizardState.config.transports = mxWizardState.config.transports.filter(t => t !== cb.dataset.transport);
        }
      });
    }
  });
}

function populateSecurityOptions() {
  const container = $('#mxWizardSecurityOptions');
  if (!container) return;
  
  const options = [
    { id: 'tls13Only', name: 'TLS 1.3 Only', desc: 'Reject TLS 1.2 and below', enabled: true },
    { id: 'certPinning', name: 'Certificate Pinning', desc: 'Pin CA certificates for outbound', enabled: true },
    { id: 'dane', name: 'DANE/TLSA', desc: 'DNS-based certificate validation', enabled: true },
    { id: 'mtaSts', name: 'MTA-STS', desc: 'Enforce TLS for inbound', enabled: true },
    { id: 'rateLimit', name: 'Rate Limiting (100/min)', desc: 'Prevent abuse', enabled: true },
  ];
  
  container.innerHTML = options.map(o => `
    <label class="check" style="padding:0.75rem;background:var(--bg);border-radius:var(--radius-sm);border:1px solid var(--line);">
      <input type="checkbox" data-security="${o.id}" ${o.enabled ? 'checked' : ''}>
      <div>
        <strong>${o.name}</strong>
        <div class="minor">${o.desc}</div>
      </div>
    </label>
  `).join('');
  
  $$('[data-security]').forEach(cb => {
    cb.checked = mxWizardState.config.security[cb.dataset.security];
    cb.addEventListener('change', () => {
      mxWizardState.config.security[cb.dataset.security] = cb.checked;
    });
  });
}

function generateReview() {
  const c = mxWizardState.config;
  return `
Domain: ${c.domain || 'Not set'}
Certificate: ${c.useLetsEncrypt ? "Let's Encrypt (auto)" : 'Custom'}
Transports: ${c.transports.join(', ')}
Security:
  TLS 1.3 Only: ${c.security.tls13Only}
  Cert Pinning: ${c.security.certPinning}
  DANE: ${c.security.dane}
  MTA-STS: ${c.security.mtaSts}
  Rate Limit: ${c.security.rateLimit}/min
Prerequisites:
  WASM: ${mxWizardState.prereqs.wasm ? '✅' : '❌'}
  Crypto: ${mxWizardState.prereqs.crypto ? '✅' : '❌'}
  HTTPS: ${mxWizardState.prereqs.https ? '✅' : '❌'}
  Port 25: ${mxWizardState.prereqs.port25 ? '✅' : '❌'}
  DNS: ${mxWizardState.prereqs.dns ? '✅' : '❌'}
`;
}

async function installMxNode() {
  const reviewEl = $('#mxWizardReview');
  if (reviewEl) reviewEl.textContent = generateReview();
  
  const installingEl = $('#mxWizardInstalling');
  const successEl = $('#mxWizardSuccess');
  const errorEl = $('#mxWizardError');
  const finishBtn = $('#mxWizardFinishBtn');
  const installBtn = $('#mxWizardInstallBtn');
  
  $('#mxWizardReview').parentElement.style.display = 'none';
  installingEl.hidden = false;
  installBtn.hidden = true;
  $$('.mx-wizard-step[data-step="6"] button').forEach(b => b.disabled = true);
  
  try {
    const config = {
      hostname: mxWizardState.config.domain,
      certPem: mxWizardState.config.certPem,
      keyPem: mxWizardState.config.keyPem,
      identity: engine?.identity,
      transports: mxWizardState.config.transports.map(id => ({ id, enabled: true })),
      smtp: { require_starttls: true, auth_over_tls_only: true, max_message_size: 52428800, rate_limit_per_minute: mxWizardState.config.security.rateLimit },
      imap: { require_tls: true },
      submission: { require_auth: true, require_starttls: true },
      security: mxWizardState.config.security,
      storage: { max_size: 1024*1024*1024 }
    };
    
    $('#mxWizardInstallStatus').textContent = 'Loading MX Node module...';
    
    const { createLocalMxNode } = await import('../../core/local-mx.mjs');
    
    $('#mxWizardInstallStatus').textContent = 'Initializing MX Node...';
    
    localMxNode = await createLocalMxNode(config);
    await localMxNode.start();
    
    uiPrefs.localMxEnabled = true;
    uiPrefs.localMxHostname = mxWizardState.config.domain;
    uiPrefs.localMxCert = mxWizardState.config.certPem;
    uiPrefs.localMxKey = mxWizardState.config.keyPem;
    saveUiPrefs();
    paintOptionalPrefs();
    
    installingEl.hidden = true;
    successEl.hidden = false;
    $('#mxWizardFinishBtn').hidden = false;
    
    toast('MX Node installed and running!');
    
  } catch (e) {
    installingEl.hidden = true;
    errorEl.hidden = false;
    $('#mxWizardErrorMsg').textContent = e.message;
    installBtn.hidden = false;
    $$('.mx-wizard-step[data-step="6"] button').forEach(b => b.disabled = false);
  }
}

function bindMxWizardEvents() {
  const wizard = $('#mxWizard');
  if (!wizard) return;
  
  $('#mxWizardClose').addEventListener('click', closeMxWizard);
  wizard.addEventListener('click', (e) => {
    if (e.target === wizard) closeMxWizard();
  });
  
  $('#mxPrereqCheckBtn').addEventListener('click', runPrereqChecks);
  $('#mxWizardNext1').addEventListener('click', () => {
    showMxWizardStep(2);
    updateDnsRecordsDisplay();
  });
  
  $('#mxWizardDomain').addEventListener('input', (e) => {
    mxWizardState.config.domain = e.target.value.trim();
    updateDnsRecordsDisplay();
  });
  $('#mxWizardPrev2').addEventListener('click', () => showMxWizardStep(1));
  $('#mxWizardCheckDnsBtn').addEventListener('click', checkDnsRecords);
  $('#mxWizardNext2').addEventListener('click', () => {
    showMxWizardStep(3);
  });
  
  $('#mxWizardUseLetsEncrypt').addEventListener('change', (e) => {
    const custom = $('#mxWizardCustomCertFields');
    const key = $('#mxWizardCustomKeyFields');
    custom.hidden = e.target.checked;
    key.hidden = e.target.checked;
    if (!e.target.checked) {
      $('#mxWizardNext3').disabled = false;
    }
  });
  $('#mxWizardCertFile').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        mxWizardState.config.certPem = reader.result;
        $('#mxWizardCertStatus').textContent = file.name;
        checkCustomCertComplete();
      };
      reader.readAsText(file);
    }
  });
  $('#mxWizardKeyFile').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        mxWizardState.config.keyPem = reader.result;
        $('#mxWizardKeyStatus').textContent = file.name;
        checkCustomCertComplete();
      };
      reader.readAsText(file);
    }
  });
  
  function checkCustomCertComplete() {
    if (mxWizardState.config.certPem && mxWizardState.config.keyPem) {
      $('#mxWizardNext3').disabled = false;
    }
  }
  
  $('#mxWizardPrev3').addEventListener('click', () => showMxWizardStep(2));
  $('#mxWizardNext3').addEventListener('click', () => {
    showMxWizardStep(4);
    populateTransports();
  });
  
  $('#mxWizardPrev4').addEventListener('click', () => showMxWizardStep(3));
  $('#mxWizardNext4').addEventListener('click', () => {
    showMxWizardStep(5);
    populateSecurityOptions();
  });
  
  $('#mxWizardPrev5').addEventListener('click', () => showMxWizardStep(4));
  $('#mxWizardNext5').addEventListener('click', () => {
    showMxWizardStep(6);
    $('#mxWizardReview').textContent = generateReview();
  });
  
  $('#mxWizardPrev6').addEventListener('click', () => showMxWizardStep(5));
  $('#mxWizardInstallBtn').addEventListener('click', installMxNode);
  
  $('#mxWizardFinishBtn').addEventListener('click', () => {
    closeMxWizard();
    showSub('network');
  });
  
  $('#mxWizardUseLetsEncrypt').addEventListener('change', (e) => {
    mxWizardState.config.useLetsEncrypt = e.target.checked;
    if (e.target.checked) {
      mxWizardState.config.certPem = '';
      mxWizardState.config.keyPem = '';
      $('#mxWizardNext3').disabled = false;
    }
  });
  
  const openWizardBtn = document.createElement('button');
  openWizardBtn.className = 'pill';
  openWizardBtn.textContent = '🧙 Open Install Wizard';
  openWizardBtn.style.marginTop = '0.75rem';
  openWizardBtn.addEventListener('click', openMxWizard);
  
  const localMxSection = $('#optLocalMx');
  if (localMxSection) {
    const warn = localMxSection.querySelector('.warn');
    if (warn) {
      warn.parentNode.insertBefore(openWizardBtn, warn);
    }
  }
}

function initMxWizard() {
  bindMxWizardEvents();
}

init();
