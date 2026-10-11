# DOM Mail

A military-grade, zero-dependency, offline-first client-side mail engine that runs entirely in your browser tab or local CLI. No server, no account, no trace, no telemetry.

## What it is

DOM Mail is a complete email client and local mail engine that lives in a single HTML page. It implements RFC 5322 message formatting, MIME multipart encoding, address parsing, cryptographic identity generation (WebCrypto Ed25519 & X25519), and end-to-end encrypted storage (Argon2id + XChaCha20-Poly1305) — all in vanilla JavaScript with zero external npm dependencies or CDN requests.

Your mail never leaves your browser. There is no backend server, no cloud database, and no network connection beyond the initial page load (or cached forever via Service Worker).

## Features & Security

- **Autonomous Identity Provisioning**: Instantly generates a cryptographic mail identity upon landing. Supports multiple local identities with an instant Identity Switcher.
- **Full Compose Workspace**: Clean, futuristic compose interface featuring `To`, `CC`, `BCC`, `Subject`, and rich text formatting (bold, italic, underline, strike, font size, font family, text/highlight colors), emoji picker, and file attachments.
- **Screen Theft & Privacy Protection**: Real-time PII obfuscation (`***`), click-to-copy masked addresses with `'Copied!'` confirmation tooltips, and anti-screenshot/print redaction.
- **Anti-Keylogger Engine**: Input masking and timing noise to defeat hardware and software keyloggers.
- **Zero Fingerprinting**: Spoofs browser APIs, canvas, WebGL, audio, and device properties to prevent tracking.
- **Encrypted Storage**: Optional Argon2id passphrase derivation combined with XChaCha20-Poly1305 authenticated encryption.
- **Enforced Content Security Policy**: A strict CSP ships as a `<meta>` tag (so it applies on GitHub Pages, which ignores `_headers`). `script-src 'self'` blocks inline script and `eval`; `connect-src 'self'` makes exfiltration to an external host impossible even under XSS; `object-src`, `frame-src`, `base-uri` and `form-action` are all locked to `none`. CI fails the build if an inline `<script>` is reintroduced. See [SECURITY.md](SECURITY.md).
- **Multi-Network Accessibility & Concurrency**: Fully accessible, concurrent, and optimized across:
  - **HTTPS / Web**: `https://domail.space` (Direct Clearnet)
  - **Tor Onion Service**: `http://domail.onion` (Tor v3 Hidden Service)
  - **I2P Eepsite**: `http://domail.i2p` (Garlic-routed I2P tunnel)
  - **Ethereum ENS / Decentralized Web**: `domail.eth` (IPFS gateway resolver)
  - **IPFS / Radicle**: `ipfs://bafybeic...` & P2P code seeding (`rad://`)
  - **Yggdrasil Mesh**: End-to-end encrypted IPv6 mesh overlay
  - **Nostr Relay**: `wss://relay.domail.space` (Encrypted DMs via NIP-04/NIP-17)
  - **Reticulum / LXMF**: Asynchronous LoRa and packet radio mesh mail
- **Compose-Time Network Dispatcher**: A fine-grained checkbox selector in the compose workspace lets you choose precisely which active network transports to broadcast/dispatch your outgoing message through (e.g., Direct + Nostr + Reticulum simultaneously).
- **Offline-First Multi-Environment Caching**: Load the application once (or cache it permanently via Service Worker) and operate entirely offline across alternative networks without ever touching the WWW again.
- **CLI Parity**: The headless Node.js CLI (`cli/domail.mjs`) provides identical network transport controls (`node cli/domail.mjs network [net] [on|off]`).
- **Zero Dependencies**: Pure ES modules, zero npm packages, zero build step.

## Optional networked features (off by default)

DOM Mail is local-only by design. Two optional features can trade that away, and
both are **disabled until you explicitly turn them on** in **Settings → Network**.
Each one shows a warning panel explaining exactly what it costs you before you
commit, and the browser and CLI builds share the same defaults.

### Armored encryption ("PGP")

`core/pgp.mjs`. Two modes, both off by default:

- **Key mode** seals the body to each recipient's X25519 public key using
  libsodium sealed boxes, optionally signed with Ed25519. Only reaches DOM Mail
  peers whose keys you already hold.
- **Passphrase mode** needs nothing but a shared secret, so **any** recipient who
  has DOM Mail can open the message — including people who will never install a
  key. This is the mode that reaches outside the project.

Both wrap the result in an OpenPGP-compatible ASCII-Armor envelope (RFC 4880 §6,
with a real CRC-24 checksum).

- **Still not OpenPGP.** GnuPG's armor tools parse the envelope and validate the
  checksum, but the payload is DOM Mail's own packet format and **will not
  decrypt in GnuPG**. Use GnuPG if you need RFC 4880 interoperability.
- **Metadata is still exposed.** From, To, Subject, Date and ciphertext size stay
  in the envelope. Timing analysis is possible regardless.
- **No silent downgrade.** With PGP on and no passphrase, a message to an address
  whose public key is unknown is *refused* rather than sent in the clear.
- The passphrase is held **in memory for the session only** and is never written
  to storage, so it must be re-entered after a reload.
- Keys come only from DOM Mail identities you have already met — there is no key
  server and nothing is fetched to learn one.

### Password hashing

The bundled `libsodium.js` exposes **no** Argon2id and no scrypt — only BLAKE2b.
`deriveKey()` therefore prefers Argon2id when a host provides it and otherwise
falls back to an iterated keyed-BLAKE2b construction (120 000 rounds, ~150 ms).
The KDF identifier and parameters are mixed into the AEAD associated data, so
data can never be silently reinterpreted under a different scheme.

### WebSocket relay

`core/relay.mjs`. Opt-in client for relaying mail between devices you control.

- **Your IP address and online times become visible to the relay operator.** On Tor
  this defeats the purpose entirely.
- **Traffic analysis remains possible** even with an encrypted body.
- If PGP is off, the relay reads the envelope in plaintext.
- **A malicious relay can drop, replay, reorder or censor** mail. There is no
  authentication of the relay and no delivery guarantee.
- DOM Mail stops being purely local and stops working offline.
- `wss://` is required for any non-local relay; plaintext `ws://` is accepted only
  between loopback addresses.

Both features are wired into the CLI too (`node cli/domail.mjs pgp on`,
`node cli/domail.mjs relay on`), so the headless and site builds behave alike.

## Screen privacy

Address masking is **on by default** in both builds, so a screenshot or a
shoulder-surfer cannot harvest a contact list:

- The identity chip shows `n***@d****.space`; clicking it copies the real address.
- Inbox, outbox and draft lists, and message headers, show masked addresses.
- **Native notifications never carry an address.** The lock screen and OS
  notification centre are outside anything a page can protect, so the sender is
  reported as "masked" rather than leaked to the operating system.
- Header values are inserted as text, never as markup, so a hostile message
  cannot inject HTML through its own headers.

Turn it off in **Settings → Privacy → Show full addresses**, or with
`node cli/domail.mjs mask on` for the CLI.

## Testing

```bash
npm test     # 96 unit tests: engine, MIME, armor, crypto, relay
npm run smoke  # boots the real page in headless Chrome and drives it
```

The smoke test asserts the things unit tests structurally cannot: that the page
boots with no exception, that libsodium starts under the real CSP, that an
identity is provisioned, that tabs switch, that the style control works, that a
message actually reaches the Outbox *and* the Inbox, and that the compose fields
clear afterwards. Both run in CI, so a regression fails the build instead of
shipping.

## Quick Start

1. Open `index.html` in any modern browser (or visit [domail.space](https://domail.space)).
2. A secure mail identity is automatically provisioned.
3. Compose and send messages instantly. All data persists locally in IndexedDB.

## Architecture

```
domail/
├── core/
│   ├── mail.mjs              # RFC 5322 / MIME engine (shared browser + CLI)
│   ├── crypto.mjs            # WebCrypto bindings (Ed25519, X25519, Argon2id)
│   ├── encrypted-store.mjs   # E2E encrypted IndexedDB wrapper
│   ├── antikeylogger.mjs     # Keylogger defenses & virtual keyboard
│   ├── screenprotection.mjs   # PII masking & screen theft protection
│   ├── fingerprinting.mjs    # Browser fingerprint spoofing
│   ├── pgp.mjs               # Optional: OpenPGP-style armor + X25519 sealing
│   ├── relay.mjs             # Optional: opt-in WebSocket relay client
│   └── domains.mjs           # Cyberpunk & hacker domain culture generator
├── assets/
│   ├── css/domail.css        # Futuristic CSS custom property theming
│   ├── js/boot.js            # Pre-paint theme, SW registration, libsodium loader
│   ├── js/error-handler.js   # Global error/unhandled-rejection surface
│   ├── js/domail.js          # Browser app controller & UI wiring
│   └── img/logo.svg          # SVG vector logo
├── cli/
│   └── domail.mjs            # Node.js CLI (ASCII inbox & mail engine)
├── test/
│   └── core.test.mjs         # 52 engine/MIME tests
│       optional.test.mjs     # 38 armor, crypto and relay tests
├── index.html                # App entry point
├── sw.js                     # Service Worker for offline-first caching
└── manifest.webmanifest      # PWA manifest
```

## License

MIT. See [LICENSE](LICENSE).
