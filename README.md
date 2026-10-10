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
- **Multi-Network Accessibility**: Fully accessible and optimized across:
  - **HTTPS / Web**: `https://domail.space`
  - **Tor Onion Service**: `http://domail.onion`
  - **I2P Eepsite**: `http://domail.i2p`
  - **Ethereum ENS / Decentralized Web**: `domail.eth` (IPFS gateway resolver)
  - **IPFS / Radicle**: `ipfs://bafybeic...`
  - **Nostr Relay**: `wss://relay.domail.space`
- **Zero Dependencies**: Pure ES modules, zero npm packages, zero build step.

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
│   └── core.test.mjs         # 52 comprehensive unit tests
├── index.html                # App entry point
├── sw.js                     # Service Worker for offline-first caching
└── manifest.webmanifest      # PWA manifest
```

## Testing

```bash
node --test test/core.test.mjs
```

52 rigorous tests covering base64 roundtrips, RFC 2047 encoded-words, header folding, address parsing, MIME multipart parsing, dot-stuffing, storage adapters, crypto sealing, and export/import roundtrips.

## License

MIT. See [LICENSE](LICENSE).
