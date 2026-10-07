# DOM Mail

A local mail engine that runs entirely in your browser tab. No server, no account, no trace.

## What it is

DOM Mail is a complete email client and local mail server that lives in a single HTML page. It implements RFC 5322 message formatting, MIME multipart encoding, address parsing, and a persistent mailbox — all in vanilla JavaScript with zero dependencies.

Your mail never leaves your browser. There is no backend, no database server, and no network connection beyond the initial page load.

## Features

- **Local mail engine**: Send and receive mail within the same browser tab. Messages are stored in IndexedDB and persist across refreshes.
- **Ephemeral identity**: Generate a new Ed25519/X25519 keypair on demand. Share your public key. Wipe everything with one click.
- **Full compose experience**: Rich text editing with bold, italic, underline, strikethrough, font size, color, and highlight. Emoji picker with skin tone support. Attachments.
- **Auto-drafts**: Composing autosaves to drafts every 450ms. Close and resume without losing work.
- **Contacts**: Automatically learns names from incoming and outgoing mail.
- **Export/Import**: Export settings only, or settings plus all mail. Restore from a backup file.
- **Notifications**: Native Notification API support plus a WebAudio chime.
- **Light/Dark mode**: Persistent theme with a random neon accent color on style overhaul.
- **CLI**: A command-line interface (`cli/domail.mjs`) that shares the same mail engine and renders an ASCII inbox.
- **Zero dependencies**: No npm packages. No build step. No framework.

## Quick start

Open `index.html` in any modern browser. Click **Create mail account**. Start sending mail to yourself.

## Architecture

```
domail/
├── core/
│   └── mail.mjs          # RFC 5322 / MIME engine (shared browser + CLI)
├── assets/
│   ├── css/domail.css    # All styles
│   ├── js/domail.js      # Browser app (IndexedDB, UI, notifications)
│   └── img/logo.svg      # Logo
├── cli/
│   └── domail.mjs        # Node.js CLI (ASCII inbox)
├── test/
│   └── core.test.mjs     # 42 tests, all passing
├── index.html            # App entry point
└── manifest.webmanifest  # PWA manifest
```

### The mail engine (`core/mail.mjs`)

The engine is a pure ES module with no DOM or Node dependencies. It provides:

- `buildMessage(opts)` — Build a complete RFC 5322 message with MIME multipart support
- `parseMessage(raw)` — Parse a raw message into a normalized envelope
- `MailEngine` — A local mail store with `send()`, `deliver()`, `list()`, `remove()`, `wipe()`, `export()`, `import()`
- `memoryStore()` / `indexedDbStore()` — Pluggable storage adapters

The same engine powers both the browser app and the CLI, so neither can drift from the other.

### Storage

All data lives in IndexedDB under the `domail` database. The engine uses a simple key-value store with keys like `mbox:inbox`, `mbox:outbox`, `mbox:drafts`, `identity`, `contacts`, `signature`.

The `wipe()` method deletes every key and clears the in-memory state. There is no recovery.

### Crypto

Identity keys are generated using the Web Crypto API:

- **Ed25519** for signing (Chrome 137+, Firefox 129+, Safari 17+)
- **X25519** for key exchange

Public keys are exported as raw base64 and displayed in a `-----BEGIN DOM MAIL PUBLIC KEY-----` block that can be copied and shared.

### Polling

The "server" is a `setInterval` loop that runs every 3 seconds. It reads the local store, diffs against previously seen message IDs, and triggers notifications for new mail. When there is nothing to do, it costs nothing.

## CLI

```bash
node cli/domail.mjs
```

The CLI renders an ASCII inbox, allows reading and composing messages, and shares the same `core/mail.mjs` engine as the browser app.

## Testing

```bash
node --test test/core.test.mjs
```

42 tests covering:
- Base64 encoding/decoding (all byte lengths, RFC 4648 vectors)
- RFC 2047 encoded-words
- Header folding
- Address parsing
- Single-part and multipart message building
- MIME tree walking and attachment extraction
- Dot-stuffing and wire format
- Engine operations (send, deliver, list, remove, wipe)
- Export/import roundtrip
- Storage adapter isolation

## Deployment

DOM Mail is hosted on GitHub Pages at [domail.space](https://domail.space).

The site is plain static HTML/CSS/JS with no build step. The `.nojekyll` file ensures GitHub Pages serves it as-is.

### DNS records

| Type  | Name | Value                                    |
|-------|------|------------------------------------------|
| A     | @    | 185.199.108.153                          |
| A     | @    | 185.199.109.153                          |
| A     | @    | 185.199.110.153                          |
| A     | @    | 185.199.111.153                          |
| CNAME | www  | neohiro.github.io                        |

The `CNAME` file in the repo root contains `domail.space`.

## License

MIT. See [LICENSE](LICENSE).
