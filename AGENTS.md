# AGENTS.md

## What this is

DOM Mail is a zero-dependency, client-side mail engine. It runs entirely in the browser (or in Node.js for the CLI) with no server component.

## Architecture

- `core/mail.mjs` — Pure ES module. RFC 5322 / MIME engine. No DOM, no Node globals. Shared by browser and CLI.
- `assets/js/domail.js` — Browser app. IndexedDB storage, WebCrypto identity, UI wiring, notifications, polling.
- `assets/css/domail.css` — All styles. CSS custom properties for theming.
- `cli/domail.mjs` — Node.js CLI. ASCII inbox, compose, read.
- `test/core.test.mjs` — 42 tests. Run with `node --test test/core.test.mjs`.

## Key invariants

1. **No network calls.** The app must never make a network request beyond the initial page load. No analytics, no telemetry, no CDN.
2. **No dependencies.** Zero npm packages. Everything is hand-rolled.
3. **Storage isolation.** All data lives in IndexedDB under the `domail` database. The `wipe()` method must destroy everything.
4. **Shared engine.** The browser app and CLI must use the same `core/mail.mjs`. Never fork the engine.

## Testing

```bash
node --test test/core.test.mjs
```

All 42 tests must pass before committing.

## Code style

- Vanilla JS (ES modules). No framework, no build step.
- CSS custom properties for all theming. No CSS framework.
- Semantic HTML. ARIA attributes for interactive elements.
- Comments explain *why*, not *what*.

## Git

- Branch: `main`
- Commit style: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- Never commit secrets, keys, or personal data.

## Agentic MCP & CLI Usage for Autonomous Bots

DOM Mail provides a fully non-interactive, scriptable Node.js CLI (`cli/domail.mjs`) that shares the exact same cryptographic mail engine as the browser app. This allows AI agents, LLM tool-use runners, and autonomous bots to communicate via end-to-end encrypted mail offline without cloud dependencies:

- `node cli/domail.mjs inbox` — check my inbox
- `node cli/domail.mjs read <id>` — read a specific message
- `node cli/domail.mjs compose <recipient@domain> <subject> <body>` — compose and send
- `node cli/domail.mjs network <status|help|<transport> [on|off|info]>` — toggle and disclose all 13 transport vectors (`direct`, `tor`, `i2p`, `ens`, `radicle`, `yggdrasil`, `nostr`, `reticulum`, `webrtc`, `ble`, `dns`, `sneakernet`, `federation`). `network help` prints the cybersecurity/anonymity disclosure for every vector.
- `node cli/domail.mjs vpn [status|on|off|set <endpoint>]` — route public clearnet egress through a SOCKS5/HTTP/WireGuard endpoint
- `node cli/domail.mjs wipe` — destroy all local stores

### Run the CLI without the `node` prefix

`cli/domail.mjs` is an ESM Node.js executable (it starts with `#!/usr/bin/env node`), so bare `node` is the zero-install invocation. The package also ships a `bin` entry: run `npm link` (or `npm install -g .` from a checkout) once, then `domail inbox` works directly for shells, agents, and cron/MCP tool runners.
