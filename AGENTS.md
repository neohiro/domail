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
