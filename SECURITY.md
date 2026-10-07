# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

DOM Mail is a client-side application. All data lives in your browser's
IndexedDB and never leaves your device unless you explicitly export it.

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via [GitHub Security Advisories](https://github.com/neohiro/domail/security/advisories/new).

We aim to acknowledge reports within 72 hours and triage within 7 days.

## Scope

- **In scope**: The mail engine (`core/mail.mjs`), the browser app (`assets/js/domail.js`), and the CLI (`cli/domail.mjs`).
- **Out of scope**: GitHub Pages hosting, DNS configuration, browser vulnerabilities.

## Design Principles

- **Zero telemetry**: No analytics, no tracking, no network calls beyond the initial page load.
- **Local-first**: All mail data stays in IndexedDB. No server component.
- **Ephemeral by default**: The wipe function destroys all data irreversibly.
- **No dependencies**: The entire application is hand-rolled vanilla JS with zero npm packages.
