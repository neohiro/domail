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
- **Enforced by the browser, not by convention**: A Content-Security-Policy is
  delivered as a `<meta http-equiv>` tag, so it applies on GitHub Pages (which
  ignores the `_headers` file) as well as on hosts that honour `_headers`.

### Content Security Policy

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self';
manifest-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none';
base-uri 'none'; form-action 'none'
```

What each restriction buys:

| Directive             | Effect                                                                 |
| --------------------- | ---------------------------------------------------------------------- |
| `script-src 'self'`   | No inline scripts, no `eval`, no CDN-hosted code. A successful XSS injection cannot execute. |
| `connect-src 'self'`  | Injected script cannot `fetch` or `XHR` to any external host, so mail content cannot be exfiltrated. |
| `object-src 'none'`   | Blocks plugin content (`<object>`, `<embed>`).                          |
| `frame-src 'none'`    | The app cannot be framed, and cannot frame third parties.               |
| `base-uri 'none'`     | Blocks `<base>` hijacking, which would otherwise repoint every relative URL. |
| `form-action 'none'`  | Blocks credential-exfiltration via form submission.                     |
| `img-src 'self' data:`| Prevents beacons via remote image loads.                                 |

`style-src` keeps `'unsafe-inline'` because the app sets CSS custom properties
imperatively for live theme overhauls and uses `style` attributes for layout
that depends on runtime measurements. Styles cannot exfiltrate data, so this
does not weaken the threat model.

### CI enforcement

`.github/workflows/pages.yml` fails the build if `index.html` regains an inline
`<script>`, or if any of the boot files go missing. This keeps the CSP honest
over time instead of silently rotting.

## Optional networked features

Two features break the local-only default. Both ship **disabled** and must be
enabled deliberately in **Settings → Network** (or via the CLI). Enabling either
one is a deliberate trade of the privacy properties above, and the UI states the
cost before you confirm.

| Feature | Module | Default | What giving it up costs |
| ------- | ------ | ------- | ---------------------- |
| Armored encryption ("PGP") | `core/pgp.mjs` | off | Envelope metadata (From, To, Subject, Date, size) stays visible; timing analysis remains possible. Not RFC 4880 interoperable. |
| WebSocket relay | `core/relay.mjs` | off | Your IP and online times become visible to the relay operator; traffic analysis possible; a malicious relay can drop, replay, reorder or censor; the app stops working offline. |

Additional notes:

- **No silent downgrade.** With PGP on, a message to an address whose public key
  is unknown is *refused*, not sent in the clear.
- **No key server.** Public keys are learned only from DOM Mail identities already
  in contact. Nothing is fetched to learn a key.
- **`ws://` is refused** for any non-loopback host, so the relay cannot silently
  downgrade to plaintext.
- **The relay is not authenticated and offers no delivery guarantee.** Treat
  anything arriving through it as untrusted input until verified at the message
  layer.

### Reporting

Both features are in scope for security review. Please use GitHub Security
Advisories rather than public issues (see above).

## Verifying the policy yourself

```bash
# Should print the three external scripts and nothing inline.
grep -oE '<script[^>]*>' index.html

# Should find no matches.
grep -rnE 'eval\(|new Function' assets core
```
