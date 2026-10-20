# MX Node — Production Status

This file records what the native node actually does today. Every statement
below is checked against the source in `src/`; when the two disagree, the
source wins and this file is the bug.

## Scope

`rust-mx-node` is a self contained mail node: it acts as the MX for its own
domain, serves SMTP, Submission and IMAP, ships the 13+ transport vectors and
installs itself as an operating system service. It has no server component
dependency on the browser app — the browser drives it over a loopback control
API.

## Protocol servers

| Server      | Ports                | Notes                                                          |
|-------------|----------------------|----------------------------------------------------------------|
| SMTP        | 25 (configurable)    | STARTTLS, AUTH PLAIN / AUTH LOGIN, relay protection, DATA      |
| Submission  | 587, 465             | Submission always requires authentication, implicit TLS on 465  |
| IMAP        | 143, 993             | IMAP4rev1: SELECT, FETCH, APPEND, SEARCH, STORE, EXPUNGE, IDLE |

- Relay protection: unauthenticated RCPT TO is only accepted for the local
domain; authenticated sessions may relay through the transport manager.
- `StoredMessage.deleted` backs `STORE \Deleted` plus `EXPUNGE`.

## Transport vectors

`TransportManager` owns every vector and is started by the node itself:
`direct`, `tor`, `i2p`, `ens`, `radicle`, `yggdrasil`, `nostr`, `reticulum`,
`webrtc`, `ble`, `dns`, `sneakernet`, `federation`, plus `lora` and
`packet_radio`.

- `TransportManager::get()` returns a cloned `Arc<RwLock<Box<dyn Transport>>>`.
- `activate(id)` and `activate_all()` bring the vectors up on startup; a vector
that fails to activate is logged and skipped, it never takes the node down.
- The `bridge` transport is the abstract peer link used by federation and ens.

## Control API (the browser wizard integration point)

A page cannot install an operating system service, so the wizard talks to the
running node over a loopback only HTTP API (`src/control.rs`, `src/http.rs`).

- Binds `127.0.0.1` by default; refuses non loopback peers.
- Authentication is a constant time comparison against a bearer token.
- No CORS headers are emitted, so a cross origin page cannot read responses.
- `public_config()` redacts the token, the certificate, the private key and every
password hash.
- The HTTP server caps the request head at 16 KiB and the body at 1 MiB.

## Operating system service

`src/service.rs` covers all three desktop platforms.

- Windows — the Service Control Manager responds to both `Stop` and the
service manager stop event by setting the stop flag.
- Linux — a `systemd` unit (`systemctl` start / stop / disable).
- macOS — a `launchd` plist.

The binary exposes `serve`, `install`, `uninstall`, `status`, `token`,
`hash-password`, `doctor`, `config`, `help` and `version`.

## Storage

`src/storage.rs` keeps messages encrypted at rest with a 32 byte master key held
in `master.key` next to the database (`0600` on unix). `load_or_create_master_key`
creates it on first run and reuses it afterwards.

## Tests

- `tests/integration_test.rs` — transport activation for direct, tor, nostr
and lora.

## Verification status

- `cargo fmt --check` — clean.
- `cargo check` / `cargo build` / `cargo test` / `cargo clippy` — **blocked by
  the environment, not by the code**: this machine has no MSVC linker. The only
  `link.exe` on PATH is GNU coreutils 8.32 from Git for Windows, which cannot
  link `x86_64-pc-windows-msvc` objects. The crate therefore cannot be compiled
  or tested here until a Visual Studio Build Tools linker is installed. The
  dependency graph resolves and the source was reviewed against the vendored
  crate sources in the local cargo registry.
