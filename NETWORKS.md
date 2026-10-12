# DOM Mail: Multi-Network Anonymity & Decentralized Hosting Architecture

DOM Mail (`neohiro/domail`) is built on a strict zero-dependency, client-side, offline-first architecture. Because the entire engine lives in a single static distribution (`index.html` + ES modules), it can be hosted and mirrored across decentralized, peer-to-peer, and darknet routing layers completely outside the traditional World Wide Web (clearnet HTTPS).

This document outlines how `neohiro/domail` is hosted, accessed, and synchronized across alternative networks, and how the **offline anonymous mail server** model operates on each route.

---

## 1. Hosting Architecture: Beyond the Clearnet WWW

To eternalize DOM Mail and make it censorship-resistant, resilient, and multi-network accessible, the static distribution is deployed across the following networks using a **GitHub (SSOT) + Tailscale Node** architecture. GitHub Actions handles building, testing, and continuous deployment, while a persistent node (accessible via Tailscale SSH) hosts the routing daemons.

### A. Tor Onion Service (`http://domail.onion`)
- **What it is**: A v3 Tor Hidden Service routed through the Tor network, providing end-to-end encrypted transport without revealing server IP locations.
- **Hosting Strategy**: 
  1. A lightweight web server (Nginx or Caddy) runs locally on the node on `127.0.0.1:8080`, serving the static files of DOM Mail.
  2. The Tor daemon (`tor`) is configured as a Hidden Service pointing to that local port.
- **Tor Configuration (`/etc/tor/torrc`)**:
  ```text
  HiddenServiceDir /var/lib/tor/domail_service/
  HiddenServicePort 80 127.0.0.1:8080
  ```
- **Address**: `http://<your-v3-hash>.onion` (or vanity address).

### B. I2P Eepsite (`http://domail.i2p`)
- **What it is**: An anonymous garlic-routed network (.i2p eepsite) where connections never touch the public internet.
- **Hosting Strategy**:
  - Run an I2P router daemon (`i2pd`) on the node.
  - Configure an HTTP server tunnel in `i2pd.conf` or `tunnels.conf` pointing to the local web root directory.
- **Configuration (`tunnels.conf`)**:
  ```ini
  [domail-eepsite]
  type = http
  host = 127.0.0.1
  port = 8080
  keys = domail-keys.dat
  ```

### C. Ethereum ENS & Decentralized Web (`domail.eth` via IPFS)
- **What it is**: Decentralized domain resolution pointing to content-addressed immutable storage.
- **Hosting Strategy**:
  - GitHub Actions builds DOM Mail, pins the output directory to IPFS (via Pinata API or a local IPFS daemon on the node), and obtains the Content Identifier (`bafybeic...`).
  - The ENS record (`domail.eth`) `contenthash` is automatically updated to point to the IPFS CID (via Ethers.js / ENS CLI actions).
  - Users resolve `domail.eth` via native ENS browsers (Brave, MetaMask) or public gateways (`domail.eth.limo`, `ipfs.io`).

### D. Radicle P2P Code Collaboration (`rad://...`)
- **What it is**: Sovereign, peer-to-peer code hosting built on Git and Git-based replication.
- **Hosting Strategy**:
  - Mirror the `neohiro/domail` GitHub repository to a Radicle seed node running on your infrastructure (`rad seed`).
  - Developers can fetch, review, and patch DOM Mail entirely off GitHub via the Radicle P2P network.

### E. Yggdrasil Mesh Network (IPv6 Overlay Mesh)
- **What it is**: An end-to-end encrypted IPv6 mesh network that forms a decentralized global IPv6 network without central infrastructure.
- **Hosting Strategy**:
  - Bind the node's local web server to the Yggdrasil IPv6 interface address (`[200::...]`).
  - Accessible directly over Yggdrasil-enabled networks and routers without DNS.

---

## 2. The Offline Anonymous Mail Server Across Networks

DOM Mail does not use a traditional IMAP/SMTP server. Instead, it relies on **client-side cryptographic identities** (Ed25519/X25519 keypairs) and **local encrypted storage** (IndexedDB). 

To make an "offline anonymous mail server" function across these networks without compromising privacy or introducing metadata leakage, DOM Mail implements decentralized message transport layers:

### How Mail Delivery Works Without a Central Server:

1. **Tor / I2P Hidden Service Dropboxes (P2P Sync)**
   - Instead of a public mail server, an instance of DOM Mail or a lightweight sync daemon runs behind a Tor/I2P Hidden Service as a **blind drop box**.
   - The drop box accepts encrypted MIME packets (`core/mail.mjs` + PGP armor / X25519 sealed boxes) via POST requests without logging IP addresses, timestamps, or metadata.
   - Recipients fetch their mail asynchronously when online by querying their designated onion/i2p mailbox drop.

2. **Nostr Relay Network (`wss://relay.domail.space` & Decentralized Relays)**
   - DOM Mail integrates with Nostr (NIP-04 / NIP-17 Encrypted Direct Messages).
   - Mail packets are wrapped as encrypted Nostr events (`kind: 4` or `kind: 1059` gift wraps) and broadcast to a self-hosted Nostr relay (`strfry` or `nostr-rs-relay`) running on your node behind SSL/Tor (`wss://`).
   - Relays act as blind, untrusted store-and-forward buffers: they store ciphertexts without knowing who is talking to whom or what the message contains.

3. **Reticulum Network Stack & LXMF (Asynchronous Mesh Mail)**
   - For ultra-resilient, offline, radio/mesh environments, DOM Mail messages can be serialized into **LXMF (Lightweight Extensible Message Format)** packets.
   - Reticulum routes messages across zero-infrastructure links (packet radio, LoRa, TCP, Bluetooth, I2P) with complete end-to-end encryption and store-and-forward delivery across intermittent mesh nodes.

4. **IPFS / ENS Content-Addressed Mailboxes**
   - For decentralized, bulletin-board style publishing or public dropboxes, encrypted mail payloads can be pinned to IPFS, allowing recipients to pull messages addressed to their public key hashes from distributed IPFS nodes.

---

## 3. Local Companion Daemons & Tor WebSocket Architecture

### Can a browser tab spin up a Tor `.onion` WebSocket server directly?
Standard web browsers (Chrome, Firefox, Safari) enforce strict process sandboxing. A pure static webpage executing in the browser **cannot** spawn raw C/C++ daemons (like `tor`), allocate TCP sockets, or manage Ed25519 hidden service private keys directly from JS global scope.

### The Offline-First Sidecar / Companion Pattern
To bridge an offline browser tab (cached via Service Worker) to Tor `.onion` networks, DOM Mail utilizes a **Local Companion Daemon Architecture**:
1. **The Static Client Download**: The user visits DOM Mail once (over HTTPS, IPFS, or `.onion`) and caches the entire app bundle offline.
2. **Local Loopback WebSocket (`ws://127.0.0.1:...`)**: DOM Mail attempts to connect to a local companion process running on the user's local machine or Tailscale node (e.g., `node tools/smtp-bridge.mjs` for the SMTP/SOCKS5 sidecar, or a tiny custom sidecar script).
3. **Tor SOCKS / Onion Bridge**: The companion daemon manages the actual Tor v3 Hidden Service connection and proxies binary mail frames over the local WebSocket, allowing the offline web tab to send and receive mail over Tor with zero clearnet leak.

---

## 4. Advanced Alternative Transport Possibilities

Beyond Tor, I2P, Nostr, and Reticulum, DOM Mail's decoupled MIME/crypto core supports several advanced experimental and production transport vectors:

1. **WebRTC P2P Data Channels (Direct Browser-to-Browser E2EE Mail)**
   - Two DOM Mail clients connect directly peer-to-peer over WebRTC data channels. Signaling is bootstrapped out-of-band via QR codes, manual SDP copy-paste, or ephemeral Nostr events. Once connected, mail streams directly browser-to-browser with zero intermediary servers.
2. **Bluetooth Low Energy (BLE) / Proximity Air-Gapped Mesh**
   - For mobile and desktop devices with BLE adapters, DOM Mail peers discover each other locally over Bluetooth GATT characteristics and exchange encrypted MIME drop packets without internet or cellular connectivity.
3. **DNS TXT / CNAME Tunneling (Censorship-Circumvention Fallback)**
   - Encrypted and base64url-encoded mail payloads are fragmented and transmitted inside DNS queries (`_mail.recipient.domain.tld`) to a custom recursive nameserver, bypassing deep packet inspection (DPI) firewalls where standard web traffic is blocked.
4. **USB / Animated QR Code "Sneakernet" (Air-Gapped Transport)**
   - For ultra-secure air-gapped environments, users export and import encrypted MIME blocks as JSON files via USB thumb drives or flashing animated QR codes scanned by a webcam.
5. **ActivityPub / Matrix / XMPP Federation Gateways**
   - Lightweight adapter daemons that bridge DOM Mail's Ed25519 cryptographic identities to federated chat and messaging networks, allowing mail to traverse open decentralized networks.

In a production deployment **every one of these transports is terminated on the
`kernel` Tailscale host** (`ssh kernel`) by a shared, hardened Docker compose
stack (`docker-compose.yml` + `Caddyfile`) so that *any user from any network* —
clearnet, `.onion`, `.i2p`, Yggdrasil, Nostr, IPFS, Radicle, Reticulum — lands on
the same DOM Mail build with their own anonymous route in:

| Container | Transport it terminates | Security posture |
| :--- | :--- | :--- |
| `caddy` | Clearnet HTTP(S) + Nostr `wss://` reverse proxy | `cap_drop: ALL` + `NET_BIND_SERVICE`, `no-new-privileges`, healthcheck |
| `tor` | `.onion` v3 hidden service | hidden-service keys persist in its own volume |
| `i2pd` | `.i2p` eepsite | console bound to loopback only |
| `nostr-relay` (strfry) | NIP-04/17 relay | `cap_drop: ALL`, no-new-privileges |
| `yggdrasil` | IPv6 mesh overlay | `NET_ADMIN` only |
| `radicle` | `rad://` seed | no-new-privileges, cap_drop |
| `ipfs` | `ipfs://` gateway + pinning | API bound to loopback only |
| `rnsd` | Reticulum / LXMF mesh | cap_drop, no-new-privileges |
| `vpn-egress` (gluetun) | SOCKS5 `:8080` / HTTP proxy `:8888` for clearnet SMTP gateways | loopback-bound only, full tunnel in a dedicated container |

`docker compose up -d` on `kernel`; per-service vertebrae are annotated in the
file itself. The SMTP bridge (`tools/smtp-bridge.mjs`) chains its TCP leg through
the `vpn-egress` SOCKS5 endpoint with `--via socks5://127.0.0.1:8080` so mail to
Gmail/Outlook exits through the tunnel, never the host's real IP.

---

## 5b. Sending to Real Clearnet Mailboxes (Gmail / Outlook / Microsoft 365)

The DOM Mail engine is network-free by design; "send" writes to the local Outbox
and loops a copy to the Inbox. Egress to actual mailboxes is provided by the
optional **SMTP bridge** daemon (see `README.md`):

- `tools/smtp-bridge.mjs --server smtp.gmail.com:587 --mode starttls ...` with
  an app password — validated by the loopback integration test
  (`test/smtp.test.mjs`) that drives the engine's `smtpSubmit()` over real TCP
  with `AUTH LOGIN` and RFC 5321 dot-stuffing.
- `--validate` proves a given provider accepts your sender + credentials without
  sending a letter.
- The protocol logic lives in `core/mail.mjs#smtpSubmit`, so the browser and CLI
  share it and the browser build still performs zero network I/O itself.

---

## 6. Per-Transport Cybersecurity & Anonymity Risk (single source of truth)

Settings → Network (site) and `cli/domail.mjs network help` (CLI) ship the same
per-vector disclosures. Summary:

| Transport | Risk | Biggest anonymity danger | Recommended mitigation |
| :--- | :--- | :--- | :--- |
| Direct WWW (80/443 TLS) | **High** | Real IP to servers/ISPs/CDNs; envelope loggable | VPN gateway or Tor; keep PGP on |
| Tor `.onion` | Low | Traffic correlation if clearnet is mixed | Circuit discipline; separate identities |
| I2P `.i2p` | Low | Misconfigured router leaks IP | Firewall the router; verify tunnel leases |
| ENS / IPFS | Medium | Gateway & RPC operators see IP/query patterns | Self-host IPFS on `kernel`; pin widely |
| Radicle `rad://` | Low | Peer gossip exposes node identity | Run the seed behind Tor/Yggdrasil |
| Yggdrasil mesh | Low | Peers observe overlay path | Add an anonymizing layer; rotate keys |
| Nostr `wss://` | Medium | Relays see IP, timing, sizes | Self-host strfry; publish over Tor/VPN |
| Reticulum / LXMF | Low | Radio direction-finding | Encrypt (LXMF/PGP); reduce power |
| WebRTC P2P | Medium | ICE leaks local/public IPs | Force TURN-only ICE; in-band signalling |
| BLE proximity | Medium | Address tracking over time | Rotate addresses; keep payload sealed |
| DNS TXT tunnel | **High** | Resolvers log everything; DPI fingerprints | Trusted DoH/DoT; rate-limit queries |
| USB/QR Sneakernet | Minimal | Physical theft / shoulder surfing | Verify fingerprints; destroy media |
| Federation gateways | Medium | Servers retain metadata; alias linkage | Self-host bridge; compartmental identities |

---

## 7. Deployment Summary

| Network Layer | Protocol / URI | Hosting Mechanism | Mail Transport Role |
| :--- | :--- | :--- | :--- |
| **Clearnet WWW** | `https://domail.space` | GitHub Pages | Public discovery & web client |
| **Tor Network** | `http://domail.onion` | Tor v3 Hidden Service + Nginx on Node | Anonymous web client & hidden mailbox drop |
| **I2P Network** | `http://domail.i2p` | `i2pd` HTTP Server Tunnel on Node | Garlic-routed web client & isolated sync |
| **Decentralized** | `domail.eth` (IPFS) | Pinata / IPFS + ENS Contenthash | Immutable code distribution |
| **P2P Mesh** | Yggdrasil IPv6 | Mesh Node Web Binding | Direct encrypted IPv6 connectivity |
| **Relay / Chat** | Nostr (`wss://`) | Self-hosted `strfry` relay | Asynchronous E2EE store-and-forward messaging |
| **Offline Mesh** | Reticulum / LXMF | Packet radio / LoRa gateways | Zero-infrastructure asynchronous mail delivery |
