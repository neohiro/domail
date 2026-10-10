/**
 * DOM Mail — opt-in WebSocket relay client.
 *
 * Zero dependencies. Pure ESM. No DOM, no Node globals required (uses the
 * global WebSocket, present in browsers and Node 22+).
 *
 * ## Default state is OFF
 *
 * Importing this module performs no I/O. Nothing connects until `connect()` is
 * called explicitly, and `connect()` refuses unless BOTH `enabled` and an
 * explicit `url` are supplied. The UI wires `enabled` from a user setting that
 * defaults to false.
 *
 * ## Threat model — read this before enabling
 *
 * Turning on a relay deliberately trades the project's core privacy property
 * away. Specifically:
 *
 *  1. **Your IP address is visible to the relay operator.** They learn where
 *     you are and when you are online. On Tor, this defeats the entire point.
 *  2. **Traffic analysis is possible.** An observer (including a hostile
 *     network or the relay itself) can correlate connection times, message
 *     sizes, and direction, even when the body is encrypted.
 *  3. **Metadata leaks unless you also enable PGP.** The envelope carries
 *     From, To, Subject, Date and size. Encrypting only the body still leaks
 *     who talks to whom and when. Use PGP with full-ciphertext encryption if
 *     metadata matters.
 *  4. **A malicious relay can drop, replay, reorder or censor messages.** There
 *     is no authentication of the relay itself and no delivery guarantee. Do
 *     not rely on it for anything you cannot afford to lose.
 *  5. **It breaks the offline-first guarantee.** DOM Mail stops being a purely
 *     local engine.
 *
 * ## Transport
 *
 * `wss://` is required unless the page itself is served over `localhost` or
 * loopback. A plaintext `ws://` connection to a remote host would expose the
 * entire session, so the client refuses to build one.
 */

const PROTOCOL_VERSION = 1;
const HEARTBEAT_MS = 30000;
const MAX_BACKOFF_MS = 60000;
const MAX_QUEUE = 500;

/** Hard ceiling on a single frame, to stop a hostile peer exhausting memory. */
export const MAX_FRAME_BYTES = 5 * 1024 * 1024;

export class RelayError extends Error {}

export class RelayClient {
  /**
   * @param {{enabled?:boolean, url?:string, onStatus?:Function, onMessage?:Function,
   *          onError?:Function, WebSocketImpl?:Function}} opts
   */
  constructor(opts = {}) {
    this.enabled = opts.enabled === true;
    this.url = opts.url || '';
    this.status = 'disabled';
    this.socket = null;
    this.queue = [];
    this.attempts = 0;
    this.heartbeatTimer = null;
    this.reconnectTimer = null;
    this.identity = null;
    /** Set by the owner once the user turns the setting back off. */
    this._closing = false;

    this.onStatus = opts.onStatus || (() => {});
    this.onMessage = opts.onMessage || (() => {});
    this.onError = opts.onError || (() => {});
    this.WebSocketImpl = opts.WebSocketImpl || (typeof WebSocket !== 'undefined' ? WebSocket : null);
  }

  /** Update identity used in the handshake. Call before connect(). */
  setIdentity(identity) {
    this.identity = identity || null;
  }

  _setStatus(status, detail) {
    this.status = status;
    this.onStatus(status, detail);
  }

  /**
   * Validate that a URL is safe to use from the current page origin.
   *
   * `ws://` is plaintext. It is permitted only when BOTH the page is local
   * (served from localhost / a file) AND the relay host is loopback, because a
   * plaintext connection to any remote host would expose the whole session.
   * Everything remote must be `wss://`.
   *
   * Exported for tests.
   */
  static validateUrl(raw, pageHost = (typeof location !== 'undefined' ? location.hostname : '')) {
    const url = String(raw || '').trim();
    if (!url) throw new RelayError('no relay URL configured');
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new RelayError('relay URL is not a valid absolute URL');
    }
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
      throw new RelayError(`relay must use ws:// or wss:// (got ${parsed.protocol})`);
    }
    if (parsed.protocol === 'wss:') return parsed.href;

    const isLoopback = (h) => h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]';
    const pageIsLocal = pageHost === '' || isLoopback(pageHost);
    if (!pageIsLocal || !isLoopback(parsed.hostname)) {
      throw new RelayError('plaintext ws:// is only permitted between local clients; use wss:// for remote relays');
    }
    return parsed.href;
  }

  /** Explicitly connect. No-op unless enabled and a valid URL are present. */
  connect() {
    if (!this.enabled) {
      this._setStatus('disabled');
      return false;
    }
    if (!this.WebSocketImpl) {
      this._setStatus('unsupported', 'this runtime has no WebSocket');
      return false;
    }
    if (this.socket && (this.socket.readyState === 0 || this.socket.readyState === 1)) {
      return true;
    }

    let href;
    try {
      href = RelayClient.validateUrl(this.url);
    } catch (e) {
      this._setStatus('error', e.message);
      this.onError(e);
      return false;
    }

    this._closing = false;
    this.attempts = 0;
    this._open(href);
    return true;
  }

  _open(href) {
    let socket;
    try {
      socket = new this.WebSocketImpl(href);
    } catch (e) {
      this._setStatus('error', e.message);
      this.onError(new RelayError(`could not open relay: ${e.message}`));
      this._scheduleReconnect(href);
      return;
    }
    this.socket = socket;
    this._setStatus('connecting');

    socket.onopen = () => {
      this.attempts = 0;
      this._setStatus('connected');
      this._send({ type: 'hello', v: PROTOCOL_VERSION, address: this.identity?.address || null });
      this._flush();
      this._startHeartbeat();
    };

    socket.onmessage = (event) => {
      let frame;
      try {
        frame = JSON.parse(typeof event.data === 'string' ? event.data : '');
      } catch {
        this.onError(new RelayError('relay sent a frame that is not JSON'));
        return;
      }
      if (frame?.type === 'pong') return;
      if (frame?.type === 'mail') {
        try {
          this.onMessage(frame);
        } catch (e) {
          this.onError(e);
        }
      }
    };

    socket.onerror = () => {
      // The DOM Event carries no useful detail; surface a generic message.
      this._setStatus('error', 'relay connection error');
    };

    socket.onclose = () => {
      this._stopHeartbeat();
      this.socket = null;
      if (this._closing) {
        this._setStatus('disconnected');
        return;
      }
      this._setStatus('disconnected');
      this._scheduleReconnect(href);
    };
  }

  _scheduleReconnect(href) {
    if (this._closing || !this.enabled) return;
    clearTimeout(this.reconnectTimer);
    this.attempts++;
    // Exponential backoff with jitter so a downed relay is not hammered.
    const base = Math.min(1000 * 2 ** Math.min(this.attempts, 6), MAX_BACKOFF_MS);
    const delay = Math.round(base * (0.5 + Math.random() * 0.5));
    this.reconnectTimer = setTimeout(() => {
      if (this.enabled && !this._closing) this._open(href);
    }, delay);
    if (this.reconnectTimer.unref) this.reconnectTimer.unref();
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.socket && this.socket.readyState === 1) {
        this._send({ type: 'ping' });
      }
    }, HEARTBEAT_MS);
    if (this.heartbeatTimer.unref) this.heartbeatTimer.unref();
  }

  _stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  _send(obj) {
    if (!this.socket || this.socket.readyState !== 1) return false;
    const text = JSON.stringify(obj);
    if (text.length > MAX_FRAME_BYTES) {
      this.onError(new RelayError('outbound frame exceeds the relay size limit'));
      return false;
    }
    this.socket.send(text);
    return true;
  }

  _flush() {
    while (this.queue.length) {
      const item = this.queue[0];
      if (!this._send(item)) return;
      this.queue.shift();
    }
  }

  /**
   * Publish a mail for relay delivery.
   * Queues while disconnected, so a send never silently disappears.
   */
  publish(mail) {
    if (!this.enabled) return { queued: false, reason: 'relay disabled' };
    const frame = { type: 'publish', v: PROTOCOL_VERSION, mail };
    if (this._send(frame)) return { queued: false, sent: true };
    if (this.queue.length >= MAX_QUEUE) {
      this.queue.shift();
    }
    this.queue.push(frame);
    return { queued: true, depth: this.queue.length };
  }

  /** Explicit disconnect. Also clears the queue and any pending reconnect. */
  disconnect(reason = 'disconnected by user') {
    this._closing = true;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this._stopHeartbeat();
    this.queue.length = 0;
    if (this.socket) {
      try { this.socket.close(1000, 'client disconnect'); } catch {}
      this.socket = null;
    }
    this._setStatus('disconnected', reason);
  }

  /** Turn the feature off entirely: disconnect and refuse future connects. */
  shutdown() {
    this.enabled = false;
    this.disconnect('relay disabled');
    this._setStatus('disabled');
  }

  stats() {
    return {
      enabled: this.enabled,
      status: this.status,
      queued: this.queue.length,
      attempts: this.attempts,
    };
  }
}

export function createRelayClient(opts = {}) {
  return new RelayClient(opts);
}

/**
 * The disclosure text rendered in Settings. Kept here so the UI and the docs
 * cannot drift apart.
 */
export const RELAY_DISCLOSURE = [
  'Enabling a relay gives up DOM Mail\'s core privacy property. Before you do, understand exactly what changes:',
  '• Your IP address and online times become visible to the relay operator. On Tor this defeats the purpose entirely.',
  '• Traffic analysis stays possible even with an encrypted body: an observer can still see who talks to whom, when, and how much data moves.',
  '• If PGP is off, the message envelope (From, To, Subject, Date) is readable by the relay in plaintext.',
  '• A malicious relay can drop, replay, reorder or censor anything it carries. There is no authentication of the relay and no delivery guarantee.',
  '• DOM Mail stops being purely local and stops working offline.',
  'Leave this off unless you specifically need to relay mail between two devices you control.',
].join('\n');

export const PGP_DISCLOSURE = [
  'DOM Mail armor is an OpenPGP-compatible envelope (RFC 4880 section 6, with CRC-24 checksums) around DOM Mail\'s own packet format.',
  'It encrypts against a recipient\'s X25519 key using libsodium sealed boxes, and can optionally sign with Ed25519.',
  'It is NOT a byte-for-byte RFC 4880 OpenPGP message and will not decrypt in GnuPG. GnuPG armor tools will still parse the envelope and validate the checksum.',
  'Enabling PGP does not by itself hide metadata: the relay still sees From, To, Subject and Date unless you encrypt the entire envelope, which DOM Mail does not yet do.',
].join('\n');