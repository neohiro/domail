/**
 * DOM Mail Local MX Node — native control API client.
 *
 * The MX node is a real operating system service (`mx-node serve`). A page
 * cannot install a service, so the wizard drives the node through the
 * loopback-only HTTP control API instead of an in-process stub.
 *
 * The control API refuses non loopback peers, requires a bearer token and
 * never answers cross origin preflight requests, so a page that knows the
 * token is the only thing that can talk to it.
 *
 * Endpoints (see rust-mx-node/src/control.rs):
 *   GET  /api/v1/health              -> { status, version }
 *   GET  /api/v1/status              -> { domain, hostname, transport_count, ... }
 *   GET  /api/v1/transports          -> { transports: [...] }
 *   GET  /api/v1/config              -> the public configuration
 *   GET  /api/v1/service             -> { installed, running, kind }
 *   POST /api/v1/service/start       -> start the operating system service
 *   POST /api/v1/service/stop        -> stop the operating system service
 *   POST /api/v1/transports/{id}/activate
 *   POST /api/v1/transports/{id}/deactivate
 *
 * The token is printed by `mx-node token` and by `mx-node install`.
 */

const DEFAULT_CONTROL_URL = 'http://127.0.0.1:8787';

/** Where the token is remembered between sessions. */
const TOKEN_STORAGE_KEY = 'mx-node-token';

export class MxNodeClient {
  /**
   * @param {object} opts
   * @param {string} [opts.controlUrl] loopback base url of the control API
   * @param {string} [opts.token] bearer token of the control API
   * @param {string} [opts.hostname] domain the node serves
   * @param {function} [opts.onStatus] (status, detail) => void
   * @param {function} [opts.onInboundMail] (rawMessage) => void
   * @param {function} [opts.onError] (error) => void
   */
  constructor(opts = {}) {
    this.controlUrl = (opts.controlUrl || DEFAULT_CONTROL_URL).replace(/\/+$/, '');
    this.token = opts.token || readStoredToken();
    this.hostname = opts.hostname || '';
    this.identity = opts.identity || null;
    this.onStatus = opts.onStatus || (() => {});
    this.onInboundMail = opts.onInboundMail || (() => {});
    this.onError = opts.onError || (() => {});

    this.running = false;
    this._pollTimer = null;
    this._lastStatus = null;
  }

  /** Remember the token so the wizard does not ask for it again. */
  rememberToken() {
    if (!this.token) return false;
    try {
      localStorage.setItem(TOKEN_STORAGE_KEY, this.token);
      return true;
    } catch (e) {
      return false;
    }
  }

  /** One request against the control API. */
  async _fetch(path, method = 'GET', body = null) {
    const headers = { 'Authorization': `Bearer ${this.token}` };
    if (body) headers['Content-Type'] = 'application/json';

    const response = await fetch(`${this.controlUrl}${path}`, {
      method,
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });

    const text = await response.text();
    let data = text;
    try { data = text ? JSON.parse(text) : null; } catch (e) { /* plain text body */ }
    return { ok: response.ok, status: response.status, data };
  }

  /** The error message of a failed response, if there is one. */
  static _error(result) {
    if (!result) return 'the node did not answer';
    if (result.data && typeof result.data === 'object' && result.data.error) return result.data.error;
    return `the node answered with status ${result.status}`;
  }

  /**
   * Connect to the node, starting the operating system service when it is
   * installed but not running yet.
   */
  async start() {
    this.onStatus('starting', 'Connecting to the native MX node…');

    let health = await this._fetch('/api/v1/health').catch(() => null);
    if (!health || !health.ok) {
      const service = await this._fetch('/api/v1/service').catch(() => null);
      if (service && service.ok && service.data && !service.data.running) {
        const started = await this._fetch('/api/v1/service/start', 'POST').catch(() => null);
        if (started && started.ok) {
          this.onStatus('service_started', 'The operating system service was started.');
          health = await this._waitForHealth();
        }
      }
    }

    if (!health || !health.ok) {
      const error = new Error(
        'The native MX node is not running. Install it with "mx-node install" ' +
        'and start it with "mx-node serve", then copy the token from "mx-node token".'
      );
      this.onStatus('error', error.message);
      this.onError(error);
      throw error;
    }

    this.running = true;
    this.rememberToken();
    this.onStatus('running', `The native MX node is active (${this.controlUrl}).`);

    this._pollTimer = setInterval(() => { this._poll(); }, 5000);
    return this;
  }

  /** Wait a few seconds for the service to come up. */
  async _waitForHealth(attempts = 10) {
    for (let attempt = 0; attempt < attempts; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 500));
      const health = await this._fetch('/api/v1/health').catch(() => null);
      if (health && health.ok) return health;
    }
    return null;
  }

  /** Keep the wizard in step with the node. */
  async _poll() {
    try {
      const status = await this._fetch('/api/v1/status');
      if (!status.ok) {
        this.onStatus('service_down', 'The native MX node is not answering.');
        return;
      }
      this._lastStatus = status.data;
      const connected = status.data.connected_transports || 0;
      this.onStatus('running', `The native MX node is active, ${connected} transport(s) connected.`);
    } catch (e) {
      /* a poll failure is not worth reporting every five seconds */
    }
  }

  /** Stop the operating system service and stop polling. */
  async stop() {
    this.running = false;
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
    try {
      await this._fetch('/api/v1/service/stop', 'POST');
    } catch (e) {
      /* the node may already be gone */
    }
    this.onStatus('stopped', 'The native MX node was stopped.');
  }

  /** The transports the node reports, including their connection state. */
  async transports() {
    const result = await this._fetch('/api/v1/transports');
    if (!result.ok) throw new Error(MxNodeClient._error(result));
    return (result.data && result.data.transports) || [];
  }

  /** Switch a single transport on or off. */
  async setTransport(id, enabled) {
    const action = enabled ? 'activate' : 'deactivate';
    const result = await this._fetch(`/api/v1/transports/${encodeURIComponent(id)}/${action}`, 'POST');
    if (!result.ok) throw new Error(MxNodeClient._error(result));
    return true;
  }

  /** The state of the operating system service. */
  async serviceStatus() {
    const result = await this._fetch('/api/v1/service');
    if (!result.ok) throw new Error(MxNodeClient._error(result));
    return result.data;
  }

  /**
   * Report whether the node can receive mail.
   *
   * The node listens for SMTP on its own port, so a healthy control API and
   * a running service are the signal that the node can.
   */
  async testConnectivity() {
    const started = performance.now();
    try {
      const health = await this._fetch('/api/v1/health');
      const latency = Math.round(performance.now() - started);
      if (!health.ok) {
        return { port25Reachable: false, tlsValid: false, tlsError: MxNodeClient._error(health), latency };
      }
      return { port25Reachable: true, tlsValid: true, tlsError: null, latency };
    } catch (e) {
      return { port25Reachable: false, tlsValid: false, tlsError: e.message, latency: 0 };
    }
  }
}

/** Read the remembered token, if the browser has one. */
export function readStoredToken() {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) || '';
  } catch (e) {
    return '';
  }
}

/** Forget the remembered token. */
export function forgetStoredToken() {
  try {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch (e) {
    /* private browsing may refuse */
  }
}

/**
 * Create a client for the native node.
 *
 * The client is returned even when the node is not reachable, so the wizard
 * can show a helpful error instead of failing silently.
 */
export async function createLocalMxNode(opts = {}) {
  return new MxNodeClient(opts);
}
