/**
 * DOM Mail — Decentralized Nostr-based Relay Discovery.
 * Discovers SMTP-capable WebSocket relay nodes across public Nostr relays.
 * Implements NIP-65 relay list caching with IndexedDB storage and health checks.
 */

const CACHE_DB_NAME = 'domail-nostr-cache';
const CACHE_STORE_NAME = 'relay-cache';
const CACHE_VERSION = 2; // Incremented for explicit schema versioning & migration hooks
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const HEALTH_CHECK_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CACHED_RELAYS = 50; // Prevent unbounded cache growth

/**
 * Initialize IndexedDB cache for Nostr relay discovery with migration hooks
 */
function initCache() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      resolve(null);
      return;
    }
    const request = indexedDB.open(CACHE_DB_NAME, CACHE_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      const oldVersion = event.oldVersion;
      const transaction = event.target.transaction;

      console.info(`[NostrDiscovery] Upgrading IndexedDB cache from v${oldVersion} to v${CACHE_VERSION}`);

      if (!db.objectStoreNames.contains(CACHE_STORE_NAME)) {
        const store = db.createObjectStore(CACHE_STORE_NAME, { keyPath: 'url' });
        store.createIndex('lastHealthCheck', 'lastHealthCheck', { unique: false });
        store.createIndex('latency', 'latency', { unique: false });
        store.createIndex('healthy', 'healthy', { unique: false });
      } else {
        // Migration hooks for future schema versions
        const store = transaction.objectStore(CACHE_STORE_NAME);
        if (oldVersion < 2) {
          // Add 'healthy' index in version 2 if missing
          if (!store.indexNames.contains('healthy')) {
            store.createIndex('healthy', 'healthy', { unique: false });
          }
        }
      }
    };
  });
}

/**
 * Get cached relays from IndexedDB
 */
async function getCachedRelays() {
  const db = await initCache();
  if (!db) return [];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CACHE_STORE_NAME, 'readonly');
    const store = tx.objectStore(CACHE_STORE_NAME);
    const request = store.getAll();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

/**
 * Save relays to IndexedDB cache
 */
async function saveCachedRelays(relays) {
  const db = await initCache();
  if (!db) return;
  
  // Enforce max cache size - keep only the best relays by latency
  const sorted = [...relays].sort((a, b) => (a.latency || Infinity) - (b.latency || Infinity));
  const toSave = sorted.slice(0, MAX_CACHED_RELAYS);
  
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CACHE_STORE_NAME, 'readwrite');
    const store = tx.objectStore(CACHE_STORE_NAME);
    for (const relay of toSave) {
      store.put(relay);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Health check a single relay via WebSocket ping (Nostr-style challenge-response)
 */
async function healthCheckRelay(relay, WebSocketImpl, timeoutMs = 3000) {
  return new Promise((resolve) => {
    if (!WebSocketImpl) {
      resolve({ ...relay, healthy: false, lastHealthCheck: Date.now(), latency: null });
      return;
    }
    let ws;
    let resolved = false;
    const challenge = Math.random().toString(36).slice(2);
    const timer = setTimeout(() => {
      if (resolved) return;
      resolved = true;
      try { ws?.close(); } catch {}
      resolve({ ...relay, healthy: false, lastHealthCheck: Date.now(), latency: null });
    }, timeoutMs);

    try {
      const start = Date.now();
      ws = new WebSocketImpl(relay.url);
      ws.onopen = () => {
        // Nostr PING: ["PING", challenge]
        ws.send(JSON.stringify(['PING', challenge]));
      };
      ws.onmessage = (event) => {
        if (resolved) return;
        try {
          const data = JSON.parse(typeof event.data === 'string' ? event.data : '');
          // Expect PONG response: ["PONG", challenge]
          if (Array.isArray(data) && data[0] === 'PONG' && data[1] === challenge) {
            resolved = true;
            clearTimeout(timer);
            const latency = Date.now() - start;
            ws.close();
            resolve({ ...relay, healthy: true, lastHealthCheck: Date.now(), latency });
          }
        } catch {}
      };
      ws.onerror = () => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        resolve({ ...relay, healthy: false, lastHealthCheck: Date.now(), latency: null });
      };
      ws.onclose = () => {
        clearTimeout(timer);
        if (!resolved) {
          resolved = true;
          resolve({ ...relay, healthy: false, lastHealthCheck: Date.now(), latency: null });
        }
      };
    } catch {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      resolve({ ...relay, healthy: false, lastHealthCheck: Date.now(), latency: null });
    }
  });
}

export class NostrRelayDiscovery {
  /**
   * @param {{nostrRelays?: string[], WebSocketImpl?: Function, cacheEnabled?: boolean}} opts
   */
  constructor(opts = {}) {
    this.nostrRelays = opts.nostrRelays || [
      'wss://relay.damus.io',
      'wss://relay.nostr.band',
      'wss://nos.lol',
    ];
    this.WebSocketImpl = opts.WebSocketImpl || (typeof WebSocket !== 'undefined' ? WebSocket : null);
    this.cacheEnabled = opts.cacheEnabled !== false;
    this._healthCheckTimer = null;
  }

  /**
   * Query public Nostr relays for SMTP-capable WebSocket relay endpoints.
   * @param {number} [timeoutMs=5000]
   * @param {boolean} [forceRefresh=false] - Skip cache and fetch fresh
   * @returns {Promise<Array<{url: string, pubkey: string, latency: number, verified: boolean, healthy?: boolean, lastHealthCheck?: number}>>}
   */
  async discoverSmtpRelays(timeoutMs = 5000, forceRefresh = false) {
    if (!this.WebSocketImpl) {
      throw new Error('No WebSocket implementation available for Nostr discovery');
    }

    // Try cache first unless forced refresh
    if (this.cacheEnabled && !forceRefresh) {
      const cached = await getCachedRelays();
      const now = Date.now();
      const validCached = cached.filter(r => 
        r.healthy !== false && 
        r.lastHealthCheck && 
        (now - r.lastHealthCheck) < CACHE_TTL_MS
      );
      if (validCached.length > 0) {
        // Return cached relays sorted by latency
        this.startHealthChecks();
        return validCached.sort((a, b) => (a.latency || Infinity) - (b.latency || Infinity));
      }
    }

    const discovered = new Map();

    await Promise.all(
      this.nostrRelays.map((nostrUrl) => {
        return new Promise((resolve) => {
          let ws;
          const timer = setTimeout(() => {
            try { ws?.close(); } catch {}
            resolve();
          }, timeoutMs);

          try {
            ws = new this.WebSocketImpl(nostrUrl);
            const start = Date.now();

            ws.onopen = () => {
              const subId = 'domail_smtp_' + Math.random().toString(36).slice(2, 8);
              const req = JSON.stringify([
                'REQ',
                subId,
                {
                  kinds: [30078, 10002],
                  '#t': ['domail-smtp-relay'],
                },
              ]);
              ws.send(req);
            };

            ws.onmessage = (event) => {
              try {
                const data = JSON.parse(typeof event.data === 'string' ? event.data : '');
                if (Array.isArray(data) && data[0] === 'EVENT') {
                  const eventObj = data[2];
                  if (eventObj && (eventObj.kind === 30078 || eventObj.kind === 10002)) {
                    const tags = eventObj.tags || [];
                    let wsUrl = '';
                    for (const tag of tags) {
                      if (tag[0] === 'r' || tag[0] === 'ws' || tag[0] === 'url') {
                        wsUrl = tag[1];
                      }
                    }
                    if (wsUrl && wsUrl.startsWith('wss://')) {
                      const latency = Date.now() - start;
                      discovered.set(wsUrl, {
                        url: wsUrl,
                        pubkey: eventObj.pubkey,
                        latency,
                        verified: true,
                        lastHealthCheck: Date.now(),
                        healthy: true,
                      });
                    }
                  }
                } else if (Array.isArray(data) && data[0] === 'EOSE') {
                  ws.close();
                }
              } catch {}
            };

            ws.onerror = () => {
              clearTimeout(timer);
              try { ws?.close(); } catch {}
              resolve();
            };

            ws.onclose = () => {
              clearTimeout(timer);
              resolve();
            };
          } catch {
            clearTimeout(timer);
            resolve();
          }
        });
      })
    );

    const results = Array.from(discovered.values()).sort((a, b) => a.latency - b.latency);

    // Cache the results
    if (this.cacheEnabled) {
      await saveCachedRelays(results);
    }

    // Start periodic health checks
    this.startHealthChecks();

    return results;
  }

  /**
   * Start periodic health checks for cached relays
   */
  startHealthChecks() {
    if (this._healthCheckTimer) return;
    this._healthCheckTimer = setInterval(async () => {
      const cached = await getCachedRelays();
      if (cached.length === 0) return;
      const healthy = await Promise.all(
        cached.map(r => healthCheckRelay(r, this.WebSocketImpl))
      );
      await saveCachedRelays(healthy);
    }, HEALTH_CHECK_INTERVAL_MS);
    if (this._healthCheckTimer.unref) this._healthCheckTimer.unref();
  }

  /**
   * Stop periodic health checks
   */
  stopHealthChecks() {
    if (this._healthCheckTimer) {
      clearInterval(this._healthCheckTimer);
      this._healthCheckTimer = null;
    }
  }

  /**
   * Get cached relays without network request
   */
  async getCachedRelays() {
    return getCachedRelays();
  }

  /**
   * Clear the cache
   */
  async clearCache() {
    const db = await initCache();
    if (!db) return;
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CACHE_STORE_NAME, 'readwrite');
      const store = tx.objectStore(CACHE_STORE_NAME);
      store.clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
}

export function createNostrDiscovery(opts) {
  return new NostrRelayDiscovery(opts);
}
