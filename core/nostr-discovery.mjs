/**
 * DOM Mail — Decentralized Nostr-based Relay Discovery.
 * Discovers SMTP-capable WebSocket relay nodes across public Nostr relays.
 */

export class NostrRelayDiscovery {
  /**
   * @param {{nostrRelays?: string[], WebSocketImpl?: Function}} opts
   */
  constructor(opts = {}) {
    this.nostrRelays = opts.nostrRelays || [
      'wss://relay.damus.io',
      'wss://relay.nostr.band',
      'wss://nos.lol',
    ];
    this.WebSocketImpl = opts.WebSocketImpl || (typeof WebSocket !== 'undefined' ? WebSocket : null);
  }

  /**
   * Query public Nostr relays for SMTP-capable WebSocket relay endpoints.
   * @param {number} [timeoutMs=5000]
   * @returns {Promise<Array<{url: string, pubkey: string, latency: number, verified: boolean}>>}
   */
  async discoverSmtpRelays(timeoutMs = 5000) {
    if (!this.WebSocketImpl) {
      throw new Error('No WebSocket implementation available for Nostr discovery');
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
              // Request relay metadata / service announcements (Kind 30078 or Kind 10002)
              const subId = 'domail_smtp_' + Math.random().toString(36).slice(2, 8);
              // Filter for relay advertisements offering smtp-bridge capability
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

    // Return sorted by lowest latency
    return Array.from(discovered.values()).sort((a, b) => a.latency - b.latency);
  }
}

export function createNostrDiscovery(opts) {
  return new NostrRelayDiscovery(opts);
}
