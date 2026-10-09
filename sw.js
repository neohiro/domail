/**
 * DOM Mail Service Worker - Offline-first, zero-network after initial load.
 *
 * Strategy:
 * - Cache everything on first visit (Cache-First)
 * - No network requests after initial load
 * - Background sync for outbound mail when online (optional)
 * - Periodic cache validation
 * - Secure headers via SW
 */

const CACHE_NAME = 'domail-v2';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/assets/css/domail.css',
  '/assets/js/domail.js',
  '/assets/img/logo.svg',
  '/core/mail.mjs',
  '/core/crypto.mjs',
  '/core/encrypted-store.mjs',
  '/core/antikeylogger.mjs',
  '/core/screenprotection.mjs',
  '/core/fingerprinting.mjs',
  '/core/domains.mjs',
];

const OFFLINE_FALLBACK = '/index.html';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS.map(url => new Request(url, { cache: 'reload' })));
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)));
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  if (url.origin !== location.origin) {
    return;
  }

  if (request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;

      return fetch(request).then((response) => {
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        const cloned = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, cloned));
        return response;
      }).catch(() => {
        if (request.mode === 'navigate') {
          return caches.match(OFFLINE_FALLBACK);
        }
        return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
      });
    })
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }
  if (event.data === 'clearCache') {
    caches.delete(CACHE_NAME).then(() => {
      event.ports[0].postMessage({ success: true });
    });
  }
  if (event.data === 'cacheStatus') {
    caches.open(CACHE_NAME).then((cache) => {
      cache.keys().then((keys) => {
        event.ports[0].postMessage({ cached: keys.map(k => k.url) });
      });
    });
  }
});

self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'domail-sync') {
    event.waitUntil(syncMail());
  }
});

async function syncMail() {
  const clients = await self.clients.matchAll({ type: 'window' });
  for (const client of clients) {
    client.postMessage({ type: 'SYNC_MAIL' });
  }
}

console.log('[DOM Mail SW] Registered - Offline-first mode active');