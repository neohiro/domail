/**
 * DOM Mail boot script.
 *
 * Runs synchronously (deferred by the module/async load) to apply the saved
 * theme before first paint, register the Service Worker, and pull in
 * libsodium. Lives in its own file so index.html needs no inline <script>,
 * which lets the Content-Security-Policy drop 'unsafe-inline' for scripts.
 */

(function () {
  try {
    var s = JSON.parse(localStorage.getItem('domail:ui') || '{}');
    var r = document.documentElement;
    r.dataset.mode = s.mode || 'dark';
    if (s.neon) r.style.setProperty('--neon', s.neon);
    if (s.accent) r.style.setProperty('--accent', s.accent);
    if (s.font) r.dataset.font = s.font;
  } catch (e) {}
})();

if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('sw.js', { scope: './' })
      .then(function (reg) {
        reg.update();
        if (reg.waiting) {
          reg.waiting.postMessage({ type: 'SKIP_WAITING' });
        }
        reg.addEventListener('updatefound', function () {
          var newWorker = reg.installing;
          if (!newWorker) return;
          newWorker.addEventListener('statechange', function () {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              // Never auto-reload: an unsolicited reload would break an
              // offline session. Surface the update and let the user decide.
              var toast = document.getElementById('toast');
              if (toast) {
                toast.textContent = 'Update available — refresh when ready';
                toast.hidden = false;
                setTimeout(function () { toast.hidden = true; }, 8000);
              }
            }
          });
        });
      })
      .catch(function (err) { console.warn('[DOM Mail] SW registration failed:', err); });
  });
}

var libsodiumLoaded = false;
function loadLibsodium() {
  if (libsodiumLoaded) return Promise.resolve();
  libsodiumLoaded = true;
  return new Promise(function (resolve, reject) {
    var script = document.createElement('script');
    script.src = 'libsodium.js';
    script.onload = function () { resolve(); };
    script.onerror = function () { reject(new Error('Failed to load libsodium.js')); };
    document.head.appendChild(script);
  });
}
window.loadLibsodium = loadLibsodium;
window.loadLibsodium().catch(function (e) { console.error('[DOM Mail] libsodium load error:', e); });