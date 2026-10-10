/**
 * DOM Mail global error surface.
 *
 * A silent module failure leaves a fully static-looking page, which is the
 * worst possible failure mode for a mail client: the user cannot tell a broken
 * deploy from a broken browser. This file turns any uncaught error or rejected
 * promise into a visible, dismissible panel with a retry affordance.
 */

(function () {
  var panel, msgEl, shown = 0;

  function ensure() {
    if (!panel) {
      panel = document.getElementById('jsError');
      msgEl = document.getElementById('jsErrorMsg');
      var retry = document.getElementById('jsErrorRetry');
      if (retry) {
        retry.addEventListener('click', function () { location.reload(); });
      }
    }
    return panel;
  }

  function show(msg) {
    if (!ensure() || !msgEl) return;
    msgEl.textContent = msg;
    if (panel.hidden) panel.hidden = false;
    // A runaway loop of rejections must not spam the console forever.
    if (++shown > 5) return;
    console.error('[DOM Mail] Fatal error:', msg);
  }

  window.showJSError = show;

  window.addEventListener('error', function (e) {
    // Ignore favicon/analytics noise from non-first-party URLs.
    if (e.filename && e.filename.indexOf(location.origin) !== 0 && e.filename.charAt(0) !== '/') {
      return;
    }
    show(e.message + (e.lineno ? ' (line ' + e.lineno + ')' : ''));
  });

  window.addEventListener('unhandledrejection', function (e) {
    var reason = e.reason;
    show('Unhandled rejection: ' + ((reason && reason.message) || String(reason)));
  });
})();