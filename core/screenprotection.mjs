/**
 * DOM Mail screen theft protection.
 *
 * Protects against:
 * - Screenshot/screen recording capture
 * - Canvas fingerprinting
 * - DOM scraping of PII
 * - Visual shoulder surfing
 * - Print-to-PDF leakage
 */

export class ScreenProtection {
  constructor(opts = {}) {
    this.enabled = opts.enabled !== false;
    this.obfuscationInterval = null;
    this.mutationObserver = null;
    this.canvasFingerprintNoise = null;
    this.printStylesInjected = false;
    this.piiSelectors = opts.piiSelectors || [
      '[data-pii]', '.identity', '.address', '.keyview', '[data-email]',
      '[data-key]', '.contact .addr', '.msg .who', '.reader .meta'
    ];
    this.originalValues = new WeakMap();
    this.respectShowFullIdentity = opts.respectShowFullIdentity || false;
    this.getShowFullIdentity = opts.getShowFullIdentity || (() => false);
    this._noiseCache = new Map(); // Use Map instead of WeakMap for cleanup
    this._debounceTimer = null;
    this._piiElements = new Set(); // Track obfuscated elements for reveal
  }

  async init() {
    if (typeof window === 'undefined') return this;
    this._injectPrintProtection();
    this._injectCanvasNoise();
    this._startPIIObfuscation();
    this._observeDOMChanges();
    this._disableDevToolsShortcuts();
    this._blockScreenCaptureAPIs();
    return this;
  }

  _injectPrintProtection() {
    if (this.printStylesInjected) return;
    const style = document.createElement('style');
    style.id = 'domail-print-protection';
    style.textContent = `
      @media print {
        [data-pii], .identity, .address, .keyview, [data-email], [data-key],
        .contact .addr, .msg .who, .reader .meta, .vk-container {
          display: none !important;
          visibility: hidden !important;
          opacity: 0 !important;
          position: absolute !important;
          left: -9999px !important;
        }
        body::after {
          content: "[REDACTED - DOM Mail privacy protection]";
          color: #666; font-size: 0.8rem; text-align: center; display: block; margin: 2rem;
        }
      }
    `;
    document.head.appendChild(style);
    this.printStylesInjected = true;
  }

  _injectCanvasNoise() {
    if (typeof HTMLCanvasElement === 'undefined') return;

    // Only protect canvases created by DOM Mail (marked with data-domail-canvas)
    // This avoids breaking third-party libraries
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    const self = this;

    function generateNoise(width, height) {
      const key = `${width}x${height}`;
      if (self._noiseCache.has(key)) return self._noiseCache.get(key);
      const tempCanvas = document.createElement('canvas');
      tempCanvas.width = width;
      tempCanvas.height = height;
      const ctx = tempCanvas.getContext('2d');
      const imageData = ctx.createImageData(width, height);
      const data = imageData.data;
      // Use crypto.getRandomValues for cryptographically secure noise
      const noiseBytes = new Uint8Array(data.length);
      crypto.getRandomValues(noiseBytes);
      for (let i = 0; i < data.length; i += 4) {
        const val = noiseBytes[i];
        data[i] = val;
        data[i + 1] = val;
        data[i + 2] = val;
        data[i + 3] = Math.min(12, noiseBytes[i + 3] & 0xF);
      }
      ctx.putImageData(imageData, 0, 0);
      // Limit cache size to prevent unbounded growth
      if (self._noiseCache.size > 50) {
        const firstKey = self._noiseCache.keys().next().value;
        self._noiseCache.delete(firstKey);
      }
      self._noiseCache.set(key, tempCanvas);
      return tempCanvas;
    }

    HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
      if (self.enabled && this.width > 0 && this.height > 0 && this.dataset.domailCanvas === 'true') {
        const noiseCanvas = generateNoise(this.width, this.height);
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = this.width;
        tempCanvas.height = this.height;
        const tempCtx = tempCanvas.getContext('2d');
        tempCtx.drawImage(this, 0, 0);
        tempCtx.globalAlpha = 0.02;
        tempCtx.drawImage(noiseCanvas, 0, 0);
        tempCtx.globalAlpha = 1.0;
        return tempCanvas.toDataURL(type, quality);
      }
      return originalToDataURL.call(this, type, quality);
    };

    HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
      if (self.enabled && this.width > 0 && this.height > 0 && this.dataset.domailCanvas === 'true') {
        const noiseCanvas = generateNoise(this.width, this.height);
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = this.width;
        tempCanvas.height = this.height;
        const tempCtx = tempCanvas.getContext('2d');
        tempCtx.drawImage(this, 0, 0);
        tempCtx.globalAlpha = 0.02;
        tempCtx.drawImage(noiseCanvas, 0, 0);
        tempCtx.globalAlpha = 1.0;
        return tempCanvas.toBlob(callback, type, quality);
      }
      return originalToBlob.call(this, callback, type, quality);
    };

    CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
      const result = originalGetImageData.call(this, sx, sy, sw, sh);
      const canvas = this.canvas;
      if (self.enabled && sw > 0 && sh > 0 && canvas?.dataset?.domailCanvas === 'true') {
        const noiseCanvas = generateNoise(sw, sh);
        const noiseCtx = noiseCanvas.getContext('2d');
        const noiseData = noiseCtx.getImageData(0, 0, sw, sh).data;
        for (let i = 0; i < result.data.length; i += 4) {
          result.data[i] ^= noiseData[i] & 0xF;
          result.data[i + 1] ^= noiseData[i + 1] & 0xF;
          result.data[i + 2] ^= noiseData[i + 2] & 0xF;
        }
      }
      return result;
    };

    this.canvasFingerprintNoise = { originalToDataURL, originalToBlob, originalGetImageData };
  }

  _startPIIObfuscation() {
    if (this.obfuscationInterval) return;
    this._obfuscatePII();
    // Run less frequently (5-8s) using setInterval with jitter
    // requestIdleCallback is not suitable for recurring intervals
    this.obfuscationInterval = setInterval(() => {
      this._obfuscatePII();
    }, 5000 + Math.random() * 3000);
  }

  _obfuscatePII() {
    if (!this.enabled) return;
    if (this.respectShowFullIdentity && this.getShowFullIdentity()) return;
    const doc = document;
    for (const selector of this.piiSelectors) {
      const elements = doc.querySelectorAll(selector);
      for (const el of elements) {
        if (el.dataset.piiProtected === 'true') continue;
        if (el.offsetWidth === 0 && el.offsetHeight === 0) continue;

        const text = el.textContent || el.innerText;
        if (!text || text.length < 3) continue;

        if (this._containsPII(text)) {
          if (!this.originalValues.has(el)) {
            this.originalValues.set(el, text);
            this._piiElements.add(el);
          }
          const obfuscated = this._obfuscateText(text);
          if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
            el.value = obfuscated;
          } else {
            el.textContent = obfuscated;
          }
          el.dataset.piiProtected = 'true';
          el.dataset.piiOriginal = 'stored';
        }
      }
    }
  }

  _containsPII(text) {
    return /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text) ||
           /-----BEGIN [A-Z ]+-----/.test(text) ||
           /\b[A-Za-z0-9._%+-]{3,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/.test(text);
  }

  _obfuscateText(text) {
    return text
      .replace(/([a-zA-Z0-9._%+-]{1,3})[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})/g,
        (_, prefix, domain, tld) => `${prefix}***@${domain.slice(0,3)}***.${tld}`)
      .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '[KEY REDACTED]')
      .replace(/[A-Za-z0-9._%+-]{20,}/g, (m) => m.slice(0, 4) + '***REDACTED***' + m.slice(-4));
  }

  _revealPII() {
    // WeakMap is not iterable, so we need to track elements separately
    // We'll use a Set to track elements that have been obfuscated
    if (this._piiElements) {
      for (const el of this._piiElements) {
        if (!document.body.contains(el)) continue;
        const original = this.originalValues.get(el);
        if (original === undefined) continue;
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
          el.value = original;
        } else {
          el.textContent = original;
        }
        el.dataset.piiProtected = 'false';
      }
      this._piiElements.clear();
    }
    this.originalValues = new WeakMap();
  }

  _observeDOMChanges() {
    if (typeof MutationObserver === 'undefined') return;
    this.mutationObserver = new MutationObserver((mutations) => {
      // Debounce: only trigger once per event loop
      if (this._debounceTimer) return;
      this._debounceTimer = setTimeout(() => {
        this._debounceTimer = null;
        let shouldObfuscate = false;
        for (const m of mutations) {
          for (const node of m.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.matches && this.piiSelectors.some(s => node.matches(s))) {
                shouldObfuscate = true;
                break;
              }
              if (node.querySelectorAll) {
                for (const sel of this.piiSelectors) {
                  if (node.querySelector(sel)) { shouldObfuscate = true; break; }
                }
                if (shouldObfuscate) break;
              }
            }
          }
          if (shouldObfuscate) break;
        }
        if (shouldObfuscate) this._obfuscatePII();
      }, 0);
    });
    // Don't observe characterData - too noisy
    this.mutationObserver.observe(document.body, { childList: true, subtree: true });
  }

  _disableDevToolsShortcuts() {
    document.addEventListener('keydown', (e) => {
      if (!this.enabled) return;
      if (e.key === 'F12' ||
          (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
          (e.ctrlKey && e.key === 'U') ||
          (e.ctrlKey && e.shiftKey && e.key === 'P') ||
          (e.metaKey && e.altKey && e.key === 'I')) {
        e.preventDefault();
        e.stopPropagation();
        return false;
      }
    }, true);

    // Also block context menu on protected elements
    document.addEventListener('contextmenu', (e) => {
      if (!this.enabled) return;
      if (e.target.closest('[data-pii], .identity, .address, .keyview, .reader')) {
        e.preventDefault();
      }
    }, true);
  }

  _blockScreenCaptureAPIs() {
    if (typeof navigator === 'undefined') return;

    // Block getDisplayMedia
    if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
      this._originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getDisplayMedia = async (constraints) => {
        if (this.enabled) {
          throw new DOMException('Screen capture blocked by DOM Mail privacy protection', 'NotAllowedError');
        }
        return this._originalGetDisplayMedia(constraints);
      };
    }

    if (navigator.getDisplayMedia) {
      this._originalGetDisplayMediaLegacy = navigator.getDisplayMedia.bind(navigator);
      navigator.getDisplayMedia = async (constraints) => {
        if (this.enabled) {
          throw new DOMException('Screen capture blocked', 'NotAllowedError');
        }
        return this._originalGetDisplayMediaLegacy(constraints);
      };
    }

    // Block canvas.captureStream
    if (typeof HTMLCanvasElement !== 'undefined') {
      this._originalCanvasCaptureStream = HTMLCanvasElement.prototype.captureStream;
      HTMLCanvasElement.prototype.captureStream = function(...args) {
        if (this.dataset.domailCanvas === 'true') {
          throw new DOMException('Canvas capture blocked by DOM Mail privacy protection', 'NotAllowedError');
        }
        return this._originalCanvasCaptureStream.apply(this, args);
      };
    }

    // Block HTMLMediaElement.captureStream
    if (typeof HTMLMediaElement !== 'undefined') {
      this._originalMediaCaptureStream = HTMLMediaElement.prototype.captureStream;
      HTMLMediaElement.prototype.captureStream = function(...args) {
        throw new DOMException('Media capture blocked by DOM Mail privacy protection', 'NotAllowedError');
      };
    }
  }

  enable() {
    this.enabled = true;
    this._startPIIObfuscation();
    this._injectCanvasNoise();
  }

  disable() {
    this.enabled = false;
    if (this.obfuscationInterval) {
      clearInterval(this.obfuscationInterval);
      this.obfuscationInterval = null;
    }
    this._revealPII();
  }

  toggle() {
    if (this.enabled) this.disable(); else this.enable();
    return this.enabled;
  }

  destroy() {
    this.disable();
    if (this.mutationObserver) {
      this.mutationObserver.disconnect();
      this.mutationObserver = null;
    }
    if (this.canvasFingerprintNoise) {
      HTMLCanvasElement.prototype.toDataURL = this.canvasFingerprintNoise.originalToDataURL;
      HTMLCanvasElement.prototype.toBlob = this.canvasFingerprintNoise.originalToBlob;
      CanvasRenderingContext2D.prototype.getImageData = this.canvasFingerprintNoise.originalGetImageData;
      this.canvasFingerprintNoise = null;
    }
    // Restore overridden capture APIs
    if (this._originalGetDisplayMedia) {
      navigator.mediaDevices.getDisplayMedia = this._originalGetDisplayMedia;
      this._originalGetDisplayMedia = null;
    }
    if (this._originalGetDisplayMediaLegacy) {
      navigator.getDisplayMedia = this._originalGetDisplayMediaLegacy;
      this._originalGetDisplayMediaLegacy = null;
    }
    if (this._originalCanvasCaptureStream) {
      HTMLCanvasElement.prototype.captureStream = this._originalCanvasCaptureStream;
      this._originalCanvasCaptureStream = null;
    }
    if (this._originalMediaCaptureStream) {
      HTMLMediaElement.prototype.captureStream = this._originalMediaCaptureStream;
      this._originalMediaCaptureStream = null;
    }
    if (this._debounceTimer) {
      clearTimeout(this._debounceTimer);
      this._debounceTimer = null;
    }
    // Clean up noise cache
    this._noiseCache.clear();
    this._piiElements.clear();
    const printStyle = document.getElementById('domail-print-protection');
    if (printStyle) printStyle.remove();
    this.originalValues = new WeakMap();
  }
}

export function createScreenProtection(opts = {}) {
  return new ScreenProtection(opts);
}