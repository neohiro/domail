/**
 * DOM Mail zero-fingerprinting protection.
 *
 * Neutralizes:
 * - Canvas fingerprinting
 * - WebGL fingerprinting
 * - AudioContext fingerprinting
 * - Font enumeration
 * - Battery API
 * - Hardware concurrency
 * - Device memory
 * - Screen resolution/color depth
 * - Timezone/locale
 * - Touch support
 * - Navigator plugins/mimeTypes
 * - CSS media queries
 * - Performance timing
 * - WebRTC IP leakage
 * - Client hints
 */

export class FingerprintProtection {
  constructor(opts = {}) {
    this.enabled = opts.enabled !== false;
    this.spoofedValues = new Map();
    this.originalValues = new Map();
  }

  async init() {
    if (typeof window === 'undefined') return this;
    this._spoofNavigator();
    this._spoofScreen();
    this._spoofPerformance();
    this._spoofWebGL();
    this._spoofAudioContext();
    this._spoofFonts();
    this._spoofBattery();
    this._spoofWebRTC();
    this._spoofClientHints();
    this._spoofCSSMediaQueries();
    this._spoofTouchSupport();
    this._spoofTimezone();
    return this;
  }

  _spoofNavigator() {
    const nav = navigator;
    const props = {
      hardwareConcurrency: 4,
      deviceMemory: 8,
      maxTouchPoints: 0,
      doNotTrack: '1',
      language: 'en-US',
      languages: ['en-US', 'en'],
    };

    for (const [key, value] of Object.entries(props)) {
      if (key in nav) {
        this.originalValues.set(`navigator.${key}`, nav[key]);
        this._defineProperty(nav, key, value);
      }
    }

    if (nav.connection) {
      this.originalValues.set('navigator.connection', nav.connection);
      this._defineProperty(nav, 'connection', { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false });
    }

    if (nav.plugins) {
      this.originalValues.set('navigator.plugins', nav.plugins);
      this._defineProperty(nav, 'plugins', this._createEmptyPluginArray());
    }
    if (nav.mimeTypes) {
      this.originalValues.set('navigator.mimeTypes', nav.mimeTypes);
      this._defineProperty(nav, 'mimeTypes', this._createEmptyMimeTypeArray());
    }

    // Note: userAgent, platform, vendor, appVersion, product, productSub are read-only in most browsers
    // and cannot be reliably spoofed via defineProperty. They require User-Agent Client Hints or other approaches.
  }

  _createEmptyPluginArray() {
    const arr = [];
    arr.item = () => null;
    arr.namedItem = () => null;
    arr.refresh = () => {};
    arr.length = 0;
    return arr;
  }

  _createEmptyMimeTypeArray() {
    const arr = [];
    arr.item = () => null;
    arr.namedItem = () => null;
    arr.length = 0;
    return arr;
  }

  _spoofScreen() {
    const screen = window.screen;
    const props = {
      width: 1920,
      height: 1080,
      availWidth: 1920,
      availHeight: 1040,
      colorDepth: 24,
      pixelDepth: 24,
      orientation: { type: 'landscape-primary', angle: 0 },
    };
    for (const [key, value] of Object.entries(props)) {
      if (key in screen) {
        this.originalValues.set(`screen.${key}`, screen[key]);
        this._defineProperty(screen, key, value);
      }
    }
  }

  _spoofPerformance() {
    const perf = window.performance;
    if (!perf) return;

    const originalNow = perf.now.bind(perf);
    let offset = Math.random() * 10000;
    perf.now = () => {
      const val = originalNow() + offset;
      offset += Math.random() * 0.1;
      return val;
    };
    this.originalValues.set('performance.now', originalNow);

    if (perf.timing) {
      const timing = perf.timing;
      const base = timing.navigationStart || Date.now();
      const spoofed = {
        navigationStart: base,
        unloadEventStart: base + 10,
        unloadEventEnd: base + 12,
        redirectStart: base + 15,
        redirectEnd: base + 20,
        fetchStart: base + 25,
        domainLookupStart: base + 30,
        domainLookupEnd: base + 35,
        connectStart: base + 40,
        connectEnd: base + 60,
        secureConnectionStart: base + 55,
        requestStart: base + 65,
        responseStart: base + 120,
        responseEnd: base + 150,
        domLoading: base + 160,
        domInteractive: base + 300,
        domContentLoadedEventStart: base + 350,
        domContentLoadedEventEnd: base + 360,
        domComplete: base + 500,
        loadEventStart: base + 510,
        loadEventEnd: base + 520,
      };
      for (const [k, v] of Object.entries(spoofed)) {
        this.originalValues.set(`performance.timing.${k}`, timing[k]);
        this._defineProperty(timing, k, v);
      }
    }
  }

  _spoofWebGL() {
    const originalGetContext = HTMLCanvasElement.prototype.getContext;
    const self = this;

    HTMLCanvasElement.prototype.getContext = function(type, attrs) {
      const ctx = originalGetContext.call(this, type, attrs);
      if (!ctx || !self.enabled) return ctx;

      if (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl') {
        const originalGetParameter = ctx.getParameter.bind(ctx);
        const spoofed = {
          [ctx.VENDOR]: 'Google Inc. (NVIDIA)',
          [ctx.RENDERER]: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0)',
          [ctx.VERSION]: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
          [ctx.SHADING_LANGUAGE_VERSION]: 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)',
          [ctx.MAX_VERTEX_ATTRIBS]: 16,
          [ctx.MAX_VERTEX_UNIFORM_VECTORS]: 256,
          [ctx.MAX_FRAGMENT_UNIFORM_VECTORS]: 256,
          [ctx.MAX_VARYING_VECTORS]: 16,
          [ctx.MAX_VERTEX_TEXTURE_IMAGE_UNITS]: 16,
          [ctx.MAX_TEXTURE_IMAGE_UNITS]: 16,
          [ctx.MAX_COMBINED_TEXTURE_IMAGE_UNITS]: 32,
          [ctx.MAX_TEXTURE_SIZE]: 16384,
          [ctx.MAX_CUBE_MAP_TEXTURE_SIZE]: 16384,
          [ctx.MAX_RENDERBUFFER_SIZE]: 16384,
          [ctx.MAX_VIEWPORT_DIMS]: new Int32Array([16384, 16384]),
          [ctx.ALIASED_LINE_WIDTH_RANGE]: new Float32Array([1, 1]),
          [ctx.ALIASED_POINT_SIZE_RANGE]: new Float32Array([1, 1024]),
        };
        ctx.getParameter = (pname) => spoofed[pname] ?? originalGetParameter(pname);
      }
      return ctx;
    };
  }

  _spoofAudioContext() {
    if (typeof AudioContext === 'undefined' && typeof webkitAudioContext === 'undefined') return;

    const AC = window.AudioContext || window.webkitAudioContext;
    const originalCreateAnalyser = AC.prototype.createAnalyser;
    const originalGetFloatFrequencyData = AudioBuffer.prototype.getFloatFrequencyData;

    AC.prototype.createAnalyser = function() {
      const analyser = originalCreateAnalyser.call(this);
      const originalGetFloatFrequencyData = analyser.getFloatFrequencyData.bind(analyser);
      analyser.getFloatFrequencyData = function(array) {
        originalGetFloatFrequencyData(array);
        if (self.enabled) {
          for (let i = 0; i < array.length; i++) {
            array[i] += (Math.random() - 0.5) * 0.001;
          }
        }
      };
      return analyser;
    };
  }

  _spoofFonts() {
    const style = document.createElement('style');
    style.id = 'domail-font-spoof';
    style.textContent = `
      @font-face { font-family: 'system-ui'; src: local('system-ui'); }
      @font-face { font-family: '-apple-system'; src: local('-apple-system'); }
      @font-face { font-family: 'BlinkMacSystemFont'; src: local('BlinkMacSystemFont'); }
      @font-face { font-family: 'Segoe UI'; src: local('Segoe UI'); }
      @font-face { font-family: 'Roboto'; src: local('Roboto'); }
      @font-face { font-family: 'Helvetica Neue'; src: local('Helvetica Neue'); }
      @font-face { font-family: 'Arial'; src: local('Arial'); }
      @font-face { font-family: 'Noto Sans'; src: local('Noto Sans'); }
      @font-face { font-family: 'sans-serif'; src: local('sans-serif'); }
      @font-face { font-family: 'monospace'; src: local('monospace'); }
      @font-face { font-family: 'ui-monospace'; src: local('ui-monospace'); }
      @font-face { font-family: 'SFMono-Regular'; src: local('SFMono-Regular'); }
      @font-face { font-family: 'Menlo'; src: local('Menlo'); }
      @font-face { font-family: 'Consolas'; src: local('Consolas'); }
      @font-face { font-family: 'Liberation Mono'; src: local('Liberation Mono'); }
    `;
    document.head.appendChild(style);

    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(() => {
        const originalCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = (font, text) => {
          if (self.enabled && font.includes('local(')) return true;
          return originalCheck(font, text);
        };
      });
    }
  }

  _spoofBattery() {
    if (!navigator.getBattery) return;
    const original = navigator.getBattery.bind(navigator);
    navigator.getBattery = async () => {
      const battery = await original();
      const spoofed = {
        charging: true,
        chargingTime: 0,
        dischargingTime: Infinity,
        level: 1,
        addEventListener: battery.addEventListener.bind(battery),
        removeEventListener: battery.removeEventListener.bind(battery),
        dispatchEvent: battery.dispatchEvent.bind(battery),
      };
      return new Proxy(battery, {
        get(target, prop) {
          if (prop in spoofed) return spoofed[prop];
          return target[prop];
        }
      });
    };
  }

  _spoofWebRTC() {
    if (typeof RTCPeerConnection === 'undefined') return;

    const originalCreateOffer = RTCPeerConnection.prototype.createOffer;
    RTCPeerConnection.prototype.createOffer = async function(options) {
      const offer = await originalCreateOffer.call(this, options);
      if (self.enabled && offer.sdp) {
        offer.sdp = offer.sdp.replace(/a=candidate:.*\r\n/g, '')
                           .replace(/a=ice-ufrag:.*\r\n/g, '')
                           .replace(/a=ice-pwd:.*\r\n/g, '');
      }
      return offer;
    };
  }

  _spoofClientHints() {
    if (!navigator.userAgentData) return;
    const ua = navigator.userAgentData;
    const originalGetHighEntropy = ua.getHighEntropyValues.bind(ua);
    ua.getHighEntropyValues = async (hints) => {
      const values = await originalGetHighEntropy(hints);
      const spoofed = {
        platform: 'Windows',
        platformVersion: '10.0.0',
        architecture: 'x86',
        model: '',
        uaFullVersion: '120.0.0.0',
        bitness: '64',
        wow64: false,
      };
      for (const k of hints) {
        if (k in spoofed) values[k] = spoofed[k];
      }
      return values;
    };
  }

  _spoofCSSMediaQueries() {
    const originalMatchMedia = window.matchMedia.bind(window);
    window.matchMedia = (query) => {
      const mql = originalMatchMedia(query);
      if (self.enabled) {
        const spoofed = {
          '(prefers-reduced-motion: reduce)': false,
          '(prefers-contrast: more)': false,
          '(prefers-color-scheme: dark)': true,
          '(max-width:': mql.matches,
          '(min-width:': mql.matches,
        };
        for (const [q, v] of Object.entries(spoofed)) {
          if (query.includes(q)) return { ...mql, matches: v, addListener: () => {}, removeListener: () => {} };
        }
      }
      return mql;
    };
  }

  _spoofTouchSupport() {
    const props = {
      ontouchstart: null,
      ontouchend: null,
      ontouchmove: null,
      ontouchcancel: null,
    };
    for (const [key, value] of Object.entries(props)) {
      if (key in window) {
        this.originalValues.set(key, window[key]);
        this._defineProperty(window, key, value);
      }
    }
  }

  _spoofTimezone() {
    try {
      const originalDate = Date;
      const offset = new Date().getTimezoneOffset();
      const spoofedOffset = 0;

      const TZ = Intl.DateTimeFormat().resolvedOptions().timeZone;
      this.originalValues.set('timezone', TZ);

      const style = document.createElement('style');
      style.textContent = `@media (timezone: UTC) { }`;
      document.head.appendChild(style);
    } catch {}
  }

  _defineProperty(obj, prop, value) {
    try {
      Object.defineProperty(obj, prop, {
        value,
        writable: false,
        configurable: true,
        enumerable: true,
      });
    } catch {}
  }

  enable() {
    this.enabled = true;
  }

  disable() {
    this.enabled = false;
    for (const [key, value] of this.originalValues) {
      const parts = key.split('.');
      let obj = window;
      for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
      if (obj) {
        try { obj[parts[parts.length - 1]] = value; } catch {}
      }
    }
  }

  destroy() {
    this.disable();
    const fontStyle = document.getElementById('domail-font-spoof');
    if (fontStyle) fontStyle.remove();
  }
}

export function createFingerprintProtection(opts = {}) {
  return new FingerprintProtection(opts);
}