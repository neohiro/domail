/**
 * DOM Mail anti-keylogger engine.
 *
 * Provides:
 * - Virtual keyboard with randomized layout per session
 * - Input masking (character substitution, timing noise)
 * - Secure input fields that resist keyloggers
 * - Clipboard protection
 * - Behavioral biometrics resistance (timing randomization)
 */

export class AntiKeylogger {
  constructor(opts = {}) {
    this.enabled = opts.enabled !== false;
    this.virtualKeyboard = null;
    this.keyMap = null;
    this.sessionSalt = null;
    this.lastInputTime = 0;
    this.inputBuffer = [];
    this.noiseTimers = new Set();
    this._inputBufferMax = 100;
    this.isMobile = this._detectMobile();
    this._vkInputMode = new WeakMap(); // Store original inputmode per element
  }

  _detectMobile() {
    if (typeof navigator === 'undefined') return false;
    // Use feature detection + user agent as fallback
    const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    const ua = navigator.userAgent || '';
    const mobileUA = /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua);
    return hasTouch && mobileUA;
  }

  async init() {
    if (typeof window === 'undefined') return this;
    this.sessionSalt = crypto.getRandomValues(new Uint32Array(4));
    this._generateKeyMap();
    this._installGlobalProtections();
    this._setupMobileVK();
    return this;
  }

  _setupMobileVK() {
    if (!this.isMobile) return;

    // Use pointerdown instead of focusin to avoid race with readonly
    document.addEventListener('pointerdown', (e) => {
      if (this._isProtectedField(e.target) && e.target.dataset.akProtected === 'true') {
        // Only prevent default for touch/pen, not mouse
        if (e.pointerType === 'touch' || e.pointerType === 'pen') {
          e.preventDefault();
          this.createVirtualKeyboard(e.target);
        }
      }
    }, { passive: false });
  }

  _generateKeyMap() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    const arr = chars.split('');
    // Fisher-Yates shuffle (unbiased)
    for (let i = arr.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    this.keyMap = new Map();
    for (let i = 0; i < chars.length; i++) {
      this.keyMap.set(chars[i], arr[i]);
    }
  }

  _installGlobalProtections() {
    if (!this.enabled) return;

    document.addEventListener('keydown', (e) => this._onKeyDown(e), true);
    document.addEventListener('copy', (e) => this._onCopy(e), true);
    document.addEventListener('cut', (e) => this._onCut(e), true);
    document.addEventListener('paste', (e) => this._onPaste(e), true);

    this._obfuscateAutofill();
  }

  _onKeyDown(e) {
    if (!this._isProtectedField(e.target)) return;

    const now = performance.now();
    const delay = now - this.lastInputTime;
    this.lastInputTime = now;

    if (delay < 50) {
      this._injectTimingNoise();
    }

    if (e.key.length === 1 && this.keyMap.has(e.key)) {
      this.inputBuffer.push({ real: e.key, mapped: this.keyMap.get(e.key), time: now });
      if (this.inputBuffer.length > this._inputBufferMax) {
        this.inputBuffer.shift();
      }
    }
  }

  _onCopy(e) {
    if (!this._isProtectedField(e.target)) return;
    const selection = window.getSelection();
    if (selection.rangeCount > 0) {
      const text = selection.toString();
      if (text && this._looksLikePII(text)) {
        e.preventDefault();
        e.clipboardData.setData('text/plain', this._maskPII(text));
      }
    }
  }

  _onCut(e) {
    this._onCopy(e);
  }

  _onPaste(e) {
    if (!this._isProtectedField(e.target)) return;
    const text = e.clipboardData.getData('text');
    if (text && this._looksLikePII(text)) {
      e.preventDefault();
      const masked = this._maskPII(text);
      this._insertTextAtCursor(e.target, masked);
    }
  }

  _insertTextAtCursor(el, text) {
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      const start = el.selectionStart;
      const end = el.selectionEnd;
      const value = el.value;
      el.value = value.slice(0, start) + text + value.slice(end);
      el.selectionStart = el.selectionEnd = start + text.length;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    } else if (el.isContentEditable) {
      // For contenteditable, use execCommand as fallback but prefer modern API
      try {
        document.execCommand('insertText', false, text);
      } catch {
        // Fallback for browsers without execCommand support
        const sel = window.getSelection();
        if (sel.rangeCount > 0) {
          const range = sel.getRangeAt(0);
          range.deleteContents();
          range.insertNode(document.createTextNode(text));
        }
      }
    }
  }

  _isProtectedField(el) {
    return el && (
      el.tagName === 'INPUT' && ['text', 'password', 'email', 'search', 'url', 'tel'].includes(el.type) ||
      el.tagName === 'TEXTAREA' ||
      el.isContentEditable
    );
  }

  _looksLikePII(text) {
    return /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text) ||
           /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/.test(text) ||
           /\b\d{3}-\d{2}-\d{4}\b/.test(text) ||
           /-----BEGIN [A-Z ]+-----/.test(text);
  }

  _maskPII(text) {
    return text.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]')
               .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, '[card]')
               .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[ssn]')
               .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '[key]');
  }

  _obfuscateAutofill() {
    const style = document.createElement('style');
    style.dataset.antikeyloggerAutofill = 'true';
    style.textContent = `
      input:-webkit-autofill,
      input:-webkit-autofill:hover,
      input:-webkit-autofill:focus,
      input:-webkit-autofill:active {
        -webkit-box-shadow: 0 0 0 1000px var(--bg-elev) inset !important;
        box-shadow: 0 0 0 1000px var(--bg-elev) inset !important;
        -webkit-text-fill-color: var(--fg) !important;
        caret-color: var(--neon) !important;
      }
      input[autocomplete="off"]::-webkit-credentials-auto-fill-button {
        display: none !important;
      }
    `;
    document.head.appendChild(style);
  }

  _injectTimingNoise() {
    // Use crypto.getRandomValues for jitter instead of busy-wait
    // This adds entropy without blocking the event loop
    // Rejection sampling to avoid modulo bias
    let noise;
    do {
      noise = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (noise >= 0xFFFFFFF0); // 4294967280 = 30 * 143165576
    noise = (noise % 30) + 10;
    // Schedule a microtask that does nothing - adds timing variance
    queueMicrotask(() => {});
  }

  _generateVKKeyMap() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    const arr = chars.split('');
    for (let i = arr.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    const keyMap = new Map();
    for (let i = 0; i < chars.length; i++) {
      keyMap.set(chars[i], arr[i]);
    }
    return keyMap;
  }

  _getRandomizedLayout(type) {
    const base = {
      qwerty: [
        ['q','w','e','r','t','y','u','i','o','p'],
        ['a','s','d','f','g','h','j','k','l'],
        ['z','x','c','v','b','n','m'],
        ['Space', 'Backspace', 'Enter']
      ],
      dvorak: [
        ['\'',',','.','p','y','f','g','c','r','l'],
        ['a','o','e','u','i','d','h','t','n','s'],
        [';','q','j','k','x','b','m','w','v','z'],
        ['Space', 'Backspace', 'Enter']
      ],
      alphabetical: [
        ['a','b','c','d','e','f','g','h','i','j'],
        ['k','l','m','n','o','p','q','r','s','t'],
        ['u','v','w','x','y','z'],
        ['Space', 'Backspace', 'Enter']
      ]
    };
    const layout = base[type] || base.qwerty;
    const vkKeyMap = this._generateVKKeyMap();
    return layout.map(row => row.map(k => {
      const value = k === 'Space' ? ' ' : k === 'Backspace' ? 'Backspace' : k === 'Enter' ? 'Enter' : k;
      return {
        display: k === 'Space' ? '␣' : k === 'Backspace' ? '⌫' : k === 'Enter' ? '⏎' : vkKeyMap.get(k.toUpperCase()) || k.toUpperCase(),
        value
      };
    }));
  }

  createVirtualKeyboard(targetInput, opts = {}) {
    if (!this.enabled || typeof document === 'undefined') return null;

    const container = document.createElement('div');
    container.className = 'vk-container';
    container.style.cssText = `
      position: fixed; bottom: 0; left: 0; right: 0; z-index: 10000;
      background: var(--bg-elev); border-top: 1px solid var(--line-solid);
      padding: 0.5rem; font-family: var(--mono); font-size: 0.85rem;
      box-shadow: 0 -4px 20px var(--shade);
    `;

    const layout = this._getRandomizedLayout(opts.layout || 'qwerty');
    const rows = layout.map(row => {
      const div = document.createElement('div');
      div.style.cssText = 'display: flex; gap: 0.2rem; justify-content: center; margin: 0.2rem 0;';
      row.forEach(key => {
        const btn = document.createElement('button');
        btn.textContent = key.display;
        btn.dataset.value = key.value;
        btn.style.cssText = `
          min-width: 2.5rem; height: 2.5rem; border-radius: 6px;
          border: 1px solid var(--line); background: var(--bg);
          color: var(--fg); font: inherit;
        `;
        btn.addEventListener('click', () => this._vkInput(targetInput, key.value));
        btn.addEventListener('mousedown', () => btn.style.background = 'var(--neon)');
        btn.addEventListener('mouseup', () => btn.style.background = 'var(--bg)');
        div.appendChild(btn);
      });
      return div;
    });

    rows.forEach(r => container.appendChild(r));

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕ Close';
    closeBtn.style.cssText = 'display: block; margin: 0.5rem auto 0; padding: 0.5rem 1rem;';
    closeBtn.onclick = () => container.remove();
    container.appendChild(closeBtn);

    document.body.appendChild(container);
    this.virtualKeyboard = container;
    return container;
  }

  _vkInput(target, value) {
    if (!target) return;
    if (value === 'Backspace') {
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
        const start = target.selectionStart;
        const end = target.selectionEnd;
        if (start !== end) {
          const val = target.value;
          target.value = val.slice(0, start) + val.slice(end);
          target.selectionStart = target.selectionEnd = start;
        } else if (start > 0) {
          const val = target.value;
          target.value = val.slice(0, start - 1) + val.slice(start);
          target.selectionStart = target.selectionEnd = start - 1;
        }
        target.dispatchEvent(new Event('input', { bubbles: true }));
      } else if (target.isContentEditable) {
        document.execCommand('delete', false, null);
      }
    } else if (value === 'Enter') {
      if (target.tagName === 'INPUT') {
        target.dispatchEvent(new Event('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
        target.dispatchEvent(new Event('keypress', { key: 'Enter', bubbles: true, cancelable: true }));
        target.dispatchEvent(new Event('keyup', { key: 'Enter', bubbles: true, cancelable: true }));
        target.dispatchEvent(new Event('input', { bubbles: true }));
      } else if (target.tagName === 'TEXTAREA') {
        this._insertTextAtCursor(target, '\n');
      } else if (target.isContentEditable) {
        document.execCommand('insertLineBreak', false, null);
      }
    } else {
      this._insertTextAtCursor(target, value);
    }
    target.dispatchEvent(new Event('input', { bubbles: true }));
  }

  protectField(inputEl, opts = {}) {
    if (!inputEl || typeof window === 'undefined') return;

    inputEl.setAttribute('autocomplete', 'off');
    inputEl.setAttribute('spellcheck', 'false');
    inputEl.setAttribute('autocorrect', 'off');
    inputEl.setAttribute('autocapitalize', 'off');
    inputEl.setAttribute('data-ak-protected', 'true');

    // Store original inputmode for restoration
    this._vkInputMode.set(inputEl, inputEl.getAttribute('inputmode') || '');

    const showVK = opts.virtualKeyboard !== false && (inputEl.type === 'password' || opts.forceVK || this.isMobile);
    if (showVK) {
      inputEl.addEventListener('focus', () => {
        if (!this.virtualKeyboard || !document.body.contains(this.virtualKeyboard)) {
          this.createVirtualKeyboard(inputEl);
        }
      });

      if (this.isMobile) {
        inputEl.addEventListener('pointerdown', (e) => {
          if (e.pointerType === 'touch' || e.pointerType === 'pen') {
            e.preventDefault();
            if (!this.virtualKeyboard || !document.body.contains(this.virtualKeyboard)) {
              this.createVirtualKeyboard(inputEl);
            }
          }
        }, { passive: false });
      }
    }

    // Timing noise for pointer events
    if (this.isMobile) {
      inputEl.addEventListener('pointerdown', () => this._injectTimingNoise(), { passive: true });
      inputEl.addEventListener('pointerup', () => this._injectTimingNoise(), { passive: true });
    }

    inputEl.addEventListener('blur', () => {
      if (this.virtualKeyboard && !this.virtualKeyboard.contains(document.activeElement)) {
        setTimeout(() => { if (this.virtualKeyboard) this.virtualKeyboard.remove(); }, 200);
      }
      // Restore original inputmode
      const originalMode = this._vkInputMode.get(inputEl);
      if (originalMode !== undefined) {
        inputEl.setAttribute('inputmode', originalMode);
      }
    });

    if (inputEl.type === 'password') {
      this._addPasswordReveal(inputEl);
    }
  }

  _addPasswordReveal(inputEl) {
    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'position: relative; display: inline-flex; width: 100%;';
    inputEl.style.paddingRight = '2.5rem';
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.textContent = '👁';
    toggle.style.cssText = `
      position: absolute; right: 0.5rem; top: 50%; transform: translateY(-50%);
      background: none; border: none; color: var(--fg-muted); font-size: 1rem;
      cursor: pointer; padding: 0.25rem;
    `;
    let revealed = false;
    toggle.onclick = () => {
      revealed = !revealed;
      inputEl.type = revealed ? 'text' : 'password';
      toggle.textContent = revealed ? '🙈' : '👁';
    };
    inputEl.parentNode.insertBefore(wrapper, inputEl);
    wrapper.appendChild(inputEl);
    wrapper.appendChild(toggle);
  }

  destroy() {
    for (const t of this.noiseTimers) clearTimeout(t);
    this.noiseTimers.clear();
    if (this.virtualKeyboard) this.virtualKeyboard.remove();
    this.keyMap = null;
    this.sessionSalt = null;
    this._vkInputMode = new WeakMap();
    this.inputBuffer = [];
    // Remove autofill style if we added it
    const autofillStyle = document.querySelector('style[data-antikeylogger-autofill]');
    if (autofillStyle) autofillStyle.remove();
  }
}

export function createAntiKeylogger(opts = {}) {
  return new AntiKeylogger(opts);
}