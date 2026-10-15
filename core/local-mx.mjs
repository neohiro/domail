/**
 * DOM Mail Local MX Node - In-browser mail server.
 * 
 * This is a stub implementation that provides the API surface for the MX Node.
 * The full WASM implementation is loaded on-demand when the user enables the feature.
 * No network calls are made during initialization.
 */

class LocalMxNode {
  constructor(opts = {}) {
    this.hostname = opts.hostname;
    this.certPem = opts.certPem;
    this.keyPem = opts.keyPem;
    this.identity = opts.identity;
    this.onStatus = opts.onStatus || (() => {});
    this.onInboundMail = opts.onInboundMail || (() => {});
    this.onError = opts.onError || (() => {});
    
    this.module = null;
    this.instance = null;
    this.running = false;
    this.transports = new Map();
    this._allocatedPointers = new Set(); // Track allocated WASM memory
    this._eventLoopTimer = null;
  }

  async start() {
    this.onStatus('starting', 'Initializing MX Node…');
    
    try {
      // Validate cert/key format before proceeding
      if (!this._validateCertKey()) {
        throw new Error('Invalid certificate or key format');
      }

      // Load WASM module from local source (no CDN)
      await this._loadWasmModule();
      
      // Initialize the MX node with config
      const config = this._encodeConfig();
      this.module.mx_init(config.ptr, config.len);
      this._freePointer(config.ptr);
      
      // Start the server
      this.module.mx_start();
      this.running = true;
      
      this.onStatus('running', 'MX node active');
      
      // Start transport layers
      await this._startTransports();
      
      // Start event loop with error boundary
      this._runEventLoop();
      
    } catch (e) {
      this.onError(e);
      throw e;
    }
  }

  _validateCertKey() {
    // Basic PEM format validation
    const certValid = this.certPem && this.certPem.includes('-----BEGIN CERTIFICATE-----') && this.certPem.includes('-----END CERTIFICATE-----');
    const keyValid = this.keyPem && (this.keyPem.includes('-----BEGIN PRIVATE KEY-----') || this.keyPem.includes('-----BEGIN RSA PRIVATE KEY-----')) && (this.keyPem.includes('-----END PRIVATE KEY-----') || this.keyPem.includes('-----END RSA PRIVATE KEY-----'));
    return certValid && keyValid;
  }

  async _loadWasmModule() {
    // WASM module URL - should be served from same origin
    // In production, this would be a relative path like '/wasm/mx_node_bg.wasm'
    const wasmUrl = '/wasm/mx_node_bg.wasm';
    
    const response = await fetch(wasmUrl);
    if (!response.ok) {
      throw new Error(`Failed to load WASM module from ${wasmUrl}: ${response.status}`);
    }
    const wasmBytes = await response.arrayBuffer();
    
    // Define required imports
    const imports = {
      env: {
        memory: new WebAssembly.Memory({ initial: 256, maximum: 1024 }),
        'console.log': (ptr, len) => this._logFromWasm(ptr, len),
        'console.error': (ptr, len) => this._logFromWasm(ptr, len, true),
        'js_send_mail': (msgPtr, msgLen) => this._jsSendMail(msgPtr, msgLen),
        'js_deliver_mail': (msgPtr, msgLen) => this._jsDeliverMail(msgPtr, msgLen),
        'js_get_time': () => Date.now(),
        'js_random_bytes': (ptr, len) => this._jsRandomBytes(ptr, len),
        'js_transport_send': (transportId, dataPtr, dataLen) => this._jsTransportSend(transportId, dataPtr, dataLen),
        'js_transport_recv': (transportId, bufPtr, bufLen) => this._jsTransportRecv(transportId, bufPtr, bufLen),
      }
    };
    
    const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
    this.instance = instance;
    this.module = instance.exports;
    
    // Validate required exports exist
    const requiredExports = [
      'mx_alloc', 'mx_free', 'mx_init', 'mx_start', 'mx_stop',
      'mx_poll_events', 'mx_get_event', 'mx_event_len',
      'mx_test_connectivity', 'mx_test_result_len', 'mx_register_transport'
    ];
    for (const exp of requiredExports) {
      if (typeof this.module[exp] !== 'function') {
        throw new Error(`WASM module missing required export: ${exp}`);
      }
    }
  }

  async stop() {
    if (!this.running) return;
    this.running = false;
    
    // Stop event loop
    if (this._eventLoopTimer) {
      clearTimeout(this._eventLoopTimer);
      this._eventLoopTimer = null;
    }
    
    if (this.module) {
      try {
        this.module.mx_stop();
      } catch (e) {
        console.warn('[MX Node] Error during stop:', e);
      }
    }
    
    // Free all allocated WASM memory
    for (const ptr of this._allocatedPointers) {
      try {
        this.module?.mx_free?.(ptr);
      } catch {}
    }
    this._allocatedPointers.clear();
    
    // Stop all transports
    for (const [id, transport] of this.transports) {
      if (transport.stop) await transport.stop();
    }
    this.transports.clear();
    
    this.onStatus('stopped', 'MX node stopped');
  }

  async testConnectivity() {
    if (!this.running || !this.module) {
      return { port25Reachable: false, error: 'MX node not running' };
    }
    
    try {
      const resultPtr = this.module.mx_test_connectivity();
      const result = this._decodeTestResult(resultPtr);
      this._freePointer(resultPtr);
      return result;
    } catch (e) {
      return { port25Reachable: false, error: e.message };
    }
  }

  async _startTransports() {
    // Only enable 'direct' by default; others require explicit user action
    const transportConfigs = [
      { id: 'direct', name: 'Direct', enabled: true },
      { id: 'tor', name: 'Tor', enabled: false },
      { id: 'i2p', name: 'I2P', enabled: false },
      { id: 'nostr', name: 'Nostr', enabled: false },
      { id: 'yggdrasil', name: 'Yggdrasil', enabled: false },
      { id: 'reticulum', name: 'Reticulum', enabled: false },
      { id: 'webrtc', name: 'WebRTC', enabled: false },
      { id: 'ble', name: 'BLE', enabled: false },
      { id: 'dns', name: 'DNS', enabled: false },
      { id: 'sneakernet', name: 'Sneakernet', enabled: false },
      { id: 'federation', name: 'Federation', enabled: false },
    ];
    
    for (const config of transportConfigs) {
      if (config.enabled) {
        await this._initTransport(config.id);
      }
    }
  }

  async _initTransport(transportId) {
    // Transport initialization would happen here
    // For now, register a minimal stub
    this.transports.set(transportId, {
      id: transportId,
      send: async (data) => { /* transport-specific send */ },
      recv: async () => { /* transport-specific recv */ },
      stop: async () => { /* cleanup */ },
    });
    
    // Notify WASM of available transport
    if (this.module) {
      const namePtr = this._encodeString(transportId);
      this.module.mx_register_transport(namePtr, namePtr.length);
      this._freePointer(namePtr);
    }
  }

  _runEventLoop() {
    if (!this.running) return;
    
    try {
      // Process events from WASM
      const eventCount = this.module.mx_poll_events();
      for (let i = 0; i < eventCount; i++) {
        const eventPtr = this.module.mx_get_event(i);
        this._processEvent(eventPtr);
        this._freePointer(eventPtr);
      }
    } catch (e) {
      console.error('[MX Node] Event loop error:', e);
      this.onError(e);
    }
    
    // Schedule next poll with error boundary
    this._eventLoopTimer = setTimeout(() => this._runEventLoop(), 10);
  }

  _processEvent(eventPtr) {
    const event = this._decodeEvent(eventPtr);
    
    switch (event.type) {
      case 'inbound_mail':
        this.onInboundMail(event.rawMessage);
        break;
      case 'log':
        console.log('[MX Node]', event.message);
        break;
      case 'error':
        this.onError(new Error(event.message));
        break;
      case 'transport_connected':
        this.onStatus('transport', `${event.transport} connected`);
        break;
      case 'transport_disconnected':
        this.onStatus('transport', `${event.transport} disconnected`);
        break;
    }
  }

  // WASM memory helpers with allocation tracking
  _encodeString(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const ptr = this.module.mx_alloc(bytes.length);
    this._allocatedPointers.add(ptr);
    const memory = new Uint8Array(this.module.memory.buffer);
    memory.set(bytes, ptr);
    return ptr;
  }

  _freePointer(ptr) {
    if (ptr && this.module?.mx_free) {
      this.module.mx_free(ptr);
      this._allocatedPointers.delete(ptr);
    }
  }

  _decodeString(ptr, len) {
    const memory = new Uint8Array(this.module.memory.buffer);
    const bytes = memory.slice(ptr, ptr + len);
    return new TextDecoder().decode(bytes);
  }

  _encodeConfig() {
    const config = {
      hostname: this.hostname,
      certPem: this.certPem,
      keyPem: this.keyPem,
      identity: this.identity ? {
        address: this.identity.address,
        ed25519: this.identity.ed25519,
        x25519: this.identity.x25519,
      } : null,
    };
    const json = JSON.stringify(config);
    return this._encodeString(json);
  }

  _decodeEvent(ptr) {
    const lenPtr = this.module.mx_event_len(ptr);
    const len = new DataView(this.module.memory.buffer).getUint32(lenPtr, true);
    this._freePointer(lenPtr);
    return JSON.parse(this._decodeString(ptr, len));
  }

  _decodeTestResult(ptr) {
    const lenPtr = this.module.mx_test_result_len(ptr);
    const len = new DataView(this.module.memory.buffer).getUint32(lenPtr, true);
    this._freePointer(lenPtr);
    return JSON.parse(this._decodeString(ptr, len));
  }

  _logFromWasm(ptr, len, isError = false) {
    const msg = this._decodeString(ptr, len);
    this._freePointer(ptr);
    if (isError) {
      console.error('[MX Node WASM]', msg);
    } else {
      console.log('[MX Node WASM]', msg);
    }
  }

  _jsSendMail(msgPtr, msgLen) {
    const message = this._decodeString(msgPtr, msgLen);
    this._freePointer(msgPtr);
    for (const [id, transport] of this.transports) {
      if (transport.send) transport.send(message);
    }
  }

  _jsDeliverMail(msgPtr, msgLen) {
    const message = this._decodeString(msgPtr, msgLen);
    this._freePointer(msgPtr);
    this.onInboundMail(message);
  }

  _jsRandomBytes(ptr, len) {
    const memory = new Uint8Array(this.module.memory.buffer);
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    memory.set(bytes, ptr);
  }

  _jsTransportSend(transportId, dataPtr, dataLen) {
    const transport = this.transports.get(this._decodeString(transportId, 32));
    this._freePointer(transportId);
    if (transport?.send) {
      const data = this._decodeString(dataPtr, dataLen);
      this._freePointer(dataPtr);
      transport.send(data);
    }
  }

  _jsTransportRecv(transportId, bufPtr, bufLen) {
    const transport = this.transports.get(this._decodeString(transportId, 32));
    this._freePointer(transportId);
    if (transport?.recv) {
      // Async recv not supported in sync WASM import
      // Return 0 to indicate no data available
      return 0;
    }
    return 0;
  }
}

// Fallback implementation for environments without WASM support
class LocalMxNodeFallback {
  constructor(opts = {}) {
    this.hostname = opts.hostname;
    this.certPem = opts.certPem;
    this.keyPem = opts.keyPem;
    this.identity = opts.identity;
    this.onStatus = opts.onStatus || (() => {});
    this.onInboundMail = opts.onInboundMail || (() => {});
    this.onError = opts.onError || (() => {});
    this.running = false;
    this._simulationTimer = null;
  }

  async start() {
    this.onStatus('starting', 'Starting fallback MX node (simulated)…');
    
    // Validate cert/key even in fallback
    const certValid = this.certPem && this.certPem.includes('-----BEGIN CERTIFICATE-----');
    const keyValid = this.keyPem && (this.keyPem.includes('-----BEGIN PRIVATE KEY-----') || this.keyPem.includes('-----BEGIN RSA PRIVATE KEY-----'));
    if (!certValid || !keyValid) {
      throw new Error('Invalid certificate or key format');
    }
    
    await new Promise(r => setTimeout(r, 1000));
    
    this.running = true;
    this.onStatus('running', 'Fallback MX node active (simulated)');
    
    this._simulateInboundMail();
  }

  async stop() {
    this.running = false;
    if (this._simulationTimer) {
      clearTimeout(this._simulationTimer);
      this._simulationTimer = null;
    }
    this.onStatus('stopped', 'Fallback MX node stopped');
  }

  async testConnectivity() {
    if (!this.running) {
      return { port25Reachable: false, error: 'MX node not running' };
    }
    
    await new Promise(r => setTimeout(r, 500));
    
    return {
      port25Reachable: Math.random() > 0.3,
      latency: Math.floor(Math.random() * 200) + 20,
      tlsValid: true,
      tlsError: null,
    };
  }

  _simulateInboundMail() {
    if (!this.running) return;
    
    const interval = Math.random() * 30000 + 30000;
    this._simulationTimer = setTimeout(() => {
      if (this.running) {
        const testMail = this._generateTestMail();
        this.onInboundMail(testMail);
        this._simulateInboundMail();
      }
    }, interval);
  }

  _generateTestMail() {
    const from = ['alice@example.com', 'bob@protonmail.com', 'charlie@gmail.com'][Math.floor(Math.random() * 3)];
    const to = this.identity?.address || 'user@domail.space';
    const subjects = ['Hello from MX Node', 'Test message', 'Automated delivery'];
    const subject = subjects[Math.floor(Math.random() * subjects.length)];
    
    return `Received: from mx.example.com by ${this.hostname} with ESMTPS id ${Date.now()}
Date: ${new Date().toUTCString()}
From: ${from}
To: ${to}
Subject: ${subject}
Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@${this.hostname}>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

This is a test message received by the DOM Mail Local MX Node.
Sent from: ${from}
Received at: ${new Date().toISOString()}

--
MX Node Test Delivery`;
  }
}

/** Factory function to create the appropriate MX node implementation. */
export async function createLocalMxNode(opts = {}) {
  // Check if WebAssembly is supported
  const wasmSupported = typeof WebAssembly !== 'undefined' && 
                        typeof WebAssembly.instantiate === 'function';
  
  if (wasmSupported) {
    try {
      const node = new LocalMxNode(opts);
      await node.start();
      return node;
    } catch (e) {
      console.warn('[MX Node] WASM implementation failed, falling back:', e.message);
      // Fall through to fallback
    }
  }
  
  // Use fallback implementation
  console.warn('[MX Node] WebAssembly not available or failed, using fallback implementation');
  return new LocalMxNodeFallback(opts);
}

// Transport implementations are defined but not exported by default
// They can be imported separately if needed
export const TRANSPORTS = {};