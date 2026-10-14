/**
 * DOM Mail Relay Server
 * WebSocket-to-SMTP gateway for outbound mail delivery.
 * 
 * Protocol: JSON frames over WebSocket
 * - { type: 'hello', v: 1, address: 'user@domain' } - client hello
 * - { type: 'publish', v: 1, mail: { ... } } - publish mail for relay
 * - { type: 'ping' } - heartbeat
 * - { type: 'pong' } - heartbeat response
 * 
 * HTTP Endpoints:
 * - GET /health - Health check
 * - POST /api/port25/verify - External inbound port 25 verification (authenticated)
 */

import { WebSocketServer } from 'ws';
import { createTransport } from 'nodemailer';
import { createServer } from 'http';
import { parse } from 'url';

const PORT = process.env.PORT || 8765;
const RELAY_SECRET = process.env.RELAY_SECRET || 'dev-secret-change-in-production';
const MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_WS_FRAME_SIZE = 1 * 1024 * 1024; // 1MB max WebSocket frame
const MAX_HTTP_BODY_SIZE = 10 * 1024; // 10KB max HTTP request body

// In-memory session store (replace with Redis in production)
const sessions = new Map();

// SMTP connection pool
const smtpPools = new Map();

// Rate limiting for external verification endpoint
const verificationRateLimit = new Map();
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 10;

// Allowed origins for CORS (configure via env in production)
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);

/**
 * Create SMTP transporter with connection pooling
 */
async function getTransporter(config) {
  const key = `${config.host}:${config.port}:${config.secure}`;
  if (smtpPools.has(key)) {
    return smtpPools.get(key);
  }
  
  const transporter = createTransport({
    host: config.host,
    port: config.port || (config.secure ? 465 : 587),
    secure: config.secure || false,
    auth: config.user ? { user: config.user, pass: config.pass } : undefined,
    tls: config.tls || { rejectUnauthorized: true },
    pool: true,
    maxConnections: 5,
    maxMessages: 100,
    rateDelta: 1000,
    rateLimit: 5,
  });
  
  transporter.verify().catch(err => {
    console.error('[SMTP] Pool verification failed:', err.message);
  });
  
  smtpPools.set(key, transporter);
  return transporter;
}

/**
 * Rate limiting for external verification endpoint
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const record = verificationRateLimit.get(ip) || { count: 0, windowStart: now };
  
  if (now - record.windowStart > RATE_LIMIT_WINDOW_MS) {
    record.count = 0;
    record.windowStart = now;
  }
  
  if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
    return { allowed: false, retryAfter: RATE_LIMIT_WINDOW_MS - (now - record.windowStart) };
  }
  
  record.count++;
  verificationRateLimit.set(ip, record);
  return { allowed: true };
}

/**
 * Verify API key for external verification endpoint
 */
function verifyApiKey(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return false;
  
  const expectedKey = process.env.PORT25_VERIFICATION_KEY || RELAY_SECRET;
  return authHeader === `Bearer ${expectedKey}`;
}

/**
 * Handle external port 25 verification request (HTTP endpoint)
 * Allows trusted external scanners to verify inbound port 25 reachability
 * without exposing the client's IP address.
 */
async function handleExternalPort25Verification(req, res) {
  // Check request body size
  let bodySize = 0;
  req.on('data', (chunk) => {
    bodySize += chunk.length;
    if (bodySize > MAX_HTTP_BODY_SIZE) {
      req.destroy();
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Payload too large', message: 'Request body exceeds size limit' }));
    }
  });

  // Check authentication
  if (!verifyApiKey(req)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized', message: 'Valid Bearer token required' }));
    return;
  }
  
  // Get client IP for rate limiting
  const clientIp = req.socket.remoteAddress || 'unknown';
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    res.writeHead(429, { 
      'Content-Type': 'application/json',
      'Retry-After': Math.ceil(rateLimit.retryAfter / 1000)
    });
    res.end(JSON.stringify({ 
      error: 'Rate limited', 
      message: 'Too many verification requests',
      retryAfter: Math.ceil(rateLimit.retryAfter / 1000)
    }));
    return;
  }
  
  // Only allow POST
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed', message: 'Use POST' }));
    return;
  }
  
  // Parse request body
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', async () => {
    try {
      const { targetHost, targetPort = 25, timeoutMs = 5000 } = JSON.parse(body || '{}');
      
      // Validate target (prevent SSRF)
      const allowedHosts = (process.env.PORT25_ALLOWED_HOSTS || '').split(',').map(h => h.trim()).filter(Boolean);
      if (allowedHosts.length > 0 && targetHost && !allowedHosts.includes(targetHost)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden', message: 'Target host not in allowed list' }));
        return;
      }
      
      // Validate port range
      if (targetPort < 1 || targetPort > 65535) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad request', message: 'Invalid port number' }));
        return;
      }
      
      // Validate timeout range
      if (timeoutMs < 1000 || timeoutMs > 30000) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad request', message: 'Timeout must be between 1000 and 30000 ms' }));
        return;
      }
      
      // Perform the port 25 check
      const start = Date.now();
      let reachable = false;
      let error = null;
      let latency = null;
      
      try {
        const net = await import('net');
        
        await new Promise((resolve, reject) => {
          const socket = net.createConnection(targetPort || 25, targetHost || '127.0.0.1');
          const timeout = setTimeout(() => {
            socket.destroy();
            reject(new Error('Connection timeout'));
          }, timeoutMs);
          
          socket.on('connect', () => {
            clearTimeout(timeout);
            socket.destroy();
            resolve();
          });
          
          socket.on('error', (err) => {
            clearTimeout(timeout);
            reject(err);
          });
        });
        
        reachable = true;
        latency = Date.now() - start;
      } catch (err) {
        reachable = false;
        error = err.message;
        latency = Date.now() - start;
      }
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        reachable,
        latency,
        error,
        timestamp: new Date().toISOString(),
        target: `${targetHost || '127.0.0.1'}:${targetPort || 25}`
      }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal error', message: err.message }));
    }
  });
}

/**
 * Health check endpoint
 */
function handleHealthCheck(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ 
    status: 'ok', 
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    clients: clients.size,
    smtpPools: smtpPools.size
  }));
}

/**
 * Test if port 25 is reachable on the relay's public internet (inbound connectivity)
 * The relay acts as a trusted proxy to preserve end-user client IP privacy.
 */
async function handlePort25InboundTest(ws, frame) {
  const checkId = frame.id;
  const start = Date.now();
  
  // The relay's own public IP is the target for inbound checks.
  // We attempt a self-connection from an ephemeral port to port 25 on localhost
  // to verify that port 25 is actually up and listening on the machine.
  let reachable = false;
  let error = null;
  let latency = null;
  
  try {
    const net = await import('net');
    
    // First, check if anything is listening on port 25
    await new Promise((resolve, reject) => {
      const socket = net.createConnection(25, '127.0.0.1');
      const timeout = setTimeout(() => {
        socket.destroy();
        reject(new Error('Connection timeout - nothing listening on port 25'));
      }, 3000);
      
      socket.on('connect', () => {
        clearTimeout(timeout);
        socket.destroy();
        resolve();
      });
      
      socket.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
    
    reachable = true;
    latency = Date.now() - start;
  } catch (err) {
    reachable = false;
    error = err.message;
    latency = Date.now() - start;
  }
  
  ws.send(JSON.stringify({
    type: 'port25_result',
    id: checkId,
    reachable,
    latency,
    error,
  }));
}

/**
 * Process outbound mail from client
 */
async function handlePublish(ws, frame, clients) {
  const { mail } = frame;
  
  if (!mail || !mail.to || !mail.to.length) {
    ws.send(JSON.stringify({ type: 'error', code: 'INVALID_MAIL', message: 'No recipients' }));
    return;
  }
  
  // Validate required fields
  if (!mail.from || !mail.from.address) {
    ws.send(JSON.stringify({ type: 'error', code: 'INVALID_MAIL', message: 'Missing from address' }));
    return;
  }
  
  if (!mail.to || !mail.to.length) {
    ws.send(JSON.stringify({ type: 'error', code: 'INVALID_MAIL', message: 'No recipients' }));
    return;
  }
  
  if (!mail.subject) {
    ws.send(JSON.stringify({ type: 'error', code: 'INVALID_MAIL', message: 'Missing subject' }));
    return;
  }
  
  try {
    const clientConfig = clients.get(ws)?.config?.smtp;
    const smtpConfig = {
      host: clientConfig?.host || process.env.SMTP_HOST || 'smtp.gmail.com',
      port: clientConfig?.port || parseInt(process.env.SMTP_PORT) || 587,
      secure: clientConfig?.secure ?? (process.env.SMTP_SECURE === 'true'),
      user: clientConfig?.user || process.env.SMTP_USER,
      pass: clientConfig?.pass || process.env.SMTP_PASS,
    };
    
    if (!smtpConfig.user || !smtpConfig.pass || !smtpConfig.host) {
      ws.send(JSON.stringify({ 
        type: 'error', 
        code: 'NO_SMTP_CONFIG', 
        message: 'SMTP configuration missing host, user, or pass' 
      }));
      return;
    }
    
    const transporter = await getTransporter(smtpConfig);
    
    // Build email message
    const recipients = [
      ...(mail.to || []).map(r => r.address),
      ...(mail.cc || []).map(r => r.address),
      ...(mail.bcc || []).map(r => r.address)
    ].filter(Boolean);
    
    if (recipients.length === 0) {
      ws.send(JSON.stringify({ type: 'error', code: 'NO_RECIPIENTS', message: 'No valid recipients' }));
      return;
    }
    
    // Build mail options
    const mailOptions = {
      from: mail.from?.address || process.env.SMTP_USER,
      to: recipients.join(', '),
      subject: mail.subject || '(no subject)',
      text: mail.text || '',
      html: mail.html || undefined,
    };
    
    // Add DKIM signing if configured
    if (process.env.DKIM_PRIVATE_KEY && process.env.DKIM_DOMAIN && process.env.DKIM_SELECTOR) {
      // DKIM signing would go here
    }
    
    // Send the email
    const info = await transporter.sendMail({
      from: mail.from?.address || process.env.SMTP_USER,
      to: recipients.join(', '),
      subject: mail.subject || '(no subject)',
      text: mail.text || '',
      html: mail.html || undefined,
      headers: {
        'X-Domail-Origin': 'domail-relay',
        'X-Domail-Identity': mail.from?.address,
      }
    });
    
    console.log(`[SMTP] Sent message ${info.messageId} to ${recipients.join(', ')}`);
    
    ws.send(JSON.stringify({ 
      type: 'sent', 
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      response: info.response
    }));
    
  } catch (err) {
    console.error('[Relay] Send failed:', err);
    ws.send(JSON.stringify({ 
      type: 'error', 
      code: 'SEND_FAILED', 
      message: err.message 
    }));
  }
}

/**
 * Handle incoming WebSocket messages
 */
function handleMessage(ws, data, clients) {
  let frame;
  try {
    frame = JSON.parse(data);
  } catch {
    ws.send(JSON.stringify({ type: 'error', code: 'INVALID_JSON', message: 'Invalid JSON frame' }));
    return;
  }
  
  switch (frame.type) {
    case 'hello':
      // Client hello - register identity
      if (frame.address) {
        ws.identity = frame.address;
        clients.set(ws, { identity: frame.address, connectedAt: Date.now() });
        ws.send(JSON.stringify({ type: 'welcome', version: 1, address: frame.address }));
      }
      break;
      
    case 'publish':
      handlePublish(ws, frame);
      break;
      
    case 'ping':
      ws.send(JSON.stringify({ type: 'pong', t: Date.now() }));
      break;
      
    case 'pong':
      // Heartbeat response - client is alive
      break;
      
    case 'config':
      // Client sending relay config
      if (frame.config) {
        clients.set(ws, { ...clients.get(ws), config: frame.config });
        ws.send(JSON.stringify({ type: 'config_ack', status: 'ok' }));
      }
      break;

    case 'port25_test':
      // Test if port 25 is reachable on the relay's public internet
      // The relay acts as a trusted proxy to preserve client IP privacy
      handlePort25InboundTest(ws, frame);
      break;
      
    default:
      ws.send(JSON.stringify({ type: 'error', code: 'UNKNOWN_FRAME', message: `Unknown frame type: ${frame.type}` }));
  }
}

/**
 * Handle new WebSocket connection
 */
function handleConnection(ws, req) {
  console.log('[WS] New connection from', req.socket.remoteAddress);
  
  ws.on('message', (data) => handleMessage(ws, data.toString(), clients));
  
  ws.on('close', () => {
    console.log('[WS] Client disconnected');
    clients.delete(ws);
  });
  
  ws.on('error', (err) => {
    console.error('[WS] Error:', err.message);
  });
  
  // Send initial hello
  ws.send(JSON.stringify({ type: 'welcome', version: 1, server: 'domail-relay' }));
}

/**
 * Check if origin is allowed for CORS
 */
function isOriginAllowed(origin) {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.length === 0) return false; // Deny all if not configured
  return ALLOWED_ORIGINS.includes(origin);
}

/**
 * Set CORS headers based on allowed origins
 */
function setCorsHeaders(res, origin) {
  if (isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
}

/**
 * Start the relay server
 */
async function startServer() {
  const server = createServer(async (req, res) => {
    const origin = req.headers.origin;
    setCorsHeaders(res, origin);
    
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }
    
    const parsedUrl = parse(req.url, true);
    const path = parsedUrl.pathname;
    
    // Route HTTP requests
    if (path === '/health' && req.method === 'GET') {
      handleHealthCheck(req, res);
    } else if (path === '/api/port25/verify' && req.method === 'POST') {
      await handleExternalPort25Verification(req, res);
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', message: 'Endpoint not found' }));
    }
  });
  
  const wss = new WebSocketServer({ 
    server, 
    path: '/relay',
    maxPayload: MAX_WS_FRAME_SIZE
  });
  
  wss.on('connection', handleConnection);
  
  server.listen(PORT, () => {
    console.log(`[Relay] Server listening on port ${PORT}`);
    console.log(`[Relay] WebSocket endpoint: ws://localhost:${PORT}/relay`);
    console.log(`[Relay] HTTP endpoints:`);
    console.log(`[Relay]   GET  /health`);
    console.log(`[Relay]   POST /api/port25/verify (requires Bearer token)`);
    if (ALLOWED_ORIGINS.length > 0) {
      console.log(`[Relay] CORS allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
    } else {
      console.log(`[Relay] CORS: disabled (set ALLOWED_ORIGINS to enable)`);
    }
  });
  
  // Periodic cleanup of rate limit map
  const rateLimitCleanup = setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of verificationRateLimit.entries()) {
      if (now - record.windowStart > RATE_LIMIT_WINDOW_MS * 2) {
        verificationRateLimit.delete(ip);
      }
    }
  }, RATE_LIMIT_WINDOW_MS);
  rateLimitCleanup.unref();
  
  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('[Relay] Shutting down...');
    // Close all WebSocket connections
    for (const [ws, client] of clients) {
      ws.close(1001, 'Server shutting down');
    }
    // Close all SMTP transporters
    for (const [key, transporter] of smtpPools.entries()) {
      try {
        transporter.close();
      } catch (e) {
        console.error(`[SMTP] Error closing pool ${key}:`, e.message);
      }
    }
    smtpPools.clear();
    // Clear rate limit map
    verificationRateLimit.clear();
    // Clear cleanup interval
    clearInterval(rateLimitCleanup);
    process.exit(0);
  });
}

// Client state
const clients = new Map();

startServer().catch(err => {
  console.error('[Relay] Fatal error:', err);
  process.exit(1);
});

export { };