/**
 * DOM Mail Relay Server
 * WebSocket-to-SMTP gateway for outbound mail delivery.
 * 
 * Protocol: JSON frames over WebSocket
 * - { type: 'hello', v: 1, address: 'user@domain' } - client hello
 * - { type: 'publish', v: 1, mail: { ... } } - publish mail for relay
 * - { type: 'ping' } - heartbeat
 * - { type: 'pong' } - heartbeat response
 */

import { WebSocketServer } from 'ws';
import { createTransport } from 'nodemailer';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { parse } from 'url';

const PORT = process.env.PORT || 8765;
const RELAY_SECRET = process.env.RELAY_SECRET || 'dev-secret-change-in-production';
const MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB

// In-memory session store (replace with Redis in production)
const sessions = new Map();

// SMTP connection pool
const smtpPools = new Map();

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
 * Verify DKIM signature if present
 */
function verifyDKIM(message) {
  // Placeholder - implement DKIM verification if needed
  return true;
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
 * Start the relay server
 */
async function startServer() {
  const server = createServer();
  const wss = new WebSocketServer({ server, path: '/relay' });
  
  wss.on('connection', handleConnection);
  
  server.listen(PORT, () => {
    console.log(`[Relay] Server listening on port ${PORT}`);
    console.log(`[Relay] WebSocket endpoint: ws://localhost:${PORT}/relay`);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('[Relay] Shutting down...');
    for (const [ws, client] of clients) {
      ws.close(1001, 'Server shutting down');
    }
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