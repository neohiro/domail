/**
 * DOM Mail MCP server (stdio JSON-RPC 2.0)
 *
 * Zero dependencies — uses only node:fs, node:readline and the shared
 * core/mail.mjs engine. Run with:
 *   node mcp/domail-mcp.mjs
 *
 * The server answers `tools/list` and `tools/call`. It does not open
 * any network listeners (loopback excepted when talking to the MX node
 * control API on behalf of an agent).
 */

import { createInterface } from 'node:readline';
import { statSync, readFileSync, writeFileSync } from 'node:fs';

// Resolve engine relative to this file (repo root /core/mail.mjs)
const enginePath = new URL('../core/mail.mjs', import.meta.url).pathname;
const { MailEngine, memoryStore } = await import(enginePath);

// One shared engine instance for this process; agents that call
// repeatedly share the same mailbox state automatically.
let engine = null;

function getEngine() {
  if (!engine) engine = new MailEngine(memoryStore());
  return engine;
}

/**
 * Read the control API token.
 *
 * The agent may set MX_NODE_TOKEN, or save the token that `mx-node token`
 * prints into core/agent-token.json. The browser build keeps its own copy
 * in localStorage, so the two never share state by accident.
 */
function readAgentToken() {
  if (process.env.MX_NODE_TOKEN) return process.env.MX_NODE_TOKEN.trim();
  try {
    const p = new URL('../core/agent-token.json', import.meta.url).pathname;
    if (statSync(p).isFile()) {
      return (JSON.parse(readFileSync(p, 'utf8')).token || '').trim();
    }
  } catch (e) { /* no token yet */ }
  return '';
}

/** Save the token so the agent finds it on the next run. */
export function saveAgentToken(token) {
  const p = new URL('../core/agent-token.json', import.meta.url).pathname;
  writeFileSync(p, JSON.stringify({ token: String(token).trim() }, null, 2));
  return p;
}

const TOOLS = [
  {
    name: 'send_email',
    description: 'Send an email through the DOM Mail engine. The message is stored in outbox; if an MX node is configured it can be delivered via transports.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient address (e.g. user@example.org)' },
        from: { type: 'string', description: 'Sender address (defaults to identity)' },
        subject: { type: 'string', description: 'Subject line' },
        body: { type: 'string', description: 'Plain text body' },
      },
      required: ['to', 'subject', 'body'],
    },
  },
  {
    name: 'compose_email',
    description: 'Compose a message into the drafts folder (not sent).',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string' },
        subject: { type: 'string' },
        body: { type: 'string' },
      },
      required: ['to', 'subject', 'body'],
    },
  },
  {
    name: 'list_inbox',
    description: 'List messages in the inbox (oldest first by default).',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: 'Max messages to return' },
      },
    },
  },
  {
    name: 'read_email',
    description: 'Read the body/subject/from of a single message by its id.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
      },
      required: ['id'],
    },
  },
  {
    name: 'mx_node_status',
    description: 'Check the native MX node control API health and service state.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'mx_node_start',
    description: 'Start the native MX node OS service through the loopback control API.',
    inputSchema: { type: 'object', properties: {} },
  },
];

function respond(id, result) {
  console.log(JSON.stringify({ jsonrpc: '2.0', id, result }));
}

function error(id, message) {
  console.log(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32603, message } }));
}

async function handleCall(id, method, params = {}) {
  try {
    const eng = getEngine();
    if (method === 'send_email') {
      const msg = {
        to: (params.to || '').split(',').map(s => ({ address: s.trim(), name: '' })),
        from: params.from ? { address: params.from.trim(), name: '' } : (eng.identity || { address: 'agent@domail.space', name: 'Agent' }),
        subject: params.subject || '(no subject)',
        text: params.body || '',
      };
      await eng.send(msg, 'outbox');
      return { status: 'sent', to: params.to, from: msg.from.address };
    }
    if (method === 'compose_email') {
      const msg = {
        to: (params.to || '').split(',').map(s => ({ address: s.trim(), name: '' })),
        from: eng.identity || { address: 'agent@domail.space', name: 'Agent' },
        subject: params.subject || '(draft)',
        text: params.body || '',
      };
      await eng.send(msg, 'drafts');
      return { status: 'drafted', id: msg.id || 'draft-' + Date.now() };
    }
    if (method === 'list_inbox') {
      const list = await eng.list('inbox');
      const limit = params.limit || 20;
      const items = list.slice(0, limit).map((m, i) => ({
        id: m.id || String(i),
        from: (m.from && m.from[0] && m.from[0].address) || m.from || 'unknown',
        subject: m.subject || '(no subject)',
        date: m.date || Date.now(),
      }));
      return { inbox: items, total: list.length };
    }
    if (method === 'read_email') {
      const id = params.id;
      if (!id) return { error: 'id is required' };
      const list = await eng.list('inbox');
      const msg = list.find(m => m.id === id);
      if (!msg) return { error: 'message not found in inbox', id };
      return {
        id: msg.id,
        from: msg.from,
        to: msg.to,
        subject: msg.subject,
        body: msg.body_text || msg.body || msg.text || '(no body)',
        date: msg.date,
        read: msg.read,
      };
    }
    if (method === 'mx_node_status') {
      const token = readAgentToken();
      if (!token) return { status: 'no_token', message: 'Run mx-node token and save the token to agent-token.json' };
      const res = await fetch('http://127.0.0.1:8787/api/v1/health', { headers: { 'Authorization': `Bearer ${token}` } });
      const body = await res.json().catch(() => ({}));
      const svc = await fetch('http://127.0.0.1:8787/api/v1/service', { headers: { 'Authorization': `Bearer ${token}` } });
      const svcBody = await svc.json().catch(() => ({}));
      return {
        node_responding: res.ok,
        version: body.version || null,
        service_installed: svcBody.installed || false,
        service_running: svcBody.running || false,
        control_api_url: 'http://127.0.0.1:8787',
        token_set: !!token,
      };
    }
    if (method === 'mx_node_start') {
      const token = readAgentToken();
      if (!token) return { error: 'Token missing. Save to agent-token.json or set env MX_NODE_TOKEN.' };
      const res = await fetch('http://127.0.0.1:8787/api/v1/service/start', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const body = await res.json().catch(() => ({}));
      return {
        ok: res.ok,
        service_started: res.ok,
        message: body.ok ? 'Service started' : (body.error || 'Unknown error'),
      };
    }
    error(id, `Unknown tool: ${method}`);
  } catch (e) {
    error(id, e.message || String(e));
  }
}

async function mainLoop() {
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
  const lines = [];
  for await (const line of rl) {
    lines.push(line.trim());
    const text = lines.join('');
    if (!text) continue;
    try {
      const req = JSON.parse(text);
      lines.length = 0;
      if (req.jsonrpc !== '2.0') {
        console.log(JSON.stringify({ error: 'jsonrpc version must be 2.0', id: req.id || null }));
        continue;
      }
      if (req.method === 'initialize') {
        respond(req.id, {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'domail-mcp', version: '1.0.0' },
        });
        continue;
      }
      if (req.method === 'tools/list') {
        respond(req.id, { tools: TOOLS });
        continue;
      }
      if (req.method === 'tools/call') {
        const params = req.params || {};
        await handleCall(req.id, params.name, params.arguments || {});
        continue;
      }
      error(req.id, `Unknown method: ${req.method}`);
    } catch (e) {
      // Partial line or bad JSON — wait for more input.
    }
  }
}

mainLoop();
