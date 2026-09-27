#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

/*
 * forzerctl — command-line client for the Forzer control plane.
 *
 * The dashboard and the MCP server are the other two clients. This one is for
 * a human at a shell: no browser, and no LLM host in the loop.
 *
 *   forzerctl                      interactive prompt (peers / run / term / cancel / sleep / update / help)
 *   forzerctl peers                list enrolled implants
 *   forzerctl run <peer> <command> run a command, print output + rc
 *   forzerctl term <peer>          interactive shell on a peer
 *   forzerctl cancel <peer>               stop the command a peer is running
 *   forzerctl sleep <peer> [secs]   tell a peer to go quiet (default 15 min)
 *
 * Flags: --url <ws://host:port>  --user <name>  --pass <secret>  --timeout <ms>
 * Env:   FORZER_URL (or FORZER_SERVER), FORZER_USER, FORZER_PASS
 *        (FORZER_MCP_* and DASH_* are accepted as fallbacks)
 */

/* No `ws` here: Node 22+ provides a WHATWG WebSocket client as a global, and
   this client only needs the client half. `WebSocket` is the global below. */
const readline = require('readline');

/* ----------------------------- options ----------------------------- */

function parseArgs(argv) {
  const opts = { timeout: 30000 };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--url' || a === '-u') opts.url = argv[++i];
    else if (a === '--user') opts.user = argv[++i];
    else if (a === '--pass' || a === '-p') opts.pass = argv[++i];
    else if (a === '--timeout') opts.timeout = parseInt(argv[++i], 10) || opts.timeout;
    else if (a === '--now') opts.now = true;   /* update: relaunch immediately instead of queueing */
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-v') opts.version = true;
    else if (a.startsWith('-')) { opts.error = `unknown flag ${a}`; }
    else rest.push(a);
  }
  opts.rest = rest;
  return opts;
}

const opts = parseArgs(process.argv.slice(2));

const URL_ = opts.url || process.env.FORZER_URL ||
  (process.env.FORZER_SERVER ? process.env.FORZER_SERVER.replace(/\/+$/, '') : '') ||
  (process.env.FORZER_MCP_URL ? process.env.FORZER_MCP_URL.replace(/\/+$/, '') : '') ||
  'ws://127.0.0.1:3000';
const USER = opts.user || process.env.FORZER_USER ||
  process.env.DASH_USER || process.env.FORZER_MCP_USER || 'Forgot';
const PASS = opts.pass || process.env.FORZER_PASS ||
  process.env.DASH_PASS || process.env.FORZER_MCP_PASS || 'HelloWorld1!';

if (opts.version) {
  process.stdout.write('forzerctl 0.1.0\n');
  process.exit(0);
}
if (opts.help) {
  process.stdout.write(`forzerctl 0.1.0 — command-line client for the Forzer control plane

usage:
  forzerctl                            interactive prompt
  forzerctl peers                      list enrolled implants
  forzerctl run <peer> <command...>    run a command on a peer
  forzerctl term <peer>                interactive shell on a peer
  forzerctl cancel <peer>              stop the command a peer is running
  forzerctl sleep <peer> [secs]       tell a peer to go quiet (default 900s)
  forzerctl ops                       list the ops a peer can be asked to do

flags:
  -u, --url <ws://host:port>   control plane (default ${URL_})
      --user <name>            dashboard user   (default ${USER})
  -p, --pass <secret>          dashboard pass   (default: built-in placeholder)
      --timeout <ms>           command timeout  (default ${opts.timeout})
  -h, --help                   this text

interactive prompt commands:
  peers                        list enrolled implants
  run <peer> <command...>      run a command on a peer
  term <peer>                  open an interactive shell (Ctrl-] to detach)
  cancel <peer>                stop the command that peer is running
  sleep <peer> [secs]          tell a peer to go quiet (default 900s)
  help                         this text
  exit                         quit
`);
  process.exit(0);
}
if (opts.error) {
  process.stderr.write('forzerctl: ' + opts.error + '\n');
  process.exit(2);
}

/* ---------------------------- transport ---------------------------- */

let ws = null;
let viewerId = null;
/* Enrolled implants, as pushed by the control plane. */
let peers = [];
let reqId = 0;
const pending = new Map();   // request id -> {resolve, reject, timer}
let mapWaiters = [];
const CONNECT_TIMEOUT = 10000;
const MAP_GRACE = 750;       // how long to wait for the first map frame

/* The built-in global, not the `ws` package. Node 22+ ships a WHATWG WebSocket
   client, which is all this CLI needs (the control plane still needs `ws` for
   the server half, which Node does not provide). Zero dependencies here. */
function wsOpen() { return !!ws && ws.readyState === WebSocket.OPEN; }

/* The control plane sends `dashboard-ready` and then the implant list in a
   *separate* frame. Resolving on `dashboard-ready` alone raced it, so every
   subcommand ran against an empty list and `run <name>` reported
   "peer not found" even though the control plane was healthy. */
function onMap(list) {
  peers = Array.isArray(list) ? list : [];
  const w = mapWaiters;
  mapWaiters = [];
  w.forEach((fn) => fn());
}

function waitForMap(ms) {
  return new Promise((resolve) => {
    let done = false;
    const fin = () => { if (!done) { done = true; resolve(); } };
    mapWaiters.push(fin);
    setTimeout(fin, ms);
  });
}

function failAllPending(err) {
  for (const [id, p] of [...pending]) {
    clearTimeout(p.timer);
    pending.delete(id);
    p.reject(err);
  }
}

function connect() {
  return new Promise((resolve, reject) => {
    const sock = new WebSocket(URL_.replace(/^http/, 'ws'));
    ws = sock;
    let settled = false;
    const fin = (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      e ? reject(e) : resolve();
    };
    /* A control plane that accepts the socket but never answers must not hang
       the client forever. */
    const timer = setTimeout(
      () => fin(new Error(`no response within ${CONNECT_TIMEOUT}ms`)), CONNECT_TIMEOUT);

    sock.addEventListener('open', () => {
      sock.send(JSON.stringify({ type: 'dashboard', user: USER, pass: PASS }));
    });
    /* Node's built-in WebSocket hands back a MessageEvent, not the raw payload
       the `ws` package did — hence ev.data. `error` is an Event too, so it gets
       re-wrapped: rejecting with the raw Event would surface as an empty
       message and hide the real cause. */
    sock.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'dashboard-ready') {
        viewerId = msg.id;
        fin();
      } else if (msg.type === 'dashboard-auth' && !msg.ok) {
        fin(new Error(msg.error || 'authentication failed'));
      } else if (msg.type === 'implants' || msg.type === 'map') {
        /* `implants` is current; `map` is the pre-identity frame type, still
           accepted so an older control plane lists something rather than hangs. */
        onMap(msg.implants || msg.peers);
      } else if (msg.type === 'command-result' || msg.type === 'cancel-result'
                 || msg.type === 'command-error') {
        const p = pending.get(msg.id);
        if (p) { clearTimeout(p.timer); pending.delete(msg.id); p.resolve(msg); }
      } else if (msg.type === 'term-data' || msg.type === 'term-exit') {
        if (msg.id && termHandler) termHandler(msg);
      }
    });
    sock.addEventListener('error', () => fin(new Error('websocket error')));
    sock.addEventListener('close', () => {
      if (ws === sock) ws = null;
      failAllPending(new Error('control plane connection lost'));
      fin(new Error('connection closed during handshake'));
    });
  });
}

function send(obj, timeoutMs) {
  return new Promise((resolve, reject) => {
    if (!wsOpen()) { reject(new Error('not connected to the control plane')); return; }
    const id = 'c' + (++reqId);
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`no reply within ${timeoutMs}ms (the peer may be busy or gone)`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    obj.id = id;
    ws.send(JSON.stringify(obj));
  });
}

function sendNow(obj) {
  if (!wsOpen()) throw new Error('not connected to the control plane');
  ws.send(JSON.stringify(obj));
}

/* Accept an implant id or a name. Ids are now derived from the implant's pinned
   key, so they survive a reboot — the name fallback stays because two boxes can
   still be configured with the same one. */
function resolvePeer(ref) {
  if (!ref) return null;
  const byId = peers.find((p) => p.id === ref);
  if (byId) return byId.id;
  const byName = peers.filter((p) => p.name === ref);
  if (byName.length === 1) return byName[0].id;
  if (byName.length > 1) {
    throw new Error(`"${ref}" matches ${byName.length} implants — use the id instead`);
  }
  return null;
}

function ago(ms) {
  if (!ms) return '—';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s / 60) + 'm ago';
  if (s < 86400) return Math.round(s / 3600) + 'h ago';
  return Math.round(s / 86400) + 'd ago';
}

function printPeers() {
  if (!peers.length) {
    process.stdout.write('no implants enrolled\n');
    return;
  }
  const w = Math.max(16, ...peers.map((p) => (p.id || '').length));
  process.stdout.write(`${'ID'.padEnd(w)}  ${'NAME'.padEnd(20)}  ${'STATE'.padEnd(8)}  LAST SEEN\n`);
  for (const p of peers) {
    const state = p.online ? 'online' : (p.status || 'offline');
    process.stdout.write(
      `${(p.id || '?').padEnd(w)}  ${(p.name || '?').padEnd(20)}  ${state.padEnd(8)}  ${ago(p.lastSeen)}\n`);
  }
}

/* ------------------------------ commands --------------------------- */

async function cmdRun(peerRef, commandLine) {
  const to = resolvePeer(peerRef);
  if (!to) throw new Error(`implant not found: ${peerRef} (try: forzerctl peers)`);
  const res = await send({ type: 'command', to, data: commandLine }, opts.timeout);
  if (res.type === 'command-error') throw new Error(res.error || 'command failed');
  if (res.data) process.stdout.write(res.data.endsWith('\n') ? res.data : res.data + '\n');
  process.stdout.write(`[rc=${res.rc === undefined ? '?' : res.rc}]\n`);
  return typeof res.rc === 'number' ? res.rc : 1;
}

/* Kill the command a peer is currently running. The agent answers with
   `cancel-result` on this request id: rc=0 means something was stopped, rc=1
   means the peer was idle. The cancelled command's own result still arrives
   separately, on its own id, with rc=124 and a note in the text — this reply
   says the kill was delivered, not what the command had already printed.

   There is no argument on purpose. A command id would be a second thing to get
   wrong, and the agent runs one command at a time, so "the running one" is not
   ambiguous. */
async function cmdCancel(peerRef) {
  const to = resolvePeer(peerRef);
  if (!to) throw new Error(`implant not found: ${peerRef} (try: forzerctl peers)`);
  const res = await send({ type: 'cancel', to }, opts.timeout);
  if (res.type === 'command-error') throw new Error(res.error || 'cancel failed');
  if (res.rc === 0) {
    process.stdout.write(`${to}: cancelled the running command\n`);
    return 0;
  }
  process.stdout.write(`${to}: nothing was running\n`);
  return 0;
}

/* Tell a peer to drop the link and stay off the network for a while. This is
   fire-and-forget: the agent answers nothing, so there is no request id to wait
   on. The peer shows as offline immediately and reappears when it wakes. */
function cmdSleep(peerRef, secs) {
  const to = resolvePeer(peerRef);
  if (!to) throw new Error(`implant not found: ${peerRef} (try: forzerctl peers)`);
  const seconds = secs === undefined ? 900 : Number(secs);
  if (!Number.isFinite(seconds) || seconds < 0 || seconds > 3600) {
    throw new Error('seconds must be between 0 and 3600');
  }
  sendNow({ type: 'sleep', to, ms: Math.round(seconds * 1000) });
  process.stdout.write(
    `${to} will disconnect now and check back in about ${Math.round(seconds / 60) || '<1'} min ` +
    '(plus up to 20% jitter)\n');
  return 0;
}

/* Push a new agent binary to a peer. The server reads the file, hashes it and
   sends the bytes down the link it already trusts, so the agent carries no
   download URL of its own. `path` defaults to the build next to the server. */
function cmdUpdate(peerRef, filePath, restart) {
  const to = resolvePeer(peerRef);
  if (!to) throw new Error(`implant not found: ${peerRef} (try: forzerctl peers)`);
  if (filePath !== undefined && !fs.existsSync(filePath)) {
    throw new Error(`no such file: ${filePath}`);
  }
  sendNow({ type: 'update', to, path: filePath, restart: restart ? 1 : 0 });
  process.stdout.write(
    `pushing ${filePath || '(server default build)'} to ${to}\n` +
    (restart
      ? 'the agent verifies the digest, installs, then relaunches now\n'
      : 'the agent verifies the digest and installs; the new image takes effect at the next agent start\n'));
  return 0;
}

/* Interactive terminal: raw stdin, escape is Ctrl-] (0x1d). Ctrl-C is
   forwarded to the peer as a real interrupt, not handled locally. */
let termHandler = null;

function cmdTerm(peerRef) {
  const to = resolvePeer(peerRef);
  if (!to) throw new Error(`implant not found: ${peerRef} (try: forzerctl peers)`);
  const sid = 't' + (++reqId);

  return new Promise((resolve, reject) => {
    let finished = false;
    const finish = (err) => {
      if (finished) return;
      finished = true;
      termHandler = null;
      try { sendNow({ type: 'term-end', to, id: sid }); } catch { /* peer may be gone */ }
      if (process.stdin.isTTY) process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      process.stdout.write('\r\n[detached]\r\n');
      err ? reject(err) : resolve(0);
    };

    termHandler = (msg) => {
      if (msg.id !== sid) return;
      if (msg.type === 'term-data' && msg.data) {
        process.stdout.write(Buffer.from(msg.data, 'base64'));
      } else if (msg.type === 'term-exit') {
        finish();
      }
    };

    process.stdout.write(`connecting to ${to} — Ctrl-] to detach, Ctrl-C interrupts\r\n`);
    sendNow({ type: 'term-start', to, id: sid });
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();

    const onData = (buf) => {
      if (buf.length === 1 && buf[0] === 0x1d) { finish(); return; }
      sendNow({
        type: 'term-input', to, id: sid,
        data: Buffer.from(buf).toString('base64'),
      });
    };
    process.stdin.on('data', onData);
  });
}

/* --------------------------- interactive --------------------------- */

async function prompt() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = () => new Promise((res) => rl.question('forzer> ', res));

  process.stdout.write(
    `forzerctl — ${URL_} as ${USER}\n` +
    "type 'help' for commands, 'exit' to quit\n");

  for (;;) {
    const line = await ask();
    const t = line.trim();
    if (!t) continue;
    const [verb, ...a] = t.split(/\s+/);

    try {
      if (verb === 'exit' || verb === 'quit') break;
      if (verb === 'help') {
        process.stdout.write(
          "commands:\n" +
          "  peers                    list enrolled implants\n" +
          "  run <peer> <command...>  run a command on a peer\n" +
          "  term <peer>              open an interactive shell (Ctrl-] to detach)\n" +
          "  sleep <peer> [secs]       tell a peer to go quiet (default 900s)\n" +
          "  help                     this text\n" +
          "  exit                     quit\n");
      } else if (verb === 'peers') {
        printPeers();
      } else if (verb === 'run') {
        await cmdRun(a[0], a.slice(1).join(' '));
      } else if (verb === 'term') {
        await cmdTerm(a[0]);
      } else if (verb === 'cancel') {
        await cmdCancel(a[0]);
      } else if (verb === 'sleep') {
        cmdSleep(a[0], a[1]);
      } else {
        process.stdout.write(`unknown command: ${verb}\n`);
      }
    } catch (e) {
      process.stdout.write(`error: ${e.message}\n`);
    }
  }
  rl.close();
  return 0;
}

function cmdOps() {
  /* Reads the catalog the control plane validates against, rather than a
     copy of the verb list kept in this file. If the two ever drift, this
     shows the truth and the client stops working loudly, instead of quietly
     offering a command the server will refuse. */
  const c = require(path.join(__dirname, '..', 'server', 'ops.js'));
  const caps = c.capabilities();
  process.stdout.write(`protocol ${c.protocol()}\n\n`);
  const rows = c.list().map((op) => {
    const arg = op.args === 'none' ? '-'
      : op.args === 'number' ? 'ms'
      : `data (max ${op.maxArg})`;
    return { op: op.name, wire: op.type, cap: op.cap, arg, desc: op.desc };
  });
  const w = rows.reduce((m, r) => Math.max(m, r.op.length), 4);
  for (const r of rows) {
    process.stdout.write(`  ${r.op.padEnd(w)}  ${r.wire.padEnd(11)} ${r.cap.padEnd(8)} ${r.arg}\n`);
    process.stdout.write(`  ${' '.repeat(w)}  ${' '.repeat(11)} ${C_DIM}${r.desc}${C_OFF}\n`);
  }
  process.stdout.write(`\ncapabilities:\n`);
  for (const [k, v] of Object.entries(caps)) {
    process.stdout.write(`  ${k.padEnd(w)}  ${C_DIM}${v}${C_OFF}\n`);
  }
  process.stdout.write(`\nreplies (implant -> operator):\n`);
  for (const r of c.catalog.implantOriginated || []) {
    process.stdout.write(`  ${r.type.padEnd(w)}  ${C_DIM}answers ${r.answers} — ${r.desc}${C_OFF}\n`);
  }
  return 0;
}

const C_DIM = '[2m', C_OFF = '[0m';

/* ------------------------------- main ------------------------------ */

/* Validate the subcommand before opening a socket: a typo should not need a
   reachable control plane to report itself. */
const SUBCOMMANDS = new Set(['peers', 'run', 'term', 'cancel', 'sleep', 'update', 'ops', 'console']);
const [sub, ...a] = opts.rest;
if (sub && !SUBCOMMANDS.has(sub)) {
  process.stderr.write(`forzerctl: unknown command "${sub}" — try --help\n`);
  process.exit(2);
}
if (sub === 'run' && (!a[0] || !a[1])) {
  process.stderr.write('forzerctl: usage: forzerctl run <peer> <command...>\n');
  process.exit(2);
}
if (sub === 'term' && !a[0]) {
  process.stderr.write('forzerctl: usage: forzerctl term <peer>\n');
  process.exit(2);
}
if (sub === 'sleep' && !a[0]) {
  process.stderr.write('forzerctl: usage: forzerctl sleep <peer> [seconds]\n');
  process.exit(2);
}

/* `ops` reads a file, not a socket, so it is answered before main() tries to
   connect. Being told what the control plane supports should not require the
   control plane to be up. */
if (sub === 'ops') {
  process.exit(cmdOps());
}

/* `console` hands the terminal to the TUI rather than reimplementing it. The
   URL and credentials are already resolved above, so pass them on the
   environment the console reads; a spawned process that silently used
   different defaults from the one the operator typed would be its own bug. */
if (sub === 'console') {
  const { spawnSync } = require('node:child_process');
  const r = spawnSync(process.execPath, [path.join(__dirname, 'console.js')].concat(a), {
    stdio: 'inherit',
    env: Object.assign({}, process.env, {
      FORZER_URL: URL_, FORZER_USER: USER, FORZER_PASS: PASS,
    }),
  });
  process.exit(r.status === null ? 1 : r.status);
}

(async function main() {
  try {
    await connect();
  } catch (e) {
    process.stderr.write(`forzerctl: cannot reach ${URL_}: ${e.message}\n`);
    process.exit(1);
  }
  process.stdout.write(`connected to ${URL_}\n`);
  /* Do not act until the mesh is known, or name resolution races the map. */
  await waitForMap(MAP_GRACE);

  let code = 0;
  try {
    if (!sub) {
      code = await prompt();
    } else if (sub === 'peers') {
      printPeers();
    } else if (sub === 'run') {
      code = await cmdRun(a[0], a.slice(1).join(' '));
    } else if (sub === 'term') {
      code = await cmdTerm(a[0]);
    } else if (sub === 'cancel') {
      code = await cmdCancel(a[0]);
    } else if (sub === 'sleep') {
      code = cmdSleep(a[0], a[1]);
    } else if (sub === 'update') {
      /* forzerctl update <peer> [file] [--now]   --now = relaunch immediately,
         default = apply at the next agent start. parseArgs consumes --now into
         opts, so it never reaches `a`. */
      code = cmdUpdate(a[0], a[1], opts.now);
    }
  } catch (e) {
    process.stderr.write('forzerctl: ' + e.message + '\n');
    code = 1;
  }
  try { ws && ws.close(); } catch { /* already gone */ }
  /* Interactive mode owns stdin; for one-shot commands nothing else is holding
     the loop open once the socket closes. */
  process.exit(code);
})();
