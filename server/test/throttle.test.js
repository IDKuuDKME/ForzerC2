'use strict';
/* Verifies the brute-force throttle.
 *
 * The dashboard password is guessable at the wire and was previously retryable
 * forever — one socket per guess, and every failure closed that socket and
 * nothing else. It is load-bearing: it is the trust boundary for every command
 * the control plane relays. So "long enough" has to be a property of the
 * server rather than of whoever chose the secret.
 *
 * There is no second secret. The enrolment key this file used to exercise is
 * gone (see the note in server.js), which leaves the dashboard password as the
 * only guessable credential — one counter, and the lockout now also stops a
 * blocked address from enrolling.
 *
 * Each test gets its own server process with deliberately tiny limits. The
 * counters are keyed on the remote address, and every test in this process
 * connects from 127.0.0.1, so a shared server would mean one test's lockout
 * silently became every other test's. Real isolation, not a shared fixture with
 * the thresholds turned up.
 */
const test = require('node:test');
const assert = require('node:assert');
const { WebSocket } = require('ws');
const { spawn } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

let nextPort = 34800;

function open(url) {
  const ws = new WebSocket(url);
  ws.msgs = [];
  ws.closed = null;
  ws.on('message', (d) => ws.msgs.push(String(d)));
  ws.on('close', (code, reason) => { ws.closed = { code, reason: String(reason) }; });
  return new Promise((resolve, reject) => {
    ws.on('open', () => resolve(ws));
    ws.on('error', (e) => reject(e));
  });
}

const closed = (ws, ms = 3000) => new Promise((resolve, reject) => {
  if (ws.closed) return resolve(ws.closed);
  const t = setTimeout(() => reject(new Error(
    `not closed within ${ms}ms; got ${JSON.stringify(ws.msgs)}`)), ms);
  ws.on('close', () => { clearTimeout(t); resolve(ws.closed); });
});

/* Start a control plane with the given throttle limits, run `fn(url, log)`,
   and make sure the process is gone afterwards. */
async function withServer(env, fn) {
  const port = nextPort++;
  const url = `ws://127.0.0.1:${port}`;
  const db = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'forzer-throttle-')), 'db.sqlite');
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      FORZER_DB: db,
      DASH_USER: 'op',
      DASH_PASS: 'op-pass',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const log = [];
  child.stdout.on('data', (d) => log.push(String(d)));
  child.stderr.on('data', (d) => log.push(String(d)));
  try {
    await new Promise((resolve, reject) => {
      const onData = (d) => { if (String(d).includes('listening')) resolve(); };
      child.stdout.on('data', onData);
      child.on('exit', (c) => reject(new Error(`server exited early (${c})`)));
      setTimeout(() => reject(new Error('server did not start in 5s')), 5000);
    });
    await fn(url, log);
  } finally {
    child.kill();
  }
}

const LIMITS = {
  FORZER_AUTH_MAX_FAILURES: '3',
  FORZER_AUTH_BLOCK_MS: '60000',
  FORZER_AUTH_DEADLINE_MS: '1000',
  FORZER_MAX_UNAUTH_PER_IP: '2',
};

async function tryDashboard(url, pass) {
  const ws = await open(url);
  ws.send(JSON.stringify({ type: 'dashboard', user: 'op', pass }));
  return ws;
}

test('repeated wrong dashboard credentials lock the address out', async () => {
  await withServer(LIMITS, async (url, log) => {
    for (let i = 0; i < 3; i++) {
      const ws = await tryDashboard(url, 'wrong');
      const c = await closed(ws);
      assert.ok([1005, 1008].includes(c.code), `a bad password closes the socket (got ${c.code})`);
    }
    assert.match(log.join(''), /locked out after 3 failed attempts/,
      'the lockout is a log line, not a silent behaviour change');

    /* The point of locking the *address* rather than counting guesses: after
       the threshold, the correct password does not work either. Anything else
       would mean the counter is advisory. */
    const ws = await tryDashboard(url, 'op-pass');
    const c = await closed(ws);
    assert.equal(c.code, 1008);
    assert.match(c.reason, /too many failed authentications/);
    assert.doesNotMatch(ws.msgs.join(''), /dashboard-ready/,
      'a locked-out address must not get a session');
  });
});

test('a locked-out address cannot enrol either', async () => {
  await withServer(LIMITS, async (url) => {
    /* Spend the budget guessing at the dashboard. The lockout is on the
       address, not on the kind of guess, so enrolment has to be shut out too
       — otherwise "is something guessing here" would be answered by which
       endpoint they happened to pick. */
    for (let i = 0; i < 3; i++) {
      const ws = await tryDashboard(url, 'wrong');
      await closed(ws);
    }
    const enrol = await open(url);
    enrol.send(JSON.stringify({
      type: 'register', name: 'x', secret: Buffer.alloc(32, 7).toString('base64'),
    }));
    const c = await closed(enrol);
    assert.equal(c.code, 1008);
    assert.match(c.reason, /too many failed authentications/,
      'a blocked address is refused at the door, before any challenge is issued');
  });
});

test('a successful login clears the record, so a fat-finger is not a lockout', async () => {
  await withServer(LIMITS, async (url) => {
    for (let i = 0; i < 2; i++) {
      const ws = await tryDashboard(url, 'wrong');
      await closed(ws);
    }
    const ok = await tryDashboard(url, 'op-pass');
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('no dashboard-ready')), 3000);
      ok.on('message', (d) => {
        if (String(d).includes('dashboard-ready')) { clearTimeout(t); resolve(); }
      });
    });
    ok.close();

    /* Two more failures must not trip the threshold of three, because the
       success reset the count. This is the assertion that distinguishes
       "cleared on success" from "never counted that attempt". */
    for (let i = 0; i < 2; i++) {
      const ws = await tryDashboard(url, 'wrong');
      await closed(ws);
    }
    const again = await tryDashboard(url, 'op-pass');
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('locked out after a success')), 3000);
      again.on('message', (d) => {
        if (String(d).includes('dashboard-ready')) { clearTimeout(t); resolve(); }
      });
    });
    again.close();
  });
});

test('a socket that never authenticates is closed', async () => {
  await withServer(LIMITS, async (url) => {
    /* No frames at all. The handshake is two round trips; a socket that never
       gets there is holding a file descriptor and a per-address allowance for
       as long as the process lives. */
    const ws = await open(url);
    const c = await closed(ws, 5000);
    assert.equal(c.code, 1008);
    assert.match(c.reason, /handshake timeout/);
  });
});

test('the number of sockets mid-handshake from one address is capped', async () => {
  await withServer({ ...LIMITS, FORZER_AUTH_DEADLINE_MS: '20000' }, async (url) => {
    /* The cap is on *unauthenticated* sockets only, so a fleet behind one
       NAT is unaffected once each of them has proved itself — which is the
       whole reason the cap is not simply a connection cap. */
    const a = await open(url);
    const b = await open(url);
    const extra = await open(url);
    const c = await closed(extra);
    assert.equal(c.code, 1008);
    assert.match(c.reason, /too many unauthenticated connections/);

    /* Authenticating hands the allowance back, so a busy control plane is not
       a cap that only ever ratchets down. */
    a.send(JSON.stringify({ type: 'dashboard', user: 'op', pass: 'op-pass' }));
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('no dashboard-ready')), 3000);
      a.on('message', (d) => {
        if (String(d).includes('dashboard-ready')) { clearTimeout(t); resolve(); }
      });
    });
    const after = await open(url);
    assert.equal(after.closed, null, 'the cap should have a slot free again');
    const blocked = await open(url);
    assert.equal(await closed(blocked).then((x) => x.reason),
      'too many unauthenticated connections', 'and still no more than the cap');

    for (const ws of [a, b, after, blocked]) { try { ws.close(); } catch (_) { /* gone */ } }
  });
});
