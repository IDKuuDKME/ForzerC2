/* End-to-end check that the CLI works with zero dependencies.
   Starts a real control plane, then runs client/forzerctl.js as a subprocess in
   a directory with no node_modules, proving nothing in the require chain pulls
   in `ws`. */
const { spawn } = require('node:child_process');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const ROOT = path.resolve(__dirname, '..', '..');
const PORT = 34871;
const DB = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'forzer-e2e-')), 'db.sqlite');

function waitFor(fn, ms, label) {
  return new Promise((res, rej) => {
    const t0 = Date.now();
    (function tick() {
      if (fn()) return res();
      if (Date.now() - t0 > ms) return rej(new Error('timeout: ' + label));
      setTimeout(tick, 25);
    })();
  });
}

(async () => {
  const server = spawn(process.execPath, [path.join(ROOT, 'server', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), FORZER_DB: DB, DASH_USER: 'u', DASH_PASS: 'p', SETUP_KEY: 'k'.repeat(32),
           /* One deliberate bad password below, against a real per-address
             counter. Raised here so the policy checks cannot lock 127.0.0.1
             out from under themselves; test/throttle.test.js owns the
             threshold's actual behaviour. */
           FORZER_AUTH_MAX_FAILURES: '1000' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const serverLog = [];
  global.__serverLog = serverLog;
  server.stdout.on('data', (d) => serverLog.push(String(d)));
  server.stderr.on('data', (d) => serverLog.push(String(d)));
  server.on('error', (e) => serverLog.push('SPAWN-ERROR ' + e.message));
  server.on('exit', (c, s) => serverLog.push('SERVER-EXIT ' + c + ' ' + s));

  try {
    await waitFor(() => serverLog.join('').includes('listening'), 10000, 'server start');
    console.log('server up on', PORT);

    const ctl = path.join(ROOT, 'client', 'forzerctl.js');

    // 1. Empty roster: proves the handshake, dashboard auth and the renamed
    //    `implants` frame all round-trip through the built-in WebSocket.
    let r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'peers']);
    console.log('peers ->', JSON.stringify(r.out.trim()));
    assert.match(r.out, /no implants enrolled/);
    assert.equal(r.code, 0, 'exit code');

    // 2. Bad credentials must still fail loudly.
    r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'wrong', 'peers']);
    console.log('bad auth ->', JSON.stringify(r.err.trim().split('\n').pop()));
    assert.notEqual(r.code, 0);
    assert.match(r.err + r.out, /auth|credential|password|denied|invalid/i);

    // 3. A real command round trip against a simulated implant, driven by the
    //    CLI itself. This is the frame path that had to change (ev.data).
    const implant = spawn(process.execPath, ['_fake-implant.js', `ws://127.0.0.1:${PORT}`], {
      cwd: __dirname,
      env: { ...process.env, SETUP_KEY: 'k'.repeat(32) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const implantLog = [];
    implant.stdout.on('data', (d) => implantLog.push(String(d)));
    implant.stderr.on('data', (d) => implantLog.push(String(d)));
    try {
      await waitFor(() => implantLog.join('').includes('ENROLLED'), 10000, 'implant enrol');
      const id = (implantLog.join('').match(/ENROLLED (\S+)/) || [])[1];
      console.log('implant enrolled as', id);
      assert.match(id, /^[0-9a-f]{16}$/, 'id is key-derived');

      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'peers']);
      console.log('roster ->\n' + r.out.trim());
      assert.match(r.out, new RegExp(id));
      assert.match(r.out, /online/);
      assert.match(r.out, /\d+s ago/, 'last-seen column renders');
      assert.doesNotMatch(r.out, /(?<![\d.])10\.64\./, 'no overlay address anywhere');

      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'run', id, 'whoami']);
      console.log('run ->', JSON.stringify(r.out.trim()));
      assert.match(r.out, /root/, 'command output came back');
      assert.match(r.out, /\[rc=0\]/, 'exit code came back');
      assert.equal(r.code, 0, 'successful command exits 0');

      /* A command that never returns must be killable, or it occupies the
         peer forever: the agent runs one at a time, so the next command is
         refused as busy and the operator has no way out. Start it in the
         background so the CLI is genuinely blocked on the reply when the
         cancel lands, which is the only arrangement that tests the ordering
         the agent actually produces. */
      const base = ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p'];
      const hung = run(ctl, [...base, 'run', id, 'hang']);
      await waitFor(() => implantLog.join('').includes('HANG '), 5000, 'implant started the long command');

      r = await run(ctl, [...base, 'cancel', id]);
      console.log('cancel ->', JSON.stringify(r.out.trim().split('\n').pop()));
      assert.equal(r.code, 0, 'cancel is a successful op');
      assert.match(r.out, /cancelled the running command/);

      const hungResult = await hung;
      assert.match(hungResult.out, /cancelled by the control plane/,
        'the killed command explains itself in its own result');
      assert.match(hungResult.out, /\[rc=124\]/, 'and reports the conventional kill status');
      await waitFor(() => implantLog.join('').includes('CANCELLED'), 5000, 'implant confirmed the cancel');

      /* Cancelling an idle peer is a no-op that says so, not a silent success
         — the operator needs to know nothing was running. */
      r = await run(ctl, [...base, 'cancel', id]);
      assert.equal(r.code, 0, 'cancelling an idle peer is not an error');
      assert.match(r.out, /nothing was running/);

      /* A command the server cannot route must fail the CLI, not hang it. */
      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'run', 'deadbeefdeadbeef', 'x']);
      assert.notEqual(r.code, 0, 'unknown implant is a non-zero exit');
      assert.match(r.err + r.out, /implant not found/i);

      /* The quiet path, end to end: the CLI tells the implant to go quiet, the
         implant drops the link, and it comes back on the SAME id — the pinned
         key is what identifies it, not the socket. */
      const sleepsBefore = implantLog.filter((l) => l.includes('SLEEP')).length;
      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'sleep', id, '1']);
      console.log('sleep ->', JSON.stringify(r.out.trim().split('\n').pop()));
      assert.equal(r.code, 0, 'sleep is a successful no-op');
      assert.match(r.out, /will disconnect now and check back in/);

      await waitFor(() => implantLog.join('').includes('SLEEP 1000'), 5000, 'implant honoured sleep');
      assert.equal(implantLog.filter((l) => l.includes('SLEEP')).length, sleepsBefore + 1);

      await waitFor(() => (implantLog.join('').match(/ENROLLED (\S+)/g) || []).length >= 2, 8000, 'implant came back');
      const ids = [...implantLog.join('').matchAll(/ENROLLED (\S+)/g)].map((m) => m[1]);
      assert.equal(ids[ids.length - 1], id, 'the id must survive a sleep cycle');

      /* And the bad-argument path must not be able to park a box for hours. */
      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'sleep', id, '99999']);
      assert.notEqual(r.code, 0, 'an out-of-range sleep is a non-zero exit');
      assert.match(r.err + r.out, /between 0 and 3600/i);

      /* Update over the control plane. There is no download URL in the agent
         any more, so this is the only way a new build gets onto a box: the
         server reads the file, announces its digest, and pushes the bytes as
         a binary frame. The implant re-hashes before it stages anything. */
      const payload = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'forzer-upd-')), 'Forzer.exe');
      const bytes = Buffer.alloc(150000);   // >64 KB, so it takes the 64-bit length path
      for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + (i >> 8)) & 0xff;
      fs.writeFileSync(payload, bytes);
      const wantSha = require('node:crypto').createHash('sha256').update(bytes).digest('hex');

      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'update', id, payload]);
      console.log('update ->', JSON.stringify(r.out.trim().split('\n')[0]));
      assert.equal(r.code, 0, 'update is a successful push');
      assert.match(r.out, /verifies the digest/);
      assert.match(r.out, /next agent start/, 'default mode queues the relaunch');

      await waitFor(() => implantLog.join('').includes('UPDATE-RECEIVED'), 8000, 'implant received the update');
      const got = implantLog.join('').match(/UPDATE-RECEIVED (\d+) ([0-9a-f]{64}) restart=(\d)/);
      assert.equal(got[1], String(bytes.length), 'the whole payload arrived');
      assert.equal(got[2], wantSha, 'the bytes hash to what was announced');
      assert.equal(got[3], '0', 'a default push is queued for the next start');

      /* --now selects the immediate mode: same payload, restart=1 on the wire. */
      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'update', id, payload, '--now']);
      assert.equal(r.code, 0, 'update --now is a successful push');
      assert.match(r.out, /relaunches now/, '--now asks for an immediate relaunch');
      await waitFor(() => (implantLog.join('').match(/restart=1/g) || []).length > 0, 8000,
        'implant received the --now push with restart=1');

      /* A path that is not a readable file must fail loudly rather than push
         an empty or partial payload. */
      r = await run(ctl, ['--url', `ws://127.0.0.1:${PORT}`, '--user', 'u', '--pass', 'p', 'update', id, payload + '.nope']);
      assert.notEqual(r.code, 0, 'a missing update file is a non-zero exit');
      assert.match(r.err + r.out, /no such file/i);
    } finally {
      implant.kill();
    }

    console.log('\nE2E PASS');
  } finally {
    server.kill();
  }
})().catch((e) => {
  console.error('E2E FAIL:', e.message);
  if (global.__serverLog) console.error('--- server log ---\n' + global.__serverLog.join(''));
  process.exit(1);
});

function run(script, args) {
  return new Promise((res) => {
    // cwd is a scratch dir with no node_modules, so any stray require('ws')
    // in the CLI would throw MODULE_NOT_FOUND rather than silently resolving
    // from a parent's node_modules.
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'forzer-cli-'));
    const p = spawn(process.execPath, [script, ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => res({ code, out, err }));
  });
}
