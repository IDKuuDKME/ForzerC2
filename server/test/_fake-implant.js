/* A minimal in-process implant, used only by the end-to-end CLI test.
 *
 * It speaks the real identity handshake over Node's built-in WebSocket, so it
 * exercises the same code path the compiled agent does — a test that used the
 * `ws` package on both ends would prove nothing about the dependency removal
 * this test exists to verify.
 *
 * Not part of the shipped system. Do not point this at anything real.
 */
'use strict';
const crypto = require('node:crypto');

const url = process.argv[2];
const SETUP_KEY = process.env.SETUP_KEY || 'k'.repeat(32);
const NAME = process.env.FAKE_NAME || 'FAKE-IMPLANT';

/* 32 bytes of CSPRNG output, used directly as the HMAC key — the same thing
   agent/ngcrypt.c does with BCryptGenRandom, and the same thing the agent
   persists DPAPI-wrapped. */
const SECRET = crypto.randomBytes(32);
let secret = null;
let nonce = null;
/* Set by a `sleep` from the control plane. The agent drops the link, waits out
   the interval plus jitter, then handshakes again on the same pinned key — so
   the id has to come back identical. */
let quietUntil = 0;
/* Set by the `update` announcement, consumed by the binary frame after it. */
let announced = null;

/* What this stand-in claims it can do. The real agent advertises the ops it
   compiled in; the server uses the advertised set to refuse work a peer cannot
   service, so a fake that stays silent would fail every op. */
const FAKE_OPS = ['exec', 'shell.open', 'shell.input', 'shell.close', 'cancel', 'sleep', 'update'];

/* Set by a `command` whose line contains `hang`. The agent runs one command at
   a time and this stand-in models that: a second command while one is running
   is refused, and `cancel` is what ends the first one — with rc=124 and a
   note in the text, the same shape the real agent produces when it kills a
   child. */
let running = null;

function connect() {
  const ws = new WebSocket(url);
  /* This is the global (undici) WebSocket, which hands binary frames back as
     a Blob unless told otherwise. The update push is exactly that, so ask for
     an ArrayBuffer and it converts to a Buffer cleanly. */
  ws.binaryType = 'arraybuffer';
  const send = (o) => ws.send(JSON.stringify(o));

  ws.addEventListener('open', () =>
    send({ type: 'register', name: NAME, secret: SECRET.toString('base64'), setupKey: SETUP_KEY,
           proto: 3, ops: FAKE_OPS }));

  ws.addEventListener('message', (ev) => {
    /* A pushed update arrives as a binary frame after a text announcement
       that names the digest. Reproduce the agent's order: refuse anything
       whose bytes do not hash to what was announced. */
    if (typeof ev.data !== 'string') {
      const buf = Buffer.isBuffer(ev.data) ? ev.data : Buffer.from(ev.data);
      if (!announced) {
        console.error('BINARY-WITHOUT-ANNOUNCEMENT', buf.length);
        process.exit(1);
      }
      const got = crypto.createHash('sha256').update(buf).digest('hex');
      if (got !== announced.sha256 || buf.length !== announced.size) {
        console.error('UPDATE-DIGEST-MISMATCH', got, announced.sha256);
        process.exit(1);
      }
      console.log('UPDATE-RECEIVED', buf.length, announced.sha256,
        'restart=' + (announced.restart ? 1 : 0));
      return;
    }
    const msg = JSON.parse(ev.data);

    if (msg.type === 'challenge') {
      nonce = Buffer.from(msg.nonce, 'base64');
      secret = SECRET;
      const proof = crypto.createHmac('sha256', secret)
        .update('forzer/client/v1').update(nonce).digest('base64');
      send({ type: 'auth', proof });
      return;
    }

    if (msg.type === 'registered') {
      if (msg.error) { console.error('REGISTER-FAILED', msg.error); process.exit(1); }
      /* Verify the server's side of the exchange, exactly as the agent does.
         A client proof must NOT satisfy this: the labels differ. */
      const expected = crypto.createHmac('sha256', secret)
        .update('forzer/server/v1').update(nonce).digest('base64');
      if (expected !== msg.serverProof) {
        console.error('SERVER-PROOF-REJECTED');
        process.exit(1);
      }
      console.log('ENROLLED', msg.id);
      return;
    }

    /* An implant is reply-only. Anything the server originates is the only
       thing it acts on. The wire shape is the agent's: {type, to, id, data, rc}. */
    if (msg.type === 'command') {
      if (msg.from && msg.from.startsWith('viewer:')) {
        if (/\bhang\b/.test(String(msg.data || ''))) {
          if (running) {
            send({ type: 'command-result', to: msg.from, id: msg.id,
                   data: 'another command is still running on this peer\n', rc: -1 });
            return;
          }
          running = { to: msg.from, id: msg.id };
          console.log('HANG', msg.id);
          return;
        }
        send({ type: 'command-result', to: msg.from, id: msg.id, data: 'root\n', rc: 0 });
      } else {
        console.error('COMMAND-WITHOUT-VIEWER-STAMP', JSON.stringify(msg));
        process.exit(1);
      }
      return;
    }

    /* Stop whatever is running. rc=0 means there was something, rc=1 means the
       peer was idle; the killed command's own result follows separately. */
    if (msg.type === 'cancel') {
      if (!msg.from || !msg.from.startsWith('viewer:')) {
        console.error('CANCEL-WITHOUT-VIEWER-STAMP', JSON.stringify(msg));
        process.exit(1);
      }
      if (!running) {
        send({ type: 'cancel-result', to: msg.from, id: msg.id, rc: 1 });
        return;
      }
      const was = running;
      running = null;
      send({ type: 'cancel-result', to: msg.from, id: msg.id, rc: 0 });
      send({ type: 'command-result', to: was.to, id: was.id,
             data: '\n...[cancelled by the control plane; process terminated]\n', rc: 124 });
      console.log('CANCELLED', was.id);
      return;
    }

    /* A minimal pseudo-terminal, so the shell path is actually covered. The
       real agent runs cmd.exe under a ConPTY; here the useful behaviour is the
       same shape - a banner on open, bytes back on input, exit on close - so a
       client that mishandles any of the three fails against this too. */
    if (msg.type === 'term-start') {
      if (!msg.from || !msg.from.startsWith('viewer:')) {
        console.error('TERM-WITHOUT-VIEWER-STAMP', JSON.stringify(msg));
        process.exit(1);
      }
      send({ type: 'term-data', to: msg.from, id: msg.id,
             data: Buffer.from('fake pty ready\r\n', 'utf8').toString('base64') });
      return;
    }
    if (msg.type === 'term-input') {
      if (!msg.from || !msg.from.startsWith('viewer:')) {
        console.error('TERM-INPUT-WITHOUT-VIEWER-STAMP', JSON.stringify(msg));
        process.exit(1);
      }
      /* Echo, the way a pty in echo mode would. A CR comes back as CRLF the
         way a Windows console would, so a client doing raw passthrough is
         exercised the same way. */
      const raw = Buffer.from(msg.data || '', 'base64').toString('latin1');
      const shown = raw.replace(/\r/g, '\r\n').replace(/\n/g, '');
      send({ type: 'term-data', to: msg.from, id: msg.id,
             data: Buffer.from(shown, 'latin1').toString('base64') });
      return;
    }
    if (msg.type === 'term-end') {
      send({ type: 'term-end', to: msg.from, id: msg.id, data: '' });
      return;
    }

    if (msg.type === 'update') {
      if (!msg.from || !msg.from.startsWith('viewer:')) {
        console.error('UPDATE-WITHOUT-VIEWER-STAMP', JSON.stringify(msg));
        process.exit(1);
      }
      announced = { sha256: msg.sha256, size: msg.size, restart: msg.restart };
      return;
    }

    /* `sleep` is the control plane telling this box to drop the link and stay
       off the network. */
    if (msg.type === 'sleep') {
      if (!msg.from || !msg.from.startsWith('viewer:')) {
        console.error('SLEEP-WITHOUT-VIEWER-STAMP', JSON.stringify(msg));
        process.exit(1);
      }
      quietUntil = Date.now() + Math.max(0, Number(msg.ms) || 0);
      console.log('SLEEP', msg.ms);
      ws.close(1000);
    }
  });

  ws.addEventListener('error', (e) => { console.error('WS-ERROR', e.message || e.error); process.exit(1); });
  ws.addEventListener('close', () => {
    const wait = quietUntil - Date.now();
    if (wait <= 0) { process.exit(0); return; }
    /* Shortened so the test does not sit out the real interval; the agent waits
       out the full one plus up to 20% of jitter. */
    setTimeout(connect, Math.min(wait, 300));
  });
}

connect();
