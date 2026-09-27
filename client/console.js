#!/usr/bin/env node
'use strict';

/*
 * forzer console - the operator's terminal.
 *
 * forzerctl is the right tool for a script and the wrong one for sitting in
 * front of a fleet: every command means reconnecting, retyping a peer id, and
 * re-reading output that has already scrolled away. This is the same control
 * plane with a live view and keystroke tasking.
 *
 *   node console.js                      full screen, if stdout is a TTY
 *   node console.js --peer <name|id>     preselect a peer
 *
 * The interesting part is that it reads the op catalog rather than hardcoding a
 * verb list. A peer that does not advertise `shell` simply has that key greyed
 * out, because the roster carries what each connection said it implements.
 * There is no attempt to shell into an old build and eat a round trip.
 *
 * Shared wire conventions with forzerctl, deliberately not shared code: that
 * file is a line-oriented CLI and this is a full-screen program with its own
 * input state machine. Coupling them would mean forzerctl carrying a TUI's
 * event loop. The protocol both speak is in shared/ops.json.
 */

const URL_ = (process.env.FORZER_URL || process.env.FORZER_SERVER || 'ws://127.0.0.1:3000')
  .replace(/\/+$/, '');
const USER = process.env.FORZER_USER || process.env.DASH_USER || 'Forgot';
const PASS = process.env.FORZER_PASS || process.env.DASH_PASS || 'HelloWorld1!';

if (!process.stdout.isTTY || !process.stdin.isTTY) {
  process.stderr.write(
    'forzer console needs a terminal.\n' +
    'This build has no line mode on purpose - a non-interactive caller wants\n' +
    'forzerctl, which is scriptable:\n\n' +
    '  forzerctl peers\n' +
    '  forzerctl run <peer> <command>\n' +
    '  forzerctl term <peer>\n');
  process.exit(1);
}

/* ------------------------------- terminal ------------------------------- */

const ESC = '\x1b';
const alt = (on) => process.stdout.write(on ? `${ESC}[?1049h` : `${ESC}[?1049l`);
const clear = () => process.stdout.write(`${ESC}[2J${ESC}[H`);
const hideCur = () => process.stdout.write(`${ESC}[?25l`);
const showCur = () => process.stdout.write(`${ESC}[?25h`);

const C = {
  reset: `${ESC}[0m`, dim: `${ESC}[2m`, bold: `${ESC}[1m`,
  red: `${ESC}[31m`, green: `${ESC}[32m`, yellow: `${ESC}[33m`,
  blue: `${ESC}[34m`, cyan: `${ESC}[36m`, grey: `${ESC}[90m`,
};

const rows = () => Math.max(10, process.stdout.rows - 2);
const cols = () => Math.max(60, process.stdout.columns || 100);
const pad = (s, n) => String(s == null ? '' : s).slice(0, n).padEnd(n);
const clip = (s, n) => (String(s == null ? '' : s).length > n
  ? String(s).slice(0, Math.max(0, n - 1)) + '…' : String(s));

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/* --------------------------------- state -------------------------------- */

let roster = [];
let selected = 0;
let mode = 'list';           // list | exec | shell | update | sleep
let input = '';              // line being typed in exec/update/sleep
let status = '';             // transient one-line message
let statusAt = 0;
let connected = false;
let reqId = 0;
const pending = new Map();   // id -> {resolve}
let session = null;          // {id, peer, buffer}
let scroll = 0;

function say(msg) { status = msg; statusAt = Date.now(); render(); }
function clearStatus() { if (Date.now() - statusAt > 6000) status = ''; }

const peerAt = (i) => roster[i];
const hasOp = (p, name) => !p || !Array.isArray(p.ops) || p.ops.length === 0 || p.ops.includes(name);

/* -------------------------------- render -------------------------------- */

function render() {
  clearStatus();
  const t = cols();
  let out = '';

  const head =
    `${C.bold}${C.cyan}forzer console${C.reset}  ${C.grey}${clip(URL_, t - 40)}${C.reset}  ` +
    `${connected ? C.green + '● connected' : C.red + '● offline'}${C.reset}` +
    `${C.grey}  as ${clip(USER, 20)}${C.reset}`;
  out += head + '\n' + `${C.grey}${'─'.repeat(t)}${C.reset}\n`;

  if (mode === 'shell' && session) {
    out += renderShell(t);
  } else if (mode === 'output' && session) {
    out += renderOutput(t);
  } else {
    /* --- roster --- */
    out += `  ${C.bold}#   PEER${C.reset}${' '.repeat(12)}${C.bold}ID${C.reset}` +
           `${' '.repeat(6)}${C.bold}STATE${C.reset}${' '.repeat(7)}${C.bold}PROTO` +
           `${C.reset}   ${C.bold}OPS${C.reset}\n`;
    if (!roster.length) {
      out += `\n  ${C.grey}no implants enrolled.${C.reset}\n`;
    }
    roster.forEach((p, i) => {
      const on = p.online;
      const sel = i === selected;
      const mark = sel ? `${C.cyan}▸${C.reset}` : ' ';
      const num = sel ? `${C.bold}${C.cyan}${i + 1}${C.reset}` : `${C.grey}${i + 1}${C.reset}`;
      const st = on ? `${C.green}online ${C.reset}` : `${C.grey}offline${C.reset}`;
      out += `${mark} ${num}  ${pad(clip(p.name, 16), 16)}  ${C.grey}${p.id}${C.reset}  ` +
             `${st}  ${C.grey}v${p.proto || 0}${C.reset}   ` +
             `${C.grey}${clip((p.ops || []).join(' ') || 'unknown', 26)}${C.reset}\n`;
    });

    const p = peerAt(selected);
    out += `\n  ${C.grey}${'─'.repeat(t - 4)}${C.reset}\n`;
    if (p) {
      out += `  ${C.dim}last seen ${ago(p.lastSeen)} · enrolled ${ago(p.firstSeen)}` +
             `${p.new ? ' · NEW' : ''}${C.reset}\n\n`;
    }

    if (mode !== 'list') {
      out += renderPrompt(t);
    } else {
      out += keys(p, t);
    }
  }

  if (status) out += `\n  ${C.yellow}${clip(status, t - 4)}${C.reset}\n`;

  process.stdout.write(out);
}

/* The tail of a finished command. `output` mode fell through to renderPrompt
   before, which drew an input line for a mode that takes no input. */
function renderOutput(t) {
  let out = `  ${C.bold}output${C.reset} ${C.grey}${clip(session.peer, 24)}` +
            `${session.rc !== undefined ? ` · ${C.reset}${C.bold}rc=${session.rc}` : ''}\n`;
  out += `  ${C.grey}${'─'.repeat(t - 4)}${C.reset}\n`;
  const lines = session.buffer.slice(-(rows() - 3));
  if (!lines.length) lines.push('(no output)');
  for (const l of lines) out += '  ' + clip(String(l).replace(/\r/g, ''), t - 4) + '\n';
  out += `\n  ${C.grey}any key to return${C.reset}\n`;
  return out;
}

function keys(p, t) {
  if (!p) return `  ${C.grey}[1-9] select   q quit${C.reset}\n`;
  const k = (n, ch, cap) => (hasOp(p, cap)
    ? `${C.bold}${ch}${C.reset}` : `${C.grey}${ch}${C.reset}`);
  /* The last-seen line is printed once, by render(), for every mode. Printing
     it here too meant the list view showed it stacked. */
  return `  ${k('e', 'e', 'exec')} exec   ` +
         `${k('s', 's', 'shell.open')} shell   ${k('u', 'u', 'update')} update   ` +
         `${k('x', 'x', 'cancel')} cancel   ` +
         `${k('z', 'z', 'sleep')} sleep   ${C.grey}[1-9] select   r refresh   q quit${C.reset}\n`;
}

function renderPrompt(t) {
  const p = peerAt(selected);
  const label = {
    exec: `exec on ${p ? p.name : '?'}`,
    update: `update ${p ? p.name : '?'} from`,
    sleep: `sleep ${p ? p.name : '?'} for`,
  }[mode] || mode;
  return `  ${C.cyan}❯${C.reset} ${clip(label, 28)} ${clip(input, t - 40)}\n` +
         `  ${C.grey}Enter to send · Esc to cancel${C.reset}\n`;
}

/* The shell pane keeps a bounded scrollback of decoded output. Full-screen
   redraw of a live ConPTY stream redraws the whole thing, so this is a tail,
   not a terminal emulator - which is also why the remote side is a real
   pty and this side is honest about being a window onto it. */
function renderShell(t) {
  const lines = session.buffer.slice(-rows() + 2);
  let out = `  ${C.bold}shell${C.reset} ${C.grey}${session.peer}${C.reset}  ` +
            `${C.grey}Ctrl-] detach · Ctrl-C interrupt${C.reset}\n`;
  out += `  ${C.grey}${'─'.repeat(t - 4)}${C.reset}\n`;
  for (const l of lines) {
    out += '  ' + clip(l.replace(/\r/g, ''), t - 4) + '\n';
  }
  return out;
}

/* --------------------------------- wire --------------------------------- */

let sock = null;

function sendNow(o) {
  if (!sock || sock.readyState !== 1) throw new Error('not connected');
  sock.send(JSON.stringify(o));
}

function connect() {
  sock = new WebSocket(URL_);
  sock.addEventListener('open', () => {
    sock.send(JSON.stringify({ type: 'dashboard', user: USER, pass: PASS }));
  });
  sock.addEventListener('message', (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    onMessage(m);
  });
  sock.addEventListener('close', () => {
    connected = false;
    if (mode === 'shell') { say('connection lost — shell detached'); mode = 'list'; session = null; }
    else say('connection lost');
    render();
    /* The control plane going away is normal (a redeploy, a restart), not an
       error state. Reconnect rather than exiting and making the operator
       notice. */
    setTimeout(() => { if (!process.exitCode) connect(); }, 3000);
  });
  sock.addEventListener('error', () => {});
}

function onMessage(m) {
  switch (m.type) {
    case 'dashboard-ready': connected = true; render(); return;
    case 'dashboard-auth':
      say(`auth rejected: ${m.error || 'invalid credentials'}`);
      process.exitCode = 1; return;
    case 'implants':
      roster = Array.isArray(m.implants) ? m.implants : [];
      if (selected >= roster.length) selected = Math.max(0, roster.length - 1);
      render(); return;
    case 'term-data': {
      if (!session || m.id !== session.id || !m.data) return;
      const text = Buffer.from(m.data, 'base64').toString('latin1');
      session.buffer.push(text);
      /* Split on newlines so the pane reflows; a bare CR is a progress
         rewrite on a Windows shell, and keeping it whole is what makes the
         output look like a terminal rather than a log. */
      while (session.buffer.length > 400) session.buffer.shift();
      render();
      return;
    }
    case 'term-exit':
      if (session && m.id === session.id) {
        session.buffer.push(`\n[session ended]${m.data ? ': ' + m.data : ''}`);
        setTimeout(() => { mode = 'list'; session = null; render(); }, 400);
      }
      return;
    case 'command-result':
    /* The reply to `cancel` is its own type, and it resolves the same pending
       request — an op is not "done" until whatever it asked for answers. */
    case 'cancel-result': {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      p.resolve(m);
      return;
    }
    case 'command-error': {
      const p = pending.get(m.id);
      say(m.error || 'command failed');
      if (p) { pending.delete(m.id); p.resolve(null); }
      return;
    }
    default: return;
  }
}

function request(frame, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const id = 'c' + (++reqId);
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(null);
      say('timed out waiting for the peer');
    }, timeoutMs);
    pending.set(id, {
      resolve: (m) => { clearTimeout(timer); resolve(m); },
    });
    try {
      sendNow(Object.assign({ id }, frame));
    } catch (e) {
      clearTimeout(timer); pending.delete(id);
      say(String(e.message || e));
      resolve(null);
    }
  });
}

/* ------------------------------- operations ----------------------------- */

async function doExec() {
  const p = peerAt(selected);
  if (!p) return say('no peer selected');
  if (!hasOp(p, 'exec')) return say(`peer does not implement exec`);
  const r = await request({ type: 'command', to: p.id, data: input });
  input = ''; mode = 'list';
  if (!r) return render();
  const out = r.data ? String(r.data) : '(no output)';
  const rc = r.rc;
  say(`rc=${rc} · ${clip(out.split('\n').filter(Boolean).slice(-1)[0] || out, 90)}`);
  /* Full output goes to a pane rather than a one-line summary: an operator
     running a command needs to read what came back, and a single clipped line
     is exactly the thing that makes a CLI painful to use against a fleet. */
  session = { id: null, peer: p.name, buffer: out.split('\n'), rc };
  mode = 'output';
  render();
}

function doShell() {
  const p = peerAt(selected);
  if (!p) return say('no peer selected');
  if (!hasOp(p, 'shell.open')) return say('peer does not implement shell');
  const id = 'c' + (++reqId);
  session = { id, peer: p.name, buffer: [] };
  mode = 'shell';
  render();
  sendNow({ type: 'term-start', to: p.id, id });
}

function detach() {
  if (session && session.id) {
    try { sendNow({ type: 'term-end', to: peerAt(selected).id, id: session.id }); } catch { /* gone */ }
  }
  session = null;
  mode = 'list';
  say('detached');
}

async function doUpdate() {
  const p = peerAt(selected);
  if (!p) return say('no peer selected');
  if (!hasOp(p, 'update')) return say('peer does not implement update');
  const path = input.trim();
  input = ''; mode = 'list';
  if (!path) return say('no path given');
  say(`pushing ${path}…`);
  const r = await request({ type: 'update', to: p.id, path }, 120000);
  if (!r) return render();
  say(r.data ? String(r.data) : 'update sent');
  render();
}

async function doSleep() {
  const p = peerAt(selected);
  if (!p) return say('no peer selected');
  const secs = parseInt(input.trim(), 10);
  input = ''; mode = 'list';
  if (!Number.isFinite(secs) || secs <= 0) return say('seconds must be a positive number');
  const r = await request({ type: 'sleep', to: p.id, ms: Math.min(secs, 3600) * 1000 });
  say(r ? `peer quiet for ${secs}s` : 'sleep not acknowledged');
  render();
}

/* -------------------------------- input --------------------------------- */

/* A single keystroke, in every mode except shell.

   Split out from onKey because stdin delivers *chunks*, not keys. Typing
   "whoami\r" into a pty arrives as one 7-byte event, and a handler that reads
   s[0] throws five characters away and then submits whatever is left over.
   That is not hypothetical: the first pty test submitted the letter q. */
function handleByte(b) {
  const ch = String.fromCharCode(b);

  if (mode === 'output') {
    if (ch === '\r' || ch === 'q' || ch === '\x1b') { mode = 'list'; session = null; }
    return;
  }

  if (mode !== 'list') {
    if (ch === '\x1b') { mode = 'list'; input = ''; return; }   // Esc
    if (ch === '\r') {
      const go = mode;
      /* Latch before the async handler starts. A pasted line often carries a
         trailing newline or several commands, and without this the remaining
         bytes land in whatever mode the handler is about to switch to. */
      mode = 'busy';
      if (go === 'exec') doExec();
      else if (go === 'update') doUpdate();
      else doSleep();
      return;
    }
    if (ch === '\x7f' || ch === '\b') { input = input.slice(0, -1); return; }
    if (ch === '\x03') { mode = 'list'; input = ''; return; }   // Ctrl-C
    if (b >= 0x20 && b !== 0x7f) input = (input + ch).slice(0, 400);
    return;
  }

  if (ch >= '1' && ch <= '9') {
    const i = Number(ch) - 1;
    if (i < roster.length) { selected = i; return; }
    say('no such peer');
    return;
  }
  switch (ch) {
    case 'e': {
      const p = peerAt(selected);
      if (!p) return say('no peer selected');
      if (!hasOp(p, 'exec')) return say('peer does not implement exec');
      mode = 'exec'; input = ''; return;
    }
    case 's': return doShell();
    case 'u': {
      const p = peerAt(selected);
      if (!p) return say('no peer selected');
      if (!hasOp(p, 'update')) return say('peer does not implement update');
      mode = 'update'; input = ''; return;
    }
    case 'x': {
      /* Stop whatever the selected peer is running, and say whether there
         was anything. The killed command's own result still arrives on its own
         line in the output pane, with rc=124. */
      const p = peerAt(selected);
      if (!p) return say('no peer selected');
      if (!hasOp(p, 'cancel')) return say('peer does not implement cancel');
      request({ type: 'cancel', to: p.id }, 10000).then((m) => {
        if (!m) return;
        say(m.rc === 0 ? 'cancelled the running command' : 'nothing was running');
        render();
      });
      return;
    }
    case 'z': {
      if (!peerAt(selected)) return say('no peer selected');
      mode = 'sleep'; input = ''; return;
    }
    case 'r': return say('the roster is pushed on every enrol and reconnect');
    case 'q': case '\x03': return quit();
    default: return;
  }
}

function onKey(buf) {
  if (mode === 'shell' && session) {
    /* In a shell every byte is content, including Ctrl-C: it interrupts the
       remote process, which is the entire point of having a real pty. */
    if (buf.length === 1 && buf[0] === 0x1d) return detach();   // Ctrl-]
    try {
      sendNow({ type: 'term-input', to: peerAt(selected).id, id: session.id,
                data: Buffer.from(buf).toString('base64') });
    } catch { detach(); }
    return;
  }
  /* Keystrokes typed while an async op is in flight belong to nobody. Drop
     them rather than let them land in the mode the handler is about to enter. */
  if (mode === 'busy') return;
  for (const b of buf) handleByte(b);
  render();
}

function quit() {
  showCur();
  alt(false);
  process.stdin.setRawMode(false);
  process.stdin.pause();
  try { sock && sock.close(); } catch { /* already gone */ }
  process.exit(0);
}

/* --------------------------------- boot --------------------------------- */

const preselect = (() => {
  const i = process.argv.indexOf('--peer');
  if (i > 0 && process.argv[i + 1]) return process.argv[i + 1];
  return null;
})();

process.on('SIGINT', () => { if (mode === 'list') quit(); });
process.on('SIGTERM', quit);
process.stdout.on('resize', render);

alt(true);
hideCur();
process.stdin.setRawMode(true);
process.stdin.resume();
process.stdin.on('data', onKey);
process.on('exit', () => { try { showCur(); alt(false); } catch { /* nothing to restore */ } });

connect();
if (preselect) say(`select a peer with 1-9 (wanted "${preselect}")`);
render();

/* The roster is pushed by the server on every change, so there is no poll here.
   This interval exists only to age the "last seen" column and to notice that
   the socket died without a close event. */
setInterval(render, 1000).unref?.();
setInterval(() => {
  if (sock && sock.readyState !== 1 && !connected) connect();
}, 5000).unref?.();
