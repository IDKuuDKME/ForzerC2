'use strict';

/*
 * ops.test.js - the op catalog.
 *
 * These cover the failure modes the old hand-written routing could not
 * express. Before the catalog, an unknown verb and a verb the target could
 * not service both fell through the same catch-all and both looked identical
 * from the operator's side: nothing at all.
 */

const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ops = require('../ops');
const catalog = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'shared', 'ops.json'), 'utf8'),
);

/* ------------------------------ the catalog ----------------------------- */

test('the catalog loads and validates', () => {
  assert.ok(Array.isArray(ops.list()));
  assert.ok(ops.list().length > 0);
  assert.ok(Number.isInteger(ops.protocol()));
});

test('every op names a capability the catalog defines', () => {
  for (const op of ops.list()) {
    assert.ok(catalog.capabilities[op.cap],
      `op ${op.name} wants cap ${op.cap}, which is not defined`);
  }
});

test('every string op declares a bound on its argument', () => {
  for (const op of ops.list()) {
    if (op.args !== 'string') continue;
    assert.ok(Number.isInteger(op.maxArg) && op.maxArg > 0,
      `op ${op.name} takes a string but has no maxArg`);
  }
});

test('no wire type is both request and reply unless it says so', () => {
  for (const r of catalog.implantOriginated || []) {
    const owner = ops.byType(r.type);
    if (owner) {
      assert.strictEqual(owner.alsoReply, true,
        `${r.type} appears in both directions without alsoReply`);
    }
  }
});

test('every reply answers an op that exists', () => {
  for (const r of catalog.implantOriginated || []) {
    assert.ok(ops.byType(r.answers), `${r.type} answers unknown op ${r.answers}`);
  }
});

test('an implant cannot originate an op the catalog lists as request-only', () => {
  /* The whole point of the reply list: it is the complete set of things a box
     may say. `command` must not be in it, or one compromised box drives the
     fleet. */
  const replies = new Set((catalog.implantOriginated || []).map((r) => r.type));
  for (const forbidden of ['command', 'term-start', 'term-input', 'sleep', 'update']) {
    assert.ok(!replies.has(forbidden), `${forbidden} must not be implant-originated`);
  }
});

/* ------------------------------- resolution ------------------------------ */

test('a known op resolves', () => {
  const r = ops.requireOp('command', ['exec']);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.op.name, 'exec');
});

test('an unknown op says so, and lists what is available', () => {
  const r = ops.requireOp('exfiltrate', []);
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /unknown op "exfiltrate"/);
  for (const op of ops.list()) {
    assert.ok(r.error.includes(op.name), `error should mention ${op.name}`);
  }
});

test('an op the peer does not implement says which one, not "unknown"', () => {
  /* The distinction that matters: the client spelled it right, the box is
     just old. Collapsing these two is what made the old catch-all useless. */
  const r = ops.requireOp('command', ['sleep']);
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /not supported by this implant/);
  assert.doesNotMatch(r.error, /unknown op/);
});

test('an empty advertised set does not block resolution', () => {
  /* An implant that predates the advertisement field has told us nothing. That
     is not the same as telling us it supports nothing, and refusing every op
     would strand the whole fleet on an old build. */
  const r = ops.requireOp('command', []);
  assert.strictEqual(r.ok, true);
});

test('the catalog rejects a duplicate wire type', () => {
  /* Guard the loader itself: this is the check that makes the file a single
     source of truth rather than a suggestion. */
  const src = fs.readFileSync(path.join(__dirname, '..', 'ops.js'), 'utf8');
  assert.match(src, /duplicate wire type/);
  assert.match(src, /missing a positive integer "protocol"/);
});

/* ------------------------- agent / catalog drift ------------------------- */

test('the agent binary advertises exactly the catalog\'s executable ops', (t) => {
  /* The join key between the C table and the JSON is the wire verb, and
     nothing at build time checks the two agree. This is what catches it: a
     verb added to the agent but not the catalog would otherwise be offered to
     clients and refused at request time, forever, with a plausible error.

     It runs `--ops-out` rather than `--ops`, and that is the whole reason this
     test is not skipped. The release build is -mwindows: it has no bound
     stdout, so `--ops` prints nothing and still exits 0. This test used to
     read stdout, conclude the build was windowless, and skip — on every run,
     silently, forever. A guard that never executes is not coverage, it is the
     appearance of coverage, which is worse. The file form gives the same
     answer in both subsystem modes, so a binary too old to support it now
     fails the suite instead of quietly stepping aside. */
  const dir = path.join(__dirname, '..', '..', 'agent');
  const expected = ops.list().filter((o) => o.executable).map((o) => o.name).sort();

  let lastWhy = 'no agent binary found';
  for (const exe of ['Forzer-debug.exe', 'Forzer.exe']) {
    const full = path.join(dir, exe);
    if (!fs.existsSync(full)) continue;
    /* A bare filename plus a child cwd, rather than a path composed here.
       These tests routinely run under a Linux Node on WSL, where anything
       path.join() builds is meaningless to the Windows binary being spawned
       (/mnt/c/... is not a path Windows can open). The cwd is set instead, so
       the argument is a filename both sides spell the same way. */
    const name = `ops-check-${process.pid}.json`;
    const outFile = path.join(dir, name);
    const r = spawnSync(full, ['--ops-out', name],
      { encoding: 'utf8', timeout: 30000, cwd: dir });
    if (r.error) { lastWhy = `${exe}: ${r.error.message}`; continue; }
    if (r.status !== 0) {
      lastWhy = `${exe} --ops-out exited ${r.status} (${(r.stderr || '').trim()})`;
      continue;
    }
    if (!fs.existsSync(outFile)) {
      /* The binary ran and claimed success but wrote nothing. That is the
         windowless build answering a flag it does not know: it printed to an
         unbound stdout and exited 0. */
      return assert.fail(`${exe} ignored --ops-out. It predates the flag — `
        + `rebuild it: cd agent; .\\build.ps1 (and .\\build.ps1 -Debug)`);
    }
    const out = fs.readFileSync(outFile, 'utf8').trim();
    fs.rmSync(outFile, { force: true });
    let parsed;
    try {
      parsed = JSON.parse(out);
    } catch (e) {
      t.diagnostic(`${exe} emitted unparseable JSON: ${out}`);
      t.diagnostic(`This is the bug the test exists for: a malformed frame is`);
      t.diagnostic(`rejected by the server's parse guard as a bare socket close.`);
      return assert.fail(`${exe} --ops-out is not valid JSON: ${out} (${e.message})`);
    }
    assert.deepStrictEqual(parsed.ops.slice().sort(), expected,
      `${exe} advertises ops the catalog does not list, or is missing some`);
    assert.strictEqual(parsed.proto, ops.protocol());
    return;
  }
  t.skip(lastWhy);
});
