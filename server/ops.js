'use strict';

/*
 * ops.js - the op catalog.
 *
 * One JSON file describes every operation an implant can be asked to perform.
 * The routing sets that used to be two hand-maintained constants in server.js
 * are now derived from it, so there is exactly one place where the verb
 * vocabulary is written down.
 *
 * The catalog is validated at load. A malformed entry throws here, at startup,
 * where an operator will see it, instead of becoming a verb that the server
 * silently refuses to relay for the life of the process.
 *
 * Note what the catalog does NOT do: it does not describe what the agent
 * actually implements. That is discovered at runtime, because the agent
 * advertises the ops it compiled in during the handshake. Keeping the two
 * separate is what lets a new op reach a fleet without a server deploy, and
 * what lets `requireOp` say "this peer cannot do that" instead of "unknown
 * verb" when the server is ahead of its implants.
 */

const fs = require('node:fs');
const path = require('node:path');

const CATALOG_PATH = path.join(__dirname, '..', 'shared', 'ops.json');

function fail(msg) {
  throw new Error(`ops catalog: ${msg}`);
}

function loadCatalog() {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));
  } catch (e) {
    fail(`cannot read ${CATALOG_PATH}: ${(e && e.message) || e}`);
  }
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.ops)) {
    fail('missing an "ops" array');
  }
  if (!Number.isInteger(raw.protocol) || raw.protocol < 1) {
    fail('missing a positive integer "protocol"');
  }
  if (!raw.capabilities || typeof raw.capabilities !== 'object') {
    fail('missing a "capabilities" object');
  }

  const byType = new Map();
  const byName = new Map();

  for (const [i, op] of raw.ops.entries()) {
    const at = `ops[${i}]`;
    if (!op || typeof op !== 'object') fail(`${at} is not an object`);
    for (const f of ['type', 'name', 'cap', 'args', 'desc', 'result']) {
      if (typeof op[f] !== 'string' || !op[f]) fail(`${at} is missing "${f}"`);
    }
    if (!['string', 'none', 'number'].includes(op.args)) {
      fail(`${at} (${op.type}) has unknown args kind "${op.args}"`);
    }
    if (!raw.capabilities[op.cap]) {
      fail(`${at} (${op.type}) wants capability "${op.cap}" which the catalog does not define`);
    }
    if (op.alsoReply !== undefined && typeof op.alsoReply !== 'boolean') {
      fail(`${at} (${op.type}) has a non-boolean alsoReply`);
    }
    if (op.args === 'string' && !(Number.isInteger(op.maxArg) && op.maxArg > 0)) {
      fail(`${at} (${op.type}) takes a string arg but has no positive maxArg`);
    }
    if (byType.has(op.type)) fail(`duplicate wire type "${op.type}"`);
    if (byName.has(op.name)) fail(`duplicate op name "${op.name}"`);
    /* A control-plane-side op has no payload: the server builds the frame. */
    op.executable = op.executable === true;
    byType.set(op.type, op);
    byName.set(op.name, op);
  }

  for (const [i, r] of (raw.implantOriginated || []).entries()) {
    for (const f of ['type', 'answers', 'desc']) {
      if (!r || typeof r[f] !== 'string' || !r[f]) {
        fail(`implantOriginated[${i}] is missing "${f}"`);
      }
    }
    if (byType.has(r.type)) {
      /* The one legal overlap is a type that is a request from one side and a
         reply from the other - `term-end`. It has to be declared, because an
         undeclared overlap is exactly how a verb quietly becomes something
         else. */
      const owner = byType.get(r.type);
      if (!owner.alsoReply) {
        fail(`"${r.type}" is both viewer-originated and implant-originated; ` +
          `set "alsoReply": true on the op if that overlap is intended`);
      }
    }
    if (!byType.has(r.answers)) {
      fail(`implantOriginated[${i}] answers "${r.answers}", which is not a known op`);
    }
  }

  return { raw, byType, byName };
}

const { raw: catalog, byType: TYPE_MAP, byName: NAME_MAP } = loadCatalog();

/* Verb sets, derived. A type reaches exactly one of these, and the catalog
   loader refuses to build a catalog where that is not true. */
const VIEWER_ROUTABLE = new Set(catalog.ops.filter((o) => o.executable).map((o) => o.type));
const IMPLANT_ROUTABLE = new Set((catalog.implantOriginated || []).map((r) => r.type));

/* Ops the server executes itself rather than relaying. `update` reads a file
   off disk, hashes it, and emits a second binary frame, so it cannot be a
   dumb relay hop. Keyed off a flag rather than a hardcoded name so adding a
   second server-side op is a catalog edit. */
const SERVER_HANDLED = new Set(
  catalog.ops.filter((o) => o.control_plane_only).map((o) => o.type),
);

/* Note the deliberate naming. The index maps are TYPE_MAP/NAME_MAP, not
   `byType`/`byName`: a `function byType()` would shadow the same name inside
   its own body and the call would become `byType.get(...)` on the function. */
function byType(type) { return TYPE_MAP.get(type) || null; }
function byName(name) { return NAME_MAP.get(name) || null; }
function list() { return catalog.ops.slice(); }
function protocol() { return catalog.protocol; }
function capabilities() { return Object.assign({}, catalog.capabilities); }

/*
 * The error a client gets for a verb that does not exist, or that exists in the
 * catalog but not on this particular peer.
 *
 * The two cases are deliberately distinguishable. "unknown verb" means the
 * client is wrong. "this peer cannot" means the fleet is mixed and the operator
 * picked an old implant. Collapsing them into one generic error is what made
 * the old catch-all so hard to work with: a typo and a version skew looked
 * identical, and both looked like nothing at all.
 */
function unknownOpError(type, opts = {}) {
  const known = list().map((o) => o.name);
  if (opts.peerOps && opts.peerOps.length) {
    const missing = known.filter((n) => !opts.peerOps.includes(n));
    if (missing.length) {
      return `peer does not implement: ${missing.join(', ')} (peer offers ${opts.peerOps.join(', ')})`;
    }
  }
  return `unknown op "${type}"; available: ${known.join(', ')}`;
}

/*
 * Resolve an op for a specific request. Returns {ok:true, op} or {ok:false,
 * error}. The peerOps check is the negotiated half: the catalog says what is
 * possible, the peer's advertised set says what is possible *here*.
 */
function requireOp(type, peerOps) {
  const op = byType(type);
  if (!op) return { ok: false, error: unknownOpError(type, { peerOps }) };
  if (Array.isArray(peerOps) && peerOps.length && !peerOps.includes(op.name)) {
    return { ok: false, error: `peer "${op.name}" not supported by this implant (${op.desc})` };
  }
  return { ok: true, op };
}

module.exports = {
  catalog,
  VIEWER_ROUTABLE,
  IMPLANT_ROUTABLE,
  SERVER_HANDLED,
  byType,
  byName,
  list,
  protocol,
  capabilities,
  requireOp,
  unknownOpError,
};
