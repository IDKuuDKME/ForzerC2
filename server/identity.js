'use strict';
/* Implant identity: a 32-byte pre-shared secret, mutually-authenticated check-in.
 *
 * This used to be ECDH P-256. The swap was forced, and the reasoning is worth
 * keeping because it is not obvious from the code:
 *
 *   - The agent could not persist an asymmetric identity. It has to reload its
 *     private key on every start, and on the host this was developed against
 *     CNG will export an ECC blob and then refuse to accept it back —
 *     BCryptImportKey and BCryptImportKeyPair both answer STATUS_NOT_SUPPORTED
 *     for private and public blobs alike, across every blob type name and both
 *     documented arities, and the ncrypt.dll KSP answers NTE_NOT_SUPPORTED for
 *     the same blob. Generation and export work; import never does.
 *   - The ECDH was not buying forward secrecy, because the control plane keeps
 *     its own private key and every implant's public key permanently. Anyone who
 *     compromises the server later can recompute every past session's secret.
 *   - It was not buying server authentication either, which the agent's TLS
 *     certificate pin already provides.
 *   - What it did buy is that a leaked registry yields only public keys. A
 *     secret-key registry means a leak can impersonate every implant. That is a
 *     real cost, and the answer is to protect the database file, not to keep a
 *     primitive the agent cannot actually execute.
 *
 * The secret is used directly as an HMAC-SHA256 key. Both sides prove they hold
 * it on every reconnect, so possession is checked continuously, and the server's
 * proof doubles as the implant's pin on the control plane — there is no
 * trust-on-first-use window and no second write to the agent's identity file.
 *
 * The secret crosses the wire exactly once, at enrolment, over the pinned TLS
 * channel. Everything downstream of that pin rests on the same channel, so the
 * one transmission is bounded by a guarantee the handshake already needed.
 */
const crypto = require('crypto');

const SECRET_LEN = 32;
const NONCE_LEN = 32;
const PROOF_LEN = 32;

/* Domain separation. Without distinct labels a client proof is a valid server
   proof and the handshake degenerates into reflection. */
const CLIENT_LABEL = Buffer.from('forzer/client/v1', 'utf8');
const SERVER_LABEL = Buffer.from('forzer/server/v1', 'utf8');
const ID_LABEL = Buffer.from('forzer/implant-id/v1', 'utf8');

/* The implant id is a function of the enrolled secret, so it is stable for the
   life of that secret and unguessable without it. 16 hex chars (64 bits) is
   enough to be unguessable inside a mesh and short enough to type. The label
   keeps the id from colliding with any other hash of the same secret. */
function implantId(secret) {
  return crypto.createHash('sha256')
    .update(ID_LABEL)
    .update(secret)
    .digest('hex')
    .slice(0, 16);
}

/* Parse and validate a wire secret. A malformed one is rejected here rather
   than reaching the HMAC, where it would surface as a silent auth failure.
   Buffer.from is lenient about base64, so check the round trip rather than
   trusting the decode: a value that does not re-encode to the same string was
   not the canonical encoding, and canonical form is what the agent emits. */
function parseSecret(b64) {
  if (typeof b64 !== 'string' || b64.length === 0 || b64.length > 128) return null;
  let secret;
  try {
    secret = Buffer.from(b64, 'base64');
  } catch {
    return null;
  }
  if (secret.length !== SECRET_LEN) return null;
  if (secret.toString('base64') !== b64) return null;
  return secret;
}

function proof(secret, label, nonce) {
  return crypto.createHmac('sha256', secret).update(label).update(nonce).digest();
}

const clientProof = (secret, nonce) => proof(secret, CLIENT_LABEL, nonce);
const serverProof = (secret, nonce) => proof(secret, SERVER_LABEL, nonce);

function newNonce() {
  return crypto.randomBytes(NONCE_LEN);
}

/* Constant-time proof check. `timingSafeEqual` throws on a length mismatch, so
   the length is validated first — a wrong-length proof is a failed proof, and
   rejecting it early leaks nothing an attacker could not learn from a wrong
   value of the right length. */
function checkProof(expected, given) {
  if (!Buffer.isBuffer(given) || given.length !== PROOF_LEN) return false;
  return crypto.timingSafeEqual(expected, given);
}

module.exports = {
  SECRET_LEN,
  NONCE_LEN,
  PROOF_LEN,
  implantId,
  parseSecret,
  clientProof,
  serverProof,
  newNonce,
  checkProof,
};
