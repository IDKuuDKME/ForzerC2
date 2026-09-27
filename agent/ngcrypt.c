/* ngcrypt.c - see ngcrypt.h. Windows CNG only; no crypto is implemented here.
 *
 * Everything resolves through GetProcAddress, so this file adds no link-time
 * dependency on bcrypt.lib. If a name below is mistyped the module fails to
 * load and ng_available() reports it, rather than the agent dying at import.
 */
#define WIN32_LEAN_AND_MEAN
/* ngcrypt.c - Windows CNG (BCrypt) primitives for the implant handshake.
 *
 * Deliberately narrow: HMAC-SHA256 and a CSPRNG, and nothing else. There is no
 * asymmetric cryptography here, and that is a considered decision rather than a
 * simplification. The handshake used to run ECDH P-256 with the identity
 * persisted as a CNG private blob, which requires re-importing that blob on
 * every start. On this host CNG will export an ECC blob and then refuse to
 * accept it back: BCryptImportKey and BCryptImportKeyPair both answer
 * STATUS_NOT_SUPPORTED for private and public blobs alike, across every blob
 * type name and both documented arities, and the KSP in ncrypt.dll answers
 * NTE_NOT_SUPPORTED for the same blob. Generation and export work; import
 * never does. A pre-shared HMAC secret removes the dependency entirely.
 *
 * bcrypt.dll is loaded at runtime and every entry point is resolved through
 * GetProcAddress, so the agent gains no static import on bcrypt.dll.
 *
 * Do not include <bcrypt.h> for the CNG prototypes. The copy shipped with
 * w64devkit declares BCryptGenerateKeyPair with four parameters instead of
 * eight and BCryptImportKeyPair shifted by one, with an out-pointer in the
 * blob-name slot. The typedefs below are the real MS signatures. */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ngcrypt.h"

/* CNG status codes we test for. The rest are treated as failure. */
#define STATUS_SUCCESS            ((LONG)0x00000000L)
#define STATUS_BUFFER_TOO_SMALL   ((LONG)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((LONG)0xC0000034L)
/* winnt.h defines this one, and defines it as a DWORD, so an unguarded
   copy here is a redefinition warning on a full SDK and a type mismatch
   everywhere. */
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER  ((LONG)0xC000000DL)
#endif

/* ------------------------------------------------------------------ */
/* Compatibility shims                                                 */
/*                                                                    */
/* w64devkit ships a deliberately trimmed <bcrypt.h>. SHA-2, the    */
/* random provider and the ECCK EY_BLOB struct are all present;    */
/* the ECDSA/ECDH algorithm names, the curve name and the private  */
/* magic are not, and without them nothing in this file compiles.  */
/* Each is a fixed documented Windows constant, not a derived     */
/* value, and every one is guarded so a full Windows SDK keeps     */
/* using its own declarations.                                      */
/* ------------------------------------------------------------------ */
#ifndef BCRYPT_ECDSA_ALGORITHM
#define BCRYPT_ECDSA_ALGORITHM           L"ECDSA_P256"
#endif
#ifndef BCRYPT_ECDH_ALGORITHM
#define BCRYPT_ECDH_ALGORITHM            L"ECDH_P256"
#endif
#ifndef BCRYPT_ECDH_P256_CURVE
#define BCRYPT_ECDH_P256_CURVE           L"ECDH_P256"
#endif
#ifndef BCRYPT_ECDSA_PRIVATE_P256_MAGIC
#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC  0x32504345   /* 'ECP2' */
#endif
#ifndef BCRYPT_ECDSA_PUBLIC_P256_MAGIC
#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC   0x31504345   /* 'ECP1' */
#endif

/* Blob type names, passed to ExportKey/ImportKey as LPCWSTR. */
/* CNG names the blob layouts by magic string, and the value of the macro is
   NOT the macro's own name — BCRYPT_ECCPUBLIC_BLOB expands to "ECCPUBLICBLOB",
   with no BCRYPT_ prefix. Passing "BCRYPT_ECCPUBLIC_BLOB" instead is not a
   compile error, it is STATUS_NOT_SUPPORTED at run time. */
#define NG_BLOB_PUBLIC   L"ECCPUBLICBLOB"
#define NG_BLOB_PRIVATE  L"ECCPRIVATEBLOB"

/* The blobs CNG actually hands back for P-256 carry the ECS1/ECS2 magics
   (BCRYPT_ECDSA_{PUBLIC,PRIVATE}_P256_BLOB), not the generic ECP1/ECP2 pair
   that NG_BLOB_* above names. Importing an ECS2 blob while declaring it ECP2
   is the mismatch that made every import fail. */
#define NG_BLOB_PUB_P256   L"BCRYPT_ECDSA_PUBLIC_P256_BLOB"
#define NG_BLOB_PRIV_P256  L"BCRYPT_ECDSA_PRIVATE_P256_BLOB"

/* ------------------------------------------------------------------ */
/* CNG entry points                                                    */
/*                                                                    */
/* These mirror the documented prototypes exactly, in order. They   */
/* are not guesses: a mismatch in arity or in which slot a pointer */
/* lands changes the call the compiler emits, and the failure then */
/* shows up as an opaque STATUS_INVALID_PARAMETER at runtime.        */
/* ------------------------------------------------------------------ */
typedef LONG (WINAPI *fn_open)(void **, LPCWSTR, LPCWSTR, ULONG);
typedef LONG (WINAPI *fn_close)(void *);
typedef LONG (WINAPI *fn_createhash)(void *, void **, PUCHAR, DWORD, PUCHAR, DWORD, ULONG);
typedef LONG (WINAPI *fn_getprop)(void *, LPCWSTR, PUCHAR, DWORD, ULONG *, ULONG);
typedef LONG (WINAPI *fn_hashdata)(void *, PUCHAR, DWORD, ULONG);
typedef LONG (WINAPI *fn_finishhash)(void *, PUCHAR, DWORD, ULONG);
typedef LONG (WINAPI *fn_destroyhash)(void *);
typedef LONG (WINAPI *fn_genrandom)(void *, PUCHAR, ULONG, ULONG);

static struct {
    int tried;
    int ok;
    fn_open            OpenAlgorithmProvider;
    fn_close           CloseAlgorithmProvider;
    fn_createhash      CreateHash;
    fn_getprop         GetProperty;
    fn_hashdata        HashData;
    fn_finishhash      FinishHash;
    fn_destroyhash     DestroyHash;
    fn_genrandom       GenRandom;
} api;

static int resolve(void *mod, const char *name, void *slot, int required) {
    FARPROC p = GetProcAddress(mod, name);
    if (!p) {
        if (required) {
            fprintf(stderr, "ngcrypt: bcrypt.dll is missing %s\n", name);
        }
        return 0;
    }
    memcpy(slot, &p, sizeof(p));
    return 1;
}

static int load(void) {
    HMODULE mod;
    if (api.tried) return api.ok;
    api.tried = 1;

    mod = LoadLibraryA("bcrypt.dll");
    if (!mod) { /* fall back to the already-loaded image, if any */
        mod = GetModuleHandleA("bcrypt.dll");
        if (!mod) { fprintf(stderr, "ngcrypt: cannot load bcrypt.dll (%lu)\n", GetLastError()); return 0; }
    }

#define REQ(field, name) \
    if (!resolve(mod, name, &api.field, 1)) { api.ok = 0; return 0; }
    REQ(OpenAlgorithmProvider, "BCryptOpenAlgorithmProvider")
    REQ(CloseAlgorithmProvider, "BCryptCloseAlgorithmProvider")
    REQ(CreateHash,          "BCryptCreateHash")
    REQ(GetProperty,         "BCryptGetProperty")
    REQ(HashData,            "BCryptHashData")
    REQ(FinishHash,          "BCryptFinishHash")
    REQ(DestroyHash,         "BCryptDestroyHash")
    REQ(GenRandom,           "BCryptGenRandom")
#undef REQ
    api.ok = 1;
    return 1;
}

int ng_available(void) { return load(); }

int ng_hmac(const BYTE *key, DWORD key_len, const BYTE *msg, DWORD msg_len, BYTE *out) {
    void *alg = NULL, *hash = NULL;
    /* The HMAC-mode hash object is 422 bytes on this host, measured with
       GetProperty — NOT BCRYPT_SHA256_OBJECT_SIZE (92), which is the plain
       hash object and is what most examples assume. Under-allocating gives
       STATUS_BUFFER_TOO_SMALL from CreateHash and a silently wrong result from
       every call after it. So ask, and keep a generous fixed buffer for the
       case where the property is unavailable. */
    BYTE obj[1024];
    DWORD obj_len = (DWORD)sizeof(obj), written = 0, cb = 0;
    int ok = 0;

    if (!load()) return 0;
    if (api.OpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                  BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS) return 0;

    if (api.GetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&written,
                        sizeof(written), &cb, 0) == STATUS_SUCCESS &&
        written > 0 && written <= sizeof(obj)) {
        obj_len = written;
    }

    /* The HMAC key goes in through pbSecret at CreateHash time. Hashing it as
       part of the message instead produces an HMAC under an EMPTY key — a
       valid-looking 32 bytes that is simply wrong, and which the selftest
       against OpenSSL is what caught. */
    if (api.CreateHash(alg, &hash, obj, obj_len, (PUCHAR)key, key_len, 0) != STATUS_SUCCESS) goto done;
    if (api.HashData(hash, (PUCHAR)msg, msg_len, 0) != STATUS_SUCCESS) goto done;
    if (api.FinishHash(hash, out, NG_PROOF_BYTES, 0) != STATUS_SUCCESS) goto done;
    ok = 1;

done:
    if (hash) api.DestroyHash(hash);
    if (alg) api.CloseAlgorithmProvider(alg);
    return ok;
}

int ng_proof(const BYTE *secret, const char *label, const BYTE *nonce,
             DWORD nonce_len, BYTE *out) {
    /* HMAC over label || nonce. The label is length-prefixed by nothing: it is a
       fixed compile-time string, so there is no ambiguity about where it ends
       and the nonce begins, and the server concatenates the same way. */
    DWORD label_len = (DWORD)strlen(label);
    BYTE buf[64];
    if (label_len + nonce_len > sizeof(buf)) return 0;
    memcpy(buf, label, label_len);
    memcpy(buf + label_len, nonce, nonce_len);
    return ng_hmac(secret, NG_SECRET_BYTES, buf, label_len + nonce_len, out);
}

int ng_equal(const BYTE *a, const BYTE *b, DWORD n) {
    volatile BYTE diff = 0;
    DWORD i;
    for (i = 0; i < n; i++) diff |= (BYTE)(a[i] ^ b[i]);
    return diff == 0;
}

int ng_random(BYTE *buf, DWORD n) {
    if (!load()) return 0;
    return api.GenRandom(NULL, buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Known-answer test                                                    */
/* ------------------------------------------------------------------ */
static const BYTE VEC_NONCE[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};
static const BYTE VEC_SECRET[NG_SECRET_BYTES] = {
    0xCC,0xFC,0x26,0x1F,0x58,0x19,0x3C,0x98,0xCA,0x4A,0xD4,0xA5,0x3B,0xBA,0xC6,0xF0,
    0xEE,0x29,0xBC,0x4D,0x48,0x43,0x80,0x90,0x44,0x69,0x08,0x62,0x2C,0xA7,0x9A,0xF6
};
static const BYTE VEC_CLIENT[NG_PROOF_BYTES] = {
    0x7A,0xC1,0xF0,0xA9,0xDA,0xD7,0x96,0xBB,0x90,0xC2,0x78,0x91,0xB5,0x03,0xA8,0x1A,
    0xD5,0x39,0xC7,0xBB,0x93,0xB9,0x46,0x7C,0x17,0xAB,0x9D,0x1B,0x1C,0x27,0xF3,0x62
};
static const BYTE VEC_SERVER[NG_PROOF_BYTES] = {
    0xEB,0xDA,0x8C,0xD3,0x2B,0x3C,0x20,0xFB,0x87,0x2D,0x2F,0xEA,0x05,0xA6,0x11,0xF9,
    0x06,0xAB,0x5A,0x8E,0x1C,0x0B,0xD5,0xE1,0x99,0x5C,0x79,0xA0,0x3C,0x9D,0x80,0xDC
};

static void hexdump(const char *label, const BYTE *b, DWORD n) {
    DWORD i;
    fprintf(stderr, "  %s ", label);
    for (i = 0; i < n; i++) fprintf(stderr, "%02X", b[i]);
    fprintf(stderr, "\n");
}


/* ------------------------------------------------------------------ */
/* Known-answer test                                                    */
/* ------------------------------------------------------------------ */
/* VEC_CLIENT and VEC_SERVER are HMAC-SHA256 over (label || nonce) keyed by
 * VEC_SECRET, produced independently with Node's crypto. They used to be
 * reached only after a successful ECDH, so a broken HMAC path was never
 * exercised: the selftest returned at the first ECDH failure every time.
 * These are now checked directly, which is the only reason the handshake
 * primitives are known to work on this host at all. */
int ng_selftest(void) {
    BYTE client[NG_PROOF_BYTES], server[NG_PROOF_BYTES];
    int fails = 0;

    if (!load()) { fprintf(stderr, "ngcrypt selftest: bcrypt.dll unavailable\n"); return 0; }

    if (!ng_proof(VEC_SECRET, NG_LABEL_CLIENT, VEC_NONCE, sizeof(VEC_NONCE), client)) {
        fprintf(stderr, "ngcrypt selftest: client HMAC failed\n");
        return 0;
    }
    if (!ng_equal(client, VEC_CLIENT, NG_PROOF_BYTES)) {
        fprintf(stderr, "ngcrypt selftest: FAIL client proof mismatch\n");
        hexdump("got     ", client, NG_PROOF_BYTES);
        hexdump("expected", VEC_CLIENT, NG_PROOF_BYTES);
        fails++;
    }

    if (!ng_proof(VEC_SECRET, NG_LABEL_SERVER, VEC_NONCE, sizeof(VEC_NONCE), server)) {
        fprintf(stderr, "ngcrypt selftest: server HMAC failed\n");
        return 0;
    }
    if (!ng_equal(server, VEC_SERVER, NG_PROOF_BYTES)) {
        fprintf(stderr, "ngcrypt selftest: FAIL server proof mismatch\n");
        hexdump("got     ", server, NG_PROOF_BYTES);
        hexdump("expected", VEC_SERVER, NG_PROOF_BYTES);
        fails++;
    }

    /* The labels must not collapse into each other, or a client proof would be
       replayable as a server proof. */
    if (ng_equal(client, server, NG_PROOF_BYTES)) {
        fprintf(stderr, "ngcrypt selftest: FAIL client and server proofs are identical\n");
        fails++;
    }

    /* ng_equal has to actually be constant-time in the sense that matters:
       a single flipped bit must change the answer. */
    if (!ng_equal(client, VEC_CLIENT, NG_PROOF_BYTES)) {
        fprintf(stderr, "ngcrypt selftest: FAIL ng_equal rejected a match\n");
        fails++;
    }
    client[0] ^= 1;
    if (ng_equal(client, VEC_CLIENT, NG_PROOF_BYTES)) {
        fprintf(stderr, "ngcrypt selftest: FAIL ng_equal accepted a 1-bit difference\n");
        fails++;
    }

    if (fails) return 0;
    printf("ngcrypt selftest: OK (HMAC-SHA256 matches OpenSSL; labels separated)\n");
    return 1;
}
