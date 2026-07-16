# NotSoSafe

A small peer-to-peer mesh control toolkit with three cooperating parts:

| Component | Path | What it is |
|-----------|------|------------|
| **Agent** | [`agent/`](./agent) | Windows C client (`Forzer.c`) that connects to the control plane over WebSocket (ws / wss via Schannel), runs remote commands and interactive shells. |
| **Control plane** | [`server/`](./server) | Node.js WebSocket server (`server.js`) that registers peers, relays signalling/commands, and serves a web dashboard. Deployable to Render. |
| **MCP server** | [`mcp/`](./mcp) | Zero-dependency Model Context Protocol server exposing the control plane (list peers, run commands, open terminals) over stdio JSON-RPC. |

## Layout

```
NotSoSafe/
├── agent/         # Windows C agent (Forzer.c) + compiled binary (Forzer.exe)
├── server/        # Node.js server.js, public/dashboard.html, render.yaml, package.json
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
# dashboard: http://localhost:3000/dashboard
```

### Agent (Windows, MinGW / MSVC cl)
```bash
cd agent
cl.exe /O2 /GS- Forzer.c ws2_32.lib advapi32.lib crypt32.lib secur32.lib urlmon.lib /Fe:Forzer.exe
FORZER_SERVER=ws://127.0.0.1:3000 FORZER_SETUP_KEY=changeme Forzer.exe
```

### MCP server
```bash
cd mcp
npm install
FORZER_SERVER=ws://127.0.0.1:3000 FORZER_MCP_USER=Forgot FORZER_MCP_PASS=HelloWorld1! node mcp-server.js
```

## Security note

This is an early-stage research/MVP build. The control plane keeps all peer state in memory
(no persistence), and the default setup key / dashboard credentials are placeholders — **override
them via environment variables before exposing anything to a network.**
