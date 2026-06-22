# RedShark Python Bridge

The Python bridge is a managed Flask sidecar that exposes **deepteam** (LLM red-teaming)
and **redteam-ai-benchmark** (AI safety benchmark) to the Go TUI agent.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  redshark (Go Bubble Tea TUI)                    │
│                                                  │
│  ┌────────────────┐   ┌─────────────────────┐   │
│  │ Registry (Go)  │◄──│ deepteam tool       │   │
│  │ 21 tools total │   │ benchmark tool      │   │
│  └───────▲────────┘   │ guardrails tool     │   │
│          │            └──────────▲──────────┘   │
│          │ HTTP JSON           │                │
│ ─────────┴────────────────────┼────────────────│
│                               │                 │
│  internal/pybridge/           │ 127.0.0.1:PORT  │
│  • Bridge.Start()             │                 │
│  • Bridge.PostJSON()          ▼                 │
│  • Bridge.GetJSON()  ┌─────────────────────┐   │
│                      │ pybridge/server.py  │   │
│                      │ Flask + deepteam   │   │
│                      │ + benchmark runner  │   │
│                      └─────────────────────┘   │
│                                │                │
│                        pybridge/.venv/          │
│                        deepteam 1.0.6          │
└──────────────────────────────────────────────────┘
```

## Quickstart

```bash
cd ~/redshark

# Python environment is auto-created on install
python3 -m venv pybridge/.venv
source pybridge/.venv/bin/activate
pip install deepteam flask

# Start the Go TUI — bridge auto-starts in background
go build -o redshark ./cmd/redshark
./redshark
```

## Endpoints

| Route | Method | Purpose |
|-------|--------|---------|
| `/health` | GET | Liveness check |
| `/vulnerabilities` | GET | List 37 deepteam vulnerability types |
| `/attacks` | GET | List 28 deepteam attack types |
| `/redteam` | POST | Run `deepteam.red_team()` assessment |
| `/benchmark` | POST | Run benchmark questions against a model |
| `/guardrails` | POST | Run deepteam guardrails check |

## Go API

```go
import "github.com/xanstomper/redteam-agent/internal/pybridge"

bridge := &pybridge.Bridge{}
if err := bridge.Start(ctx); err == nil {
    defer bridge.Stop()
    reg := tools.RegistryWithBridge(deps, bridge)
    // reg includes deepteam, benchmark, guardrails tools
}
```

## Failure modes

- **Python not installed** → bridge fails to start, agent logs warning, falls back to 18 Go-only tools
- **deepteam import error** → `/redteam` returns `{status:"error", error:"..."}` with Python traceback in JSON
- **Bridge crashes after start** → not currently auto-restarted (planned); agent controller can reconnect on next tool call
- **Port conflict** → `findFreePort()` retries with `127.0.0.1:0` binding, so collisions are impossible

## Source repos

- https://github.com/confident-ai/deepteam (MIT)
- https://github.com/toxy4ny/redteam-ai-benchmark (MIT)
- https://github.com/requie/AI-Red-Teaming-Guide (templates only; MIT)
