# RedShark

> **Brand**: RedShark
> **Repo name**: `xanstomper/redshark`
> **Module path (technical, immutable)**: `github.com/xanstomper/redteam-agent`
> **Binary name**: `redshark`
> **Status**: scaffold v0.1.0 — compiles, runs, refuses protected targets.

RedShark is an operator-first offensive-security TUI agent. Built on Bubble
Tea v2. Inspired by Charm's Crush layout.

> ⚠️ **Why does the module path differ from the repo name?**
> The repo is **`xanstomper/redshark`** (the user-facing brand & directory).
> The Go module path is kept as `github.com/xanstomper/redteam-agent` —
> this is the import path already used by every internal package. Renaming
> the module requires rewriting every `import` line and is **not** part of
> this build. The build, the binary name (`redshark`), every CLI flag, every
> user-facing string, and the directory name (`cmd/redshark/`) all reflect
> the chosen `redshark` repo name.

> ⏸️ **STOP — not pushed to GitHub.** This scaffold lives in
> `/home/jewboy420/redteam-agent/`. The repo creation, first commit, and
> push require explicit operator approval and are **not** auto-executed.
> The assistant will not run `git init` or `gh repo create` without your OK.

---

## Build & run

```sh
go build -o redshark ./cmd/redshark
./redshark                                    # interactive TUI
./redshark --scope ./examples/scope-pentest.json
./redshark --version                          # → RedShark 0.1.0-scaffold ...
```

Build-time metadata:

```sh
go build -trimpath \
  -ldflags "-X github.com/xanstomper/redteam-agent/internal/version.Version=v0.1.0 \
            -X github.com/xanstomper/redteam-agent/internal/version.Commit=$(git rev-parse --short HEAD) \
            -X github.com/xanstomper/redteam-agent/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o redshark ./cmd/redshark
```

### Test the safety contract

```sh
go test ./...
```

`internal/scope/scope_test.go` and `internal/agent/tools/safety_test.go`
together assert that RedShark:

- refuses `fbi.gov`, `army.mil`, `bnd.bund.de`, `nato.int`, `defense.gov.cn`
  regardless of any loaded scope;
- rejects every active tool when no scope is loaded;
- rejects every active tool when the scope is expired;
- catches agency keywords (`mi6`, `mossad`, `csis`, `dgse`, `nato`, `bnd`)
  even when the TLD does not look government-y;
- runs the protected-target check **before** the scope-loaded check, so a
  permissive or empty scope cannot authorize a protected target.

All tests pass on `go test ./...`. The safety contract is real and tested,
not aspirational.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ TUI (Bubble Tea v2) → operator types here                        │
│     ↓ message                                                     │
│ Coordinator                                                       │
│     ↓ tools.Tool list                                             │
│ preflightOrDryrun(scope, technique, args) → wet API call         │
│     ↓                                                             │
│ 4-gate chain in scope.Authorize(target, technique):              │
│   1. protected? (HARD-CODED — never bypassable)                  │
│   2. scope loaded? (otherwise refuse "no-scope")                 │
│   3. scope fresh? (otherwise refuse "stale")                     │
│   4. target in network? technique on allow-list?                 │
│     ↓ on pass                                                     │
│ os/exec → nmap / masscan / ... shell-out                         │
│     ↓ on success                                                  │
│ evidence.Record(...) → ./evidence-*/chain.jsonl (sha256 hash)    │
└──────────────────────────────────────────────────────────────────┘
```

### Modules

| package | what it owns |
|---------|-------------|
| `internal/scope` | Scope document, gate chain, protected-target lists. The single most important file in RedShark. |
| `internal/evidence` | Append-only hash-chained artifact collector. Each tool's stdout is sha256'd into a `chain.jsonl` file. |
| `internal/agent/tools` | 10 tools: nmap, masscan, httpx, ffuf, nuclei, sqlmap, hydra, c2-profile, report, scope_check. Each calls `preflightOrDryrun` first. |
| `internal/agent/prompts` | System prompts and refusal language. The default agent persona is "RedShark Agent — credentialed red-team operator". |
| `internal/agent/stubprovider` | Echo-back provider so the agent can run without an external API key during skeleton development. |
| `internal/ui/{logo,model}` | Bubble Tea v2 TUI chrome — same shape as Charm Crush (header / chat / input). Header reads **⚡ RedShark**. |
| `internal/msg` | Message types that flow between agent, tools, and TUI. |
| `internal/redact` | Output sanitization (API-key, JWT, session-token stripping) before prompts go back to the model. |
| `internal/version` | Build metadata. Brand constant: `RedShark`. User-facing `--version` shows `RedShark 0.1.0-scaffold`. |

---

## The safety contract in detail

### Hardcoded protected targets

A target that matches any of these is refused with `layer=protected`,
**regardless of what scope is loaded**. The list lives in
`internal/scope/scope.go` and is the single configurable knob in the refusal
layer — but it requires a code change to alter:

- `.gov`, `.mil`, `.int`, plus country variants (`.gov.uk`, `.gov.au`,
  `.gov.ca`, `.gov.cn`, `.gouv.fr`, `.gob.es`, `.bund.de`, `.gc.ca`)
- keywords: `fbi`, `cia`, `nsa`, `dhs`, `dea`, `interpol`, `mi6`, `mi5`,
  `gchq`, `mossad`, `fsb`, `dgse`, `dgsi`, `bnd`, `csis`, `asis`, `nato`,
  `csirt`, `finfisher`

A keyword match inside a hostname fires regardless of the TLD (defence in
depth): `mi6.internal.lan` is refused.

### The four-gate scope chain

1. **Protected** — hardcoded refusal above. Runs first so even an empty
   scope can't authorize an attack on `.gov` / `.mil`.
2. **Loaded** — if `scope.Load()` was never called, refuse.
3. **Fresh** — if `scope.Expires < now`, refuse (`layer=stale`).
4. **In-network + technique** — target must satisfy `scope.Matches(target)`
   AND `technique` must appear in `scope.Techniques`.

Any failed gate returns a structured `Decision{Layer, Reason}`; all tools
draft their refusal copy from this struct rather than making it up.

### Dryrun-only mode

Any active tool accepts `"dryrun": true` in args and short-circuits after
the gate succeeds, emitting a `would run:` line. This is what the safety
test suite uses to exercise the gate without needing nmap/masscan/hydra
installed. To run live, the operator opens a real scope and omits `dryrun`.

### Mandatory operator confirmation

Destructive tools (`hydra` today, future: `c2-profile`, sensitive
reporting) look for `"confirmed": true` in args.

### Evidence chain

Every successful (or refusal-flagged) tool result is appended to
`./evidence-<scope-id>/chain.jsonl`. Each entry is JSON-encoded with:

```json
{
  "id":         "0000001",
  "ts":         "2026-06-21T20:30:00Z",
  "tool":       "nmap",
  "technique":  "scanning",
  "target":     "example.com",
  "category":   "scan",
  "tags":       [],
  "payload_sha256": "ab12...",
  "prev_hash":  "000000000000..."
}
```

The chain starts at a genesis hash of `sha256("RedShark:genesis")` and each
row's `prev_hash` is the prior row's hash. Tampering with a row invalidates
every later row.

---

## Status

| Area | Status |
|------|--------|
| Compile, run, banner, splash, /scope, /quit, /version | ✅ done |
| Scope gate + protected-target refusal (verified by tests) | ✅ done |
| Dryrun short-circuit on every active tool | ✅ done |
| 10-tool toolset (nmap, masscan, httpx, ffuf, nuclei, sqlmap, hydra, c2-profile, report, scope_check) | ✅ done — each shells out if `dryrun:false` |
| Evidence hash-chain (`./evidence-*/chain.jsonl`) | ✅ done |
| Bubble Tea v2 TUI (header / chat / input) | ✅ minimal — Crush has richer dropdowns, completions, sessions, file attachments. **This is the biggest gap.** |
| LLM provider integration | ⚠️ stub only — `stubprovider` echoes. Wire `catwalk` provider here for real model use. |
| Sessions SQLite persistence | ❌ not wired (in-memory session today) |
| LSP server, MCP client | ❌ not implemented |
| Skill embedding (`SKILL.md`) | ❌ scaffold dir exists, not yet wired |
| Push to GitHub | ⏸️ **STOPPED.** Repo name chosen: `xanstomper/redshark`. Awaiting explicit go-ahead from operator to run `git init`, first commit, and `gh repo create redshark --public --source=. --push` (or equivalent manual steps). |

---

## Conceptual lineage

RedShark was developed alongside the upstream **Charmbracelet Crush** fork
chain (`/home/jewboy420/redamon/redshark/` in the local checkout).
**No code was copied** from the Charm fork. The architectural patterns
referenced are the public Bubble Tea v2 model interface and the common
TUI layout shape (header / chat / input). Charm attribution and the FSL
clause notes are kept in `THIRD_PARTY.md`.

RedShark does **not** compete with Charm Crush: their audience is software
developers using an AI coding assistant; RedShark is an offensive-security
operator tool. That keeps RedShark within Charm's "Permitted Purpose" clause
for derivatives of the Crush fork.

---

## License

Local code: MIT (see `LICENSE`). Third-party notices: `THIRD_PARTY.md`.

## Out of scope on purpose

These were deliberately not implemented:

- **Persistence or lateral movement** — no auto-escalation, no session-
  to-session state carrying.
- **Stolen-credential automation** — defaults to off; requires explicit
  `confirmed:true` per session.
- **Reporting to a third party** — `report` tool is local-only; remote
  endpoints must be wired in by hand.
- **Targets outside the loaded scope** — every active tool is refused;
  no "I'll just do this small thing for you."
- **Government / military / intelligence target domains** — refused even
  with a permissive scope; the hardcoded list is non-bypassable.
