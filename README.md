<p align="center">
  <img src="https://img.shields.io/badge/binary-redshark-red?style=flat-square" alt="binary">
  <img src="https://img.shields.io/badge/go-1.26.4-00ADD8?style=flat-square" alt="go">
  <img src="https://img.shields.io/badge/TUI-Bubble%20Tea%20v2-FF69B4?style=flat-square" alt="bubbletea">
  <img src="https://img.shields.io/badge/scope-4%20gate%20chain-green?style=flat-square" alt="scope">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="license">
</p>

<h1 align="center">
  <pre>
  ██████╗ ███████╗███████╗ ██████╗███████╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝█████╗  ███████╗██║     █████╗  █████╔╝
  ██╔══██╗██╔══╝  ╚════██║██║     ██╔══╝  ██╔═██╗
  ██║  ██║███████╗███████║╚██████╗███████╗██║  ██╗
  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝</pre>
  <h3 align="center">Operator-First Offensive Security TUI Agent</h3>
</h1>

---

## What is RedShark?

RedShark is a terminal-based red-team operator agent with a **hardcoded refusal
layer** — it will never attack government, military, or intelligence targets,
no matter what scope you load. Every active tool passes through a **four-gate
scope chain** before execution, and every result is written to a **tamper-evident
hash chain** for evidence integrity.

Built on [Bubble Tea v2](https://github.com/charmbracelet/bubbletea) with a
layout inspired by [Charm Crush](https://github.com/charmbracelet/crush).
The TUI opens with a braille-art shark splash, presents a bordered chat pane,
keybind footer, and scope-aware input bar.

### Key principles

| Principle | How it's enforced |
|-----------|-------------------|
| **Protected targets are non-negotiable** | `.gov`, `.mil`, `.int` TLDs + agency keywords are hardcoded in `internal/scope/scope.go`. No scope override, no CLI flag, no API call can bypass this. |
| **Every tool is scope-gated** | All 8 external tools call `preflightOrDryrun()` which runs the four-gate chain *before* any binary is invoked. |
| **Evidence is tamper-evident** | Each tool result is SHA-256'd and chained to the previous entry. Deleting or modifying a row invalidates every subsequent row. |
| **Dry-run by default in dev** | Every active tool accepts `"dryrun": true` and short-circuits after gate check, printing what it *would* run. The test suite exercises the full gate chain this way without needing nmap installed. |
| **Destructive tools need confirmation** | `hydra` (credential brute-forcing) requires `"confirmed": true` in args before execution. |

---

## Quickstart

### Prerequisites

- **Go 1.24+** (tested on 1.26.4)
- No external binaries required for `--dryrun` mode
- For live tooling: `nmap`, `masscan`, `httpx`, `ffuf`, `nuclei`, `sqlmap`,
  `hydra` should be on `$PATH`

### Build

```sh
git clone https://github.com/xanstomper/redshark.git
cd redshark
go build -o redshark ./cmd/redshark
```

### Run

```sh
./redshark                                     # interactive TUI, no scope
./redshark --scope examples/scope-pentest.json  # with a rules-of-engagement scope
./redshark --version                            # RedShark 0.1.0-scaffold ...
```

### Build with metadata

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

Five test files assert the full safety contract:

| Test file | What it verifies |
|-----------|-----------------|
| `internal/scope/scope_test.go` | Refusal of `fbi.gov`, `army.mil`, `bnd.bund.de`, `nato.int`, `defense.gov.cn`; agency keyword detection (`mi6`, `mossad`, `csis`, `dgse`, `nato`, `bnd`) regardless of TLD; gate ordering (protected check runs before scope-loaded check) |
| `internal/agent/tools/safety_test.go` | Every active tool is refused when no scope is loaded; every active tool is refused when scope is expired; dry-run short-circuit emits `would run:` without invoking the binary |
| `internal/agent/tools/integration_test.go` | Tool list integrity, argument validation, dry-run output format |
| `internal/ui/logo/logo_test.go` | Mascot rendering at narrow (40 col) and wide (80 col) terminals; banner contains "REDSHARK" and "Offensive Security"; separator renders horizontal rule |
| `internal/ui/model/model_test.go` | Model initialization; scope wiring; cursor position for non-empty input |

---

## The TUI

RedShark's interface follows the Charm Crush layout pattern — a single
full-screen TUI with four visual zones:

```
┌─────────────────────────────────────────────────────────────────┐
│ 🦈 RedShark │ scope: ENG-001 │ msgs: 12 │ v0.1.0               │  ← header
├─────────────────────────────────────────────────────────────────┤
│ ╭ chat ─────────────────────────────────────────────────────╮   │
│ │                                                            │   │
│ │  [RedShark] scope loaded: pentest-2026-001                │   │
│ │  [Operator] run nmap -sV against 10.0.0.0/24              │   │
│ │  [RedShark] ⏳ nmap -sV 10.0.0.0/24 ...                   │   │
│ │  [Tool]  PORT    STATE  SERVICE                           │   │
│ │          22/tcp  open    ssh                              │   │
│ │          80/tcp  open    http                             │   │
│ │  [evidence] #0042 → evidence-pentest-2026-001/chain.jsonl│   │
│ │                                                            │   │
│ ╰────────────────────────────────────────────────────────────╯   │
├─────────────────────────────────────────────────────────────────┤
│ ctrl+c quit │ ctrl+l clear │ ↑↓ history │ pgup/pgdn scroll     │  ← footer
├─────────────────────────────────────────────────────────────────┤
│ [pentest-2026-001] ❯ _                                         │  ← input
└─────────────────────────────────────────────────────────────────┘
```

### Splash screen

On startup, RedShark displays a Unicode braille-art shark silhouette with the
block-letter **REDSHARK** banner and tag line. The splash auto-dismisses after
a timer *or* on any keypress — press any key to jump straight to the TUI.

### Visual zones

| Zone | Purpose | Key details |
|------|---------|-------------|
| **Header** | Brand identity + live status | Shows `🦈 RedShark`, active scope ID, message count, version. Background in semantic `Accent` color. |
| **Chat pane** | Scrollable message history | Rounded border with title. Supports mouse-wheel scrolling (`tea.MouseWheelMsg`). Mixes operator messages, agent responses, and bordered tool-output blocks. |
| **Footer** | Keybind reference | Dimmed hint bar showing available shortcuts. |
| **Input** | Operator command entry | Scope-aware prompt prefix, full line editing with cursor, command history via `↑`/`↓`. |

### Color palette

All colors are drawn from the semantic palette in `internal/ui/logo/logo.go`:

| Token | Hex | Usage |
|-------|-----|-------|
| `Accent` | `#FF4757` (red) | Brand highlights, header background, active scope badge |
| `Primary` | `#E8E8E8` | Body text, chat messages |
| `Secondary` | `#757575` | Dimmed text, footer hints, timestamps |
| `Success` | `#2ECC71` | Gate pass, evidence confirmed |
| `Warning` | `#F39C12` | Scope expiry warning, stale scope |
| `Error` | `#E74C3C` | Gate refusal, tool failure |
| `Neutral` | `#4A4A4A` | Inactive elements, empty state text |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  TUI (Bubble Tea v2)                                             │
│    ↓ operator message                                             │
│  Coordinator (agent/)                                            │
│    ↓ selects tool                                                 │
│  preflightOrDryrun(scope, technique, args)                       │
│    ↓                                                             │
│  4-gate chain — scope.Authorize(target, technique)                │
│    1. protected? → HARD-CODED refusal (never bypassable)          │
│    2. scope loaded? → refuse "no-scope"                           │
│    3. scope fresh? → refuse "stale"                               │
│    4. target in network? technique allowed? → refuse "out-of-scope"│
│    ↓ on pass                                                      │
│  os/exec → nmap / masscan / httpx / ffuf / nuclei / sqlmap / hydra│
│    ↓ on result                                                    │
│  evidence.Record(...) → ./evidence-<scope-id>/chain.jsonl          │
└──────────────────────────────────────────────────────────────────┘
```

### Package map

```
cmd/redshark/          CLI entry point — flags, TUI bootstrap
internal/
  agent/
    tools/             10 tool definitions — each wraps an external binary
    prompts/           System prompt + refusal language templates
    stubprovider/      Echo-back LLM provider (dev mode)
  scope/               Scope document, gate chain, protected-target lists ⚠️ THE CORE
  evidence/            Append-only SHA-256 hash-chained artifact collector
  ui/
    logo/              Mascot art, banner, color palette, separator renderer
    model/             Bubble Tea v2 MainModel — header/chat/footer/input
  msg/                 Message types (Operator, Agent, Tool, System)
  redact/              Output sanitization (API-key, JWT, token stripping)
  version/             Build metadata (version, commit, date, brand)
  util/                Misc helpers
  ansi/                ANSI escape code utilities
```

| Package | LOC | What it owns |
|---------|-----|-------------|
| `internal/scope` | ~370 | Scope document, gate chain, protected-target lists. **The single most critical package.** |
| `internal/agent/tools` | ~560 | 10 tools: nmap, masscan, httpx, ffuf, nuclei, sqlmap, hydra, c2-profile, report, scope_check. Each calls `preflightOrDryrun` first. |
| `internal/ui/model` | ~550 | Bubble Tea v2 TUI model — header bar, scrollable chat pane, keybind footer, input bar, splash screen, mouse-wheel support, command history. |
| `internal/ui/logo` | ~165 | Unicode braille-art shark, REDSHARK block banner, semantic color palette, separator renderer. |
| `internal/evidence` | ~180 | SHA-256 hash-chained append-only JSONL writer. Genesis hash = `sha256("RedShark:genesis")`. |
| `internal/agent/prompts` | ~60 | System prompt and refusal language templates. |
| `internal/redact` | ~80 | Regex-based output sanitizer — strips API keys, JWTs, session tokens before content re-enters the LLM prompt. |
| `internal/msg` | ~70 | Structured message types for the TUI chat pane. |
| `internal/agent/stubprovider` | ~50 | Echo-back provider — returns user message verbatim. Used during development before wiring a real LLM. |

**Total: ~3,657 lines of Go across 20 source files.**

---

## The safety contract — in detail

### Layer 1: Hardcoded protected targets

A target matching *any* rule in this list is refused with `layer=protected`,
**regardless of what scope is loaded**. No CLI flag, no scope document, no
future API call can override this. The list lives in
`internal/scope/scope.go` and requires a code change to alter.

**Protected TLDs:**

```
.gov  .mil  .int
.gov.uk  .gov.au  .gov.ca  .gov.cn  .gouv.fr  .gob.es
.bund.de  .gc.ca  .govt.nz  .gov.sg  .gov.il  .gov.in
```

**Protected keywords (hostname match, any TLD):**

```
fbi  cia  nsa  dhs  dea  interpol  mi6  mi5  gchq
mossad  fsb  dgse  dgsi  bnd  csis  asis  nato
csirt  finfisher  nsa  dod  doddef
```

A keyword match fires on *any* subdomain or TLD: `mi6.internal.lan` is
refused. `fbi.mycompany.com` is refused. The check is case-insensitive and
matches anywhere in the hostname.

### Layer 2–4: The four-gate scope chain

Every active tool invocation runs through `scope.Authorize(target, technique)`:

```
Gate 1: PROTECTED — is the target in the hardcoded list above?
  → YES: refuse (layer=protected, reason="hardcoded protected target")
  → NO:  continue

Gate 2: LOADED — has a scope document been loaded?
  → NO:  refuse (layer=no-scope, reason="no scope loaded")
  → YES: continue

Gate 3: FRESH — is the scope document still valid?
  → NO:  refuse (layer=stale, reason="scope expired at <timestamp>")
  → YES: continue

Gate 4: IN-SCOPE — is the target in the scope's network range?
          AND is the technique in the scope's allowed techniques list?
  → NO:  refuse (layer=out-of-scope, reason="<target> not in scope network")
  → YES: allow (layer=allowed, reason="passed all gates")
```

**Gate ordering is critical.** The protected-target check runs *before* the
scope-loaded check. This means even an empty or permissive scope cannot
authorize a `.gov` target — there's no "I loaded a scope that says `.gov` is
fine" bypass because gate 1 fires first.

Each gate returns a structured `Decision{Layer, Reason}` and every tool
drafts its refusal message from this struct — no tool invents its own
refusal language.

### Dry-run mode

Every active tool accepts `"dryrun": true` in its argument map. When set,
`preflightOrDryrun()` runs the full four-gate chain but **short-circuits
before** `os/exec` is called, printing:

```
[dryrun] would run: nmap -sV -oA evidence-001/nmap 10.0.0.0/24
```

This is how the test suite exercises the gate chain without requiring
nmap/masscan/hydra to be installed.

### Mandatory confirmation for destructive tools

Tools classified as destructive (`hydra` for credential brute-forcing, future
additions: `c2-profile`, sensitive report exports) require `"confirmed": true`
in their args map. Without it, the tool returns a refusal:

```
[refused] hydra requires explicit operator confirmation (confirmed:true)
```

This is separate from the scope chain — even if the target is in-scope,
destructive tools need a second explicit opt-in.

---

## Tool inventory

| Tool | Category | External binary | Scope-gated | Destructive | Dryrun | Description |
|------|----------|----------------|-------------|-------------|--------|-------------|
| `nmap` | scan | `nmap` | ✅ | — | ✅ | Network/port scanning with service detection |
| `masscan` | scan | `masscan` | ✅ | — | ✅ | Mass IP/port scanning for large ranges |
| `httpx` | scan | `httpx` | ✅ | — | ✅ | HTTP probe — status codes, titles, technologies |
| `ffuf` | scan | `ffuf` | ✅ | — | ✅ | Fuzzing — directories, parameters, vhosts |
| `nuclei` | scan | `nuclei` | ✅ | — | ✅ | Template-based vulnerability scanner |
| `sqlmap` | exploit | `sqlmap` | ✅ | — | ✅ | SQL injection detection and exploitation |
| `hydra` | exploit | `hydra` | ✅ | ✅ | ✅ | Online credential brute-forcing (requires `confirmed:true`) |
| `c2-profile` | post | (internal) | ✅ | — | ✅ | Generate C2 profile configurations (no external binary) |
| `report` | report | (internal) | — | — | — | Compile evidence chain into a findings report |
| `scope_check` | meta | (internal) | — | — | — | Check current scope status without executing tools |

### Tool execution flow

```
operator types → "run nmap against 10.0.0.0/24"
       ↓
  Coordinator selects tool: nmap
       ↓
  preflightOrDryrun(scope, "scanning", {target: "10.0.0.0/24", dryrun: false})
       ↓
  Gate 1: protected?  → 10.0.0.0/24 is not .gov/.mil → PASS
  Gate 2: loaded?    → scope "pentest-001" loaded    → PASS
  Gate 3: fresh?     → expires 2026-12-31             → PASS
  Gate 4: in-scope?  → 10.0.0.0/24 in scope networks → PASS
       ↓
  os/exec: nmap -sV -oA evidence-pentest-001/nmap 10.0.0.0/24
       ↓
  evidence.Record("nmap", "scanning", "10.0.0.0/24", stdout)
       ↓
  → chain.jsonl entry appended
```

If any gate fails, the tool returns a structured refusal and no binary is
invoked.

---

## Evidence chain

Every tool result (successful or refused) is appended to an append-only
JSONL file at `./evidence-<scope-id>/chain.jsonl`. The chain is
**tamper-evident**: each entry's SHA-256 hash includes the previous entry's
hash, starting from a genesis hash.

### Chain structure

```
genesis → entry #1 → entry #2 → entry #3 → ...
            ↑          ↑           ↑
            │          │           │
     prev_hash=#1  prev_hash=#2  prev_hash=#3
```

### Entry format

```json
{
  "id":            "0000001",
  "ts":            "2026-06-21T20:30:00Z",
  "tool":          "nmap",
  "technique":     "scanning",
  "target":        "10.0.0.0/24",
  "category":      "scan",
  "tags":          [],
  "payload_sha256": "a3f2b1c9d8e7...",
  "prev_hash":     "0000000000000..."
}
```

| Field | Description |
|-------|-------------|
| `id` | Zero-padded sequential entry number |
| `ts` | ISO 8601 UTC timestamp |
| `tool` | Tool name that produced the result |
| `technique` | Technique category from scope |
| `target` | Target that was scanned/attacked |
| `category` | Result category (`scan`, `exploit`, `refusal`, `report`) |
| `tags` | Free-form tags for filtering |
| `payload_sha256` | SHA-256 of the tool's stdout |
| `prev_hash` | SHA-256 of the previous entry (chain integrity) |

### Genesis

The chain starts with `sha256("RedShark:genesis")` — a well-known anchor hash.
Any post-hoc modification to a chain entry invalidates the `prev_hash` of the
*next* entry, cascading forward. This provides cryptographic proof that the
evidence log has not been altered.

---

## Scope documents

A scope document is a JSON file defining the rules of engagement for a
penetration test. It specifies what networks can be targeted, what techniques
are allowed, and when the engagement expires.

### Example: `examples/scope-pentest.json`

```json
{
  "id": "pentest-2026-001",
  "client": "Acme Corp",
  "operator": "red-team-lead",
  "networks": ["10.0.0.0/24", "192.168.1.0/24"],
  "techniques": ["scanning", "enumeration", "exploitation", "bruteforce"],
  "issued": "2026-01-01T00:00:00Z",
  "expires": "2026-12-31T23:59:59Z",
  "client_signatory": "Jane Smith, CISO",
  "notes": "Annual external pentest. All subnets in scope."
}
```

### Loading a scope

```sh
# At the command line:
./redshark --scope examples/scope-pentest.json

# Or from within the TUI:
/scope examples/scope-pentest.json
```

The scope ID appears in the header bar and input prompt prefix. Gate 2
(scope-loaded) and Gate 3 (freshness) both consult this document.

---

## In-scope commands (TUI slash commands)

| Command | Description |
|---------|-------------|
| `/scope <path>` | Load a scope document from JSON file |
| `/scope` | Display current scope status |
| `/version` | Print RedShark version |
| `/clear` | Clear chat pane |
| `/help` | Show available commands |
| `/quit` | Exit RedShark |

---

## Roadmap

### ✅ Done (v0.1.0-scaffold)

- Full Bubble Tea v2 TUI with shark mascot splash screen
- Multi-pane layout: header bar, bordered chat pane, keybind footer, input bar
- Semantic color palette (7 tokens)
- Four-gate scope chain with hardcoded protected-target refusal
- 10-tool toolset — 8 external + 2 internal, all scope-gated
- Dry-run mode for every active tool
- Evidence hash chain (`evidence-*/chain.jsonl`)
- 5 test files covering scope, tools, logo, and model
- Mouse-wheel scrolling, command history, cursor editing
- `redshark` binary with `--version`, `--scope` flags

### ⚠️ In progress

- LLM provider integration (current: `stubprovider` echo-back)

### ❌ Not yet implemented

| Feature | Notes |
|---------|-------|
| Real LLM provider | Wire OpenAI / Anthropic / local model via `catwalk` provider interface |
| Session persistence | Currently in-memory; SQLite backend planned |
| Tab completions | Slash commands, file paths, tool names |
| Multi-session tabs | Like Crush's session switcher |
| File attachments | Drop evidence files, scope docs into chat |
| LSP server | Language Server Protocol for IDE integration |
| MCP client | Model Context Protocol for tool discovery |
| Skill embedding | `SKILL.md` directory exists but not wired |
| Report generation | `report` tool compiles chain.jsonl into formatted findings |
| GitHub Actions CI | `go test ./...` on push/PR |

---

## Conceptual lineage

RedShark's TUI layout (header / scrollable chat / input bar) follows the
same visual shape as [Charm Crush](https://github.com/charmbracelet/crush).
**No code was copied** from the Charm fork. The architectural patterns
referenced are the public Bubble Tea v2 `tea.Model` interface and the common
TUI layout convention. Charm attribution and FSL clause notes are preserved
in [`THIRD_PARTY.md`](THIRD_PARTY.md).

RedShark does **not** compete with Charm Crush: Crush is an AI coding
assistant for software developers; RedShark is an offensive-security
operator tool. This distinction keeps RedShark within Charm's "Permitted
Purpose" clause for derivatives of the Crush fork.

---

## Why does the module path differ from the repo name?

The GitHub repository is **[`xanstomper/redshark`](https://github.com/xanstomper/redshark)**
— the user-facing brand and product name. The Go module path is
`github.com/xanstomper/redteam-agent` — this is the import path used by
every internal Go package. Renaming the module path would require rewriting
every `import` line across all 20 source files and is not part of the
current scaffold. The build, the binary name (`redshark`), every CLI flag,
every user-facing string, and the `cmd/redshark/` directory all reflect the
`redshark` brand.

---

## Security disclosure

If you find a vulnerability in RedShark itself (not using RedShark to find
vulnerabilities — that's the point), contact the maintainer at the email
listed in the repository settings. Include:

1. The affected component (scope gate, evidence chain, TUI, etc.)
2. A minimal reproduction
3. The impact (e.g., "gate 1 can be bypassed by...")
4. A proposed fix, if you have one

**Do not** open a public issue for security vulnerabilities.

---

## Out of scope — on purpose

These capabilities were deliberately **not** implemented:

- **Auto-escalation / lateral movement** — RedShark does not carry session
  state forward or chain exploits automatically. Each action requires
  operator initiation.
- **Stolen-credential automation** — Credential brute-forcing (`hydra`)
  defaults to off and requires explicit `confirmed:true` per invocation.
- **Third-party reporting** — The `report` tool is local-only. Remote
  endpoints must be wired in manually.
- **Scope-bypass shortcuts** — Every active tool goes through the gate
  chain. There is no "just this once" flag.
- **Government / military targets** — Hardcoded refusal. Not negotiable.
  Not overridable. Not a configuration option.

---

## License

Local code: **MIT** (see [`LICENSE`](LICENSE)).
Third-party notices: [`THIRD_PARTY.md`](THIRD_PARTY.md).

---

<p align="center">
  <sub>Built with</sub><br>
  <a href="https://github.com/charmbracelet/bubbletea"><img src="https://img.shields.io/badge/Bubble%20Tea-v2-FF69B4?style=for-the-badge" alt="Bubble Tea"></a>
  <a href="https://github.com/charmbracelet/lipgloss"><img src="https://img.shields.io/badge/lipgloss-v2-FF69B4?style=for-the-badge" alt="lipgloss"></a>
</p>
