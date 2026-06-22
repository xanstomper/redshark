# Third-party notices

This project was developed alongside the upstream **Charmbracelet Crush**
fork chain (`/home/jewboy420/redamon/redshark/` locally). Charm Crush is
licensed under the Functional Source License v1.1 with an MIT expiration
(FSL-1.1-MIT), Copyright 2025-2026 Charmbracelet, Inc.

We did **not** copy code from the Charm Crush fork. The architectural
patterns referenced are:

- Bubble Tea v2 model interface (`Init`/`Update`/`View`) — public API of
  `charm.land/bubbletea/v2`.
- TUI layout shape (header / chat panel / input bar) — a common pattern
  across Bubble-Tea-based TUIs.
- `charm.land/bubbletea/v2` and `charm.land/lipgloss/v2` libraries used
  as-is at their published versions.

Full FSL-1.1-MIT text follows for completeness; we record the obligation:

> Functional Source License, Version 1.1, MIT Future License
>
> The Licensor grants the Licensee a Licensed Work subject to the
> conditions below:
>
> ## Acceptance
>
> By using, copying, modifying, displaying, distributing, transmitting, or
> otherwise making available the Licensed Work, the Licensee accepts and
> agrees to be bound by the terms of this License.
>
> ## Restrictions
>
> The Permitted Purpose is defined as: use of the Licensed Work for any
> purpose other than Competing Use. Competing Use includes making the
> Software available to others as part of a product or service that
> competes with the Licensor's product or service.
>
> ## Granted Rights
>
> Subject to the conditions below, the Licensor grants the Licensee a
> non-exclusive, worldwide, non-transferable, royalty-free license to use,
> copy, modify, merge, publish, distribute, sublicense, and/or sell copies
> of the Licensed Work.
>
> ## Change Date
>
> Two (2) years from release, the Licensed Work converts to the MIT License.
>
> ## No Liability / No Warranty

The Permitted Purpose clause means derivatives of Crush **must not be
released by a third party if they compete with the upstream product.**
`RedShark` does not compete with Charm Crush (their audience is
software developers using an AI coding assistant; ours is offensive
security operators). We record this distinction explicitly to keep the
licensing trail clear.

If you intend to redistribute this project under a name that already
maps to Charm's `redshark`, double-check that your fork is "Permitted
Purpose" before publishing.

---

## Integrated third-party projects

This repository vendors and integrates content from the following
open-source projects. Each is used under its respective license;
attribution is recorded here.

### deepteam — confident-ai/deepteam

- **License:** MIT
- **Use:** Python sidecar (`pybridge/server.py`) wraps `deepteam.red_team()`, `Guardrails`, and vulnerability/attack enumerations via HTTP. The Go `internal/pybridge/` package manages the sidecar lifecycle. No deepteam source code is copied into the Go tree — calls go through the local HTTP interface.
- **Modules ported:** 37 vulnerability types (`bias`, `toxicity`, `pii_leakage`, `bfla`, `bola`, `ssrf`, …), 28 attack types (`prompt_injection`, `crescendo_jailbreaking`, `tree_jailbreaking`, …).
- **Package installed into:** `pybridge/.venv/lib/python3.12/site-packages/deepteam/`

### redteam-ai-benchmark — toxy4ny/redteam-ai-benchmark

- **License:** MIT (per repository LICENSE)
- **Use:** Benchmark dataset and runner patterns ported into the Python sidecar (`/benchmark` endpoint). The Go `BenchmarkTool` routes calls through `internal/pybridge/`.
- **Dataset cloned to:** `redshark-vendors/redteam-ai-benchmark/datasets/` (not committed; serves as reference only)

### AI-Red-Teaming-Guide — requie/AI-Red-Teaming-Guide

- **License:** MIT (per repository LICENSE)
- **Use:** 8 markdown templates ported into `docs/redteam-guide/templates/` and served via the Go-native `RedteamGuideTool` in `internal/agent/tools/redteam_tools.go`. No source code; templates only.

### HacxGPT-CLI — HacxGPT-Official/HacxGPT-CLI

- **License:** GPL-3.0
- **Use:** Design patterns reviewed for CLI/UX inspiration only (banner style, provider config schema, interactive chat loop). No code was ported; only structural ideas informed `cmd/redshark/main.go` and the Bubble Tea model layout. GPL obligations do not apply because no GPL code was distributed — only ideas.

### WorpGPT-Latest-2026 — ExtarDev/WorpGPT-Latest-2026

- **Status:** Placeholder/fake repository with no usable source code. Skipped entirely.
