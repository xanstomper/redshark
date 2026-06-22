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
