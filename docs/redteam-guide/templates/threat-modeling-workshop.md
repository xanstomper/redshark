# Threat Modeling Workshop Template (AI Systems)

## Workshop Goals
- Identify highest-risk abuse paths for the AI system.
- Prioritize red-team test scenarios by business impact and exploitability.
- Assign owners and due dates for controls and mitigations.

## Participants
- Product owner
- AI/ML engineer
- Security engineer / red team
- Detection / SOC representative
- Legal / compliance (for high-risk domains)

## Pre-Read Checklist
- Architecture diagram and trust boundaries
- Data flow (inputs, retrieval, tools, outputs)
- List of model capabilities and enabled tools/actions
- Existing guardrails (input/output/content/policy)
- Known incidents or prior findings

## 120-Minute Agenda
1. Scope and assumptions (15 min)
2. System walkthrough (20 min)
3. Threat brainstorming (30 min)
4. Risk scoring and prioritization (30 min)
5. Test plan and owners (20 min)
6. Wrap-up and next steps (5 min)

## Output Artifacts
- Prioritized risk register
- Red-team test plan for next sprint
- Detection/monitoring gaps backlog
- Signed-off risk acceptance for deferred items

---

## Worked Example Output — "SupportAgent" RAG + email assistant

### Prioritized Risk Register (excerpt)
| # | Abuse path | OWASP ASI | Likelihood | Impact | Risk score | Owner | Due |
|---|-----------|-----------|-----------|--------|-----------|-------|-----|
| 1 | Indirect prompt injection via uploaded doc → email exfiltration | ASI02/ASI06 | High | Critical | **Critical** | Platform Sec | 2026-06-10 |
| 2 | Over-broad `send_email` tool (no recipient allowlist) | ASI02 | High | High | **High** | Agent Team | 2026-06-14 |
| 3 | Cross-tenant retrieval from shared vector store | — | Medium | Critical | **High** | Data Eng | 2026-06-21 |
| 4 | Low-resource-language jailbreak parity gap | — | Medium | Medium | **Medium** | Safety | 2026-07-01 |
| 5 | Memory poisoning across sessions | ASI06 | Low | High | **Medium** | Agent Team | 2026-07-01 |

### Risk scoring used
`Risk = Likelihood × Impact × Exploitability` (see guide's Risk Prioritization Framework), mapped to Critical/High/Medium/Low bands.

### Red-Team Test Plan (next sprint)
- Seed corpus with poisoned doc; measure obedience rate (`pi-indirect-002`).
- Fuzz `send_email` recipients; confirm allowlist + human-confirm (`tool-misuse-005`).
- Cross-tenant retrieval probe (`xtenant-007`).
- Swahili/Tagalog jailbreak parity vs. English (`multiling-008`).

### Detection/Monitoring Gaps
- No alert on outbound email to non-allowlisted domains.
- No egress monitoring per tool call.

### Risk Acceptance (deferred)
- Item #5 accepted until 2026-07-01 by Product Owner (low current likelihood; memory feature behind flag).
