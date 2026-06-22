# AI Security PR Checklist

## Core
- [ ] Threat model updated if behavior/capability changed
- [ ] New or modified prompts added to security regression suite
- [ ] Tool authorization boundary validated (least privilege)
- [ ] Prompt injection and jailbreak tests executed for changed flows
- [ ] Data handling reviewed for PII/log retention requirements
- [ ] Output filtering and policy checks validated
- [ ] Monitoring/detection rules updated for new failure modes
- [ ] Residual risks documented in model/system card

## Agentic systems (if the change touches agents/tools)
- [ ] **Memory integrity**: writes to agent memory/context are validated, sourced, and TTL-bound (no unbounded trust of persisted state)
- [ ] **Inter-agent auth**: messages between agents are authenticated and identity-bound (guards against second-order/ASI07 escalation)
- [ ] **MCP/tool pinning**: tool, plugin, and MCP server definitions are version-pinned and checksum-verified; no runtime re-registration
- [ ] **Tool output as data**: tool/retrieval responses are treated as data, never as instructions
- [ ] **New tools reviewed**: any added tool/plugin/MCP server passed provenance + behavioral review (ASI04 supply chain)
- [ ] **Autonomy bounds**: high-impact actions require human confirmation resistant to consent fatigue
- [ ] **Agent registry**: any new agent is registered with scoped, expiring credentials (no shadow/rogue agents, ASI10)
