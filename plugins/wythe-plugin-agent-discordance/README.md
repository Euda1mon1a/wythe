# `wythe-plugin-agent-discordance` (`#117`)

Read-only `wythe.plugins` companion for cross-channel agent continuity and cross-agent isolation (`DISC-001`, `DISC-002`):

- **Consumes declarative route mappings + redacted SDK receipts** (`.wythe/agent_routes.json` and `.wythe/agent_receipts.json`, or companion/MCP inputs) without ingesting transcripts, audio, credentials, or production memory dumps.
- **`DISC-001` (Same-Agent Fragmentation / Policy Drift):** Flags routes declared to resolve to the same agent and continuity group when observed identity, scope, policy version, or synthetic canary pickup diverge without an explicit privacy/session or device-capability boundary. Cache misses and wording differences are never treated as identity drift.
- **`DISC-002` (Cross-Agent / Cross-Principal Boundary Leak):** Flags distinct agents or counterparty routes sharing model/host infrastructure when task state, memory packets, or grants cross an isolation boundary.
- **Fail-Closed Epistemics:** Missing caller or authorization receipts remain `unverified` (or `hop_only` when only an intermediate host hop was observed), never `passed`.
