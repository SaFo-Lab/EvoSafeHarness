# dtap_camel_v1 — CaMeL ported to the DTAP defense framework (baseline)

**Type:** human-designed baseline (port), not a Pareto-GEPA search candidate.
**Original:** `benchmarks/agentdyn-src/src/agentdojo/defenses/camel/`.

## What was ported (as close to CaMeL's logic as the interface allows)
| CaMeL component | Port |
|---|---|
| Capability = (sources, readers) | `Capabilities(sources, public)`; `SourceEnum{User,CaMeL,Assistant,Tool}`; `is_trusted` = sources ⊆ {User,CaMeL}; `is_public` |
| deny-by-default `check_policy` | `_check_policy`: reads & uncontaminated traces pass; state-changing calls on a contaminated trace must be authorised, else **Denied** |
| per-tool security policies (`WorkspaceSecurityPolicyEngine`) | os-filesystem policies: egress (`send_email`/`post_message*`) exfil rule, `execute_command` network-egress rule, write/edit/move/create intent rule |
| confidentiality rule (`can_readers_read_value`) | egress of untrusted-derived data to a recipient not named in the user query → Denied |
| **dual-LLM** (privileged plans from trusted query; quarantined parses untrusted data) | authorisation decided by a **quarantined LLM** (Bedrock-Haiku judge proxy) given ONLY `ctx.metadata["instruction"]` + an ABSTRACT action description — never the untrusted bytes. Fail-closed. |

## The one honest divergence
Real CaMeL gets *precise* per-value capabilities from a custom interpreter that
runs the privileged-LLM's Python program. The DTAP `Defense` interface is a
per-tool-call hook, not an interpreter, so the program-synthesis flow can't be
hosted. We approximate data-flow with **hook taint propagation**:
`on_post_tool_call` marks environment-read outputs as untrusted `Tool` source
(contaminating the trace + recording fragments); `on_pre_tool_call` runs the
policy engine on every state-changing call. The *enforcement* layer (where
CaMeL's guarantee bites) is faithful; data-flow precision is approximate
(string-provenance vs interpreter-tracked values).

## Threat-model scope (same as real CaMeL)
Defends **indirect** prompt injection (malicious instructions smuggled through
untrusted file/message content the agent reads). Does **not** defend **direct**
attacks: a malicious *user* instruction is `User`-sourced = trusted by
construction, so CaMeL authorises it — by design. Expect CaMeL to cut indirect
ASR with little effect on direct ASR.

## Cost
Deterministic for reads, uncontaminated traces, and plain exfiltration. One cheap
quarantined-LLM (Haiku) call per *contaminated state-changing* call — logged to
`cost_events.jsonl` like every other LiteLLM call; see `scripts/cost_report.py`.

## Section table (DTAP bundle surfaces)
| Section | Surface | Status | Behaviour |
|---|---|---|---|
| INPUT-FILTER | NL | empty | system prompt unchanged |
| PRE-TOOL-GATE / EXEC-ISOLATE | code | **active** | `on_pre_tool_call`: deny-by-default policy on contaminated state-changing calls |
| POST-EXEC-AUDIT | code | **active** | `on_post_tool_call`: taint environment reads (no redaction) |
| ROLLBACK | code | empty | — |
