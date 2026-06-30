# dtap_drift_v1 — DRIFT ported to the DTAP defense framework (baseline)

**Type:** human-designed baseline (port). **Original:** `benchmarks/agentdyn-src/src/agentdojo/defenses/drift/`.

## Ported (DRIFT plan-then-validate)
| DRIFT component | Port |
|---|---|
| plan construction (`CONSTRAINTS_BUILD_PROMPT` → `initial_constraints_build`) | planner LLM builds `<function_trajectory>` + `<parameter_checklist>` from `ctx.metadata["instruction"]` + tool list, once per trace (lazy) |
| trajectory constraint validation (`node_check`) | in-plan tool (name ∈ trajectory) → allowed, deterministic |
| `alignment_judge` (ported prompt) | on a deviation, an LLM judges Yes/No that the current trajectory still serves the original query — from trajectories + query ONLY (no untrusted output) |
| `[CALL ERROR]` refusal | misaligned → `PermissionError` (recoverable; agent replans) |

## Threat scope (same as the original)
Defends **indirect** prompt injection: an injected instruction makes the agent
call a function not on the plan derived from the trusted query → judged misaligned
→ refused. Does **not** defend **direct** attacks: the malicious goal is the user
query, so the plan already contains the malicious trajectory.

## Honest simplifications
- DRIFT's per-parameter checklist `node_check` (data-constraint matching) is the
  brittle part of the original and is **not enforced**; the function-trajectory +
  alignment-judge core is. Same-function param-only redirections (e.g. an in-plan
  `write_file` aimed at a different path) are a known blind spot of DRIFT's
  trajectory focus.
- Planner + alignment judge run on the Bedrock-Haiku judge proxy (cost-logged via
  `cost_events.jsonl`). The judge fires **only on deviations**, like the original.
- **Fail-open** if the planner LLM fails (no plan ⇒ cannot validate) so planner
  flakiness doesn't destroy utility; logged.

## Section table
| Section | Surface | Status | Behaviour |
|---|---|---|---|
| INPUT-FILTER | NL | empty | system prompt unchanged |
| PRE-TOOL-GATE | code | **active** | `on_pre_tool_call`: plan-consistency / trajectory-alignment gate |
| POST-EXEC-AUDIT / ROLLBACK | code | empty | — |
