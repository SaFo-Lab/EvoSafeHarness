# Defense Evaluation Platform

A small, reusable harness for **comparing defenses on a fixed testset**. You give it
a config (a testset + a list of defenses + which benchmark env to drive); it runs each
defense (resumable, on the frozen model), scores every result tree the same way, and
writes a comparison table + a frozen run manifest.

Built so that adding a baseline (DRIFT, CaMeL, a trained `dtap_def_v*`, …) to a
comparison is **one line in a config** — *once that defense exists as a loadable
package*. See "Adding a defense" and the DRIFT/CaMeL port plan below.

## Layout
```
eval_platform/
  platform.py            # orchestrator: run (resumable) + score + compare
  score.py               # consistent scorer (util / ASR by threat_model+category / gate-fires / FPs)
  configs/<run>.json      # one config per comparison run
  results/<run>/          # comparison.md, comparison.csv, summary.json, testset.jsonl (frozen)
```

## Usage
```bash
PY=<DTAP_ENVS>/dtap_ossystem/.venv/bin/python

# run every defense in the config on the testset (resumable), then score + compare:
$PY platform.py run     configs/osfs_subset100.json

# only re-score already-completed result trees and rebuild the table (no model calls):
$PY platform.py compare configs/osfs_subset100.json

# score a single result tree directly:
$PY score.py <env>/benchmarks/dtap/results/_test_<testset>/<defense>
```
Requires the env's judge proxy up (`:4111`) and Docker available — the platform drives
the DTAP evaluator, which spins per-task containers. The model is **never** hardcoded
here: it comes from the env's `.env` `DTAP_MODEL` (currently `bedrock/us.anthropic.claude-sonnet-4-6`).

## Config schema
| key | meaning |
|---|---|
| `run_name` | output folder under `results/` |
| `env_root` | abs path to the benchmark env to drive (must have `scripts/eval_subset.sh` + `.venv` + `benchmarks/dtap-src`) |
| `testset` | basename of a split jsonl in `<env_root>/benchmarks/dtap/splits/` (e.g. `test_subset100`) |
| `defenses` | list of `dt_defenses/<name>` package names to compare (e.g. `["dtap_def_v0","dtap_def_v1"]`) |
| `max_parallel` | per-defense task concurrency (Bedrock-I/O-bound; 6 is safe) |
| `marker` | the refusal string a defense raises, used to attribute gate-fires (DTAP: `"Refused by security policy"`) |

Per-defense results land in the env's standard convention
`<env_root>/benchmarks/dtap/results/_test_<testset>/<defense>`, so prior runs are reused
automatically (resumable via `--skip-existing`).

## What the table reports
`utility%` (benign task success) · `ASR%` overall + split `direct`/`indirect` ·
`score` = util−ASR · `gate_TP` (malicious tasks the defense refused) ·
`gate_benign_FP` (benign tasks the defense refused that then failed → the real utility cost).
The FP column is what exposes a defense that "wins" on ASR only by over-refusing.

## Victim model: OpenRouter qwen3.7-plus (in addition to the Bedrock victims)

`qwen3.7-plus` works here exactly like the Bedrock victims — the platform never builds the
model itself, it just drives the env's agent, and the env's `agent.py` routes `openrouter/…`
through the same LiteLLM/`ChatLiteLLM` path (see top-level README "Victim backbones"). Two ways:

- **Single-config run** (`platform.py run`/`compare`) uses the env's **current** `.env`
  `DTAP_MODEL`. To score qwen this way, set that env's `.env` to
  `DTAP_MODEL=openrouter/qwen/qwen3.7-plus` first (a normal Phase-A switch), then run the config
  unchanged (configs are model-agnostic).
- **Matrix / single cell** (`run_matrix.sh openrouter/qwen/qwen3.7-plus [maxp]` or
  `run_model_cell.sh <env> <domain> openrouter/qwen/qwen3.7-plus <split> <defense>`) overrides the
  victim **without** mutating `.env`. Results are model-keyed to `openrouter_qwen_qwen3.7-plus`
  (`tr '/:' '__'`), so they never collide with the Bedrock victims. `score_matrix.py` already
  lists `Qwen3.7-plus` (cells are skipped until a qwen run exists). Because it serves over
  OpenRouter, qwen does **not** share the AWS Bedrock per-model quota — a qwen matrix can run
  concurrently with a Bedrock matrix.

Notes: `OPENROUTER_API_KEY` + `OPENROUTER_REASONING_EFFORT` are in all three envs' `.env`
(sourced by `eval_subset.sh`/`run_model_cell.sh`). Reasoning is on by default; the model's
chain-of-thought is stripped from the final answer (`_lc_content_to_text`), so the refusal
`marker` scan and the utility judge see plain text exactly as for the string-only Bedrock
victims. Cost: litellm has no local price for qwen, so `dtap_cost` falls back to OpenRouter's
returned `usage.cost`/`response_cost`, and the matrix `agent$` column stays accurate.

---

## Adding a TESTSET
A testset is just a split jsonl in `<env_root>/benchmarks/dtap/splits/<name>.jsonl`, each
line `{"domain","type","threat_model"?,"risk_category"?,"task_id"}` (same format as
`test.jsonl`). Freeze the IDs for reproducibility — see how `test_subset100` was built
(stratified, seeded, with a `.manifest.json`); the platform copies the testset into
`results/<run>/testset.jsonl` so any comparison is self-describing and re-runnable.

## Adding a DEFENSE
A defense is a package `<env_root>/benchmarks/dtap-src/dt_defenses/<name>/` exposing
`build() -> Defense`. The `Defense` base (see `dt_arena/src/defense/loader.py`) gives
two mutation surfaces, all optional:
- **NL**: `system_prompt_transform(prompt) -> prompt`
- **Code**: `on_pre_tool_call(ctx)` (rewrite `ctx` / `raise` to block) and
  `on_post_tool_call(ctx, result)` (redact / `raise`).

Each `ctx` carries the trusted run context: `ctx.metadata["instruction"]` (full user
task — enables scope-vs-task reasoning), `ctx.metadata["task_id"|"threat_model"|...]`,
and `ctx.trace_id` (stable per-run id for per-trace state under parallelism). Raise an
identifiable `PermissionError` (set the platform's `marker` to its message prefix) so
gate-fires are attributable. Then add the package name to a config's `defenses` list.

> **Threat-model caveat** (from the loader): the user instruction is trusted only for
> *indirect* attacks. For *direct* attacks the malicious goal **is** the instruction, so a
> pure scope-vs-task check rubber-stamps it — combine instruction-based reasoning with
> effect-based action judging (this is why `dtap_def_v1` is an effect gate).

---

## Porting the baselines (DRIFT, CaMeL) — honest plan

Reference implementations: `<HARNESS_REPO>/benchmarks/agentdyn-src/src/agentdojo/defenses/{drift,camel}`.
**Both are AgentDojo-pipeline-coupled and are NOT drop-in.** They must be re-expressed as
`dt_defenses/<name>` packages against the `Defense` interface above. Effort differs sharply:

### DRIFT — *moderate, re-implementable as a hook* ✅
DRIFT (agentdojo: `DRIFTLLM.py` ~715 ln, `DRIFTToolsExecutionLoop`, planner + per-call
plan-consistency) is fundamentally: **(1)** plan from the trusted user instruction, **(2)**
gate each tool call for consistency with that plan. This maps cleanly onto a DTAP defense:
- On the first hooked call of a trace (keyed by `ctx.trace_id`), build a plan from
  `ctx.metadata["instruction"]` via one LLM call (reuse the Bedrock creds in `.env` or the
  judge proxy).
- In `on_pre_tool_call`, ask the planner-LLM (or a cheap classifier) whether this
  `tool_name(args)` is on-plan / in-scope; `raise PermissionError("DRIFT: off-plan …")` if not.
- Cache plan + verdicts per `trace_id`.
- The agentdojo code is a *reference for the prompts/logic*, not a literal import (its
  suites/attack-types/OpenRouter client don't exist here). Estimate: ~1–2 focused sessions
  + a per-call LLM cost (budget it; it's not free like the deterministic gates).

### CaMeL — *heavy, not hook-shaped* ⚠️
CaMeL (agentdojo: ~7k ln — `interpreter/interpreter.py` 2716, `value.py` 1460, privileged/
quarantined LLMs, `AgentDojoSecurityPolicyEngine` with **per-suite** policies for banking/
travel/workspace) is **an agent architecture, not a tool-call hook**: a privileged LLM emits
a Python program over the tool API, a quarantined LLM handles untrusted data, and a custom
interpreter runs it with capability/taint tracking under domain security policies. It does
not fit `on_pre_tool_call` — it replaces the agent loop. A faithful port needs:
1. the interpreter + value/taint machinery (portable but large),
2. a `make_namespace` over DTAP's os-filesystem tools (`read_file/write_file/edit_file/
   move_file/execute_command/...`),
3. **a brand-new os-filesystem `SecurityPolicy`** (agentdojo only ships banking/travel/
   workspace — none applies here),
4. harness changes so the privileged-plan/interpreter flow can drive the agent (beyond the
   current `Defense` hook surface).

Recommendation: treat CaMeL as its own scoped task. Options, cheapest→faithful:
(a) **scoped CaMeL** — interpreter + os-filesystem namespace + a minimal taint/policy that
covers the os-filesystem threat classes (approximate, documented as such); or
(b) **full port** — multi-day, likely needs `dt_arena` agent-loop changes. Decide scope
before starting; do not present an approximation as the published CaMeL.

Both ports get compared exactly like the trained defenses: add their package name to a
config's `defenses` list and re-run `platform.py run`.
