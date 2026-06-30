#!/usr/bin/env bash
# Thin wrapper around the DTAP evaluation CLI for the os-filesystem training env.
#
# Loads $ROOT/.env, sets PYTHONPATH so the vendored source + dt_defenses resolve,
# runs everything from the vendored source root (required: eval/evaluation.py uses
# relative imports and per-task Docker/MCP setup), and applies sensible defaults
# (langchain backend, zai.glm-5 via Bedrock). Pass through any extra eval flags.
#
# Example:
#   DTAP_DEFENSE_CANDIDATE=dtap_def_v0 \
#   bash scripts/run_dtap.sh --task-list benchmarks/dtap/splits/stage1_smoke.jsonl --max-parallel 2
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/benchmarks/dtap-src"
VENV_PY="$ROOT/.venv/bin/python"

# shellcheck disable=SC1090
[ -f "$ROOT/.env" ] && set -a && . "$ROOT/.env" && set +a

# Some code paths touch an OpenAI client during arg parsing; keep a dummy set.
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
export PYTHONPATH="$SRC:${PYTHONPATH:-}"

# Ensure the permission judge (Claude Haiku 4.5 on Bedrock, OpenAI-compatible
# shim) is up. Benign + indirect tasks deny every permission request without it,
# which silently caps measured utility. Malicious/direct tasks bypass it via
# their own PERMISSION_AUTO_APPROVE=true.
JUDGE_PORT="${JUDGE_PROXY_PORT:-4111}"
if ! curl -sf "http://127.0.0.1:${JUDGE_PORT}/health" >/dev/null 2>&1; then
  echo "[run_dtap] starting permission-judge proxy on :${JUDGE_PORT} (Haiku 4.5 / Bedrock)"
  setsid "$VENV_PY" "$ROOT/scripts/judge_proxy.py" --port "$JUDGE_PORT" \
    > /tmp/judge_proxy.log 2>&1 < /dev/null &
  disown
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:${JUDGE_PORT}/health" >/dev/null 2>&1 && break
    sleep 1
  done
fi
if ! curl -sf "http://127.0.0.1:${JUDGE_PORT}/health" >/dev/null 2>&1; then
  echo "[run_dtap] ERROR: permission-judge proxy not reachable on :${JUDGE_PORT}; see /tmp/judge_proxy.log" >&2
  exit 1
fi
echo "[run_dtap] permission judge: $(curl -sf http://127.0.0.1:${JUDGE_PORT}/health)"

MODEL="${DTAP_MODEL:-zai.glm-5}"
AGENT="${DTAP_AGENT_TYPE:-langchain}"

# Resolve a relative --task-list against $ROOT before we cd into $SRC.
args=()
while [ $# -gt 0 ]; do
  if [ "$1" = "--task-list" ]; then
    args+=("$1"); shift
    case "$1" in
      /*) args+=("$1") ;;
      *)  args+=("$ROOT/$1") ;;
    esac
    shift
  else
    args+=("$1"); shift
  fi
done

cd "$SRC"

# Snapshot the cost log so we can report ONLY this run's spend at the end
# (the log is shared/appended across runs + the judge proxy).
COST_LOG="${DTAP_COST_LOG:-$ROOT/benchmarks/dtap/cost_events.jsonl}"
COST_PRE=0
[ -f "$COST_LOG" ] && COST_PRE=$(wc -l < "$COST_LOG" | tr -d ' ')

set +e
"$VENV_PY" eval/evaluation.py \
  --agent-type "$AGENT" \
  --model "$MODEL" \
  "${args[@]}"
RC=$?
set -e

echo
echo "[run_dtap] ===== cost for this run (model=$MODEL) ====="
"$VENV_PY" "$ROOT/scripts/cost_report.py" --since-line "$COST_PRE" || true

exit "$RC"
