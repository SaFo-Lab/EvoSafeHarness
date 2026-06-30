#!/usr/bin/env bash
# Run a defense candidate on a frozen TEST subset with the CONFIGURED model
# (DTAP_MODEL from .env — Sonnet 4-6), resumable (--skip-existing), durable
# results under results/_test_<splitbase>/<cand>. Unlike eval_test.sh this does
# NOT hardcode the stale zai.glm-5 model, and unlike eval_split.sh it does NOT
# rm -rf the results dir (so an interrupted run can resume).
# Usage: scripts/eval_subset.sh <split_basename> <cand1> [cand2 ...]
#        scripts/eval_subset.sh test_subset100 dtap_def_v1
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/benchmarks/dtap-src"
[ -f "$ROOT/.env" ] && set -a && . "$ROOT/.env" && set +a
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"

SPLITBASE="$1"; shift
SPLIT="$ROOT/benchmarks/dtap/splits/${SPLITBASE}.jsonl"
[ -f "$SPLIT" ] || { echo "ERROR: no split $SPLIT" >&2; exit 1; }

MODEL="${DTAP_MODEL:-$(grep -E '^DTAP_MODEL=' "$ROOT/.env" | cut -d= -f2-)}"
MODEL="${MODEL:-bedrock/us.anthropic.claude-sonnet-4-6}"
MAXP="${MAXP:-6}"

# judge proxy must be up (permission judge = Haiku)
JUDGE_PORT="${JUDGE_PROXY_PORT:-4111}"
curl -sf "http://127.0.0.1:${JUDGE_PORT}/health" >/dev/null 2>&1 || {
  echo "ERROR: judge proxy not on :$JUDGE_PORT" >&2; exit 1; }

echo "[eval_subset] split=$SPLITBASE model=$MODEL max-parallel=$MAXP n=$(wc -l <"$SPLIT")"
for CAND in "$@"; do
  RR="$ROOT/benchmarks/dtap/results/_test_${SPLITBASE}/$CAND"
  mkdir -p "$RR"
  echo "=== $(date +%H:%M:%S) $CAND on ${SPLITBASE}.jsonl ==="
  ( cd "$SRC" && DTAP_DEFENSE_CANDIDATE="$CAND" EVAL_RESULTS_ROOT="$RR" PYTHONPATH="$SRC" \
    "$ROOT/.venv/bin/python" eval/evaluation.py --task-list "$SPLIT" \
      --agent-type langchain --model "$MODEL" --max-parallel "$MAXP" --skip-existing \
      >> "$RR/run.log" 2>&1 )
  echo "=== $(date +%H:%M:%S) $CAND done (results: $RR) ==="
done
echo "ALL_DONE"
