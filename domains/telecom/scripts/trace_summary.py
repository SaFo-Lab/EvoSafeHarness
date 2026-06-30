#!/usr/bin/env python3
"""Summarize a candidate's run: per-task verdict + tool-call sequence.

Usage:
  scripts/trace_summary.py dtap_def_v0 --stage stage3_search [--only fail]
  scripts/trace_summary.py dtap_def_v0 --stage stage3_search --show-block

Prints, for every judged task in the stage:
  <type/risk>  task_id  util=.. asr=..   then the ordered tool calls (name + subject ids).
`--only fail`   -> only benign-failures and attack-successes (the losses).
Helps diagnose where poisoned content was read and which effect-bearing call landed.
"""
from __future__ import annotations
import argparse, json, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = ROOT / "benchmarks" / "dtap" / "results"

CUST = re.compile(r"CUST\d+")
ORDER = re.compile(r"O-\d+")


def load_traj(task_dir: Path):
    for f in task_dir.glob("trajectory_*.json"):
        try:
            return json.loads(f.read_text())
        except Exception:
            continue
    return None


def tool_calls(traj):
    calls = []
    for e in traj.get("trajectory", []):
        if e.get("role") == "agent" and e.get("metadata", {}).get("tool_name"):
            md = e["metadata"]
            name = md["tool_name"]
            params = md.get("tool_params", {}) or {}
            # compact subject id
            ids = []
            for k, v in params.items():
                sv = str(v)
                if k in ("customer_id", "order_id", "event_id", "email_id", "sms_id",
                         "ticket_id", "thread_id", "area", "field"):
                    ids.append(f"{k}={sv[:30]}")
            calls.append((name, ", ".join(ids), params))
    return calls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate")
    ap.add_argument("--stage", default="stage3_search")
    ap.add_argument("--only", choices=["fail", "all"], default="all")
    ap.add_argument("--full-params", action="store_true")
    args = ap.parse_args()

    base = RESULTS / args.candidate / args.stage
    rows = []
    for jr in sorted(base.rglob("judge_result.json")):
        d = json.loads(jr.read_text())
        td = jr.parent
        parts = jr.relative_to(base).parts
        # .../telecom/<benign|malicious>/<...>/<task_id>/judge_result.json
        kind = "benign" if "benign" in parts else "malicious"
        # find risk subdir
        try:
            ti = parts.index("telecom")
            tag = "/".join(parts[ti + 1:-1])
        except ValueError:
            tag = "/".join(parts[:-1])
        ts = d.get("task_success"); at = d.get("attack_success")
        traj = load_traj(td)
        calls = tool_calls(traj) if traj else []
        rows.append((kind, tag, ts, at, calls, traj))

    n_b = sum(1 for r in rows if r[0] == "benign")
    n_m = len(rows) - n_b
    util = 100*sum(1 for r in rows if r[0]=="benign" and r[2]) / n_b if n_b else 0
    asr = 100*sum(1 for r in rows if r[0]=="malicious" and r[3]) / n_m if n_m else 0
    print(f"# {args.candidate} / {args.stage}: util={util:.1f}% asr={asr:.1f}% score={util-asr:.1f}  (n_b={n_b} n_m={n_m})\n")

    for kind, tag, ts, at, calls, traj in rows:
        is_loss = (kind == "benign" and not ts) or (kind == "malicious" and at)
        if args.only == "fail" and not is_loss:
            continue
        flag = "LOSS" if is_loss else "ok  "
        verdict = f"util={ts}" if kind == "benign" else f"asr={at}"
        instr = (traj.get("task_info", {}).get("original_instruction") or "")[:90].replace("\n"," ") if traj else ""
        print(f"[{flag}] {tag:38s} {verdict:12s} | {instr}")
        for name, ids, params in calls:
            extra = ""
            if args.full_params:
                extra = "  " + json.dumps(params)[:160]
            print(f"        - {name}({ids}){extra}")
        print()


if __name__ == "__main__":
    main()
