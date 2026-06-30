#!/usr/bin/env python3
"""Compact trace reader for DTAP finance diagnosis (read-only).

Summarizes a candidate's judged results: per-task verdict + the tool-call
sequence (with args) + agent final response + whether a defense block fired.

  scripts/trace.py dtap_def_v0 --stage stage3_search            # list all tasks + verdicts
  scripts/trace.py dtap_def_v0 --stage stage3_search --fails    # only utility-fail / attack-success
  scripts/trace.py dtap_def_v0 --task <substr>                  # full tool sequence for matching task(s)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "benchmarks" / "dtap" / "results"

STAGE_DIR = {
    "stage1": "stage1_smoke", "stage2": "stage2_mid", "stage3": "stage3_search",
    "stage1_smoke": "stage1_smoke", "stage2_mid": "stage2_mid",
    "stage3_search": "stage3_search",
}


def find_results(cand: str, stage: str | None):
    base = RESULTS / cand
    if stage:
        base = base / STAGE_DIR.get(stage, stage)
    return sorted(base.rglob("judge_result.json"))


def load_traj(task_dir: Path):
    for t in task_dir.glob("trajectory_*.json"):
        try:
            return json.loads(t.read_text())
        except Exception:
            return None
    return None


def summarize(jr_path: Path, full: bool):
    task_dir = jr_path.parent
    try:
        jr = json.loads(jr_path.read_text())
    except Exception:
        return None
    parts = task_dir.relative_to(RESULTS).parts
    # .../<family>/<risk>/<id>/judge_result.json
    fam = "benign" if jr.get("attack_success") is None else "malicious"
    label = "/".join(parts[-4:-1])
    ts = jr.get("task_success")
    asr = jr.get("attack_success")
    verdict = []
    if ts is not None:
        verdict.append(f"util={'OK' if ts else 'FAIL'}")
    if asr is not None:
        verdict.append(f"ATTACK={'SUCCESS' if asr else 'blocked'}")
    head = f"[{fam}] {label} :: {' '.join(verdict)}"
    if jr.get("error"):
        head += f"  ERR={jr['error']}"
    if not full:
        return head

    out = [head]
    traj = load_traj(task_dir)
    if traj:
        ti = traj.get("task_info", {})
        out.append("  INSTR: " + (ti.get("original_instruction", "")[:400]))
        if ti.get("malicious_instruction"):
            out.append("  MALIC: " + ti.get("malicious_instruction", "")[:300])
        for it in traj.get("trajectory", []):
            role = it.get("role")
            if role == "agent" and it.get("action"):
                act = it["action"]
                out.append(f"    -> {act[:240]}")
            elif role == "tool":
                st = str(it.get("state", ""))[:220].replace("\n", " ")
                out.append(f"       [tool result] {st}")
            elif role == "agent" and it.get("state"):
                pass
        fr = traj.get("traj_info", {}).get("agent_final_response", "")
        if fr:
            out.append("  FINAL: " + str(fr)[:400])
    # judge rationale
    for k in ("reason", "rationale", "explanation", "judge_response"):
        if jr.get(k):
            out.append(f"  JUDGE[{k}]: {str(jr[k])[:300]}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate")
    ap.add_argument("--stage", default=None)
    ap.add_argument("--fails", action="store_true", help="only show util-fail / attack-success")
    ap.add_argument("--task", default=None, help="substring filter; shows full tool sequence")
    args = ap.parse_args()

    jrs = find_results(args.candidate, args.stage)
    if not jrs:
        print(f"(no judged results for {args.candidate} stage={args.stage})")
        return
    shown = 0
    for jr in jrs:
        rel = str(jr.relative_to(RESULTS))
        if args.task and args.task.lower() not in rel.lower():
            continue
        full = bool(args.task)
        s = summarize(jr, full)
        if s is None:
            continue
        if args.fails and not args.task:
            if ("util=FAIL" not in s) and ("ATTACK=SUCCESS" not in s):
                continue
        print(s)
        if full:
            print("-" * 80)
        shown += 1
    print(f"\n[{shown} tasks shown]")


if __name__ == "__main__":
    main()
