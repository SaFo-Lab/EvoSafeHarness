#!/usr/bin/env python3
"""Read-only CLI over DTAP candidate history (for the proposer and humans).

Reads ``benchmarks/dtap/results/<candidate>/meta.json`` files written by
``cascade.py``. Never touches the held-out TEST split.

  runlog.py top [--by score|utility|asr] [--n 10] [--stage stage_3]
  runlog.py show <candidate>
  runlog.py failures <candidate> [--stage stage_3]
  runlog.py diff <cand_a> <cand_b>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "benchmarks" / "dtap" / "results"
DEFENSES = ROOT / "benchmarks" / "dtap-src" / "dt_defenses"


def _load_all() -> list[dict]:
    metas = []
    if not RESULTS.is_dir():
        return metas
    for meta in sorted(RESULTS.glob("*/meta.json")):
        try:
            metas.append(json.loads(meta.read_text()))
        except Exception:
            continue
    return metas


def _stage_summary(meta: dict, stage: str) -> dict:
    return (meta.get("stages", {}).get(stage, {}) or {}).get("score_summary", {}) or {}


def cmd_top(args):
    metas = _load_all()
    rows = []
    for m in metas:
        s = _stage_summary(m, args.stage)
        if s.get("score") is None and args.by == "score":
            continue
        rows.append((m["candidate"], s.get("utility_pct"), s.get("asr_pct"), s.get("score"),
                     m.get("passed_stage"), m.get("parent")))
    keyidx = {"utility": 1, "asr": 2, "score": 3}[args.by]
    reverse = args.by != "asr"  # lower ASR is better
    rows.sort(key=lambda r: (r[keyidx] is None, r[keyidx] if r[keyidx] is not None else 0), reverse=reverse)
    print(f"{'candidate':22s} {'util%':>6s} {'asr%':>6s} {'score':>7s}  {'passed':10s} parent  ({args.stage})")
    print("-" * 78)
    for c, u, a, sc, passed, parent in rows[: args.n]:
        print(f"{c:22s} {fmt(u):>6s} {fmt(a):>6s} {fmt(sc):>7s}  {str(passed):10s} {parent or ''}")


def fmt(x):
    return "-" if x is None else f"{x:.1f}"


def cmd_show(args):
    meta = RESULTS / args.candidate / "meta.json"
    if not meta.is_file():
        print(f"no meta.json for {args.candidate}")
        return
    m = json.loads(meta.read_text())
    print(json.dumps(m, indent=2))
    bundle = DEFENSES / args.candidate / "BUNDLE.md"
    if bundle.is_file():
        print("\n--- BUNDLE.md ---")
        print(bundle.read_text())


def cmd_failures(args):
    root = RESULTS / args.candidate / args.stage
    if not root.is_dir():
        print(f"no results dir {root}")
        return
    n = 0
    for jr in sorted(root.rglob("judge_result.json")):
        data = json.loads(jr.read_text())
        rel = jr.parent.relative_to(root)
        benign = data.get("attack_success") is None
        failed = (benign and not data.get("task_success")) or (not benign and data.get("attack_success"))
        if failed:
            n += 1
            kind = "UTILITY-MISS" if benign else "ATTACK-SUCCESS"
            msg = data.get("task_message") if benign else data.get("attack_message")
            print(f"[{kind}] {rel}\n    {str(msg)[:240]}")
    if n == 0:
        print("no failing tasks (all benign passed, no attacks succeeded)")


def cmd_diff(args):
    for cand in (args.a, args.b):
        m = RESULTS / cand / "meta.json"
        s = _stage_summary(json.loads(m.read_text()), "stage_3") if m.is_file() else {}
        print(f"{cand:22s} util={fmt(s.get('utility_pct'))} asr={fmt(s.get('asr_pct'))} score={fmt(s.get('score'))}")
    for cand in (args.a, args.b):
        b = DEFENSES / cand / "BUNDLE.md"
        print(f"\n=== {cand}/BUNDLE.md ===\n{b.read_text() if b.is_file() else '(missing)'}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("top"); p.add_argument("--by", choices=["score", "utility", "asr"], default="score")
    p.add_argument("--n", type=int, default=10); p.add_argument("--stage", default="stage_3"); p.set_defaults(fn=cmd_top)

    p = sub.add_parser("show"); p.add_argument("candidate"); p.set_defaults(fn=cmd_show)

    p = sub.add_parser("failures"); p.add_argument("candidate"); p.add_argument("--stage", default="stage_3")
    p.set_defaults(fn=cmd_failures)

    p = sub.add_parser("diff"); p.add_argument("a"); p.add_argument("b"); p.set_defaults(fn=cmd_diff)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
