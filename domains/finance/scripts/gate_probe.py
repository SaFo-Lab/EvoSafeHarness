#!/usr/bin/env python3
"""Offline gate probe — fast pre-cascade FP/FN sanity for a finance defense.

NOT a substitute for the cascade (synthetic args, no model loop) — a cheap
pre-filter to catch obvious over-blocks (benign in-scope effects) and confirm
the gate fires on the known attack shapes BEFORE spending a real run.

Each case feeds optional prior tool *reads* through ``on_post_tool_call`` (to
arm any taint/compromise state), then the effect call through
``on_pre_tool_call``; reports block (hook raised) vs pass.

Usage:  scripts/gate_probe.py dtap_def_v1
        scripts/gate_probe.py dtap_def_v1 --cases scripts/gate_cases.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "benchmarks" / "dtap-src"


def load_env():
    for ln in (ROOT / ".env").read_text().splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#") and "=" in ln:
            k, v = ln.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def make_ctx(tool, args, instruction, server="finance", trace_id="probe-trace"):
    from dt_arena.src.types.hooks import ToolCallContext
    md = {"instruction": instruction, "domain": "finance"}
    return ToolCallContext(framework="probe", server=server, tool_name=tool,
                           arguments=dict(args), trace_id=trace_id, metadata=md)


async def run_case(defense, case):
    """Returns (blocked: bool, err: str|None)."""
    from dt_arena.src.types.hooks import ToolCallResult
    instr = case.get("instruction", "")
    trace = case.get("trace_id", "probe-" + case.get("label", "x"))
    # 1. feed prior reads to arm any post-exec state
    for rd in case.get("prior_reads", []):
        ctx = make_ctx(rd["tool"], rd.get("args", {}), instr,
                       server=rd.get("server", "finance"), trace_id=trace)
        res = ToolCallResult(raw=rd.get("raw", ""))
        try:
            await defense.on_post_tool_call(ctx, res)
        except Exception:
            pass
    # 1b. feed prior EFFECT calls through on_pre (to build per-trace state, e.g. a
    #     round-trip/wash ledger). Swallow any block — we only want the side-effect
    #     of the defense recording these as having happened.
    for ef in case.get("prior_effects", []):
        ctx = make_ctx(ef["tool"], ef.get("args", {}), instr,
                       server=ef.get("server", "finance"), trace_id=trace)
        try:
            await defense.on_pre_tool_call(ctx)
        except Exception:
            pass
        # also feed a successful post so the defense can record completion if it does
        try:
            await defense.on_post_tool_call(ctx, ToolCallResult(raw=ef.get("raw", "ok")))
        except Exception:
            pass
    # 2. the effect call
    ctx = make_ctx(case["tool"], case.get("args", {}), instr,
                   server=case.get("server", "finance"), trace_id=trace)
    try:
        await defense.on_pre_tool_call(ctx)
        return False, None
    except Exception as e:
        return True, f"{type(e).__name__}: {e}"


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate")
    ap.add_argument("--cases", default=str(Path(__file__).resolve().parent / "gate_cases.json"))
    args = ap.parse_args()
    load_env()
    sys.path.insert(0, str(SRC))
    os.environ["DTAP_DEFENSE_CANDIDATE"] = args.candidate
    from dt_arena.src.defense.loader import _load_candidate
    defense = _load_candidate(args.candidate)
    assert defense is not None, f"could not load {args.candidate}"

    cases = json.loads(Path(args.cases).read_text())
    n_ok = n_fp = n_fn = 0
    print(f"== gate_probe {args.candidate} : {len(cases)} cases ==\n")
    for c in cases:
        blocked, err = await run_case(defense, c)
        expect = c["expect_block"]
        ok = blocked == expect
        tag = "OK " if ok else ("FP!" if (blocked and not expect) else "FN!")
        if ok:
            n_ok += 1
        elif blocked and not expect:
            n_fp += 1
        else:
            n_fn += 1
        print(f"[{tag}] {c.get('label','?'):30s} expect_block={expect} got_block={blocked}")
        if not ok and err:
            print(f"        -> {err[:150]}")
        elif blocked and err:
            print(f"        (block msg) {err[:120]}")
    print(f"\nsummary: {n_ok}/{len(cases)} ok | false-positives(benign blocked)={n_fp} | false-negatives(attack passed)={n_fn}")


if __name__ == "__main__":
    asyncio.run(main())
