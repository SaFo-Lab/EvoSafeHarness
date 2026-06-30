#!/usr/bin/env python3
"""Offline validator for the caller-scope extractor.

Loads every TRAIN task's trusted instruction + (for malicious) the malicious
goal, runs the candidate extractor, and reports whether:
  - benign:    the caller's own id is recognised as OWNED (scope non-empty, correct)
  - malicious: the attack's *target* id is NOT in the owned scope (would be gated)

Pure string analysis, no model calls. Lets us tune the ownership heuristic to
cleanly separate self-service from third-party-command BEFORE a cascade run.
"""
from __future__ import annotations
import sys, json, yaml, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DS = ROOT / "benchmarks" / "dtap-src" / "dataset" / "telecom"
sys.path.insert(0, str(ROOT / "benchmarks" / "dtap-src" / "dt_defenses"))

# import the extractor under test from the v1 package (falls back to local copy)
def get_extractor():
    import importlib
    mod = importlib.import_module("dtap_def_v1.defense")
    return mod.extract_owned_scope

CUST = re.compile(r"CUST\d+")
ORDER = re.compile(r"O-\d+")


def goal_target_ids(goal: str):
    return set(CUST.findall(goal)) | set(ORDER.findall(goal))


def main():
    try:
        extract = get_extractor()
    except Exception as e:
        print(f"could not import dtap_def_v1.defense.extract_owned_scope: {e}")
        sys.exit(1)

    benign_ok = benign_bad = 0
    mal_gated = mal_slip = 0
    rows = []
    for line in open(ROOT / "benchmarks/dtap/splits/train.jsonl"):
        d = json.loads(line)
        t = d["type"]; tid = d["task_id"]
        if t == "benign":
            p = DS / "benign" / tid / "config.yaml"
        else:
            p = DS / "malicious" / d["threat_model"] / d["risk_category"] / tid / "config.yaml"
        if not p.exists():
            continue
        c = yaml.safe_load(p.read_text())
        instr = (c.get("Task", {}).get("task_instruction") or "").strip()
        owned = extract(instr)
        owned_ids = owned if isinstance(owned, set) else set(owned)
        if t == "benign":
            ids = set(CUST.findall(instr)) | set(ORDER.findall(instr))
            # benign: every id the user names should be owned (self-service)
            ok = ids.issubset(owned_ids) if ids else True  # forum/area tasks: no cust id
            benign_ok += ok; benign_bad += (not ok)
            if not ok:
                rows.append(("BENIGN-MISSCOPE", tid, instr[:70], f"ids={ids} owned={owned_ids}"))
        else:
            goal = c.get("Attack", {}).get("malicious_goal", "")
            tgts = goal_target_ids(goal)
            # attack gated iff at least one target id is NOT owned
            gated = any(g not in owned_ids for g in tgts) if tgts else None
            if gated is None:
                rows.append(("MAL-NOTARGETID", f"{d['threat_model']}/{d['risk_category']}/{tid}", goal[:70], f"owned={owned_ids}"))
            elif gated:
                mal_gated += 1
            else:
                mal_slip += 1
                rows.append(("MAL-SLIP", f"{d['threat_model']}/{d['risk_category']}/{tid}", goal[:70], f"tgts={tgts} owned={owned_ids}"))

    print(f"BENIGN: {benign_ok} correctly-scoped, {benign_bad} mis-scoped (would over-block)")
    print(f"MALICIOUS: {mal_gated} target-off-scope (gated), {mal_slip} target-in-scope (slip)\n")
    for tag, tid, txt, extra in rows:
        print(f"[{tag}] {tid}\n    {txt}\n    {extra}")


if __name__ == "__main__":
    main()
