#!/usr/bin/env python3
"""Reusable defense-evaluation platform.

Give it a CONFIG (a testset + a list of defenses + which benchmark env to drive)
and it will: run each defense on the testset (resumable, correct frozen model),
score every result tree consistently, and write a comparison table + a frozen
run manifest. Built so adding a new baseline (DRIFT, CaMeL, ...) is just adding
its name to the `defenses` list once it exists as a `dt_defenses/<name>` package.

Config (JSON), see configs/ for examples:
{
  "run_name":     "osfs_subset100",
  "env_root":     "/abs/path/to/proposer_workspace/dtap_ossystem",
  "testset":      "test_subset100",          # basename of a split in <env>/benchmarks/dtap/splits/
  "defenses":     ["dtap_def_v0", "dtap_def_v1"],
  "max_parallel": 6,
  "marker":       "Refused by security policy" # defense-refusal string for gate-fire detection
}

The per-defense result tree is the env's standard convention so existing runs are
reused automatically:  <env_root>/benchmarks/dtap/results/_test_<testset>/<defense>

Usage:
    platform.py run     configs/osfs_subset100.json     # run (resumable) + score + compare
    platform.py compare configs/osfs_subset100.json     # score existing results only, no runs
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from score import score_tree, print_summary, benign_regressions, DEFAULT_MARKER  # noqa: E402


def load_config(path: str) -> dict:
    cfg = json.load(open(path))
    cfg.setdefault("max_parallel", 6)
    cfg.setdefault("marker", DEFAULT_MARKER)
    for k in ("run_name", "env_root", "testset", "defenses"):
        if k not in cfg:
            sys.exit(f"config missing required key: {k}")
    return cfg


def result_root(cfg: dict, defense: str) -> str:
    return os.path.join(
        cfg["env_root"], "benchmarks", "dtap", "results",
        f"_test_{cfg['testset']}", defense,
    )


def run_defense(cfg: dict, defense: str) -> None:
    """Run one defense on the testset via the env's resumable eval_subset.sh."""
    runner = os.path.join(cfg["env_root"], "scripts", "eval_subset.sh")
    if not os.path.isfile(runner):
        sys.exit(f"no runner at {runner} (env_root wrong, or env lacks eval_subset.sh)")
    env = dict(os.environ, MAXP=str(cfg["max_parallel"]))
    print(f"\n=== running {defense} on {cfg['testset']} (parallel={cfg['max_parallel']}) ===",
          flush=True)
    rc = subprocess.call(["bash", runner, cfg["testset"], defense], env=env)
    if rc != 0:
        print(f"  WARNING: runner exited {rc} for {defense} (scoring whatever completed)")


def out_dir(cfg: dict) -> str:
    d = os.path.join(HERE, "results", cfg["run_name"])
    os.makedirs(d, exist_ok=True)
    return d


def write_reports(cfg: dict, scored: dict) -> None:
    od = out_dir(cfg)
    # full json
    json.dump({"config": cfg, "scores": scored},
              open(os.path.join(od, "summary.json"), "w"), indent=2)
    # freeze the testset ids used (provenance / future alignment)
    split = os.path.join(cfg["env_root"], "benchmarks", "dtap", "splits",
                         f"{cfg['testset']}.jsonl")
    if os.path.isfile(split):
        with open(split) as f, open(os.path.join(od, "testset.jsonl"), "w") as g:
            g.write(f.read())

    cols = ["defense", "n", "utility%", "ASR%", "ASR_direct%", "ASR_indirect%",
            "score", "gate_TP", "gate_benign_FP"]
    rows = []
    for name in cfg["defenses"]:
        s = scored[name]
        tm = s["asr_by_threat_model"]
        rows.append([
            name, s["n_results"],
            _f(s["benign"]["utility_pct"]), _f(s["asr_overall_pct"]),
            _f(tm.get("direct", {}).get("asr_pct")), _f(tm.get("indirect", {}).get("asr_pct")),
            _f(s["score"]), len(s["gate_fires_malicious"]), len(s["gate_fires_benign_fp"]),
        ])
    # csv
    with open(os.path.join(od, "comparison.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(cols); w.writerows(rows)
    # markdown
    md = [f"# Comparison — {cfg['run_name']}", "",
          f"- testset: `{cfg['testset']}` · env: `{cfg['env_root']}`",
          f"- model: frozen `DTAP_MODEL` from env `.env` · marker: `{cfg['marker']}`",
          "", "| " + " | ".join(cols) + " |",
          "|" + "|".join(["---"] * len(cols)) + "|"]
    for r in rows:
        md.append("| " + " | ".join(str(x) for x in r) + " |")
    md += ["", "_gate_TP = malicious tasks the defense refused; "
           "gate_benign_FP = benign tasks the defense refused that then failed (utility cost)._"]

    # Pairwise benign-regression breakdown vs the baseline (= first defense in the
    # list). Separates gate-caused FPs (attributable utility cost) from no-gate
    # regressions (run-to-run variance), since raw utility% at small n is noisy.
    base = cfg["defenses"][0]
    md += ["", f"## Benign regressions vs baseline `{base}` (gate-caused = real cost; no-gate = variance)"]
    for name in cfg["defenses"][1:]:
        reg = benign_regressions(scored[base], scored[name])
        md.append(
            f"- **{name}**: {len(reg['gate_caused'])} gate-caused FP {reg['gate_caused'] or ''} · "
            f"{len(reg['variance'])} no-gate (variance) {reg['variance'] or ''} · "
            f"{len(reg['recovered'])} recovered {reg['recovered'] or ''}")
    md += ["", "_At n=30 benign the agent has ~20pp run-to-run variance (per domain_spec); "
           "compare gate-caused FPs, not raw utility deltas._"]
    open(os.path.join(od, "comparison.md"), "w").write("\n".join(md) + "\n")
    print(f"\nwrote {od}/comparison.md , comparison.csv , summary.json , testset.jsonl")
    print("\n" + "\n".join(md))


def _f(x):
    return f"{x:.1f}" if isinstance(x, (int, float)) else "—"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["run", "compare"])
    ap.add_argument("config")
    a = ap.parse_args()
    cfg = load_config(a.config)
    scored = {}
    for d in cfg["defenses"]:
        if a.mode == "run":
            run_defense(cfg, d)
        rr = result_root(cfg, d)
        if not os.path.isdir(rr):
            print(f"  (no results for {d} at {rr}; skipping)")
            scored[d] = score_tree(rr, cfg["marker"])  # yields zeros/None
            continue
        scored[d] = score_tree(rr, cfg["marker"])
        print_summary(scored[d], d)
    write_reports(cfg, scored)


if __name__ == "__main__":
    main()
