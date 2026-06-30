#!/usr/bin/env python3
"""Score the full cross-model matrix and aggregate per-cell agent (victim) cost.

For every (victim_model, domain, defense) cell:
  - util% / ASR%(dir/ind) / score / gate TP / benign-FP   via score.score_tree
  - agent $ + LLM calls   from the dedicated per-cell cost log
    (<safe_model>__<domain>__<defense>__<split>_agent.jsonl, gapfill appends to same)

Sonnet reference (os-filesystem) is scored from the harness_archive tree.
finance/telecom Sonnet are taken from the prior RESULTS doc (printed as known).

Usage: score_matrix.py            # prints table + writes results/CROSS_MODEL_RESULTS.{md,json}
"""
import json, os, glob, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from score import score_tree  # noqa

SPLIT = "test_subset100"
MARKER = "Refused by security policy"
DOMAINS = [("os-filesystem", "dtap_ossystem"), ("finance", "dtap_finance"), ("telecom", "dtap_telecom")]
DEFENSES = ["dtap_def_v0", "dtap_camel_v1", "dtap_drift_v1"]
MODELS = [("GLM-5", "bedrock/zai.glm-5"), ("Kimi-2.5", "bedrock/moonshotai.kimi-k2.5"),
          ("Qwen3.7-plus", "openrouter/qwen/qwen3.7-plus"),
          ("DeepSeek-v4-flash", "openrouter/deepseek/deepseek-v4-flash")]  # cells skipped until a run exists


def safe(m):
    return m.replace("/", "_").replace(":", "_")


def cost_for(env, model, domain, defense):
    sm = safe(model)
    p = os.path.join(WS, env, "benchmarks", "dtap", "costs",
                     f"{sm}__{domain}__{defense}__{SPLIT}_agent.jsonl")
    c = calls = inp = cin = out = 0
    if os.path.isfile(p):
        for ln in open(p):
            ln = ln.strip()
            if not ln:
                continue
            try:
                e = json.loads(ln)
            except Exception:
                continue
            calls += 1
            c += e.get("cost_usd") or 0.0
            inp += e.get("input_tokens") or 0
            cin += e.get("cached_input_tokens") or 0
            out += e.get("output_tokens") or 0
    return dict(cost=c, calls=calls, inp=inp, cin=cin, out=out)


def cell_tree(env, defense, model):
    return os.path.join(WS, env, "benchmarks", "dtap", "results", f"_test_{SPLIT}",
                        defense, "benchmark", "langchain", safe(model))


def fnum(x):
    return f"{x:.1f}" if isinstance(x, (int, float)) else "—"


def score_cell(tree):
    s = score_tree(tree, MARKER)
    asr_tm = s["asr_by_threat_model"]
    d = asr_tm.get("direct", {}).get("asr_pct")
    i = asr_tm.get("indirect", {}).get("asr_pct")
    return dict(n=s["n_results"], util=s["benign"]["utility_pct"], asr=s["asr_overall_pct"],
                asr_d=d, asr_i=i, score=s["score"],
                tp=len(s["gate_fires_malicious"]), fp=len(s["gate_fires_benign_fp"]))


def main():
    rows = []
    grand = {m[0]: 0.0 for m in MODELS}
    for mname, mid in MODELS:
        for domain, env in DOMAINS:
            for d in DEFENSES:
                tree = cell_tree(env, d, mid)
                if not os.path.isdir(tree):
                    continue
                sc = score_cell(tree)
                co = cost_for(env, mid, domain, d)
                grand[mname] += co["cost"]
                rows.append(dict(model=mname, domain=domain, defense=d.replace("dtap_def_", "").replace("dtap_", ""),
                                 **sc, **co))
    # print
    hdr = f"{'model':<9} {'domain':<13} {'defense':<9} {'n':>4} {'util':>6} {'ASRall':>7} {'ASR_d':>6} {'ASR_i':>6} {'score':>7} {'TP':>3} {'FP':>3} {'agent$':>8} {'calls':>7}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['model']:<9} {r['domain']:<13} {r['defense']:<9} {r['n']:>4} "
              f"{fnum(r['util']):>6} {fnum(r['asr']):>7} {fnum(r['asr_d']):>6} {fnum(r['asr_i']):>6} "
              f"{fnum(r['score']):>7} {r['tp']:>3} {r['fp']:>3} {r['cost']:>8.3f} {r['calls']:>7}")
    print("-" * len(hdr))
    for m, tot in grand.items():
        print(f"{m} agent-cost total: ${tot:.2f}")
    # write json
    out = {"split": SPLIT, "marker": MARKER, "rows": rows, "agent_cost_total": grand}
    json.dump(out, open(os.path.join(HERE, "results", "CROSS_MODEL_RESULTS.json"), "w"), indent=2)
    print("\nwrote results/CROSS_MODEL_RESULTS.json")


if __name__ == "__main__":
    main()
