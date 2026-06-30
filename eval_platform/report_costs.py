#!/usr/bin/env python3
"""Per-(domain,defense) cost from the dedicated logs written by run_baselines.sh.

base-agent cost  = costs/<domain>_<defense>_agent.jsonl   (Sonnet, dominant)
judge+auditor    = costs/<domain>_judge.jsonl sliced by costs/<domain>_judge_boundaries.tsv
                   (Haiku permission judge + CaMeL/DRIFT quarantined-LLM calls)

Usage: report_costs.py <env_root> <domain> [defense ...]
Cost events are one JSON/line: {cost_usd,input_tokens,cached_input_tokens,
cache_creation_tokens,output_tokens,model,...}.
"""
import json, os, sys

DEFENSES_DEFAULT = ["dtap_def_v0", "dtap_camel_v1", "dtap_drift_v1"]


def agg(lines):
    t = dict(calls=0, cost=0.0, inp=0, cin=0, ccreate=0, out=0)
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            e = json.loads(ln)
        except Exception:
            continue
        t["calls"] += 1
        t["cost"] += e.get("cost_usd") or 0.0
        t["inp"] += e.get("input_tokens") or 0
        t["cin"] += e.get("cached_input_tokens") or 0
        t["ccreate"] += e.get("cache_creation_tokens") or 0
        t["out"] += e.get("output_tokens") or 0
    return t


def read(path):
    return open(path).read().splitlines() if os.path.isfile(path) else []


def main():
    env_root, domain = sys.argv[1], sys.argv[2]
    defenses = sys.argv[3:] or DEFENSES_DEFAULT
    costs = os.path.join(env_root, "benchmarks", "dtap", "costs")
    judge_log = os.path.join(costs, f"{domain}_judge.jsonl")
    judge_lines = read(judge_log)

    # boundaries: defense -> start line in judge log (+ __end__)
    bnd = {}
    bpath = os.path.join(costs, f"{domain}_judge_boundaries.tsv")
    order = []
    for ln in read(bpath):
        name, start = ln.split("\t")
        bnd[name] = int(start)
        order.append(name)

    rows = []
    grand = dict(cost=0.0)
    for i, d in enumerate(defenses):
        agent = agg(read(os.path.join(costs, f"{domain}_{d}_agent.jsonl")))
        # judge window [start, next_start)
        if d in bnd:
            start = bnd[d]
            nxt = order[order.index(d) + 1] if order.index(d) + 1 < len(order) else None
            end = bnd[nxt] if nxt else len(judge_lines)
            judge = agg(judge_lines[start:end])
        else:
            judge = agg([])  # judge attribution unavailable
        total = agent["cost"] + judge["cost"]
        grand["cost"] += total
        rows.append((d, agent, judge, total))

    print(f"\n=== COST — {domain} ({env_root}) ===")
    hdr = f"{'defense':<16} {'agent$':>9} {'judge$':>8} {'TOTAL$':>9} {'agent_calls':>11} {'in_tok':>10} {'cached_in':>11} {'out_tok':>9}"
    print(hdr); print("-" * len(hdr))
    for d, a, j, total in rows:
        print(f"{d:<16} {a['cost']:>9.3f} {j['cost']:>8.3f} {total:>9.3f} "
              f"{a['calls']:>11} {a['inp']:>10} {a['cin']:>11} {a['out']:>9}")
    print("-" * len(hdr))
    print(f"{'DOMAIN TOTAL':<16} {'':>9} {'':>8} {grand['cost']:>9.3f}")

    out = {"domain": domain, "env_root": env_root,
           "defenses": {d: {"agent": a, "judge": j, "total_usd": total}
                        for d, a, j, total in rows},
           "domain_total_usd": grand["cost"]}
    op = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", f"cost_{domain}.json")
    os.makedirs(os.path.dirname(op), exist_ok=True)
    json.dump(out, open(op, "w"), indent=2)
    print(f"wrote {op}")


if __name__ == "__main__":
    main()
