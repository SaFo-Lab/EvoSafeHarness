#!/usr/bin/env python3
"""Build the frozen TRAIN (60) + held-out TEST (100) splits for a single DTAP domain.

Mirrors the curation used for `dtap_ossystem` so a new single-domain env is
directly comparable:

  TRAIN  = 60  tasks = 20 benign / 20 direct / 20 indirect   (proposer search pool)
  TEST   = held-out remainder (pool - TRAIN), proposer must NOT read
  TEST_SUBSET100 = 100 tasks = 30 benign / 35 direct / 35 indirect   (TEST ⊂)

Stratification key = risk_category (round-robin) inside each of the three
buckets, so every category of the domain's taxonomy is represented and the
held-out test reuses different task_ids than TRAIN (genuine generalization).

The script enumerates tasks directly from the dataset tree (every directory
containing a `config.yaml`), so it adapts to:
  - flat benign     dataset/<domain>/benign/<task_id>/                (telecom, os-filesystem, crm, ...)
  - nested benign   dataset/<domain>/benign/<risk_category>/<task_id>/ (finance, code, legal, research)
  - malicious       dataset/<domain>/malicious/<threat_model>/<risk_category>/<task_id>/

Outputs (under benchmarks/):
  dtap-src/benchmark/<domain>/{benign,direct,indirect}.jsonl   full pool manifest
  dtap/splits/train.jsonl                  60-task TRAIN pool
  dtap/splits/test.jsonl                   held-out remainder (TEST)
  dtap/splits/test_subset100.jsonl         100-task frozen held-out subset (TEST ⊂)
  dtap/splits/stage1_smoke.jsonl  (3)      cascade smoke subset   (TRAIN ⊂)
  dtap/splits/stage2_mid.jsonl    (12)     cascade gated subset   (TRAIN ⊂)
  dtap/splits/stage3_search.jsonl (30)     cascade scored subset  (TRAIN ⊂)
  dtap/splits/stage4_wide.jsonl   (60)     full TRAIN pool
  dtap/split_manifest.json                 counts, seed, distributions
  dtap/splits/test_subset100.manifest.json seed + per-category allocation

Deterministic: same (domain, seed) reproduces byte-identical files.
"""
from __future__ import annotations

import argparse
import json
import os
import random
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / "benchmarks" / "dtap-src"
OUT = ROOT / "benchmarks" / "dtap"
SPLITS = OUT / "splits"

TRAIN_PER_BUCKET = 20                                # 20 + 20 + 20 = 60
TEST_TARGETS = {"benign": 30, "direct": 35, "indirect": 35}   # = 100
STAGE_SIZES = {"stage1_smoke": 3, "stage2_mid": 12, "stage3_search": 30}


# --------------------------------------------------------------------------- #
# enumeration
# --------------------------------------------------------------------------- #
def _dataset_root() -> Path:
    env = os.environ.get("DTAP_DATASET_ROOT")
    if env:
        return Path(env)
    return SRC / "dataset"


def enumerate_domain(domain: str) -> list[dict]:
    """Return one record per task dir (a dir containing config.yaml)."""
    root = _dataset_root() / domain
    if not root.is_dir():
        raise SystemExit(f"[ERROR] dataset domain not found: {root}")
    records: list[dict] = []
    for cfg in sorted(root.rglob("config.yaml")):
        rel = cfg.parent.relative_to(root).parts          # parts after <domain>/
        if not rel:
            continue
        kind = rel[0]
        if kind == "benign":
            if len(rel) == 2:                              # benign/<task_id>
                records.append({"domain": domain, "type": "benign", "task_id": rel[1]})
            elif len(rel) == 3:                            # benign/<cat>/<task_id>
                records.append({"domain": domain, "type": "benign",
                                "risk_category": rel[1], "task_id": rel[2]})
        elif kind == "malicious" and len(rel) == 4:        # malicious/<tm>/<cat>/<id>
            records.append({"domain": domain, "type": "malicious",
                            "threat_model": rel[1], "risk_category": rel[2],
                            "task_id": rel[3]})
    return records


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _bucket(r: dict) -> str:
    return "benign" if r["type"] == "benign" else r.get("threat_model", "malicious")


def _stratum(r: dict) -> str:
    if r["type"] == "benign":
        return r.get("risk_category", "_flat")
    return r.get("risk_category", "-")


def _ident(r: dict):
    return (r.get("domain", ""), r["type"], r.get("threat_model", ""),
            r.get("risk_category", ""), str(r["task_id"]))


def _id_sort(r: dict):
    tid = str(r["task_id"])
    return (int(tid), "") if tid.isdigit() else (1 << 30, tid)


def _key(r: dict):
    return (r["type"], r.get("threat_model", ""), r.get("risk_category", ""), _id_sort(r))


def _rr_sample(pool, k, rng):
    """Round-robin over risk-category strata, deterministic. Returns up to k recs."""
    if k <= 0 or not pool:
        return []
    if k >= len(pool):
        return list(pool)
    by_s = defaultdict(list)
    for r in pool:
        by_s[_stratum(r)].append(r)
    for s in by_s:
        by_s[s].sort(key=_id_sort)
        rng.shuffle(by_s[s])
    chosen, strata = [], sorted(by_s)
    while len(chosen) < k:
        progressed = False
        for s in strata:
            if by_s[s]:
                chosen.append(by_s[s].pop())
                progressed = True
                if len(chosen) == k:
                    break
        if not progressed:
            break
    return chosen


def _balanced_sample(pool, k, rng):
    """Pick k records balanced across benign/direct/indirect, then round-robin
    across risk categories inside each bucket. (Used for cascade stage subsets.)"""
    if k >= len(pool):
        return list(pool)
    buckets = defaultdict(list)
    for r in pool:
        buckets[_bucket(r)].append(r)
    order = ["benign", "direct", "indirect"]
    base, extra = divmod(k, 3)
    alloc = {b: base for b in order}
    for i in range(extra):
        alloc[order[i]] += 1
    chosen = []
    for b in order:
        chosen.extend(_rr_sample(buckets.get(b, []), alloc[b], rng))
    return chosen


def _write_jsonl(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in sorted(records, key=_key):
            f.write(json.dumps(r) + "\n")


def _alloc(records) -> dict:
    d = defaultdict(int)
    for r in records:
        d[_stratum(r)] += 1
    return dict(sorted(d.items()))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--seed", type=int, default=20260604)
    args = ap.parse_args()
    domain = args.domain

    records = enumerate_domain(domain)
    by_bucket = defaultdict(list)
    for r in records:
        by_bucket[_bucket(r)].append(r)
    pools = {b: by_bucket.get(b, []) for b in ("benign", "direct", "indirect")}

    # feasibility check
    need = {"benign": TRAIN_PER_BUCKET + TEST_TARGETS["benign"],
            "direct": TRAIN_PER_BUCKET + TEST_TARGETS["direct"],
            "indirect": TRAIN_PER_BUCKET + TEST_TARGETS["indirect"]}
    for b in pools:
        if len(pools[b]) < need[b]:
            raise SystemExit(f"[ERROR] {domain} {b}: pool {len(pools[b])} < required {need[b]}")

    # write the full pool manifest
    bench = SRC / "benchmark" / domain
    _write_jsonl(bench / "benign.jsonl", pools["benign"])
    _write_jsonl(bench / "direct.jsonl", pools["direct"])
    _write_jsonl(bench / "indirect.jsonl", pools["indirect"])

    # TRAIN: 20 / 20 / 20, round-robin across categories
    rng_tr = random.Random(args.seed)
    train = []
    for b in ("benign", "direct", "indirect"):
        train.extend(_rr_sample(pools[b], TRAIN_PER_BUCKET, rng_tr))
    train_idents = {_ident(r) for r in train}
    assert len(train) == 60, len(train)

    # TEST = pool - TRAIN  (full held-out remainder)
    test = [r for r in records if _ident(r) not in train_idents]

    # TEST_SUBSET100: from TEST, 30 / 35 / 35, round-robin across categories
    rng_te = random.Random(args.seed + 100)
    test_by_bucket = defaultdict(list)
    for r in test:
        test_by_bucket[_bucket(r)].append(r)
    subset = []
    for b in ("benign", "direct", "indirect"):
        subset.extend(_rr_sample(test_by_bucket[b], TEST_TARGETS[b], rng_te))
    subset_idents = {_ident(r) for r in subset}

    # cascade stage subsets (drawn from TRAIN)
    stages = {}
    for key, size in STAGE_SIZES.items():
        stages[key] = _balanced_sample(train, size, random.Random(args.seed + size))
    stages["stage4_wide"] = list(train)

    # ---- invariants ----
    assert train_idents.isdisjoint(subset_idents), "TRAIN ∩ TEST_SUBSET100 != 0"
    assert all(_ident(r) not in train_idents for r in test), "TRAIN leaked into TEST"
    assert subset_idents.issubset({_ident(r) for r in test}), "subset not ⊂ TEST"
    assert len(subset) == 100, len(subset)
    sb = defaultdict(int)
    for r in subset:
        sb[_bucket(r)] += 1
    assert dict(sb) == TEST_TARGETS, dict(sb)

    # ---- write splits ----
    _write_jsonl(SPLITS / "train.jsonl", train)
    _write_jsonl(SPLITS / "test.jsonl", test)
    _write_jsonl(SPLITS / "test_subset100.jsonl", subset)
    for key, recs in stages.items():
        _write_jsonl(SPLITS / f"{key}.jsonl", recs)

    # ---- manifests ----
    split_manifest = {
        "domain": domain,
        "seed": args.seed,
        "stratify_key": "risk_category (round-robin within bucket)",
        "counts": {
            "pool_benign": len(pools["benign"]),
            "pool_direct": len(pools["direct"]),
            "pool_indirect": len(pools["indirect"]),
            "train": len(train),
            "test_heldout": len(test),
            "test_subset100": len(subset),
            **{k: len(v) for k, v in stages.items()},
        },
        "train_distribution": {b: _alloc([r for r in train if _bucket(r) == b])
                               for b in ("benign", "direct", "indirect")},
        "note": ("TRAIN is the proposer search pool (60 = 20/20/20). TEST is the "
                 "held-out remainder; test_subset100 ⊂ TEST is the frozen 100-task "
                 "(30/35/35) held-out evaluation. TRAIN ∩ TEST = 0. Frozen once "
                 "search starts."),
    }
    (OUT / "split_manifest.json").write_text(json.dumps(split_manifest, indent=2) + "\n")

    subset_manifest = {
        "seed": args.seed + 100,
        "targets": TEST_TARGETS,
        "source": "splits/test.jsonl",
        "allocation": {
            "benign": _alloc([r for r in subset if _bucket(r) == "benign"]),
            "direct": _alloc([r for r in subset if _bucket(r) == "direct"]),
            "indirect": _alloc([r for r in subset if _bucket(r) == "indirect"]),
        },
        "n_total": 100,
        "composition": dict(sb),
        "disjoint_from_train": True,
    }
    (SPLITS / "test_subset100.manifest.json").write_text(json.dumps(subset_manifest, indent=2) + "\n")

    # ---- report ----
    print(f"[{domain}] pool: benign={len(pools['benign'])} direct={len(pools['direct'])} indirect={len(pools['indirect'])}")
    print(f"[{domain}] TRAIN=60 (20/20/20)  TEST_heldout={len(test)}  TEST_SUBSET100=100 (30/35/35)")
    print(f"[{domain}] TRAIN ∩ TEST_SUBSET100 = 0  ✓   subset ⊂ TEST ✓")
    print(f"[{domain}] stages: " + " ".join(f"{k}={len(v)}" for k, v in stages.items()))
    print("  train direct categories:", json.dumps(split_manifest["train_distribution"]["direct"]))


if __name__ == "__main__":
    main()
