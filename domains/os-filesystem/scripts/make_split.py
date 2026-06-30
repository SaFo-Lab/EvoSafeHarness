#!/usr/bin/env python3
"""Build the frozen train/test split + cascade stage subsets for DTAP os-filesystem.

Reads the three benchmark task lists shipped with the domain
(``benchmark/os-filesystem/{benign,direct,indirect}.jsonl``), performs a
deterministic stratified split into a small TRAIN search pool and a large
held-out TEST set, then carves cheap cascade stage subsets out of TRAIN.

Stratification key = (type, threat_model, risk_category) so every cell of the
risk taxonomy is represented proportionally in both halves and in every stage.

Outputs (under ``benchmarks/dtap/``):
  split_manifest_v1.json     full manifest (counts, seed, record lists)
  splits/train.jsonl         TRAIN search pool      (~20%)
  splits/test.jsonl          held-out TEST set      (~80%, proposer must NOT read)
  splits/stage1_smoke.jsonl  fixed smoke subset     (TRAIN ⊃)
  splits/stage2_mid.jsonl    gated mid subset       (TRAIN ⊃)
  splits/stage3_search.jsonl scored search subset   (TRAIN ⊃)

Re-running with the same seed reproduces byte-identical files. Do NOT re-run
once search has started — the manifest is a frozen artifact.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                                  # proposer_workspace/dtap_ossystem
SRC = ROOT / "benchmarks" / "dtap-src"
BENCH = SRC / "benchmark" / "os-filesystem"
OUT = ROOT / "benchmarks" / "dtap"
SPLITS = OUT / "splits"

TASK_FILES = ["benign.jsonl", "direct.jsonl", "indirect.jsonl"]


def _stratum(rec: dict) -> str:
    return "/".join([
        rec.get("type", "?"),
        rec.get("threat_model", "-"),
        rec.get("risk_category", "-"),
    ])


def _load_records() -> list[dict]:
    records: list[dict] = []
    for fn in TASK_FILES:
        path = BENCH / fn
        with path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def _stratified_split(records, train_frac, seed):
    """Split records into (train, test) stratified by `_stratum`, deterministic."""
    rng = random.Random(seed)
    by_stratum = defaultdict(list)
    for r in records:
        by_stratum[_stratum(r)].append(r)
    train, test = [], []
    for stratum in sorted(by_stratum):
        items = sorted(by_stratum[stratum], key=lambda r: (r["type"], r.get("threat_model", ""), r.get("risk_category", ""), int(r["task_id"])))
        rng.shuffle(items)
        # ceil so every non-empty stratum contributes >=1 train example
        n_train = max(1, round(len(items) * train_frac))
        train.extend(items[:n_train])
        test.extend(items[n_train:])
    return train, test


def _type_bucket(rec: dict) -> str:
    """Top-level bucket for balancing: benign / direct / indirect."""
    if rec.get("type") == "benign":
        return "benign"
    return rec.get("threat_model", "malicious")  # 'direct' or 'indirect'


def _rr_sample(pool, k, rng):
    """Round-robin over risk-category strata within one bucket, deterministic."""
    if k <= 0 or not pool:
        return []
    if k >= len(pool):
        return list(pool)
    by_stratum = defaultdict(list)
    for r in pool:
        by_stratum[_stratum(r)].append(r)
    for s in by_stratum:
        by_stratum[s] = sorted(by_stratum[s], key=lambda r: int(r["task_id"]))
        rng.shuffle(by_stratum[s])
    chosen, strata = [], sorted(by_stratum)
    while len(chosen) < k:
        progressed = False
        for s in strata:
            if by_stratum[s]:
                chosen.append(by_stratum[s].pop())
                progressed = True
                if len(chosen) == k:
                    break
        if not progressed:
            break
    return chosen


def _stratified_sample(pool, k, seed):
    """Pick k records balanced across benign/direct/indirect, then by risk cat.

    Utility is estimated only on benign tasks and ASR only on malicious tasks,
    so every stage needs a healthy share of all three buckets. We allocate ~k/3
    to each bucket (remainder to benign first), then round-robin across risk
    categories inside each malicious bucket. Deterministic for a fixed seed.
    """
    if k >= len(pool):
        return list(pool)
    rng = random.Random(seed)
    buckets = defaultdict(list)
    for r in pool:
        buckets[_type_bucket(r)].append(r)

    order = ["benign", "direct", "indirect"]
    base, extra = divmod(k, 3)
    alloc = {b: base for b in order}
    for i in range(extra):  # give leftovers to benign, then direct
        alloc[order[i]] += 1

    chosen = []
    for b in order:
        chosen.extend(_rr_sample(buckets.get(b, []), alloc[b], rng))
    return chosen


def _key(r):
    return (r["type"], r.get("threat_model", ""), r.get("risk_category", ""), int(r["task_id"]))


def _write_jsonl(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in sorted(records, key=_key):
            f.write(json.dumps(r) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train-frac", type=float, default=0.20)
    ap.add_argument("--stage1", type=int, default=3, help="fixed smoke subset size")
    ap.add_argument("--stage2", type=int, default=12, help="gated mid subset size")
    ap.add_argument("--stage3", type=int, default=30, help="scored search subset size")
    args = ap.parse_args()

    records = _load_records()
    train, test = _stratified_split(records, args.train_frac, args.seed)

    # cascade subsets are drawn from TRAIN only
    stage1 = _stratified_sample(train, args.stage1, seed=args.seed + 1)
    stage2 = _stratified_sample(train, args.stage2, seed=args.seed + 2)
    stage3 = _stratified_sample(train, args.stage3, seed=args.seed + 3)

    def dist(recs):
        d = defaultdict(int)
        for r in recs:
            d[_stratum(r)] += 1
        return dict(sorted(d.items()))

    manifest = {
        "version": 1,
        "domain": "os-filesystem",
        "seed": args.seed,
        "train_frac": args.train_frac,
        "stratify_key": "type/threat_model/risk_category",
        "counts": {
            "total": len(records),
            "train": len(train),
            "test": len(test),
            "stage1_smoke": len(stage1),
            "stage2_mid": len(stage2),
            "stage3_search": len(stage3),
        },
        "train_distribution": dist(train),
        "test_distribution": dist(test),
        "train": sorted(train, key=_key),
        "test": sorted(test, key=_key),
        "stage1_smoke": sorted(stage1, key=_key),
        "stage2_mid": sorted(stage2, key=_key),
        "stage3_search": sorted(stage3, key=_key),
        "note": (
            "Frozen artifact. TRAIN is the proposer search pool; cascade stages "
            "sample subsets of TRAIN. TEST is held out for final evaluation and "
            "must NOT be read by the proposer during search."
        ),
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "split_manifest_v1.json").write_text(json.dumps(manifest, indent=2) + "\n")
    _write_jsonl(SPLITS / "train.jsonl", train)
    _write_jsonl(SPLITS / "test.jsonl", test)
    _write_jsonl(SPLITS / "stage1_smoke.jsonl", stage1)
    _write_jsonl(SPLITS / "stage2_mid.jsonl", stage2)
    _write_jsonl(SPLITS / "stage3_search.jsonl", stage3)

    print(f"wrote {OUT/'split_manifest_v1.json'}")
    print(json.dumps(manifest["counts"], indent=2))
    print("train distribution:")
    for k, v in manifest["train_distribution"].items():
        print(f"  {v:3d}  {k}")


if __name__ == "__main__":
    main()
