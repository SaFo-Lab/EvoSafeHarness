#!/usr/bin/env python3
"""Fast sanity check for a single-domain DTAP training environment.

Domain-agnostic: detects the domain from the sole directory under
``benchmarks/dtap-src/dataset/``. Prints "ENVIRONMENT READY" if every check
passes. Does NOT make a model call or spin up Docker (that happens in the
cascade); this only verifies wiring + that every split task resolves to a real
dataset directory.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "benchmarks" / "dtap-src"
DTAP = ROOT / "benchmarks" / "dtap"

ok = True


def check(label, cond, detail=""):
    global ok
    mark = "✓" if cond else "✗"
    print(f"  {mark} {label}" + (f" — {detail}" if detail else ""))
    if not cond:
        ok = False


def _load_env():
    env_file = ROOT / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _detect_domain() -> str:
    ds = SRC / "dataset"
    doms = [d.name for d in ds.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if len(doms) != 1:
        raise SystemExit(f"[ERROR] expected exactly one domain under {ds}, found {doms}")
    return doms[0]


def main():
    sys.path.insert(0, str(SRC))
    _load_env()
    domain = _detect_domain()
    print(f"DTAP environment check ({domain})\n")

    # 1. vendored source imports resolve to THIS workspace
    try:
        import agent, dt_arena, eval as _e, utils  # noqa
        check("vendored source imports", str(SRC) in agent.__file__, agent.__file__)
    except Exception as e:
        check("vendored source imports", False, repr(e))

    # 2. LiteLLM + langchain-litellm available (Bedrock route) — construct only, no call
    _model = os.environ.get("DTAP_MODEL", "bedrock/us.anthropic.claude-sonnet-4-6")
    _route = _model if _model.startswith(("bedrock/", "litellm/")) else f"bedrock/{_model}"
    try:
        import litellm  # noqa
        from langchain_litellm import ChatLiteLLM
        ChatLiteLLM(model=_route, max_tokens=16)
        check(f"LiteLLM Bedrock route ({_model})", True)
    except Exception as e:
        check(f"LiteLLM Bedrock route ({_model})", False, repr(e))

    # 3. defense loader + v0 baseline
    try:
        os.environ["DTAP_DEFENSE_CANDIDATE"] = "dtap_def_v0"
        from dt_arena.src.defense.loader import _load_candidate, Defense
        from dt_arena.src.types.hooks import ToolCallHook
        d = _load_candidate("dtap_def_v0")
        check("defense loader + dtap_def_v0", d is not None and isinstance(d, Defense)
              and isinstance(d, ToolCallHook))
    except Exception as e:
        check("defense loader + dtap_def_v0", False, repr(e))

    # 4. split manifest present + consistent (TRAIN 60, TEST_SUBSET100 100)
    try:
        m = json.loads((DTAP / "split_manifest.json").read_text())
        c = m["counts"]
        train_n = sum(1 for _ in (DTAP / "splits" / "train.jsonl").open())
        sub_n = sum(1 for _ in (DTAP / "splits" / "test_subset100.jsonl").open())
        consistent = (c["train"] == 60 == train_n) and (c["test_subset100"] == 100 == sub_n)
        check("split manifest", consistent,
              f"train={c['train']}(lines={train_n}) test_subset100={c['test_subset100']}(lines={sub_n}) "
              f"test_heldout={c['test_heldout']}")
        for s in ["stage1_smoke.jsonl", "stage2_mid.jsonl", "stage3_search.jsonl",
                  "stage4_wide.jsonl", "train.jsonl", "test.jsonl", "test_subset100.jsonl"]:
            check(f"split file {s}", (DTAP / "splits" / s).is_file())
    except Exception as e:
        check("split manifest", False, repr(e))

    # 5. dataset + benchmark present for the domain
    check(f"{domain} dataset", (SRC / "dataset" / domain).is_dir())
    check(f"{domain} benchmark", (SRC / "benchmark" / domain / "benign.jsonl").is_file())

    # 5b. EVERY split task resolves to a real dataset dir with config.yaml
    try:
        from utils.task_helpers import build_task_dir
        missing = []
        n = 0
        for sp in ["train.jsonl", "test_subset100.jsonl"]:
            for line in (DTAP / "splits" / sp).open():
                line = line.strip()
                if not line:
                    continue
                n += 1
                rec = json.loads(line)
                td = build_task_dir(rec)
                if td is None or not (td / "config.yaml").is_file():
                    missing.append((sp, rec))
        check("all train+subset tasks resolve to dataset dirs", not missing,
              f"{n - len(missing)}/{n} resolved" + (f"; e.g. {missing[0]}" if missing else ""))
    except Exception as e:
        check("all train+subset tasks resolve to dataset dirs", False, repr(e))

    # 6. AWS Bedrock token present (value not printed)
    env_file = ROOT / ".env"
    has_token = "AWS_BEARER_TOKEN_BEDROCK" in os.environ
    if not has_token and env_file.is_file():
        has_token = "AWS_BEARER_TOKEN_BEDROCK=" in env_file.read_text()
    check("AWS_BEARER_TOKEN_BEDROCK present", has_token, "in .env or environment")

    # 7. DTAP_DATASET_ROOT points inside THIS env
    root_ok = str(ROOT) in os.environ.get("DTAP_DATASET_ROOT", "")
    check("DTAP_DATASET_ROOT points into this env", root_ok,
          os.environ.get("DTAP_DATASET_ROOT", "<unset>"))

    print()
    if ok:
        print("ENVIRONMENT READY")
        sys.exit(0)
    print("ENVIRONMENT NOT READY — fix the ✗ items above")
    sys.exit(1)


if __name__ == "__main__":
    main()
