#!/usr/bin/env python3
"""Fast sanity check for the DTAP os-filesystem training environment.

Prints "ENVIRONMENT READY" if every check passes. Does NOT make a model call or
spin up Docker (that happens in the cascade); this only verifies wiring.
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
    """Populate os.environ from .env (without overriding the live shell) so the
    checks below reflect the ACTUAL configured model, not the code default."""
    env_file = ROOT / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def main():
    sys.path.insert(0, str(SRC))
    _load_env()
    print("DTAP environment check (os-filesystem)\n")

    # 1. vendored source imports resolve to THIS workspace
    try:
        import agent, dt_arena, eval as _e, utils  # noqa
        good = str(SRC) in agent.__file__
        check("vendored source imports", good, agent.__file__)
    except Exception as e:
        check("vendored source imports", False, repr(e))

    # 2. LiteLLM + langchain-litellm available (Bedrock route) — use the configured model
    _model = os.environ.get("DTAP_MODEL", "zai.glm-5")
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

    # 4. split manifest present + consistent (v2 = downsampled 60-task TRAIN; v1 kept for TEST)
    try:
        m = json.loads((DTAP / "split_manifest_v2.json").read_text())
        c = m["counts"]
        train_n = sum(1 for _ in (DTAP / "splits" / "train.jsonl").open())
        consistent = (c["train"] == 60 == train_n) and (c["test"] == 480)
        check("split manifest (v2)", consistent,
              f"train={c['train']} test={c['test']} reserve={c.get('reserve_dropped_from_train')} "
              f"(train.jsonl lines={train_n})")
        for s in ["stage1_smoke.jsonl", "stage2_mid.jsonl", "stage3_search.jsonl",
                  "stage4_wide.jsonl", "train.jsonl", "test.jsonl"]:
            check(f"split file {s}", (DTAP / "splits" / s).is_file())
    except Exception as e:
        check("split manifest (v2)", False, repr(e))

    # 5. os-filesystem dataset + benchmark present
    check("os-filesystem dataset", (SRC / "dataset" / "os-filesystem" / "benign" / "1").is_dir())
    check("os-filesystem benchmark", (SRC / "benchmark" / "os-filesystem" / "benign.jsonl").is_file())

    # 6. AWS Bedrock token present (value not printed)
    env_file = ROOT / ".env"
    has_token = "AWS_BEARER_TOKEN_BEDROCK" in os.environ
    if not has_token and env_file.is_file():
        has_token = "AWS_BEARER_TOKEN_BEDROCK=" in env_file.read_text()
    check("AWS_BEARER_TOKEN_BEDROCK present", has_token, "in .env or environment")

    print()
    if ok:
        print("ENVIRONMENT READY")
        sys.exit(0)
    print("ENVIRONMENT NOT READY — fix the ✗ items above")
    sys.exit(1)


if __name__ == "__main__":
    main()
