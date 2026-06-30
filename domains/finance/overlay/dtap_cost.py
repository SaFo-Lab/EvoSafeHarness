"""Cost / token accounting for the DTAP os-filesystem harness.

Captures, for **every** LiteLLM call made in a run — the base agent, any
in-defense auditor calls, and (if installed there) the permission judge —
the four quantities the operator cares about:

    * input tokens          (uncached prompt tokens)
    * cached input tokens    (prompt-cache reads)
    * output tokens          (completion tokens)
    * number of calls

plus cache-creation tokens and an estimated USD cost (via litellm), broken
down per model.

How it works: `install()` registers a LiteLLM success/failure callback that
appends one JSON line per call to a shared log (default
`benchmarks/dtap/cost_events.jsonl`, override with `$DTAP_COST_LOG`). Single-line
appends under PIPE_BUF are atomic on POSIX, so multiple processes (eval +
judge_proxy) can write the same log safely. `summarize()` aggregates the log.

Usage:
    import dtap_cost; dtap_cost.install()          # once, before LLM calls (idempotent)
    ...
    python dtap_cost.py summarize                  # print the analysis
    python dtap_cost.py summarize --reset          # clear the log
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent                       # benchmarks/dtap-src
_DEFAULT_LOG = _HERE.parent / "dtap" / "cost_events.jsonl"     # benchmarks/dtap/cost_events.jsonl

_installed = False
_lock = threading.Lock()


def log_path() -> Path:
    return Path(os.environ.get("DTAP_COST_LOG", str(_DEFAULT_LOG)))


def count_events(path: Optional[str] = None) -> int:
    """Number of event lines currently in the log (0 if absent).

    Snapshot this before a run, then pass it to ``summarize(since_line=...)`` to
    scope the report to only the events appended during that run (agent +
    in-defense + judge), ignoring all-time history left in the shared log.
    """
    p = Path(path) if path else log_path()
    if not p.exists():
        return 0
    with p.open() as f:
        return sum(1 for _ in f)


# --- usage extraction -------------------------------------------------------

def _g(obj: Any, *names, default=0):
    """First present attribute/key among `names` (handles objects and dicts)."""
    for n in names:
        if obj is None:
            break
        v = getattr(obj, n, None)
        if v is None and isinstance(obj, dict):
            v = obj.get(n)
        if v is not None:
            return v
    return default


def _extract(response_obj: Any) -> dict:
    """Pull token counts out of a LiteLLM/OpenAI/Anthropic-shaped usage object.

    input_tokens here is the UNCACHED prompt portion: providers report
    `prompt_tokens` as the full prompt (cached + uncached), so we subtract the
    cache-read tokens to avoid double counting.
    """
    usage = _g(response_obj, "usage", default=None)
    prompt = int(_g(usage, "prompt_tokens", "input_tokens", default=0) or 0)
    completion = int(_g(usage, "completion_tokens", "output_tokens", default=0) or 0)
    cached = int(_g(usage, "cache_read_input_tokens", default=0) or 0)
    # OpenAI nests cached under prompt_tokens_details.cached_tokens
    if not cached:
        det = _g(usage, "prompt_tokens_details", default=None)
        cached = int(_g(det, "cached_tokens", default=0) or 0)
    cache_creation = int(_g(usage, "cache_creation_input_tokens", default=0) or 0)
    input_uncached = max(prompt - cached, 0)
    return {
        "input_tokens": input_uncached,
        "cached_input_tokens": cached,
        "cache_creation_tokens": cache_creation,
        "output_tokens": completion,
    }


def record(model: str, response_obj: Any = None, ok: bool = True, err: str = "") -> None:
    """Append one cost event. Safe to call directly (e.g. from a proxy)."""
    ev = {"ts": time.time(), "pid": os.getpid(), "model": model or "?", "ok": ok}
    ev.update(_extract(response_obj) if response_obj is not None else
              {"input_tokens": 0, "cached_input_tokens": 0, "cache_creation_tokens": 0, "output_tokens": 0})
    cost = None
    if response_obj is not None:
        try:
            import litellm
            cost = float(litellm.completion_cost(completion_response=response_obj))
        except Exception:
            cost = None
        # Fallback for models litellm doesn't price locally (e.g. OpenRouter
        # qwen/qwen3.7-plus -> "model isn't mapped yet"): OpenRouter returns the
        # authoritative cost in usage.cost / _hidden_params.response_cost.
        if not cost:
            hp = getattr(response_obj, "_hidden_params", None) or {}
            rc = hp.get("response_cost") if isinstance(hp, dict) else None
            if rc is None:
                rc = _g(_g(response_obj, "usage", default=None), "cost", default=None)
            try:
                cost = float(rc) if rc is not None else cost
            except (TypeError, ValueError):
                pass
    ev["cost_usd"] = cost
    if err:
        ev["err"] = err[:200]
    p = log_path()
    line = json.dumps(ev) + "\n"
    with _lock:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:          # O_APPEND: atomic per line across processes
            f.write(line)


def install(verbose: bool = True) -> None:
    """Register the LiteLLM callback (idempotent)."""
    global _installed
    if _installed:
        return
    try:
        import litellm
        from litellm.integrations.custom_logger import CustomLogger
    except Exception as e:                       # litellm missing -> no-op
        if verbose:
            print(f"[dtap_cost] litellm unavailable, cost tracking disabled: {e}")
        return

    tracker = self = _Tracker()  # noqa
    # litellm fires callbacks listed in .callbacks for both sync and async paths
    existing = [c for c in (litellm.callbacks or []) if not isinstance(c, _Tracker)]
    litellm.callbacks = existing + [tracker]
    _installed = True
    if verbose:
        print(f"[dtap_cost] cost tracking ON -> {log_path()}")


try:
    from litellm.integrations.custom_logger import CustomLogger as _Base
except Exception:                                # allow import without litellm
    class _Base:  # type: ignore
        pass


class _Tracker(_Base):
    def _model_of(self, kwargs):
        return (kwargs or {}).get("model") or "?"

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        record(self._model_of(kwargs), response_obj, ok=True)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        record(self._model_of(kwargs), response_obj, ok=True)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        record(self._model_of(kwargs), None, ok=False, err=str(response_obj)[:200])

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        record(self._model_of(kwargs), None, ok=False, err=str(response_obj)[:200])


# --- analysis ---------------------------------------------------------------

_FIELDS = ("calls", "input_tokens", "cached_input_tokens", "cache_creation_tokens", "output_tokens")


def summarize(path: Optional[str] = None, since_line: int = 0) -> dict:
    """Aggregate the cost log into per-model and overall totals.

    ``since_line`` skips the first N event lines, so passing the value returned
    by ``count_events()`` before a run yields just that run's cost.

    Returns {"overall": {...}, "by_model": {model: {...}}, "n_events": int,
             "n_failed": int}, each row carrying the four headline metrics plus
             cache_creation_tokens and cost_usd.
    """
    p = Path(path) if path else log_path()
    by_model: dict[str, dict] = {}

    def blank():
        d = {f: 0 for f in _FIELDS}
        d["cost_usd"] = 0.0
        return d

    n_events = n_failed = 0
    if p.exists():
        for idx, line in enumerate(p.open()):
            if idx < since_line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            n_events += 1
            if not e.get("ok", True):
                n_failed += 1
            row = by_model.setdefault(e.get("model", "?"), blank())
            row["calls"] += 1
            for f in _FIELDS[1:]:
                row[f] += int(e.get(f, 0) or 0)
            if e.get("cost_usd") is not None:
                row["cost_usd"] += float(e["cost_usd"])

    overall = {f: 0 for f in _FIELDS}
    overall["cost_usd"] = 0.0
    for row in by_model.values():
        for f in _FIELDS:
            overall[f] += row[f]
        overall["cost_usd"] += row["cost_usd"]

    return {"overall": overall, "by_model": by_model, "n_events": n_events,
            "n_failed": n_failed, "log_path": str(p)}


def format_report(s: dict) -> str:
    cols = ["model", "calls", "input_tok", "cached_in", "cache_create", "output_tok", "cost_usd"]
    w = [28, 7, 12, 12, 13, 11, 11]

    def fmt_row(vals):
        return "  ".join(str(v).rjust(width) if i else str(v).ljust(width)
                         for i, (v, width) in enumerate(zip(vals, w)))

    lines = [fmt_row(cols), fmt_row(["-" * x for x in w])]

    def row_vals(name, r):
        return [name, r["calls"], r["input_tokens"], r["cached_input_tokens"],
                r["cache_creation_tokens"], r["output_tokens"], f"${r['cost_usd']:.4f}"]

    for name in sorted(s["by_model"]):
        lines.append(fmt_row(row_vals(name, s["by_model"][name])))
    lines.append(fmt_row(["-" * x for x in w]))
    lines.append(fmt_row(row_vals("TOTAL", s["overall"])))
    foot = f"\nevents={s['n_events']} failed_calls={s['n_failed']} log={s['log_path']}"
    return "\n".join(lines) + foot


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="DTAP cost / token analysis")
    sub = ap.add_subparsers(dest="cmd")
    sp = sub.add_parser("summarize", help="print per-model token + cost analysis")
    sp.add_argument("--log", default=None)
    sp.add_argument("--reset", action="store_true", help="clear the log instead of summarizing")
    sp.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    sp.add_argument("--since-line", type=int, default=0,
                    help="skip the first N event lines (scope to one run)")
    args = ap.parse_args()
    if args.cmd == "summarize" and args.reset:
        p = Path(args.log) if args.log else log_path()
        if p.exists():
            p.unlink()
        print(f"[dtap_cost] cleared {p}")
        return
    s = summarize(args.log, since_line=getattr(args, "since_line", 0))
    print(json.dumps(s, indent=2) if getattr(args, "json", False) else format_report(s))


if __name__ == "__main__":
    _cli()
