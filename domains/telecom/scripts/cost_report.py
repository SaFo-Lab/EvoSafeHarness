#!/usr/bin/env python3
"""Cost / token analysis for DTAP runs — thin CLI over `dtap_cost`.

Reads the cost-event log written during runs (every LiteLLM call: base agent,
in-defense auditor, permission judge) and prints input / cached-input / output
tokens, number of calls, and estimated USD cost, broken down per model.

    .venv/bin/python scripts/cost_report.py              # table for the default log
    .venv/bin/python scripts/cost_report.py --json       # machine-readable
    .venv/bin/python scripts/cost_report.py --log PATH   # a specific log
    .venv/bin/python scripts/cost_report.py --reset       # clear the log before a fresh run
"""
import argparse
import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "benchmarks" / "dtap-src"
sys.path.insert(0, str(SRC))
import dtap_cost  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default=None, help="cost-event log (default: benchmarks/dtap/cost_events.jsonl)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--reset", action="store_true", help="delete the log and exit")
    ap.add_argument("--since-line", type=int, default=0,
                    help="skip the first N event lines — scope the report to a single run")
    args = ap.parse_args()

    if args.reset:
        p = Path(args.log) if args.log else dtap_cost.log_path()
        if p.exists():
            p.unlink()
        print(f"cleared {p}")
        return

    s = dtap_cost.summarize(args.log, since_line=args.since_line)
    print(json.dumps(s, indent=2) if args.json else dtap_cost.format_report(s))


if __name__ == "__main__":
    main()
