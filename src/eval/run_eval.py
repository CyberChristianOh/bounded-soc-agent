"""
CLI entrypoint. Runs the attack suite against the baseline agent, then
against the hardened agent, and writes a before/after comparison.

Usage:
    python -m src.eval.run_eval            # full run (seeds x 3 variants each)
    python -m src.eval.run_eval --quick     # 1 case per seed, no mutation, fast/cheap smoke test
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.agent.target_agent import TargetAgent  # noqa: E402
from src.defense.hardened_agent import build_hardened_agent  # noqa: E402
from src.redteam.harness import (  # noqa: E402
    ERROR_RATE_WARN_THRESHOLD,
    expand_seeds,
    run_suite,
    summarize,
)
from src.redteam.seeds import SEEDS  # noqa: E402

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "results")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="1 case per seed, no mutation")
    parser.add_argument("--mutations", type=int, default=2)
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set (checked .env and environment).")
        sys.exit(1)

    if args.quick:
        cases = expand_seeds(SEEDS, mutations_per_seed=0, mutate=False)
    else:
        cases = expand_seeds(SEEDS, mutations_per_seed=args.mutations, mutate=True)

    print(f"\n=== Running {len(cases)} attack cases against BASELINE agent ===")
    baseline_results = run_suite(lambda: TargetAgent(), cases, label="baseline")
    baseline_summary = summarize(baseline_results)

    print(f"\n=== Running {len(cases)} attack cases against HARDENED agent ===")
    hardened_results = run_suite(lambda: build_hardened_agent(), cases, label="hardened")
    hardened_summary = summarize(hardened_results)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    output = {
        "timestamp": timestamp,
        "num_cases": len(cases),
        "baseline": {"summary": baseline_summary, "results": baseline_results},
        "hardened": {"summary": hardened_summary, "results": hardened_results},
    }

    out_path = os.path.join(RESULTS_DIR, f"eval_{timestamp}.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    latest_path = os.path.join(RESULTS_DIR, "latest.json")
    with open(latest_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print_report(baseline_summary, hardened_summary, len(cases))
    print(f"\nFull results written to {out_path}")


def print_report(baseline_summary, hardened_summary, num_cases):
    empty = {"asr": 0, "scored": 0, "errors": 0, "confirmed_success": 0}

    print("\n" + "=" * 78)
    print(f"ATTACK SUCCESS RATE (ASR) -- {num_cases} attack cases per agent")
    print("ASR is over SCORED cases; errored cases are excluded and counted separately.")
    print("=" * 78)
    print(f"{'category':<22}{'baseline ASR':<18}{'hardened ASR':<18}{'delta':<10}{'err':<6}")
    print("-" * 78)

    all_cats = sorted(set(baseline_summary["by_category"]) | set(hardened_summary["by_category"]))
    for cat in all_cats:
        b = baseline_summary["by_category"].get(cat, empty)
        h = hardened_summary["by_category"].get(cat, empty)
        errs = b["errors"] + h["errors"]
        # A delta is only meaningful if BOTH sides actually produced
        # scored cases. Printing "+0pp" when one side collected no data
        # would read as "the defense made no difference" rather than
        # "we don't know" -- the exact conflation this phase exists to
        # eliminate.
        if b["scored"] and h["scored"]:
            delta = f"{(b['asr'] - h['asr']) * 100:+.0f}pp"
        else:
            delta = "n/a"
        print(
            f"{cat:<22}"
            f"{_asr_cell(b):<18}"
            f"{_asr_cell(h):<18}"
            f"{delta:<10}"
            f"{errs if errs else '-'}"
        )
    print("-" * 78)
    print(
        f"{'OVERALL':<22}"
        f"{_asr_cell(baseline_summary, overall=True):<18}"
        f"{_asr_cell(hardened_summary, overall=True):<18}"
    )
    print("=" * 78)


def _asr_cell(bucket, overall: bool = False) -> str:
    """Render one ASR cell as a fixed-shape 'hits/scored (NN%)' string."""
    if overall:
        hits, scored, asr = bucket["overall_success"], bucket["overall_scored"], bucket["overall_asr"]
    else:
        hits, scored, asr = bucket["confirmed_success"], bucket["scored"], bucket["asr"]
    if not scored:
        return "n/a (0 scored)"
    return f"{hits}/{scored} ({asr*100:.0f}%)"

    _print_error_notice(baseline_summary, hardened_summary)


def _print_error_notice(baseline_summary, hardened_summary):
    """
    Errors get their own callout rather than a footnote. A run with a
    high error rate can produce a clean-looking table that is mostly
    noise, and the whole point of tracking errors separately is that
    somebody actually sees them.
    """
    total_errors = baseline_summary["overall_errors"] + hardened_summary["overall_errors"]
    if not total_errors:
        print("no errored cases -- every attempted case produced a scored verdict\n")
        return

    print(
        f"\nERRORED CASES: {baseline_summary['overall_errors']} baseline, "
        f"{hardened_summary['overall_errors']} hardened "
        f"({total_errors} total, excluded from ASR above)"
    )
    if not (baseline_summary["trustworthy"] and hardened_summary["trustworthy"]):
        print(
            "  WARNING: error rate exceeds "
            f"{ERROR_RATE_WARN_THRESHOLD*100:.0f}% -- treat these numbers as provisional.\n"
            "  Re-run before citing them. See results/*.json for per-case error detail."
        )
    print()


if __name__ == "__main__":
    main()
