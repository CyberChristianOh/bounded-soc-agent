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
from src.redteam.harness import expand_seeds, run_suite, summarize  # noqa: E402
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
    print("\n" + "=" * 72)
    print(f"ATTACK SUCCESS RATE (ASR) -- {num_cases} attack cases per agent")
    print("=" * 72)
    header = f"{'category':<22}{'baseline ASR':<18}{'hardened ASR':<18}{'delta':<10}"
    print(header)
    print("-" * 72)

    all_cats = sorted(set(baseline_summary["by_category"]) | set(hardened_summary["by_category"]))
    for cat in all_cats:
        b = baseline_summary["by_category"].get(cat, {"asr": 0, "total": 0, "confirmed_success": 0})
        h = hardened_summary["by_category"].get(cat, {"asr": 0, "total": 0, "confirmed_success": 0})
        delta = b["asr"] - h["asr"]
        print(
            f"{cat:<22}"
            f"{b['confirmed_success']}/{b['total']} ({b['asr']*100:.0f}%){'':<6}"
            f"{h['confirmed_success']}/{h['total']} ({h['asr']*100:.0f}%){'':<6}"
            f"{delta*100:+.0f}pp"
        )
    print("-" * 72)
    print(
        f"{'OVERALL':<22}"
        f"{baseline_summary['overall_success']}/{baseline_summary['overall_total']} "
        f"({baseline_summary['overall_asr']*100:.0f}%){'':<6}"
        f"{hardened_summary['overall_success']}/{hardened_summary['overall_total']} "
        f"({hardened_summary['overall_asr']*100:.0f}%)"
    )
    print("=" * 72)


if __name__ == "__main__":
    main()
