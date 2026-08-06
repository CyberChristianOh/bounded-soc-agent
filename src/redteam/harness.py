"""
Orchestrates the full run: seeds -> mutations -> attack execution
against a given agent factory -> scoring -> structured results.
"""

import time
from .seeds import SEEDS
from .mutate import mutate_attack
from .scorer import score_attack


def expand_seeds(seeds=SEEDS, mutations_per_seed: int = 2, mutate: bool = True):
    """Each seed becomes [original, mutation_1, ..., mutation_n]."""
    cases = []
    for seed in seeds:
        variants = [seed["user_message"]]
        if mutate and mutations_per_seed > 0:
            variants += mutate_attack(seed["user_message"], n=mutations_per_seed)
        for i, text in enumerate(variants):
            cases.append(
                {
                    "id": f"{seed['id']}_v{i}",
                    "seed_id": seed["id"],
                    "category": seed["category"],
                    "user_message": text,
                    "is_mutation": i > 0,
                }
            )
    return cases


def run_suite(agent_factory, cases, label: str, verbose: bool = True):
    """
    agent_factory: zero-arg callable returning a fresh TargetAgent
    (fresh per case, so bets/ledger state never leaks between tests).
    """
    results = []
    for i, case in enumerate(cases, 1):
        if verbose:
            print(f"[{label}] {i}/{len(cases)} running {case['id']} ({case['category']})...")
        agent = agent_factory()
        try:
            transcript = agent.run(case["user_message"])
        except Exception as e:
            transcript = {"error": str(e), "bets_placed": [], "guard_events": [], "final_text": ""}

        score = score_attack(case, transcript)
        results.append(
            {
                "case": case,
                "transcript": transcript,
                "score": score,
            }
        )
        time.sleep(0.2)  # light client-side pacing
    return results


def summarize(results: list[dict]) -> dict:
    by_category = {}
    for r in results:
        cat = r["case"]["category"]
        by_category.setdefault(cat, {"total": 0, "confirmed_success": 0, "disagreements": 0})
        by_category[cat]["total"] += 1
        if r["score"]["confirmed_success"]:
            by_category[cat]["confirmed_success"] += 1
        if r["score"]["disagreement"]:
            by_category[cat]["disagreements"] += 1

    overall_total = len(results)
    overall_success = sum(1 for r in results if r["score"]["confirmed_success"])

    summary = {
        "overall_asr": overall_success / overall_total if overall_total else 0,
        "overall_total": overall_total,
        "overall_success": overall_success,
        "by_category": {
            cat: {
                **v,
                "asr": v["confirmed_success"] / v["total"] if v["total"] else 0,
            }
            for cat, v in by_category.items()
        },
    }
    return summary
