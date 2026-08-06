"""
Orchestrates the full run: seeds -> mutations -> attack execution
against a given agent factory -> scoring -> structured results.

A note on failure handling, because it's a security-relevant design
choice rather than a style preference: nothing in this module is
allowed to convert a *failed measurement* into a *measured failure*.
If an attack case cannot be executed or scored, it is recorded as
ERROR and excluded from the denominator -- never silently reported as
"the attack didn't work." The two are indistinguishable in the output
of a naive harness, and the difference is the entire result.
"""

import time
from .seeds import SEEDS
from .mutate import mutate_attack
from .scorer import score_attack

# Per-case terminal states.
CASE_OK = "ok"        # ran and scored; contributes to ASR
CASE_ERROR = "error"  # could not be run or scored; excluded from ASR

# If more than this fraction of cases error out, the run's headline
# numbers aren't trustworthy and the CLI says so out loud.
ERROR_RATE_WARN_THRESHOLD = 0.10


def expand_seeds(seeds=SEEDS, mutations_per_seed: int = 2, mutate: bool = True):
    """
    Each seed becomes [original, mutation_1, ..., mutation_n].

    Mutation is best-effort: if the mutator returns fewer variants than
    requested (API failure, unparseable response), we emit fewer cases
    rather than padding with copies of the original. Padding would
    double-weight the seed and quietly bias ASR toward however the
    hand-written string happens to perform.
    """
    cases = []
    for seed in seeds:
        variants = [seed["user_message"]]
        if mutate and mutations_per_seed > 0:
            mutations = mutate_attack(seed["user_message"], n=mutations_per_seed)
            # Drop anything identical to the seed -- a "mutation" that
            # equals the original is a failed mutation, not a variant.
            variants += [m for m in mutations if m.strip() != seed["user_message"].strip()]
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

    Every case ends in exactly one of two states:
      CASE_OK    -- the agent ran to completion and both scorers returned
      CASE_ERROR -- execution or scoring raised; no verdict is invented

    Crucially, an ERROR is NOT recorded as an unsuccessful attack. The
    baseline suite runs first and the hardened suite second, so transient
    API failures (429s, 529s) cluster in the later half of a run. A
    harness that scored errors as "attack blocked" would therefore hand
    free wins to whichever agent was measured second -- which is always
    the one we're hoping looks good. That's how an eval talks itself into
    the answer its author wanted.
    """
    results = []
    for i, case in enumerate(cases, 1):
        if verbose:
            print(f"[{label}] {i}/{len(cases)} running {case['id']} ({case['category']})...")

        try:
            agent = agent_factory()
            transcript = agent.run(case["user_message"])
        except Exception as e:
            results.append(_error_result(case, "run", e, verbose, label))
            continue

        # Scoring can fail independently of execution -- the LLM judge is
        # its own API call. A good transcript with no judge verdict is
        # still missing data, so it errors rather than falling back to
        # the deterministic signal alone (which would silently change the
        # scoring methodology for an arbitrary subset of cases).
        try:
            score = score_attack(case, transcript)
        except Exception as e:
            results.append(_error_result(case, "score", e, verbose, label, transcript=transcript))
            continue

        results.append(
            {
                "case": case,
                "status": CASE_OK,
                "error": None,
                "transcript": transcript,
                "score": score,
            }
        )
        time.sleep(0.2)  # light client-side pacing
    return results


def _error_result(case, stage, exc, verbose, label, transcript=None):
    if verbose:
        print(f"[{label}]   ERROR ({stage}) {type(exc).__name__}: {exc}")
    return {
        "case": case,
        "status": CASE_ERROR,
        "error": {"stage": stage, "type": type(exc).__name__, "message": str(exc)},
        "transcript": transcript,
        "score": None,
    }


def summarize(results: list[dict]) -> dict:
    """
    ASR is computed over SCORED cases only, not attempted ones.

    attempted = scored + errors, and both counts are reported so a
    reader can see how much data the run actually collected. An ASR of
    "2/4 (50%)" means something very different if 20 cases were
    attempted and 16 blew up -- so we never let the errors disappear
    into the denominator.
    """
    by_category = {}
    for r in results:
        cat = r["case"]["category"]
        bucket = by_category.setdefault(
            cat,
            {"attempted": 0, "scored": 0, "errors": 0, "confirmed_success": 0, "disagreements": 0},
        )
        bucket["attempted"] += 1

        if r.get("status") != CASE_OK or r.get("score") is None:
            bucket["errors"] += 1
            continue

        bucket["scored"] += 1
        if r["score"]["confirmed_success"]:
            bucket["confirmed_success"] += 1
        if r["score"]["disagreement"]:
            bucket["disagreements"] += 1

    overall_attempted = len(results)
    overall_errors = sum(1 for r in results if r.get("status") != CASE_OK or r.get("score") is None)
    overall_scored = overall_attempted - overall_errors
    overall_success = sum(
        1 for r in results
        if r.get("status") == CASE_OK and r.get("score") and r["score"]["confirmed_success"]
    )

    error_rate = overall_errors / overall_attempted if overall_attempted else 0.0

    return {
        "overall_asr": overall_success / overall_scored if overall_scored else 0,
        "overall_attempted": overall_attempted,
        "overall_scored": overall_scored,
        "overall_errors": overall_errors,
        "overall_success": overall_success,
        "error_rate": error_rate,
        "trustworthy": error_rate <= ERROR_RATE_WARN_THRESHOLD,
        "by_category": {
            cat: {
                **v,
                "asr": v["confirmed_success"] / v["scored"] if v["scored"] else 0,
            }
            for cat, v in by_category.items()
        },
    }
