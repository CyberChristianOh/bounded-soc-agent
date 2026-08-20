"""
Single place where Anthropic clients are constructed, and where API
failures are classified.

Two design notes, both deliberate:

1. We do NOT hand-roll exponential backoff. The SDK already implements
   it (`max_retries`), respects Retry-After, and is far better tested
   than anything written here would be. What the SDK cannot do is retry
   a whole multi-turn agent conversation -- it only sees one HTTP call
   at a time -- so that layer lives in the harness instead.

2. Failures are sorted into three buckets rather than treated
   uniformly. Retrying is not free: it costs wall-clock time, it costs
   money on calls that did succeed, and on a misconfigured run it turns
   a five-second failure into a twenty-minute one. The classification
   below decides what is worth retrying, what should fail the single
   case, and what should stop the entire suite immediately.
"""

import os

import anthropic

# Per-HTTP-call retries handled inside the SDK. Higher than the SDK
# default of 2 because eval runs are long, bursty, and unattended --
# the cost of an extra retry is far lower than the cost of losing a
# case and having to re-run the suite.
DEFAULT_MAX_RETRIES = 5

# Per-request ceiling. The SDK default (600s) is far too generous for
# an eval: a hung request would stall a run for ten minutes while
# looking indistinguishable from slow progress.
DEFAULT_TIMEOUT_S = 60.0


class MissingAPIKey(RuntimeError):
    """Raised at client construction rather than at first API call."""


# Misconfiguration, not bad luck. Retrying cannot fix these, and every
# subsequent case will fail identically -- so the suite aborts rather
# than grinding through N identical failures and reporting a run whose
# every case errored.
FATAL_ERRORS = (
    anthropic.AuthenticationError,   # 401 -- bad or missing key
    anthropic.PermissionDeniedError,  # 403 -- key lacks access
)

# Transient. Worth retrying the whole case: server-side capacity,
# rate limits, or network flakiness that has nothing to do with the
# attack being tested.
TRANSIENT_ERRORS = (
    anthropic.RateLimitError,       # 429
    anthropic.OverloadedError,      # 529
    anthropic.InternalServerError,  # 5xx
    anthropic.APIConnectionError,   # includes APITimeoutError
)

# Everything else (400s, validation failures, unexpected exceptions)
# fails the single case without retrying and without aborting the run.
# A malformed request for one attack string should not cost the other
# 47 cases, but it also will not succeed on a second attempt.


def build_client(
    max_retries: int = DEFAULT_MAX_RETRIES,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> anthropic.Anthropic:
    """
    Construct an Anthropic client with consistent retry/timeout policy.

    Every API call in this project -- target agent, action guard, LLM
    judge, attack mutator -- goes through here, so retry behaviour is
    uniform across the eval. If the guard retried differently from the
    agent, measured ASR would partly reflect which component happened
    to be more resilient to API weather rather than which defense
    worked.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise MissingAPIKey(
            "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and "
            "add your key, or export it in your shell."
        )
    return anthropic.Anthropic(api_key=api_key, max_retries=max_retries, timeout=timeout)


def is_fatal(exc: BaseException) -> bool:
    """True if the whole run should stop rather than continue."""
    return isinstance(exc, (MissingAPIKey,) + FATAL_ERRORS)


def is_transient(exc: BaseException) -> bool:
    """True if re-running the case has a real chance of succeeding."""
    if is_fatal(exc):
        return False
    return isinstance(exc, TRANSIENT_ERRORS)


def describe(exc: BaseException) -> dict:
    """Structured error detail for the results file."""
    detail = {"type": type(exc).__name__, "message": str(exc)}
    status = getattr(exc, "status_code", None)
    if status is not None:
        detail["status_code"] = status
    return detail
