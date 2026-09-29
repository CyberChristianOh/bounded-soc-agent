"""
The deterministic verification boundary.

    agent proposal (untrusted JSON)
        -> parse into the containment DSL        (INV-0, fail closed)
        -> run every invariant                   (INV-1..6, fail closed)
        -> Decision: ALLOW / REQUIRE_HUMAN / DENY, bound to the plan digest
        -> audit log

Nothing here calls a model. Given the same plan, environment and
evidence, the shield always returns the same verdict -- which is what
lets a safety claim be tested exhaustively rather than sampled.

When a plan is not approved, Decision.feedback() gives the Strategic
Reasoner a structured account of what was wrong, so it can propose a
less destructive alternative instead of just failing (graceful
degradation). The feedback is built only from invariant messages and
validated identifiers, never from the rejected plan's free text, so a
payload can't bounce back into the reasoner's context through it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from ..dsl.actions import ContainmentPlan, PlanParseError, parse_plan
from .audit import AuditLog
from .environment import Environment
from .incident import IncidentContext
from .invariants import INVARIANTS, Finding, Invariant, Verdict


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    findings: tuple[Finding, ...]
    incident_id: str
    plan: ContainmentPlan | None = None
    plan_digest: str | None = None
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    signature: str = ""  # set by the issuing PolicyShield; see PolicyShield.is_authentic

    def _signed_fields(self) -> bytes:
        return f"{self.verdict.name}|{self.incident_id}|{self.plan_digest}|{self.evaluated_at}".encode()

    @property
    def approved(self) -> bool:
        return self.verdict is Verdict.ALLOW and self.plan is not None

    def feedback(self) -> str:
        if self.approved:
            return "Plan APPROVED."
        head = {
            Verdict.DENY: "Plan REJECTED. Propose a revised plan; do not resubmit denied actions unchanged.",
            Verdict.REQUIRE_HUMAN: "Plan HELD for human approval. To act autonomously, remove or narrow "
            "the flagged actions.",
        }[self.verdict]
        lines = [head]
        for f in sorted(self.findings, key=lambda f: (-f.verdict, f.invariant)):
            lines.append(f"- [{f.invariant} {f.verdict.name}] {f.message}")
            if f.hint:
                lines.append(f"    fix: {f.hint}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "verdict": self.verdict.name,
            "plan_digest": self.plan_digest,
            "plan": self.plan.model_dump(mode="json") if self.plan else None,
            "findings": [
                {
                    "invariant": f.invariant,
                    "verdict": f.verdict.name,
                    "action_index": f.action_index,
                    "message": f.message,
                }
                for f in self.findings
            ],
            "evaluated_at": self.evaluated_at,
        }


class PolicyShield:
    def __init__(
        self,
        env: Environment,
        invariants: list[Invariant] | None = None,
        audit: AuditLog | None = None,
    ):
        self.env = env
        self.invariants = list(INVARIANTS if invariants is None else invariants)
        self.audit = audit
        self._key = secrets.token_bytes(32)  # per-process; the executor trusts only this shield

    def is_authentic(self, decision: Decision) -> bool:
        """True if this shield issued `decision` and its plan still matches the approved digest."""
        expected = hmac.new(self._key, decision._signed_fields(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, decision.signature):
            return False
        return decision.plan is None or decision.plan.digest() == decision.plan_digest

    def evaluate(self, raw_plan: str | bytes | dict, incident: IncidentContext) -> Decision:
        try:
            plan = parse_plan(raw_plan)
        except PlanParseError as e:
            findings = tuple(
                Finding("INV-0", Verdict.DENY, f"not a valid containment plan: {err}")
                for err in e.errors
            )
            return self._record(Decision(Verdict.DENY, findings, incident.incident_id))

        findings: list[Finding] = []
        if plan.incident_id != incident.incident_id:
            findings.append(
                Finding("INV-0", Verdict.DENY, "plan is for a different incident than the one under evaluation")
            )
        for inv in self.invariants:
            try:
                findings.extend(inv.check(plan, self.env, incident))
            except Exception as exc:  # a broken rule must never become a silent pass
                findings.append(
                    Finding(inv.id, Verdict.DENY, f"{inv.name} raised {type(exc).__name__}; failing closed")
                )

        verdict = max((f.verdict for f in findings), default=Verdict.ALLOW)
        return self._record(
            Decision(verdict, tuple(findings), incident.incident_id, plan, plan.digest())
        )

    def _record(self, decision: Decision) -> Decision:
        sig = hmac.new(self._key, decision._signed_fields(), hashlib.sha256).hexdigest()
        decision = replace(decision, signature=sig)
        if self.audit is not None:
            self.audit.append(decision.to_dict())
        return decision
