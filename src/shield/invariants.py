"""
The invariant library: the rules no containment plan may break, no
matter how it was produced or what the telemetry said.

Every invariant is a pure function of (plan, environment, incident).
None of them read free text -- not the action `rationale`, not the
evidence `summary` -- so there is nothing in here for a prompt
injection to talk to.

Each finding carries one of three verdicts:
  ALLOW          -- nothing to report
  REQUIRE_HUMAN  -- legitimate in some incidents, but not something a
                    machine does alone (disabling a domain admin,
                    touching a Tier-0 host, wide blast radius)
  DENY           -- never executed automatically, full stop

The plan's verdict is the most severe finding. Plans are approved or
rejected as a whole: half-executing a containment plan leaves the
network in a state nobody reasoned about.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Iterable, Iterator

from ..dsl.actions import (
    BlockNetwork,
    ContainmentPlan,
    DisableAccount,
    IsolateHost,
    KillProcess,
    QuarantineFile,
    SuspendProcess,
)
from .environment import Environment, Service
from .incident import IncidentContext


class Verdict(IntEnum):
    ALLOW = 0
    REQUIRE_HUMAN = 1
    DENY = 2


@dataclass(frozen=True)
class Finding:
    invariant: str
    verdict: Verdict
    message: str
    action_index: int | None = None
    hint: str = ""


CheckFn = Callable[[ContainmentPlan, Environment, IncidentContext], Iterable[Finding]]


@dataclass(frozen=True)
class Invariant:
    id: str
    name: str
    description: str
    check: CheckFn


INVARIANTS: list[Invariant] = []


def invariant(id: str, name: str, description: str):
    def register(fn: CheckFn) -> CheckFn:
        INVARIANTS.append(Invariant(id, name, description, fn))
        return fn

    return register


def _covers(port: int | None, protocol: str, svc: Service) -> bool:
    """Would a rule on (port, protocol) hit this service?"""
    return (port is None or port == svc.port) and protocol in ("any", svc.protocol)


def _describe(i: int, a) -> str:
    target = getattr(a, "host", None) or getattr(a, "principal", "?")
    return f"action #{i} ({a.action} {target})"


@invariant(
    "INV-1",
    "known_targets",
    "Every host an action touches must be in the asset inventory.",
)
def known_targets(plan, env, incident) -> Iterator[Finding]:
    for i, a in enumerate(plan.actions):
        host = getattr(a, "host", None)
        if host is not None and env.asset(host) is None:
            yield Finding(
                "INV-1", Verdict.DENY,
                f"{_describe(i, a)}: host is not in the asset inventory", i,
                "target only inventoried hosts; an unknown name may be hallucinated or injected",
            )


@invariant(
    "INV-2",
    "critical_asset_protection",
    "Tier-0 hosts are never isolated; any other change on Tier-0, or to a protected "
    "principal, needs a human.",
)
def critical_asset_protection(plan, env, incident) -> Iterator[Finding]:
    for i, a in enumerate(plan.actions):
        if isinstance(a, DisableAccount):
            if a.principal in env.protected_principals:
                yield Finding(
                    "INV-2", Verdict.REQUIRE_HUMAN,
                    f"{_describe(i, a)}: principal is protected (Tier-0 / service identity)", i,
                    "disable the compromised user or session instead, or escalate",
                )
            continue
        asset = env.asset(getattr(a, "host", ""))
        if asset is None or asset.tier != 0:
            continue
        if isinstance(a, IsolateHost):
            yield Finding(
                "INV-2", Verdict.DENY,
                f"{_describe(i, a)}: Tier-0 host ({asset.role}) can never be network-isolated", i,
                "contain the source of the activity (the client host, process or account) instead",
            )
        elif isinstance(a, (KillProcess, SuspendProcess, QuarantineFile)):
            yield Finding(
                "INV-2", Verdict.REQUIRE_HUMAN,
                f"{_describe(i, a)}: host changes on Tier-0 ({asset.role}) need human approval", i,
            )


@invariant(
    "INV-3",
    "service_availability",
    "Production services stay up: no whole-host isolation of Tier-1, no killing a "
    "declared service process, no broad blocks on a critical port.",
)
def service_availability(plan, env, incident) -> Iterator[Finding]:
    for i, a in enumerate(plan.actions):
        asset = env.asset(getattr(a, "host", ""))
        if asset is None:
            continue
        if isinstance(a, IsolateHost) and asset.tier == 1:
            yield Finding(
                "INV-3", Verdict.DENY,
                f"{_describe(i, a)}: production host ({asset.role}) cannot be wholesale-isolated", i,
                "use surgical containment: suspend_process on the malicious PID, or block_network "
                "to the specific remote",
            )
        elif isinstance(a, (KillProcess, SuspendProcess)) and a.image in asset.critical_images():
            yield Finding(
                "INV-3", Verdict.DENY,
                f"{_describe(i, a)}: {a.image} serves a critical service on this host", i,
                "block the malicious remote at the network layer instead of stopping the service",
            )
        elif isinstance(a, BlockNetwork):
            yield from _block_availability(i, a, env, asset)


def _block_availability(i, a: BlockNetwork, env, asset) -> Iterator[Finding]:
    single_address = a.remote.num_addresses == 1
    if a.direction == "inbound":
        hit = [s.name for s in asset.critical_services if _covers(a.port, a.protocol, s)]
        if hit and not single_address:
            yield Finding(
                "INV-3", Verdict.DENY,
                f"{_describe(i, a)}: inbound block on critical service(s) {', '.join(hit)} "
                f"covers a whole range ({a.remote})", i,
                "block the single attacking address, not a range",
            )
        return
    # Outbound from a server into another server's critical service severs an
    # application dependency (web -> db). From a workstation, it's containment.
    if asset.tier > 1:
        return
    for dep in env.assets_in(a.remote):
        if dep.host == asset.host:
            continue
        hit = [s.name for s in dep.critical_services if _covers(a.port, a.protocol, s)]
        if hit:
            yield Finding(
                "INV-3", Verdict.REQUIRE_HUMAN,
                f"{_describe(i, a)}: severs {asset.host} -> {dep.host} ({', '.join(hit)}), "
                "a server-to-server dependency", i,
            )


@invariant(
    "INV-4",
    "structural_safety",
    "No action may target OS-critical processes or PIDs, block overly broad ranges, "
    "or quarantine system files without a human.",
)
def structural_safety(plan, env, incident) -> Iterator[Finding]:
    lim = env.limits
    for i, a in enumerate(plan.actions):
        asset = env.asset(getattr(a, "host", ""))
        if isinstance(a, (KillProcess, SuspendProcess)):
            os_pid = asset is not None and (
                (asset.os == "windows" and a.pid <= 4) or (asset.os == "linux" and a.pid == 1)
            )
            if a.image in env.protected_images or os_pid:
                yield Finding(
                    "INV-4", Verdict.DENY,
                    f"{_describe(i, a)}: {a.image} (pid {a.pid}) is OS-critical; stopping it "
                    "crashes or reboots the host", i,
                    "if the OS process is being abused (e.g. LSASS dumping), stop the process "
                    "doing the abusing",
                )
        elif isinstance(a, BlockNetwork):
            floor = lim.min_prefix_v4 if a.remote.version == 4 else lim.min_prefix_v6
            if a.remote.prefixlen < floor:
                yield Finding(
                    "INV-4", Verdict.DENY,
                    f"{_describe(i, a)}: {a.remote} is broader than /{floor}", i,
                    f"block specific addresses or at most a /{floor}",
                )
        elif isinstance(a, QuarantineFile) and env.is_protected_path(a.path):
            yield Finding(
                "INV-4", Verdict.REQUIRE_HUMAN,
                f"{_describe(i, a)}: file is under a protected system path", i,
            )


@invariant(
    "INV-5",
    "blast_radius_budget",
    "Containment is time-bounded and limited in how many actions, hosts and accounts "
    "one plan can touch.",
)
def blast_radius_budget(plan, env, incident) -> Iterator[Finding]:
    lim = env.limits
    if len(plan.actions) > lim.max_actions_per_plan:
        yield Finding(
            "INV-5", Verdict.DENY,
            f"plan has {len(plan.actions)} actions; limit is {lim.max_actions_per_plan}",
            hint="split containment into prioritized stages",
        )
    for i, a in enumerate(plan.actions):
        ttl = getattr(a, "ttl_seconds", None)
        if ttl is not None and ttl > lim.max_ttl_seconds:
            yield Finding(
                "INV-5", Verdict.DENY,
                f"{_describe(i, a)}: ttl {ttl}s exceeds {lim.max_ttl_seconds}s", i,
                f"use ttl_seconds <= {lim.max_ttl_seconds}; a human can extend it",
            )
    hosts = plan.hosts()
    if len(hosts) > lim.max_hosts_per_plan:
        yield Finding(
            "INV-5", Verdict.REQUIRE_HUMAN,
            f"plan touches {len(hosts)} hosts; autonomous limit is {lim.max_hosts_per_plan}",
        )
    accounts = {a.principal for a in plan.actions if isinstance(a, DisableAccount)}
    if len(accounts) > lim.max_accounts_per_plan:
        yield Finding(
            "INV-5", Verdict.REQUIRE_HUMAN,
            f"plan disables {len(accounts)} accounts; autonomous limit is {lim.max_accounts_per_plan}",
        )


@invariant(
    "INV-6",
    "evidence_grounding",
    "Every action must cite existing evidence records, and its target must appear in them.",
)
def evidence_grounding(plan, env, incident) -> Iterator[Finding]:
    for i, a in enumerate(plan.actions):
        missing = [r for r in a.evidence_refs if r not in incident.evidence]
        if missing:
            yield Finding(
                "INV-6", Verdict.DENY,
                f"{_describe(i, a)}: cites {len(missing)} evidence record(s) that do not exist", i,
                "cite only evidence refs present in the incident",
            )
            continue
        recs = [incident.evidence[r] for r in a.evidence_refs]
        if not _grounded(a, recs):
            yield Finding(
                "INV-6", Verdict.DENY,
                f"{_describe(i, a)}: target does not appear in the cited evidence", i,
                "cite the record where this exact host / pid / address / account / file was observed",
            )


def _grounded(a, recs) -> bool:
    if isinstance(a, (KillProcess, SuspendProcess)):
        return any((a.host, a.pid, a.image) in r.processes for r in recs)
    if isinstance(a, BlockNetwork):
        return any(a.host in r.hosts for r in recs) and any(
            ip in a.remote for r in recs for ip in r.ips
        )
    if isinstance(a, IsolateHost):
        return any(a.host in r.hosts for r in recs)
    if isinstance(a, DisableAccount):
        return any(a.principal in r.principals for r in recs)
    if isinstance(a, QuarantineFile):
        return any((a.host, a.sha256) in r.files for r in recs)
    return False  # an action type nobody taught the grounding rule about fails closed
