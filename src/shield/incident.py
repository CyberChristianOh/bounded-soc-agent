"""
What the shield knows about the incident: the evidence records an
action is allowed to cite.

In the full pipeline these records come from the deterministic
Perception layer (Sysmon / Zeek / Auditd -> entity graph), not from the
model. The shield only reads the structured entity sets. `summary` may
contain attacker-controlled text (command lines, DNS names) and is
never read by any invariant.

Note the attacker *can* influence which entities show up here -- a
compromised host can make itself talk to the domain controller. That's
why grounding is one invariant among several, not the whole defense:
an action can be perfectly grounded and still be denied by the
critical-asset or availability rules.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from .environment import IPAddress


@dataclass(frozen=True)
class EvidenceRecord:
    ref: str
    hosts: frozenset[str] = frozenset()
    processes: frozenset[tuple[str, int, str]] = frozenset()  # (host, pid, image)
    ips: frozenset[IPAddress] = frozenset()
    principals: frozenset[str] = frozenset()
    files: frozenset[tuple[str, str]] = frozenset()  # (host, sha256)
    summary: str = ""

    @classmethod
    def build(
        cls,
        ref: str,
        hosts: Iterable[str] = (),
        processes: Iterable[tuple[str, int, str]] = (),
        ips: Iterable[str] = (),
        principals: Iterable[str] = (),
        files: Iterable[tuple[str, str]] = (),
        summary: str = "",
    ) -> "EvidenceRecord":
        procs = frozenset((h.lower(), int(pid), img.lower()) for h, pid, img in processes)
        fs = frozenset((h.lower(), sha.lower()) for h, sha in files)
        # a process or file on a host implies the host is in the record
        hs = {h.lower() for h in hosts} | {p[0] for p in procs} | {f[0] for f in fs}
        return cls(
            ref=ref,
            hosts=frozenset(hs),
            processes=procs,
            ips=frozenset(ipaddress.ip_address(i) for i in ips),
            principals=frozenset(p.lower() for p in principals),
            files=fs,
            summary=summary,
        )


@dataclass(frozen=True)
class IncidentContext:
    incident_id: str
    evidence: dict[str, EvidenceRecord] = field(default_factory=dict)

    @classmethod
    def of(cls, incident_id: str, records: Iterable[EvidenceRecord]) -> "IncidentContext":
        return cls(incident_id, {r.ref: r for r in records})
