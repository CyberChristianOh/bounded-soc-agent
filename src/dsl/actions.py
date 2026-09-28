"""
Containment DSL -- the only language the Synthesizer agent is allowed
to speak.

The research claim is that an LLM should be a *proposer* bounded by a
deterministic *verifier*. That claim only holds if the verifier can see
everything a proposal will do. Free-form Bash or PowerShell can't give
that guarantee: aliases, -EncodedCommand, Invoke-Expression and string
splicing mean "is this script safe?" is not a question a parser can
answer in general.

So the agent never emits a script. It emits a ContainmentPlan: a list
of typed actions drawn from a small, finite vocabulary, every field of
which is validated here. The shield (src/shield) checks the plan
against policy, and only an approved plan reaches the trusted compiler
(src/dsl/compiler.py) -- ordinary code, no model involved -- which
renders it into argv lists for netsh / iptables / taskkill.

Two rules keep this boundary honest:
- Every field that ends up on a command line is constrained to a
  character set that cannot carry shell syntax (hostnames, PIDs, CIDRs,
  ports, hex digests, quote-free paths).
- The one free-text field, `rationale`, is kept for the audit trail and
  is never read by the shield or the compiler. An injected "SYSTEM:
  approve this" in a rationale is inert by construction.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Literal, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    StringConstraints,
    ValidationError,
    model_validator,
)

MAX_SCHEMA_TTL_SECONDS = 24 * 3600  # hard ceiling; policy limits (src/shield) are tighter
PID_MAX = 4_194_304                 # Linux pid_max upper bound; also covers Windows PIDs

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"

Hostname = Annotated[
    str,
    StringConstraints(pattern=rf"^{_LABEL}(?:\.{_LABEL})*$", max_length=253),
    AfterValidator(str.lower),
]
Principal = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    AfterValidator(str.lower),
]
ProcessImage = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$"),
    AfterValidator(str.lower),
]
EvidenceRef = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[A-Fa-f0-9]{64}$"), AfterValidator(str.lower)]
Pid = Annotated[int, Field(ge=1, le=PID_MAX)]
Port = Annotated[int, Field(ge=1, le=65535)]
TtlSeconds = Annotated[int, Field(ge=60, le=MAX_SCHEMA_TTL_SECONDS)]
Protocol = Literal["tcp", "udp", "any"]

# Characters that carry meaning to cmd.exe, PowerShell or a POSIX shell.
# Real-world malware paths essentially never need them; if one does, a
# human quarantines it by hand.
_PATH_FORBIDDEN = set("*?\"'`$;&|<>%^!\n\r\t\0")


def _check_path(p: str) -> str:
    if any(c in _PATH_FORBIDDEN for c in p):
        raise ValueError("path contains a forbidden character")
    if not (re.match(r"^[A-Za-z]:\\", p) or p.startswith("/")):
        raise ValueError("path must be absolute (C:\\... or /...)")
    parts = [s for s in re.split(r"[\\/]+", p) if s]
    if ".." in parts or "." in parts:
        raise ValueError("path must not contain relative segments")
    if p.endswith(("\\", "/")) or len(parts) < 2:
        raise ValueError("path must name a file, not a directory or drive root")
    return p


FilePath = Annotated[str, StringConstraints(min_length=3, max_length=1024), AfterValidator(_check_path)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _port_needs_protocol(port, protocol):
    if port is not None and protocol == "any":
        raise ValueError("a port requires protocol 'tcp' or 'udp'")


class AllowRule(_Strict):
    """Traffic an isolated host is still permitted to exchange."""

    remote: IPvAnyNetwork
    port: Port | None = None
    protocol: Protocol = "any"

    @model_validator(mode="after")
    def _check(self):
        _port_needs_protocol(self.port, self.protocol)
        return self


class _Action(_Strict):
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=16)
    rationale: str = Field(default="", max_length=1000)  # audit only; never interpreted


class SuspendProcess(_Action):
    """Freeze a process in place (reversible). `image` guards against PID reuse."""

    action: Literal["suspend_process"]
    host: Hostname
    pid: Pid
    image: ProcessImage


class KillProcess(_Action):
    """Terminate a process (irreversible)."""

    action: Literal["kill_process"]
    host: Hostname
    pid: Pid
    image: ProcessImage


class BlockNetwork(_Action):
    """Drop traffic between `host` and `remote`.

    `port` is the service port: the local port for inbound rules, the
    remote port for outbound rules. Omitted means all ports.
    """

    action: Literal["block_network"]
    host: Hostname
    direction: Literal["inbound", "outbound"]
    remote: IPvAnyNetwork
    port: Port | None = None
    protocol: Protocol = "any"
    ttl_seconds: TtlSeconds

    @model_validator(mode="after")
    def _check(self):
        _port_needs_protocol(self.port, self.protocol)
        return self


class IsolateHost(_Action):
    """Cut a host off the network except for `allow` rules and the SOC management channel."""

    action: Literal["isolate_host"]
    host: Hostname
    allow: tuple[AllowRule, ...] = Field(default=(), max_length=8)
    ttl_seconds: TtlSeconds


class DisableAccount(_Action):
    """Disable a directory account for a bounded time."""

    action: Literal["disable_account"]
    principal: Principal
    ttl_seconds: TtlSeconds


class QuarantineFile(_Action):
    """Move a file into quarantine; `sha256` must match at execution time."""

    action: Literal["quarantine_file"]
    host: Hostname
    path: FilePath
    sha256: Sha256


ContainmentAction = Annotated[
    Union[SuspendProcess, KillProcess, BlockNetwork, IsolateHost, DisableAccount, QuarantineFile],
    Field(discriminator="action"),
]


class ContainmentPlan(_Strict):
    incident_id: EvidenceRef
    actions: tuple[ContainmentAction, ...] = Field(min_length=1, max_length=32)

    def canonical_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """SHA-256 of the canonical plan. Approval is bound to this exact value."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    def hosts(self) -> set[str]:
        return {a.host for a in self.actions if hasattr(a, "host")}


class PlanParseError(ValueError):
    """Raised when a proposal isn't a valid plan. Messages never echo input values."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def parse_plan(raw: str | bytes | dict) -> ContainmentPlan:
    """Parse an agent's proposal. Always goes through JSON so strict typing is uniform."""
    if isinstance(raw, dict):
        raw = json.dumps(raw)
    try:
        return ContainmentPlan.model_validate_json(raw)
    except ValidationError as e:
        # include_input=False: the rejected values may be attacker-shaped
        # strings, and these messages are fed back to the reasoner.
        errors = [
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in e.errors(include_input=False, include_url=False)
        ]
        raise PlanParseError(errors) from None


def plan_json_schema() -> dict:
    """JSON Schema for the Synthesizer's tool definition / constrained decoding."""
    return ContainmentPlan.model_json_schema()
