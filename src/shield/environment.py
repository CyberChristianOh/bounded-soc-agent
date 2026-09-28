"""
The defender's ground truth: asset inventory, criticality tiers and
policy limits. This is trusted configuration, written by humans and
loaded from disk -- never derived from telemetry or model output.

Tiers follow the usual AD tiering model:
  0 -- identity / control plane (domain controllers, PKI, IAM)
  1 -- production servers (databases, web, line-of-business apps)
  2 -- endpoints (workstations, dev boxes)
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

EXAMPLE_ENVIRONMENT = Path(__file__).parent / "policies" / "lab_environment.json"


@dataclass(frozen=True)
class Service:
    name: str
    port: int
    protocol: Literal["tcp", "udp"]
    image: str | None = None  # process that serves it, if known


@dataclass(frozen=True)
class Asset:
    host: str
    tier: int
    role: str
    os: Literal["windows", "linux"]
    ip: IPAddress | None
    critical_services: tuple[Service, ...] = ()

    def critical_images(self) -> set[str]:
        return {s.image for s in self.critical_services if s.image}


@dataclass(frozen=True)
class PolicyLimits:
    max_ttl_seconds: int = 4 * 3600
    max_actions_per_plan: int = 10
    max_hosts_per_plan: int = 3
    max_accounts_per_plan: int = 2
    min_prefix_v4: int = 24  # broadest IPv4 range a single block may cover
    min_prefix_v6: int = 64


@dataclass(frozen=True)
class Environment:
    assets: dict[str, Asset]
    protected_principals: frozenset[str] = frozenset()
    protected_images: frozenset[str] = frozenset()
    protected_paths: tuple[str, ...] = ()
    management_networks: tuple[IPNetwork, ...] = ()  # always reachable from an isolated host
    limits: PolicyLimits = field(default_factory=PolicyLimits)

    def asset(self, host: str) -> Asset | None:
        return self.assets.get(host.lower())

    def assets_in(self, net: IPNetwork) -> list[Asset]:
        return [a for a in self.assets.values() if a.ip is not None and a.ip in net]

    def is_protected_path(self, path: str) -> bool:
        p = path.replace("\\", "/").lower()
        return any(p.startswith(prefix) for prefix in self.protected_paths)

    @classmethod
    def from_dict(cls, d: dict) -> "Environment":
        assets = {}
        for a in d["assets"]:
            host = a["host"].lower()
            assets[host] = Asset(
                host=host,
                tier=int(a["tier"]),
                role=a["role"],
                os=a["os"],
                ip=ipaddress.ip_address(a["ip"]) if a.get("ip") else None,
                critical_services=tuple(
                    Service(s["name"], int(s["port"]), s["protocol"], (s.get("image") or "").lower() or None)
                    for s in a.get("critical_services", [])
                ),
            )
        return cls(
            assets=assets,
            protected_principals=frozenset(p.lower() for p in d.get("protected_principals", [])),
            protected_images=frozenset(i.lower() for i in d.get("protected_images", [])),
            protected_paths=tuple(p.replace("\\", "/").lower() for p in d.get("protected_paths", [])),
            management_networks=tuple(ipaddress.ip_network(n) for n in d.get("management_networks", [])),
            limits=PolicyLimits(**d.get("limits", {})),
        )

    @classmethod
    def load(cls, path: str | Path = EXAMPLE_ENVIRONMENT) -> "Environment":
        return cls.from_dict(json.loads(Path(path).read_text()))
