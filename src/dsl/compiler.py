"""
Trusted compiler: approved ContainmentPlan -> concrete commands.

This is the only place containment turns into something a host would
run, and it is ordinary deterministic code. Three properties matter:

1. It refuses anything the shield didn't issue and approve
   (signature + plan digest check), so there's no path from model
   output to a command line that skips verification.
2. It emits argv lists, never shell strings, from fields the DSL has
   already constrained. `rationale` is never read.
3. Every reversible command carries its undo, and time-bounded actions
   carry their TTL, so the executor can roll containment back on its
   own.

Stage 1 of the research runs in dry-run mode: commands are rendered
and logged, not executed. The live executor (Stage 2 lab) consumes the
same CompiledCommand objects.
"""

from __future__ import annotations

from dataclasses import dataclass

from .actions import (
    BlockNetwork,
    DisableAccount,
    IsolateHost,
    KillProcess,
    QuarantineFile,
    SuspendProcess,
)

IDENTITY_TARGET = "identity:active_directory"
WIN_QUARANTINE_DIR = "C:\\ProgramData\\BoundedQuarantine"
LINUX_QUARANTINE_DIR = "/var/quarantine"

Argv = tuple[str, ...]


@dataclass(frozen=True)
class CompiledCommand:
    action_index: int
    target: str  # host, or IDENTITY_TARGET for directory changes
    os: str
    argv: Argv
    undo: tuple[Argv, ...] = ()
    ttl_seconds: int | None = None
    precondition: str | None = None  # checked by the executor right before running


class CompilationRefused(RuntimeError):
    pass


def compile_plan(decision, shield) -> list[CompiledCommand]:
    from ..shield.invariants import Verdict  # local import: dsl must not depend on shield at import time

    if decision.verdict is not Verdict.ALLOW or decision.plan is None:
        raise CompilationRefused(f"plan was not approved (verdict {decision.verdict.name})")
    if not shield.is_authentic(decision):
        raise CompilationRefused("decision was not issued by this shield, or the plan changed after approval")

    env = shield.env
    tag_base = f"bounded-{decision.plan_digest[:12]}"
    out: list[CompiledCommand] = []
    for i, a in enumerate(decision.plan.actions):
        tag = f"{tag_base}-{i}"
        if isinstance(a, DisableAccount):
            out.append(_disable_account(i, a))
            continue
        asset = env.asset(a.host)
        render = _WINDOWS if asset.os == "windows" else _LINUX
        out.extend(render[type(a)](i, a, tag, env))
    return out


def _cmd(i, a, os_, argv, **kw) -> CompiledCommand:
    return CompiledCommand(i, a.host, os_, tuple(argv), **kw)


def _proto_port_win(protocol, port, direction):
    args = []
    if protocol != "any":
        args.append(f"protocol={protocol.upper()}")
    if port is not None:
        args.append(f"{'localport' if direction == 'in' else 'remoteport'}={port}")
    return args


def _proto_port_linux(protocol, port):
    args = []
    if protocol != "any":
        args += ["-p", protocol]
    if port is not None:
        args += ["--dport", str(port)]
    return args


def _iptables(net) -> str:
    return "iptables" if net.version == 4 else "ip6tables"


# ---- Windows ----------------------------------------------------------------

def _win_suspend(i, a, tag, env):
    return [_cmd(i, a, "windows", ["pssuspend64.exe", "-accepteula", "-nobanner", str(a.pid)],
                 undo=(("pssuspend64.exe", "-accepteula", "-nobanner", "-r", str(a.pid)),),
                 precondition=f"pid {a.pid} is {a.image}")]


def _win_kill(i, a, tag, env):
    return [_cmd(i, a, "windows", ["taskkill.exe", "/PID", str(a.pid), "/F"],
                 precondition=f"pid {a.pid} is {a.image}")]


def _win_block(i, a, tag, env):
    d = "in" if a.direction == "inbound" else "out"
    argv = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={tag}", f"dir={d}",
            "action=block", f"remoteip={a.remote}", *_proto_port_win(a.protocol, a.port, d)]
    return [_cmd(i, a, "windows", argv,
                 undo=(("netsh", "advfirewall", "firewall", "delete", "rule", f"name={tag}"),),
                 ttl_seconds=a.ttl_seconds)]


def _win_isolate(i, a, tag, env):
    allows = [(r.remote, r.port, r.protocol) for r in a.allow] + [(n, None, "any") for n in env.management_networks]
    cmds = []
    for k, (net, port, proto) in enumerate(allows):
        for d in ("out", "in"):
            name = f"name={tag}-allow{k}{d}"
            argv = ["netsh", "advfirewall", "firewall", "add", "rule", name, f"dir={d}", "action=allow",
                    f"remoteip={net}", *_proto_port_win(proto, port, "out")]
            cmds.append(_cmd(i, a, "windows", argv,
                             undo=(("netsh", "advfirewall", "firewall", "delete", "rule", name),),
                             ttl_seconds=a.ttl_seconds))
    # Allow rules first, then flip the default: the management channel never drops.
    # Caveat for the live executor: a default-block profile does not override
    # pre-existing allow rules on the host, so Stage 2 should isolate through
    # EDR network containment or a WFP filter rather than netsh alone.
    cmds.append(_cmd(i, a, "windows",
                     ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
                     undo=(("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                            "blockinbound,allowoutbound"),),
                     ttl_seconds=a.ttl_seconds))
    return cmds


def _win_quarantine(i, a, tag, env):
    src = a.path.replace("'", "''")  # DSL already forbids quotes; doubled anyway
    dst = f"{WIN_QUARANTINE_DIR}\\{a.sha256}.bin"
    move = "Move-Item -LiteralPath '{}' -Destination '{}' -Force"
    return [_cmd(i, a, "windows",
                 ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", move.format(src, dst)],
                 undo=(("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", move.format(dst, src)),),
                 precondition=f"sha256({a.path}) == {a.sha256}")]


# ---- Linux ------------------------------------------------------------------

def _lx_suspend(i, a, tag, env):
    return [_cmd(i, a, "linux", ["kill", "-STOP", str(a.pid)], undo=(("kill", "-CONT", str(a.pid)),),
                 precondition=f"pid {a.pid} is {a.image}")]


def _lx_kill(i, a, tag, env):
    return [_cmd(i, a, "linux", ["kill", "-KILL", str(a.pid)], precondition=f"pid {a.pid} is {a.image}")]


def _lx_rule(chain, flag, net, proto, port, tag, target):
    return [chain, flag, str(net), *_proto_port_linux(proto, port), "-m", "comment", "--comment", tag, "-j", target]


def _lx_block(i, a, tag, env):
    chain, flag = ("INPUT", "-s") if a.direction == "inbound" else ("OUTPUT", "-d")
    rule = _lx_rule(chain, flag, a.remote, a.protocol, a.port, tag, "DROP")
    ipt = _iptables(a.remote)
    return [_cmd(i, a, "linux", [ipt, "-I", *rule], undo=((ipt, "-D", *rule),), ttl_seconds=a.ttl_seconds)]


def _lx_isolate(i, a, tag, env):
    allows = [(r.remote, r.port, r.protocol) for r in a.allow] + [(n, None, "any") for n in env.management_networks]
    cmds = []
    pos = {"iptables": {"INPUT": 1, "OUTPUT": 1}, "ip6tables": {"INPUT": 1, "OUTPUT": 1}}
    for net, port, proto in allows:
        ipt = _iptables(net)
        for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s")):
            rule = _lx_rule(chain, flag, net, proto, port, tag, "ACCEPT")
            cmds.append(_cmd(i, a, "linux", [ipt, "-I", chain, str(pos[ipt][chain]), *rule[1:]],
                             undo=((ipt, "-D", *rule),), ttl_seconds=a.ttl_seconds))
            pos[ipt][chain] += 1
    # Drops go directly after the allows, ahead of any pre-existing ACCEPT rules.
    for ipt in ("iptables", "ip6tables"):
        for chain in ("OUTPUT", "INPUT"):
            rule = [chain, "-m", "comment", "--comment", tag, "-j", "DROP"]
            cmds.append(_cmd(i, a, "linux", [ipt, "-I", chain, str(pos[ipt][chain]), *rule[1:]],
                             undo=((ipt, "-D", *rule),), ttl_seconds=a.ttl_seconds))
    return cmds


def _lx_quarantine(i, a, tag, env):
    dst = f"{LINUX_QUARANTINE_DIR}/{a.sha256}.bin"
    return [_cmd(i, a, "linux", ["mv", "--", a.path, dst], undo=(("mv", "--", dst, a.path),),
                 precondition=f"sha256({a.path}) == {a.sha256}")]


# ---- Directory ----------------------------------------------------------------

def _disable_account(i, a: DisableAccount) -> CompiledCommand:
    return CompiledCommand(i, IDENTITY_TARGET, "windows", ("net", "user", a.principal, "/active:no", "/domain"),
                           undo=(("net", "user", a.principal, "/active:yes", "/domain"),),
                           ttl_seconds=a.ttl_seconds)


_WINDOWS = {SuspendProcess: _win_suspend, KillProcess: _win_kill, BlockNetwork: _win_block,
            IsolateHost: _win_isolate, QuarantineFile: _win_quarantine}
_LINUX = {SuspendProcess: _lx_suspend, KillProcess: _lx_kill, BlockNetwork: _lx_block,
          IsolateHost: _lx_isolate, QuarantineFile: _lx_quarantine}
