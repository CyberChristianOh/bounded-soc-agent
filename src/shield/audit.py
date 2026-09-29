"""
Tamper-evident audit log for shield decisions.

Each line is a JSON entry holding the SHA-256 of the previous entry, so
editing, deleting or reordering any past decision breaks the chain from
that point on. This is the software half of the "write-once audit
store" in the research design; the other half is putting the file on
append-only / WORM storage so it can't simply be rewritten wholesale.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = 0, GENESIS
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                e = json.loads(line)
                self._seq, self._prev = e["seq"] + 1, e["hash"]

    def append(self, record: dict) -> str:
        entry = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "prev": self._prev,
            "record": record,
        }
        entry["hash"] = _entry_hash(entry)
        with self.path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._seq, self._prev = self._seq + 1, entry["hash"]
        return entry["hash"]

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, index of the first bad line or None)."""
        prev = GENESIS
        for i, line in enumerate(self.path.read_text().splitlines()):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return False, i
            if e.get("seq") != i or e.get("prev") != prev or e.get("hash") != _entry_hash(e):
                return False, i
            prev = e["hash"]
        return True, None
