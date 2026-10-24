"""Diagnostic findings model.

Every check the tool runs produces :class:`Finding` objects with a
machine-readable status, the human evidence that supports the result, and
optional remediation advice.  Findings are stored in :class:`FindingStore`
on the CLI session and later correlated by ``analyze.py``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

# Status values (kept as plain constants so JSON output is stable).
PASS = "PASS"
FAIL = "FAIL"
WARNING = "WARNING"
NOT_TESTED = "NOT TESTED"

# Ordering used for severity ranking (lower = better).
_STATUS_RANK = {PASS: 0, NOT_TESTED: 1, WARNING: 2, FAIL: 3}

# Check origin - makes it explicit where the evidence came from.
SCOPE_LOCAL = "local"            # ran on the machine ssl-doctor runs on
SCOPE_REMOTE_NET = "remote-net"  # network check against a remote endpoint
SCOPE_SERVER = "server"          # executed on the remote server via SSH


@dataclass
class Finding:
    check: str                    # short machine name, e.g. "tls.handshake"
    title: str                    # human title
    status: str                   # PASS / FAIL / WARNING / NOT TESTED
    scope: str                    # local / remote-net / server
    evidence: List[str] = field(default_factory=list)
    detail: str = ""              # longer free-form explanation
    recommendation: str = ""      # practical remediation, if any
    target: str = ""              # e.g. "host:port" or a file path
    ts: float = field(default_factory=time.time)

    def worst_rank(self) -> int:
        return _STATUS_RANK.get(self.status, 99)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["ts_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts))
        return d


class FindingStore:
    """Ordered collection of findings for one interactive session."""

    def __init__(self) -> None:
        self._items: List[Finding] = []

    def add(self, finding: Finding) -> Finding:
        self._items.append(finding)
        return finding

    def extend(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            self.add(f)
        return findings

    def all(self) -> List[Finding]:
        return list(self._items)

    def clear(self) -> None:
        self._items.clear()

    def by_scope(self, scope: str) -> List[Finding]:
        return [f for f in self._items if f.scope == scope]

    def counts(self) -> Dict[str, int]:
        out = {PASS: 0, FAIL: 0, WARNING: 0, NOT_TESTED: 0}
        for f in self._items:
            out[f.status] = out.get(f.status, 0) + 1
        return out

    def __len__(self) -> int:  # noqa: D105
        return len(self._items)
