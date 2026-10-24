"""Tamper-evident audit log.

Each organization has its own hash chain::

    hash_n = sha256(hash_{n-1} + "\\n" + entry_n)      (hash_0 = 64 zeros)

``entry`` is the canonical JSON (sorted keys, compact) of the audited event,
stored verbatim, so any party can re-verify an export without knowing how
the database renders values. Appends serialize per organization with a
transaction-scoped advisory lock. The table is insert-only for the
application role, and UPDATE/DELETE are rejected by a trigger.
``verify_rows`` detects any edit, reorder or gap, including ones made outside
the application.

    python -m ssldoctor_service.audit verify --dsn "<dsn>" --org <uuid>
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable, Optional, Tuple
from uuid import UUID

GENESIS = "0" * 64

# Every action the service records (documented in docs/audit.md).
ACTIONS = (
    "member.signin", "member.create", "member.role_change", "member.remove",
    "sso.configure", "sso.enforce",
    "agent.enrollment_token", "agent.enroll", "agent.revoke",
    "target.create", "target.monitoring",
    "channel.create", "channel.delete",
    "scan.start", "report.export", "audit.export",
)


def canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev_hash: str, entry: str) -> str:
    return hashlib.sha256((prev_hash + "\n" + entry).encode()).hexdigest()


def record(conn, org_id: UUID, actor: str, action: str, obj: Optional[str] = None,
           source_ip: Optional[str] = None, details: Optional[dict] = None,
           now: Optional[datetime] = None) -> dict:
    """Append one audit entry inside the caller's (tenant-scoped) transaction."""
    if action not in ACTIONS:
        raise ValueError(f"unknown audit action {action!r}")
    now = now or datetime.now(timezone.utc)
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 7413))", (str(org_id),))
    last = conn.execute("SELECT seq, hash FROM app.audit_log WHERE org_id = %s "
                        "ORDER BY seq DESC LIMIT 1", (org_id,)).fetchone()
    seq, prev = (last["seq"] + 1, last["hash"]) if last else (1, GENESIS)
    event = {"org_id": str(org_id), "seq": seq, "at": now.isoformat(), "actor": actor,
             "action": action, "object": obj, "source_ip": source_ip,
             "details": details or {}}
    entry = canonical(event)
    h = chain_hash(prev, entry)
    conn.execute("INSERT INTO app.audit_log (org_id, seq, created_at, actor, action, object, "
                 "source_ip, entry, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, "
                 "%s, %s)", (org_id, seq, now, actor, action, obj, source_ip, entry, prev, h))
    return {"seq": seq, "hash": h}


def verify_rows(rows: Iterable[dict]) -> Tuple[bool, Optional[int], str]:
    """Verify an ordered chain. Returns (ok, first bad seq, reason).

    `rows` need seq, prev_hash, hash, entry, plus (optionally) the queryable
    columns actor/action/object, which are cross-checked against the entry.
    """
    prev, expected_seq = GENESIS, 1
    for r in rows:
        seq = r["seq"]
        if seq != expected_seq:
            return False, expected_seq, f"entry {expected_seq} is missing (found {seq})"
        if r["prev_hash"] != prev:
            return False, seq, "prev_hash does not link to the previous entry"
        if chain_hash(prev, r["entry"]) != r["hash"]:
            return False, seq, "hash does not match the entry content"
        try:
            ev = json.loads(r["entry"])
        except ValueError:
            return False, seq, "entry is not valid JSON"
        if ev.get("seq") != seq:
            return False, seq, "entry sequence number differs from the row"
        for col in ("actor", "action", "object"):
            if col in r and r[col] != ev.get(col):
                return False, seq, f"column '{col}' differs from the hashed entry"
        prev, expected_seq = r["hash"], seq + 1
    return True, None, f"{expected_seq - 1} entries verified"


def verify_org(conn, org_id: UUID) -> Tuple[bool, Optional[int], str]:
    rows = conn.execute("SELECT seq, actor, action, object, entry, prev_hash, hash FROM "
                        "app.audit_log WHERE org_id = %s ORDER BY seq", (org_id,)).fetchall()
    return verify_rows(rows)


def main(argv=None) -> int:
    import psycopg
    from psycopg.rows import dict_row
    ap = argparse.ArgumentParser(description="Verify an organization's audit chain")
    ap.add_argument("command", choices=["verify"])
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--org", required=True, type=UUID)
    args = ap.parse_args(argv)
    with psycopg.connect(args.dsn, row_factory=dict_row) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", (str(args.org),))
        ok, bad, reason = verify_org(conn, args.org)
    print(("OK: " if ok else f"BROKEN at entry {bad}: ") + reason)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
