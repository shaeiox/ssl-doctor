"""Monitoring: scheduled re-scans, expiry/drift conditions, deduplicated alerts.

    python -m ssldoctor_service.monitor --dsn "<app dsn>" [--every 30]

* ``schedule(db, now)`` enqueues jobs for monitored targets whose
  ``next_scan_at`` has passed, and advances it by the target's interval.
* ``evaluate(...)`` runs when a result is stored. It derives the current
  conditions from the document's structured ``facts`` and findings, and keeps
  one open/closed state per (target, condition). An alert is queued only when
  a condition *opens*, so a persisting problem alerts once.
* ``dispatch(db, now)`` delivers queued alerts (email via SMTP, HMAC-signed
  webhooks) and records the outcome.

All work runs tenant-scoped. Only "which orgs have work" is read cross-tenant,
through SECURITY DEFINER functions.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import smtplib
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Dict, List, Optional
from uuid import UUID

from .db import Database

STATEFUL = ("expiry_soon", "expired", "chain_incomplete", "endpoint_inconsistent")
LEAF_CHANGED = "leaf_changed:"           # event conditions, one per new leaf

_SUMMARY = {
    "expiry_soon": "certificate expires in {days} days",
    "expired": "certificate EXPIRED {ago} days ago",
    "chain_incomplete": "the server no longer sends a complete certificate chain",
    "endpoint_inconsistent": "endpoints of this target present different certificates",
    "leaf_changed": "the presented certificate changed",
}


# ------------------------------------------------------------------ scheduling

class IntervalTooShort(ValueError):
    pass


def set_monitoring(conn, org_id: UUID, target_id: UUID, interval: Optional[int],
                   threshold: int, now: datetime) -> Optional[dict]:
    minimum = conn.execute("SELECT min_interval_seconds FROM app.organizations "
                           "WHERE id = %s", (org_id,)).fetchone()["min_interval_seconds"]
    if interval is not None and interval < minimum:
        raise IntervalTooShort(f"interval {interval}s is below this plan's minimum "
                               f"of {minimum}s")
    return conn.execute(
        "UPDATE app.targets SET monitor_interval_seconds = %s, expiry_threshold_days = %s, "
        "next_scan_at = CASE WHEN %s::int IS NULL THEN NULL ELSE %s END "
        "WHERE id = %s AND org_id = %s RETURNING id, monitor_interval_seconds, "
        "expiry_threshold_days, next_scan_at",
        (interval, threshold, interval, now, target_id, org_id)).fetchone()


def enqueue_scan(conn, org_id: UUID, target_id: UUID) -> List[dict]:
    """One job per active agent assigned to the target, of that agent's role."""
    agents = conn.execute(
        "SELECT a.id, a.role FROM app.agents a JOIN app.target_agents ta ON ta.agent_id = "
        "a.id WHERE ta.target_id = %s AND a.org_id = %s AND a.revoked_at IS NULL",
        (target_id, org_id)).fetchall()
    return [conn.execute("INSERT INTO app.scan_jobs (org_id, target_id, agent_id, kind) "
                         "VALUES (%s, %s, %s, %s) RETURNING *",
                         (org_id, target_id, a["id"], a["role"])).fetchone() for a in agents]


def schedule(db: Database, now: datetime) -> int:
    jobs = 0
    with db.system() as conn:
        orgs = [r["org_id"] for r in conn.execute(
            "SELECT * FROM app.orgs_with_due_targets(%s)", (now,)).fetchall()]
    for org_id in orgs:
        with db.org(org_id) as conn:
            due = conn.execute(
                "SELECT id, monitor_interval_seconds FROM app.targets WHERE org_id = %s AND "
                "monitor_interval_seconds IS NOT NULL AND next_scan_at <= %s "
                "FOR UPDATE SKIP LOCKED", (org_id, now)).fetchall()
            for t in due:
                jobs += len(enqueue_scan(conn, org_id, t["id"]))
                conn.execute("UPDATE app.targets SET next_scan_at = %s WHERE id = %s",
                             (now + timedelta(seconds=t["monitor_interval_seconds"]), t["id"]))
    return jobs


# ------------------------------------------------------------------ evaluation

def conditions_of(doc: dict, threshold_days: int, now: datetime) -> Dict[str, dict]:
    """Current conditions (name -> details) of one findings document."""
    out: Dict[str, dict] = {}
    facts = doc.get("facts") or {}
    leaf = facts.get("leaf") or {}
    if leaf.get("not_after"):
        days = (datetime.fromisoformat(leaf["not_after"]) - now).days
        if days < 0:
            out["expired"] = {"ago": -days}
        elif days <= threshold_days:
            out["expiry_soon"] = {"days": days}
    if facts.get("chain_status") in ("incomplete", "broken"):
        out["chain_incomplete"] = {"chain_status": facts["chain_status"]}
    if any(f["check"] == "tls.multiip" and f["status"] == "WARNING"
           for f in doc.get("findings", [])):
        out["endpoint_inconsistent"] = {}
    return out


def evaluate(conn, org_id: UUID, target_id: UUID, result_id: UUID, doc: dict,
             now: datetime) -> List[str]:
    """Update alert state for a newly stored result. Returns conditions opened."""
    if not doc.get("facts"):
        return []                          # server-side results carry no endpoint facts
    t = conn.execute("SELECT host, port, expiry_threshold_days FROM app.targets "
                     "WHERE id = %s AND org_id = %s", (target_id, org_id)).fetchone()
    current = conditions_of(doc, t["expiry_threshold_days"], now)
    prev = conn.execute(
        "SELECT id, document FROM app.scan_results WHERE target_id = %s AND org_id = %s "
        "AND id <> %s AND document ? 'facts' ORDER BY created_at DESC LIMIT 1",
        (target_id, org_id, result_id)).fetchone()
    leaf = (doc["facts"].get("leaf") or {}).get("sha256")
    prev_leaf = ((prev["document"]["facts"].get("leaf") or {}).get("sha256")
                 if prev else None)
    if leaf and prev_leaf and leaf != prev_leaf:
        current[LEAF_CHANGED + leaf] = {"from": prev_leaf, "to": leaf}

    state = {r["condition"]: r for r in conn.execute(
        "SELECT condition, is_open FROM app.alert_state WHERE target_id = %s AND org_id = %s",
        (target_id, org_id)).fetchall()}
    opened = []
    for cond, details in current.items():
        row = state.get(cond)
        if row and row["is_open"]:
            conn.execute("UPDATE app.alert_state SET last_result_id = %s WHERE target_id = %s "
                         "AND condition = %s", (result_id, target_id, cond))
            continue
        conn.execute(
            "INSERT INTO app.alert_state (org_id, target_id, condition, is_open, opened_at, "
            "last_result_id) VALUES (%s, %s, %s, true, %s, %s) ON CONFLICT (target_id, "
            "condition) DO UPDATE SET is_open = true, opened_at = EXCLUDED.opened_at, "
            "closed_at = NULL, last_result_id = EXCLUDED.last_result_id",
            (org_id, target_id, cond, now, result_id))
        _queue_alert(conn, org_id, target_id, cond, details, t, result_id,
                     prev["id"] if prev else None, now)
        opened.append(cond)
    for cond, row in state.items():                     # cleared conditions re-arm
        if row["is_open"] and cond in STATEFUL and cond not in current:
            conn.execute("UPDATE app.alert_state SET is_open = false, closed_at = %s, "
                         "last_result_id = %s WHERE target_id = %s AND condition = %s",
                         (now, result_id, target_id, cond))
    return opened


def _queue_alert(conn, org_id, target_id, cond, details, target, result_id, prev_id, now):
    key = "leaf_changed" if cond.startswith(LEAF_CHANGED) else cond
    payload = {
        "event": "ssl-doctor.alert", "condition": key,
        "target": f"{target['host']}:{target['port']}", "target_id": str(target_id),
        "summary": _SUMMARY[key].format(**details), "details": details,
        "result_id": str(result_id),
        "previous_result_id": str(prev_id) if prev_id else None,
        "at": now.isoformat(),
    }
    for ch in conn.execute("SELECT id FROM app.notification_channels WHERE org_id = %s",
                           (org_id,)).fetchall():
        conn.execute("INSERT INTO app.alerts (org_id, target_id, channel_id, condition, "
                     "payload) VALUES (%s, %s, %s, %s, %s)",
                     (org_id, target_id, ch["id"], cond, json.dumps(payload)))


# ------------------------------------------------------------------ delivery

def sign_webhook(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def send_webhook(url: str, secret: Optional[str], payload: dict, timeout: float = 10) -> None:
    body = json.dumps(payload, sort_keys=True).encode()
    ts = str(int(time.time()))
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-SSLDoctor-Timestamp", ts)
    if secret:
        req.add_header("X-SSLDoctor-Signature", sign_webhook(secret, ts, body))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"webhook answered {resp.status}")


def send_email(address: str, payload: dict, timeout: float = 10) -> None:
    host = os.environ.get("SSLDOCTOR_SMTP_HOST", "localhost")
    port = int(os.environ.get("SSLDOCTOR_SMTP_PORT", "25"))
    msg = EmailMessage()
    msg["From"] = os.environ.get("SSLDOCTOR_SMTP_FROM", "ssl-doctor@localhost")
    msg["To"] = address
    msg["Subject"] = f"[SSL Doctor] {payload['target']}: {payload['summary']}"
    msg.set_content(json.dumps(payload, indent=2))
    with smtplib.SMTP(host, port, timeout=timeout) as smtp:
        if os.environ.get("SSLDOCTOR_SMTP_STARTTLS") == "1":
            smtp.starttls()
        if os.environ.get("SSLDOCTOR_SMTP_USER"):
            smtp.login(os.environ["SSLDOCTOR_SMTP_USER"], os.environ["SSLDOCTOR_SMTP_PASSWORD"])
        smtp.send_message(msg)


def dispatch(db: Database, now: Optional[datetime] = None, max_attempts: int = 5) -> int:
    now = now or datetime.now(timezone.utc)
    sent = 0
    with db.system() as conn:
        orgs = [r["org_id"] for r in conn.execute(
            "SELECT * FROM app.orgs_with_pending_alerts()").fetchall()]
    for org_id in orgs:
        with db.org(org_id) as conn:
            rows = conn.execute(
                "SELECT al.id, al.payload, al.attempts, ch.kind, ch.address, ch.secret "
                "FROM app.alerts al JOIN app.notification_channels ch ON ch.id = "
                "al.channel_id WHERE al.org_id = %s AND al.status = 'pending' "
                "ORDER BY al.created_at FOR UPDATE OF al SKIP LOCKED", (org_id,)).fetchall()
            for a in rows:
                try:
                    if a["kind"] == "webhook":
                        send_webhook(a["address"], a["secret"], a["payload"])
                    else:
                        send_email(a["address"], a["payload"])
                    conn.execute("UPDATE app.alerts SET status = 'sent', sent_at = %s, "
                                 "attempts = attempts + 1 WHERE id = %s", (now, a["id"]))
                    sent += 1
                except Exception as exc:  # noqa: BLE001 - record and retry later
                    final = a["attempts"] + 1 >= max_attempts
                    conn.execute("UPDATE app.alerts SET attempts = attempts + 1, "
                                 "last_error = %s, status = %s WHERE id = %s",
                                 (str(exc)[:500], "failed" if final else "pending", a["id"]))
    return sent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SSL Doctor scheduler + alert dispatcher")
    ap.add_argument("--dsn", default=os.environ.get("SSLDOCTOR_APP_DSN"), required=False)
    ap.add_argument("--every", type=float, default=30.0, help="seconds between ticks")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    if not args.dsn:
        ap.error("--dsn or SSLDOCTOR_APP_DSN is required")
    db = Database(args.dsn)
    while True:
        now = datetime.now(timezone.utc)
        jobs, sent = schedule(db, now), dispatch(db, now)
        if jobs or sent:
            print(f"{now:%Y-%m-%dT%H:%M:%SZ} enqueued {jobs} job(s), sent {sent} alert(s)",
                  flush=True)
        if args.once:
            return 0
        time.sleep(args.every)


if __name__ == "__main__":
    raise SystemExit(main())
