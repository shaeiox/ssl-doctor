"""Scan agent: enroll once with a one-time token, then long-poll for jobs.

    ssl-doctor agent enroll <service-url> <enrollment-token> [--state FILE]
    ssl-doctor agent run [--once] [--state FILE]

* Outbound HTTPS only: the agent opens every connection; it listens on nothing.
* Role-bound: a "client" agent runs network + client-machine checks, a
  "server" agent runs the read-only nginx checks on the host it is installed
  on. Jobs of the other kind are declined.
* Allowlisted: a job names only a kind and a target. Nothing received from the
  service is executed.

Standard library only.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from . import __version__, certpolicy, local, netchecks, report, server
from .analyze import diagnose

DEFAULT_STATE = os.path.expanduser("~/.ssl-doctor/agent.json")


class AgentError(RuntimeError):
    pass


class AgentClient:
    def __init__(self, url: str, credential: str = "", timeout: float = 40.0,
                 ca_file: Optional[str] = None) -> None:
        self.url = url.rstrip("/")
        self.credential = credential
        self.timeout = timeout
        self._ctx = ssl.create_default_context(cafile=ca_file) \
            if self.url.startswith("https://") else None

    def request(self, method: str, path: str, body: Any = None,
                timeout: Optional[float] = None) -> Tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("User-Agent", f"ssl-doctor-agent/{__version__}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.credential:
            req.add_header("Authorization", f"Bearer {self.credential}")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout,
                                        context=self._ctx) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                detail = json.loads(raw).get("detail")
            except Exception:  # noqa: BLE001
                detail = raw.decode("utf-8", "replace")[:200]
            return exc.code, {"detail": detail}

    # -- protocol
    def enroll(self, token: str) -> Dict[str, Any]:
        status, data = self.request("POST", "/v1/agent/enroll", {"token": token})
        if status != 201:
            raise AgentError(f"enrollment refused ({status}): {data.get('detail')}")
        return data

    def next_job(self, wait: float = 20.0) -> Optional[Dict[str, Any]]:
        status, data = self.request("POST", f"/v1/agent/jobs/next?wait={wait:g}",
                                    timeout=wait + 15)
        if status == 204:
            return None
        if status != 200:
            raise AgentError(f"polling failed ({status}): {(data or {}).get('detail')}")
        return data

    def upload(self, job_id: str, document: Dict[str, Any]) -> Dict[str, Any]:
        status, data = self.request("POST", f"/v1/agent/jobs/{job_id}/result", document)
        if status != 201:
            raise AgentError(f"upload refused ({status}): {data.get('detail')}")
        return data

    def decline(self, job_id: str, reason: str) -> None:
        status, data = self.request("POST", f"/v1/agent/jobs/{job_id}/decline",
                                    {"reason": reason})
        if status != 200:
            raise AgentError(f"decline refused ({status}): {data.get('detail')}")


# ------------------------------------------------------------------ checks

def run_client_checks(host: str, port: int, sni: Optional[str],
                      timeout: float = 8.0) -> Dict[str, Any]:
    items, facts = netchecks.run_remote_diagnostics(host, port, sni=sni, timeout=timeout)
    if facts.get("cert"):
        items.insert(0, netchecks.domain_profile(host, port, facts.get("ips", []), facts))
    items += local.run_local_for_remote(facts)
    return report.build_payload(items, diagnose(items), _meta(host, port, "client"),
                                facts=netchecks.export_facts(facts))


def run_server_checks(host: str, port: int, sni: Optional[str],
                      timeout: float = 8.0) -> Dict[str, Any]:
    domain = sni or host
    sess = server.LocalSession(tls_host=domain, tls_port=port)
    _dns, ips = netchecks.check_dns(host, timeout)
    items = sess.overview() + sess.webserver_detection() + sess.nginx_scan(
        domain, port, addresses=tuple(ips))
    _hs, hs_facts = netchecks.check_tls_basic(host, port, domain, timeout)
    presented = hs_facts["cert"].sha256 if hs_facts.get("cert") else ""
    chain = hs_facts.get("chain")
    items.append(sess.compare_configured_vs_presented(
        presented, presented_chain=[c.sha256 for c in chain] if chain else None,
        presented_from=hs_facts.get("handshake_ip") or ""))
    items.append(sess.inventory_finding(presented))
    items += sess.log_scan()
    # configured chains only: endpoint facts (leaf, chain_status) belong to client runs
    facts = {"certificates": sess.chain_facts} if sess.chain_facts else None
    return report.build_payload(items, diagnose(items), _meta(host, port, "server"),
                                facts=facts)


def _meta(host: str, port: int, kind: str) -> Dict[str, Any]:
    return {"target": f"{host}:{port}", "producer": f"agent/{kind}"}


RUNNERS = {"client": run_client_checks, "server": run_server_checks}


def handle_job(client: AgentClient, role: str, job: Dict[str, Any]) -> str:
    """Run one job. Returns 'done' or 'declined'."""
    kind = job.get("kind")
    if kind != role or kind not in RUNNERS:
        client.decline(job["job_id"], f"agent role '{role}' cannot run '{kind}' jobs")
        return "declined"
    t = job["target"]
    options = job.get("options") or {}
    try:
        warn = certpolicy.parse_warn_days(options.get("expiry_warn_days",
                                                      certpolicy.DEFAULT_WARN_DAYS))
    except ValueError as exc:
        client.decline(job["job_id"], f"invalid job option: {exc}")
        return "declined"
    previous = certpolicy.warn_days()
    certpolicy.set_warn_days(warn)
    try:
        doc = RUNNERS[kind](t["host"], int(t["port"]), t.get("sni"))
    finally:
        certpolicy.set_warn_days(previous)
    client.upload(job["job_id"], doc)
    return "done"


# ------------------------------------------------------------------ state + CLI

def save_state(path: str, state: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(state, fh)
    except OSError as exc:
        raise AgentError(f"cannot write agent state {path}: {exc.strerror or exc}") from None


def load_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except FileNotFoundError:
        raise AgentError(f"no agent state at {path}: run `ssl-doctor agent enroll "
                         "<url> <token>` first (or pass --state FILE)") from None
    except OSError as exc:
        raise AgentError(f"cannot read agent state {path}: {exc.strerror or exc}") from None
    except ValueError:
        raise AgentError(f"agent state {path} is not valid JSON; enroll again") from None
    if not isinstance(state, dict):
        raise AgentError(f"agent state {path} is not an agent state document; enroll again")
    return state


def serve(state: Dict[str, Any], once: bool = False, wait: float = 20.0) -> int:
    client = AgentClient(state["url"], state["credential"])
    backoff = 1.0
    while True:
        try:
            job = client.next_job(wait)
            backoff = 1.0
            if job:
                outcome = handle_job(client, state["role"], job)
                print(f"job {job['job_id']} ({job['kind']}): {outcome}", flush=True)
            if once:
                return 0
        except AgentError as exc:
            print(f"agent: {exc}", file=sys.stderr, flush=True)
            if "revoked" in str(exc) or "unknown agent" in str(exc):
                return 2
            if once:
                return 1
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)
        except (urllib.error.URLError, OSError) as exc:
            print(f"agent: service unreachable: {exc}", file=sys.stderr, flush=True)
            if once:
                return 1
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)


def main(argv) -> int:
    args = list(argv)
    state_path = DEFAULT_STATE
    if "--state" in args:
        i = args.index("--state")
        state_path = args[i + 1]
        del args[i:i + 2]
    if args[:1] == ["enroll"] and len(args) == 3:
        client = AgentClient(args[1])
        data = client.enroll(args[2])
        save_state(state_path, {"url": args[1], **data})
        print(f"enrolled as {data['role']} agent '{data['name']}' ({data['agent_id']}); "
              f"credential stored in {state_path} (0600)")
        return 0
    if args[:1] == ["run"]:
        return serve(load_state(state_path), once="--once" in args)
    print("usage: ssl-doctor agent enroll <url> <token> | ssl-doctor agent run [--once]"
          " [--state FILE]", file=sys.stderr)
    return 64
