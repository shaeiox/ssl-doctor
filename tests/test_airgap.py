"""self-hosted-deployment 12.5: install + scan with NO network egress.

Runs itself again inside a fresh network namespace (``unshare -n``): only a
loopback interface exists, so any outbound connection fails. Inside it, only
the release bundle is used: verify, ``ssldoctor-server init/run``, enroll the
agent executable, scan an internal (loopback) leaf-only TLS endpoint, and check
the platform diagnoses the missing intermediate as a server cause.

Needs root (namespaces), a Linux build (dist/linux) and the release tooling.
"""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packaging"))
INSIDE = "SSLDOCTOR_AIRGAP_INSIDE"


def can_run():
    import importlib.util
    return (sys.platform.startswith("linux") and os.geteuid() == 0
            and shutil.which("unshare") and shutil.which("openssl")
            and os.path.exists(os.path.join(ROOT, "dist", "linux", "ssl-doctor"))
            and importlib.util.find_spec("cyclonedx_py") is not None)


def http(port, token, method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def inside_namespace(archive: str, work: str) -> dict:
    """The air-gapped part. Returns facts for the outer test to assert on."""
    facts = {}
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    # 1. prove there is no egress
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        facts["egress"] = "open"
    except OSError as exc:
        facts["egress"] = f"blocked ({exc.__class__.__name__}: {exc})"
    # 2. extract + verify the bundle
    with tarfile.open(archive) as t:
        t.extractall(work)
    bundle = os.path.join(work, [d for d in os.listdir(work) if d.startswith("ssl-doctor-")][0])
    import release
    facts["verify"] = release.verify(bundle)[:2]
    env = {"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "HOME": work, "LANG": "C.UTF-8"}
    server = os.path.join(bundle, "ssldoctor-server", "ssldoctor-server")
    agent_exe = os.path.join(bundle, "bin", "ssl-doctor-agent")
    # 3. install the platform
    data = os.path.join(work, "data")
    port = 18443
    init = subprocess.run([server, "init", "--data", data, "--org", "Air-gapped Ltd",
                           "--listen", f"127.0.0.1:{port}", "--run-as", "nobody"],
                          env=env, capture_output=True, text=True, timeout=180)
    facts["init_rc"] = init.returncode
    token = re.search(r"token \(shown once\): (\S+)", init.stdout).group(1)
    srv = subprocess.Popen([server, "run", "--data", data, "--monitor-every", "1"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = None
    try:
        for _ in range(200):
            try:
                facts["health"] = http(port, token, "GET", "/healthz")
                break
            except OSError:
                time.sleep(0.3)
        # 4. an internal endpoint with the customer's mistake: leaf-only chain
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        from fixtures.pki import HOSTNAME, get_pki
        from fixtures.tls_server import TLSServer
        pki = get_pki()
        tls = TLSServer(pki, "leaf-only").__enter__()
        # 5. enroll the agent EXECUTABLE and scan
        tok = http(port, token, "POST", "/v1/enrollment-tokens",
                   {"name": "dc1-client", "role": "client"})["token"]
        state = os.path.join(work, "agent.json")
        enroll = subprocess.run([agent_exe, "enroll", f"http://127.0.0.1:{port}", tok,
                                 "--state", state], env=env, capture_output=True, text=True)
        facts["enroll_rc"] = enroll.returncode
        agent_id = json.load(open(state))["agent_id"]
        t = http(port, token, "POST", "/v1/targets", {"host": "127.0.0.1", "port": tls.port,
                                                    "sni": HOSTNAME, "agent_ids": [agent_id]})
        http(port, token, "POST", f"/v1/targets/{t['id']}/scans")
        agent_env = dict(env, SSL_CERT_FILE=pki.bundle("root", "intermediate"))
        run = subprocess.run([agent_exe, "run", "--once", "--state", state], env=agent_env,
                             capture_output=True, text=True, timeout=180)
        facts["agent_rc"], facts["agent_out"] = run.returncode, run.stdout + run.stderr
        results = http(port, token, "GET", f"/v1/targets/{t['id']}/results")
        doc = http(port, token, "GET", f"/v1/results/{results[0]['id']}")["document"]
        facts["overall"] = doc["diagnosis"]["overall"]
        facts["top_cause"] = doc["diagnosis"]["causes"][0]
    finally:
        if tls:
            tls.__exit__()
        srv.send_signal(signal.SIGTERM)
        srv.wait(timeout=60)
    return facts


@unittest.skipUnless(can_run(), "needs root, unshare, openssl, a dist/linux build")
class AirGapTests(unittest.TestCase):

    def test_install_and_scan_without_network(self):
        import release
        out = tempfile.mkdtemp(prefix="ssldoctor-airgap-", dir="/tmp")
        os.chmod(out, 0o755)
        try:
            key = os.path.join(out, "key.pem")
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key],
                           check=True)
            archive = release.build(os.path.join(ROOT, "dist", "linux"), key, out)
            work = os.path.join(out, "work")
            os.makedirs(work)
            os.chmod(work, 0o755)
            p = subprocess.run(["unshare", "-n", sys.executable, "-W", "ignore", __file__,
                                archive, work], env=dict(os.environ, **{INSIDE: "1"}),
                               capture_output=True, text=True, timeout=900)
            self.assertEqual(p.returncode, 0, p.stderr[-3000:])
            facts = json.loads(p.stdout.strip().splitlines()[-1])
        finally:
            shutil.rmtree(out, ignore_errors=True)
        self.assertTrue(facts["egress"].startswith("blocked"), facts["egress"])
        self.assertEqual(facts["verify"], [True, True])
        self.assertEqual(facts["init_rc"], 0)
        self.assertEqual(facts["health"], {"status": "ok"})
        self.assertEqual(facts["enroll_rc"], 0)
        self.assertEqual(facts["agent_rc"], 0, facts["agent_out"])
        self.assertEqual(facts["overall"], "FAIL")
        self.assertEqual(facts["top_cause"]["origin"], "server")
        self.assertIn("full chain", facts["top_cause"]["summary"])


if __name__ == "__main__":
    if os.environ.get(INSIDE) == "1":
        print(json.dumps(inside_namespace(sys.argv[1], sys.argv[2])))
    else:
        unittest.main()
