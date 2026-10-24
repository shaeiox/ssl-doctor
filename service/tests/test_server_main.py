"""self-hosted-deployment 12.1: ssldoctor-server lifecycle with embedded PostgreSQL."""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

import pgfixture

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def server_cmd():
    """How to invoke ssldoctor-server: the built binary if given, else the module."""
    exe = os.environ.get("SSLDOCTOR_SERVER_EXE")
    return [exe] if exe else [sys.executable, "-W", "ignore", "-m",
                              "ssldoctor_service.server_main"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Install:
    """A fresh data directory (reachable by the run-as user when we are root)."""

    def __init__(self):
        self.base = tempfile.mkdtemp(prefix="ssldoctor-srv-", dir="/tmp")
        os.chmod(self.base, 0o755)
        self.data = os.path.join(self.base, "data")
        self.port = free_port()
        if os.environ.get("SSLDOCTOR_SERVER_EXE"):
            # built executable: prove it needs no Python (nothing on PATH but sbin)
            self.env = {"PATH": "/usr/sbin:/sbin", "HOME": "/tmp", "LANG": "C.UTF-8"}
        else:
            self.env = dict(os.environ, PYTHONPATH=os.pathsep.join(
                [os.path.join(ROOT, "service"), ROOT]))
        self.runas = ["--run-as", os.environ.get("SSLDOCTOR_PG_USER", "nobody")] \
            if os.geteuid() == 0 else []

    def run(self, *args, timeout=180):
        return subprocess.run(server_cmd() + list(args), env=self.env, capture_output=True,
                              text=True, timeout=timeout)

    def init(self):
        p = self.run("init", "--data", self.data, "--org", "Acme",
                     "--listen", f"127.0.0.1:{self.port}", *self.runas)
        assert p.returncode == 0, p.stderr
        return re.search(r"owner API token \(shown once\): (\S+)", p.stdout).group(1)

    def serve(self):
        self.proc = subprocess.Popen(server_cmd() + ["run", "--data", self.data,
                                                     "--monitor-every", "1"],
                                     env=self.env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz",
                                            timeout=2) as r:
                    return json.loads(r.read())
            except OSError:
                if self.proc.poll() is not None:
                    raise AssertionError(self.proc.stdout.read())
                time.sleep(0.3)
        raise AssertionError("server did not become healthy")

    def stop(self):
        if getattr(self, "proc", None) and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=60)

    def cleanup(self):
        self.stop()
        shutil.rmtree(self.base, ignore_errors=True)


def api(port, token, method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"null")


@unittest.skipUnless(pgfixture.available() and os.name != "nt", "PostgreSQL binaries needed")
class ServerLifecycleTests(unittest.TestCase):

    def setUp(self):
        self.inst = Install()

    def tearDown(self):
        self.inst.cleanup()

    def test_init_then_run_answers_healthz_and_api(self):
        token = self.inst.init()
        for path, mode in ((self.inst.data, 0o700),
                           (os.path.join(self.inst.data, "config.json"), 0o600)):
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(mode), path)
        self.assertEqual(self.inst.serve(), {"status": "ok"})
        t = api(self.inst.port, token, "POST", "/v1/targets",
                {"host": "intranet.example", "port": 443})
        self.assertEqual(api(self.inst.port, token, "GET", f"/v1/targets/{t['id']}")["host"],
                         "intranet.example")

    def test_data_survives_restart_and_upgrade_and_audit_verifies(self):
        token = self.inst.init()
        self.inst.serve()
        api(self.inst.port, token, "POST", "/v1/targets", {"host": "keep.example", "port": 443})
        self.inst.stop()
        up = self.inst.run("upgrade", "--data", self.inst.data)
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn("backup:", up.stdout)
        self.assertTrue(os.listdir(os.path.join(self.inst.data, "backups")))
        va = self.inst.run("verify-audit", "--data", self.inst.data)
        self.assertEqual(va.returncode, 0, va.stdout + va.stderr)
        self.assertIn("OK", va.stdout)
        self.inst.serve()
        hosts = [t["host"] for t in api(self.inst.port, token, "GET", "/v1/targets")]
        self.assertIn("keep.example", hosts)

    def test_refuses_root_without_run_as(self):
        if os.geteuid() != 0:
            self.skipTest("only meaningful as root")
        p = self.inst.run("init", "--data", self.inst.data)
        self.assertEqual(p.returncode, 2)
        self.assertIn("refusing to run PostgreSQL as root", p.stderr)

    def test_double_init_refused(self):
        self.inst.init()
        p = self.inst.run("init", "--data", self.inst.data, *self.inst.runas)
        self.assertEqual(p.returncode, 1)
        self.assertIn("already initialized", p.stderr)


if __name__ == "__main__":
    unittest.main()
