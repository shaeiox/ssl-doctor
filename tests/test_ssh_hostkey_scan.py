"""Host keys are retrieved even when ssh-keyscan cannot negotiate a key exchange.

Regression cover for a field bug: `/server connect` stopped with
"cannot reach the SSH service / host key: choose_kex: unsupported KEX method
sntrup761x25519-sha512@openssh.com" while `ssh user@host` worked. ssh-keyscan
proposes OpenSSH's compiled-in default KEX list unfiltered (myproposal.h always
leads with sntrup761x25519), but a build without USE_SNTRUP761X25519 cannot run
it once a modern server agrees to it. ssh filters the same defaults down to what
the binary implements (readconf.c), so the host key is read through ssh.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from ssl_doctor import server

ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAICbsFicp0MZLjvWnjthrjzafNve0FNnHYFoq3AI16qgI"
RSA = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7fakefakefake"
KEX_ERROR = "choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com"


def option(argv, name):
    for index, arg in enumerate(argv):
        if arg == "-o" and argv[index + 1].startswith(name + "="):
            return argv[index + 1].split("=", 1)[1]
    return None


class FakeOpenSSH:
    """ssh-keyscan, ssh and ssh-keygen as seen on the affected machine."""

    def __init__(self, keyscan_error=KEX_ERROR, server_keys=None, hashed=False):
        self.keyscan_error = keyscan_error
        self.server_keys = {"ssh-ed25519": ED25519, "ssh-rsa": RSA} \
            if server_keys is None else server_keys
        self.hashed = hashed
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        tool = os.path.basename(argv[0])
        if tool == "ssh-keyscan":
            return subprocess.CompletedProcess(argv, 1, "", self.keyscan_error + "\n")
        if tool == "ssh":
            return self.ssh(argv)
        if tool == "ssh-keygen":
            return self.keygen(argv)
        raise AssertionError(f"unexpected command {argv}")

    def ssh(self, argv):
        wanted = option(argv, "HostKeyAlgorithms").split(",")
        key_type = next((t for t in self.server_keys
                         if t in wanted or (t == "ssh-rsa" and "rsa-sha2-512" in wanted)),
                        None)
        if key_type is None:
            return subprocess.CompletedProcess(
                argv, 255, "", "Unable to negotiate: no matching host key type found\n")
        assert option(argv, "StrictHostKeyChecking") == "accept-new"
        name = "|1|c2FsdA==|aGFzaA==" if self.hashed else "files.example.com"
        with open(option(argv, "UserKnownHostsFile"), "a") as fh:
            fh.write(f"{name} {key_type} {self.server_keys[key_type]}\n")
        return subprocess.CompletedProcess(argv, 255, "", "Permission denied (publickey).\n")

    def keygen(self, argv):
        if "-lf" in argv:
            with open(argv[argv.index("-lf") + 1]) as fh:
                rows = [ln.split() for ln in fh if ln.strip()]
            return subprocess.CompletedProcess(
                argv, 0, "".join(f"256 SHA256:{r[2][-8:]} {r[0]} ({r[1]})\n" for r in rows), "")
        lookup, path = argv[argv.index("-F") + 1], argv[argv.index("-f") + 1]
        with open(path) as fh:
            found = [ln for ln in fh if ln.split()[:1] == [lookup]]
        return subprocess.CompletedProcess(argv, 0 if found else 1, "".join(found), "")


class HostKeyScanFallback(unittest.TestCase):

    def setUp(self):
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        patches = [mock.patch.object(server, "STATE_DIR", state),
                   mock.patch.object(server.shutil, "which", lambda name: f"/usr/bin/{name}")]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.known_hosts = os.path.join(state, "known_hosts")

    def use(self, fake):
        patch = mock.patch.object(server.subprocess, "run", fake)
        patch.start()
        self.addCleanup(patch.stop)
        return fake

    def test_a_kex_failure_in_ssh_keyscan_falls_back_to_ssh(self):
        self.use(FakeOpenSSH())
        info = server.host_key_status("files.example.com", 22, timeout=3)
        self.assertEqual(info.status, "unknown")             # reachable, not yet trusted
        self.assertEqual(len(info.fingerprints), 2)

    def test_the_trusted_key_is_stored_and_then_matches(self):
        self.use(FakeOpenSSH())
        ok, _ = server.store_host_key("files.example.com", 22, timeout=3)
        self.assertTrue(ok)
        with open(self.known_hosts) as fh:
            stored = sorted(ln.split()[1] for ln in fh if ln.strip())
        self.assertEqual(stored, ["ssh-ed25519", "ssh-rsa"])
        self.assertEqual(server.host_key_status("files.example.com", 22, 3).status, "trusted")

    def test_hashed_names_are_stored_under_the_lookup_name(self):
        self.use(FakeOpenSSH(hashed=True))
        server.store_host_key("files.example.com", 2222, timeout=3)
        with open(self.known_hosts) as fh:
            names = {ln.split()[0] for ln in fh if ln.strip()}
        self.assertEqual(names, {"[files.example.com]:2222"})

    def test_the_probe_can_never_authenticate(self):
        fake = self.use(FakeOpenSSH())
        server.host_key_status("files.example.com", 22, timeout=3)
        probes = [argv for argv in fake.calls if os.path.basename(argv[0]) == "ssh"]
        self.assertTrue(probes)
        for argv in probes:
            for name in ("PubkeyAuthentication", "PasswordAuthentication",
                         "KbdInteractiveAuthentication", "GSSAPIAuthentication",
                         "HostbasedAuthentication"):
                self.assertEqual(option(argv, name), "no", name)
            self.assertEqual(option(argv, "BatchMode"), "yes")

    def test_a_changed_key_is_still_detected_through_the_fallback(self):
        with open(self.known_hosts, "w") as fh:
            fh.write(f"files.example.com ssh-ed25519 {ED25519[:-4]}AAAA\n")
        self.use(FakeOpenSSH())
        self.assertEqual(server.host_key_status("files.example.com", 22, 3).status, "changed")

    def test_both_errors_are_reported_when_the_fallback_also_fails(self):
        self.use(FakeOpenSSH(server_keys={}))
        info = server.host_key_status("files.example.com", 22, timeout=3)
        self.assertEqual(info.status, "unreachable")
        self.assertIn("unsupported KEX method", info.detail)
        self.assertIn("no matching host key type", info.detail)

    def test_an_unreachable_host_does_not_trigger_the_fallback(self):
        fake = self.use(FakeOpenSSH(keyscan_error="connect to files.example.com port 22: "
                                                  "Connection refused"))
        info = server.host_key_status("files.example.com", 22, timeout=3)
        self.assertEqual(info.status, "unreachable")
        self.assertFalse([a for a in fake.calls if os.path.basename(a[0]) == "ssh"])


if __name__ == "__main__":
    unittest.main()
