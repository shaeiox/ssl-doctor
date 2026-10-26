"""Every server-side check runs end to end on a connected session.

Regression cover for a field bug: `/scan` step 3 stopped with
"NameError: name 'fatal' is not defined" right after "reading server
identity". The streaming refactor (a024efe) dropped the `self.run(...)` call
from `ServerSession.overview()` while keeping the code that reads its result,
and no test ran a server check against a connected session.
"""

from __future__ import annotations

import unittest
from typing import List

from ssl_doctor import findings as F, server

IDENTITY = ("Linux files 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\n---\n"
            'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n---\n'
            "uid=1000(eleven) gid=1000(eleven) groups=1000(eleven)\n")


class FakeServer(server.ServerSession):
    """A connected session whose remote commands return canned output."""

    def __init__(self, rc=0, out=IDENTITY, err="", fatal=""):
        super().__init__(server.SSHConfig(host="files.example.com", username="eleven"))
        self.connected = True
        self.reply = (rc, out, err, fatal)
        self.commands: List[str] = []

    def run(self, remote_cmd):
        self.commands.append(remote_cmd)
        return self.reply


class Overview(unittest.TestCase):

    def test_overview_reads_the_server_identity(self):
        session = FakeServer()
        [finding] = session.overview()
        self.assertEqual(finding.status, F.PASS)
        self.assertIn("uid=1000(eleven) gid=1000(eleven) groups=1000(eleven)", finding.evidence)
        self.assertIn("uname -a", session.commands[0])

    def test_overview_streams_the_finding_it_returns(self):
        emitted = []
        returned = FakeServer().overview(emit=emitted.append)
        self.assertEqual(emitted, returned)

    def test_a_failing_command_is_a_fail_finding(self):
        [finding] = FakeServer(rc=1, out="", err="sh: uname: not found").overview()
        self.assertEqual(finding.status, F.FAIL)
        self.assertEqual(finding.evidence, ["sh: uname: not found"])

    def test_a_transport_failure_is_reported(self):
        [finding] = FakeServer(rc=124, out="", fatal="command timed out after 20s").overview()
        self.assertEqual(finding.status, F.FAIL)
        self.assertEqual(finding.evidence, ["command timed out after 20s"])


class EveryCheckRuns(unittest.TestCase):
    """No check may raise on a connected session, whatever the server answers."""

    CHECKS = {
        "overview": lambda s, emit: s.overview(emit=emit),
        "webserver_detection": lambda s, emit: s.webserver_detection(emit=emit),
        "tls_config_scan": lambda s, emit: s.tls_config_scan(emit=emit),
        "log_scan": lambda s, emit: s.log_scan(emit=emit),
        "file_permissions": lambda s, emit: s.file_permissions(["/etc/ssl/certs/site.pem"]),
        "scan_cert": lambda s, emit: s.scan_cert("/etc/ssl/certs/site.pem", emit=emit),
        "nginx_scan": lambda s, emit: s.nginx_scan("files.example.com", emit=emit),
        "compare_configured_vs_presented":
            lambda s, emit: s.compare_configured_vs_presented("ab" * 32, emit=emit),
        "service_scan": lambda s, emit: s.service_scan("files.example.com", emit=emit),
        "inventory_finding": lambda s, emit: [s.inventory_finding("ab" * 32)],
    }
    REPLIES = {
        "success": (0, IDENTITY, "", ""),
        "empty": (0, "", "", ""),
        "error": (1, "", "permission denied", ""),
        "transport": (255, "", "", "command timed out after 20s"),
    }

    def test_every_check_completes(self):
        for check, call in self.CHECKS.items():
            for name, reply in self.REPLIES.items():
                with self.subTest(check=check, reply=name):
                    emitted = []
                    result = call(FakeServer(*reply), emitted.append)
                    results = result if isinstance(result, list) else [result]
                    self.assertTrue(all(isinstance(f, F.Finding) for f in results))


class DiscoveryNeverRaises(unittest.TestCase):
    """nginx discovery over the real SSH probe, whatever the server answers."""

    def test_every_reply_kind(self):
        for name, reply in EveryCheckRuns.REPLIES.items():
            with self.subTest(reply=name):
                session = FakeServer(*reply)
                d = session.discover_nginx()
                self.assertIs(session.discover_nginx(), d)       # cached per connection
                self.assertIn(d.level, ("none", "candidate"))

    def test_the_cache_is_cleared_on_disconnect(self):
        session = FakeServer()
        first = session.discover_nginx()
        session.disconnect()
        session.connected = True
        self.assertIsNot(session.discover_nginx(), first)


if __name__ == "__main__":
    unittest.main()
