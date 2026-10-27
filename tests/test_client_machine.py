"""client-machine-diagnostics: checks about the machine running SSL Doctor.

Audit A: `local.certutil` was FAIL whenever the word "error" appeared anywhere
in a successful `certutil -verify` output.
"""

import http.server
import ssl
import subprocess
import threading
import time
import unittest
from email.utils import formatdate
from unittest import mock

from fixtures.pki import get_pki, openssl_available

from ssl_doctor import findings as F
from ssl_doctor import local, netchecks
from ssl_doctor.analyze import diagnose

SUCCESS_TAIL = "Leaf certificate revocation check passed\nCertUtil: -verify command completed successfully.\n"

CHAIN_DUMP = """Issuer:
    CN=Example Intermediate
Subject:
    CN=www.example.com
-------- CERT_CHAIN_CONTEXT --------
ChainContext.dwInfoStatus = CERT_TRUST_HAS_PREFERRED_ISSUER (0x100)
SimpleChain.dwInfoStatus = CERT_TRUST_HAS_PREFERRED_ISSUER (0x100)
CertContext[0][0]: dwInfoStatus=102 dwErrorStatus=0
  Issuer: CN=Example Intermediate
Exclude leaf cert:
Full chain:
""" + SUCCESS_TAIL

URL_FAILURE = ('  Failed "CDP" Time: 0\n'
               "    Error retrieving URL: The server name or address could not be resolved "
               "0x80072ee7 (WinHttp: 12007 ERROR_WINHTTP_NAME_NOT_RESOLVED)\n"
               "    http://crl.example.com/int.crl\n" + SUCCESS_TAIL)

CHAINING_FAILED = ("CertUtil: -verify command FAILED: 0x800b010a (-2146762486 CERT_E_CHAINING)\n"
                   "CertUtil: A certificate chain could not be built to a trusted root "
                   "authority.\n")


def certutil(stdout="", rc=0, stderr="", raises=None):
    """Run check_certutil_verify as on Windows, with certutil's result mocked."""
    run = mock.Mock(side_effect=raises) if raises else mock.Mock(
        return_value=subprocess.CompletedProcess([], rc, stdout, stderr))
    with mock.patch.object(local, "IS_WINDOWS", True), \
            mock.patch.object(local.shutil, "which", return_value=r"C:\Windows\certutil.exe"), \
            mock.patch.object(local.subprocess, "run", run):
        return local.check_certutil_verify("leaf.cer")


class CertutilResult(unittest.TestCase):

    def test_regression_a_success_with_a_chain_dump(self):
        self.assertEqual(certutil(CHAIN_DUMP).status, F.PASS)

    def test_error_inside_a_certificate_name(self):
        out = "Subject:\n    CN=error-reporting.example.com\n" + SUCCESS_TAIL
        self.assertEqual(certutil(out).status, F.PASS)

    def test_unreachable_cdp_url_is_not_a_chain_failure(self):
        f = certutil(URL_FAILURE)
        self.assertEqual(f.status, F.PASS)
        self.assertTrue(any("could not be retrieved" in e and "crl.example.com" in e
                            for e in f.evidence), f.evidence)

    def test_localised_success(self):
        out = ("Überprüfung der Sperrung des Endzertifikats erfolgreich\n"
               "CertUtil: -verify-Befehl wurde erfolgreich ausgeführt.\n")
        self.assertEqual(certutil(out).status, F.PASS)

    def test_chain_cannot_be_built(self):
        f = certutil(CHAINING_FAILED, rc=0x800b010a)
        self.assertEqual(f.status, F.FAIL)
        self.assertTrue(any("0x800b010a" in e for e in f.evidence), f.evidence)

    def test_failure_code_from_the_exit_status(self):
        f = certutil("CertUtil: -verify-Befehl ist FEHLGESCHLAGEN\n", rc=0x80092012)
        self.assertEqual(f.status, F.FAIL)
        self.assertTrue(any("0x80092012" in e for e in f.evidence), f.evidence)

    def test_access_denied_when_starting_certutil(self):
        f = certutil(raises=PermissionError(13, "Access is denied"))
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertTrue(any("Access is denied" in e for e in f.evidence), f.evidence)

    def test_timeout(self):
        f = certutil(raises=subprocess.TimeoutExpired("certutil", 60))
        self.assertEqual(f.status, F.NOT_TESTED)


class HeaderServer:
    """HTTPS server answering '/' with the headers a test chooses; `redirect`
    sends the first request on to https://localhost:<port>/ (another host name)."""

    def __init__(self, date_offset=0.0, age=None, redirect=False):
        self.date_offset, self.age, self.redirect = date_offset, age, redirect

    def __enter__(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                host = (self.headers.get("Host") or "").split(":")[0]
                if outer.redirect and host != "localhost":
                    self.send_response(301)
                    self.send_header("Location", f"https://localhost:{outer.port}/")
                else:
                    self.send_response(200)
                    if outer.age is not None:
                        self.send_header("Age", str(outer.age))
                self.send_header("Content-Length", "0")
                self.end_headers()

            def date_time_string(self, timestamp=None):
                return formatdate(time.time() + outer.date_offset, usegmt=True)

            def log_message(self, *args):
                pass

        p = get_pki()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(p.leaf, p.leaf_key)
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def facts(self):
        _f, facts = netchecks.check_https("127.0.0.1", self.port, None, 5)
        return facts


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ServerTimeReference(unittest.TestCase):

    def test_reference_records_receive_time_rtt_and_host(self):
        with HeaderServer() as srv:
            before = time.time()
            facts = srv.facts()
        self.assertGreaterEqual(facts["server_time_received"], before)
        self.assertGreaterEqual(facts["server_time_rtt"], 0)
        self.assertEqual(facts["server_time_host"], "127.0.0.1")
        self.assertEqual(facts["server_time_age"], 0)

    def test_age_is_added_to_the_date(self):
        with HeaderServer(date_offset=-600, age=600) as srv:
            facts = srv.facts()
        self.assertEqual(facts["server_time_age"], 600)
        self.assertLess(abs(facts["server_time"].timestamp() - facts["server_time_received"]),
                        5)

    def test_malformed_age_is_recorded(self):
        with HeaderServer(age="soon") as srv:
            facts = srv.facts()
        self.assertIn("Age", facts["server_time_problem"])

    def test_redirect_target_names_its_host(self):
        with HeaderServer(redirect=True) as srv:
            facts = srv.facts()
        self.assertEqual(facts["server_time_host"], "localhost")


def skew_finding(skew, rtt=0.0, received_ago=1.0, age=0, host="shop.test",
                 target="shop.test", problem=""):
    """local.clockskew for a reference received `received_ago` seconds ago,
    while this machine is `skew` seconds ahead of the server."""
    now = time.time()
    received = now - received_ago
    ref = {"server_time_epoch": received - skew, "server_time_received": received,
           "server_time_rtt": rtt, "server_time_host": host, "server_time_age": age,
           "server_time_problem": problem, "target": target}
    return [f for f in local.check_os_and_clock(ref["server_time_epoch"], reference=ref)
            if f.check == "local.clockskew"][0]


class ClockSkew(unittest.TestCase):

    def test_regression_d_stale_reference_is_not_tested(self):
        f = skew_finding(0, received_ago=360)
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertTrue(any("reference is 360s old" in e for e in f.evidence), f.evidence)

    def test_fresh_agreeing_clocks_pass(self):
        f = skew_finding(1.5)
        self.assertEqual(f.status, F.PASS)

    def test_age_correction_is_named(self):
        f = skew_finding(0, age=600)
        self.assertEqual(f.status, F.PASS)
        self.assertTrue(any("Age correction" in e for e in f.evidence), f.evidence)

    def test_boundaries_with_the_minimum_uncertainty(self):
        for skew, status in ((61, F.PASS), (62, F.WARNING), (301, F.WARNING), (302, F.FAIL)):
            for sign in (1, -1):
                with self.subTest(skew=sign * skew):
                    self.assertEqual(skew_finding(sign * skew).status, status)

    def test_boundary_within_a_larger_uncertainty(self):
        self.assertEqual(skew_finding(301, rtt=2).status, F.WARNING)
        self.assertEqual(skew_finding(304, rtt=2).status, F.FAIL)

    def test_source_and_uncertainty_are_named(self):
        f = skew_finding(400, rtt=0.4, host="login.example.net", target="shop.test")
        text = " ".join(f.evidence)
        self.assertIn("login.example.net", text)
        self.assertIn("redirect", text)
        self.assertIn("uncertainty", text)

    def test_malformed_age_is_not_tested(self):
        self.assertEqual(skew_finding(0, problem="malformed Age header 'soon'").status,
                         F.NOT_TESTED)


class ClockCause(unittest.TestCase):

    def items(self, verify_error):
        def f(check, status, *ev, scope=F.SCOPE_REMOTE_NET):
            return F.Finding(check, check, status, scope, list(ev))
        return [f("tls.handshake", F.PASS, "negotiated"), f("tls.chain", F.PASS, "linked"),
                f("tls.verify", F.FAIL, f"validation failed: {verify_error}"),
                f("local.clockskew", F.FAIL, "this machine is 900s ahead",
                  scope=F.SCOPE_LOCAL)]

    def clock_causes(self, d):
        return [c for c in d.causes if "Client clock is significantly off" in c.summary]

    def test_missing_issuer_is_not_blamed_on_the_clock(self):
        d = diagnose(self.items("unable to get local issuer certificate"))
        self.assertEqual(self.clock_causes(d), [])
        self.assertTrue(d.causes)            # the issuer cause is still raised

    def test_expired_certificate_with_a_skewed_clock(self):
        d = diagnose(self.items("certificate has expired"))
        self.assertEqual([c.certainty for c in self.clock_causes(d)], ["probable"])


class LocalAfterTls(unittest.TestCase):
    """The documented sequence: `/tls`, then `/local` more than 120 s later."""

    def test_documented_wording(self):
        from ssl_doctor import cli
        import contextlib
        import io
        app = cli.SSLDoctorCLI()
        received = time.time() - 300
        app.remote_facts = {"host": "shop.test", "server_time_epoch": received,
                            "server_time_received": received, "server_time_rtt": 0.05,
                            "server_time_host": "shop.test", "server_time_age": 0}
        with contextlib.redirect_stdout(io.StringIO()):
            app.execute("/local")
        [f] = [x for x in app.store.all() if x.check == "local.clockskew"]
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertRegex(" ".join(f.evidence),
                         r"server time reference is 30\ds old; repeat the network check")


if __name__ == "__main__":
    unittest.main()
