"""tls-negotiation-diagnostics: validation handshakes classify transport failures.

R5: a stalled validation handshake was `tls.verify` FAIL plus a probable
"certificate" cause, although nothing about the certificate was learned.
"""

import unittest
from unittest import mock

from fixtures.fault_server import FaultServer
from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.tls_server import TLSServer

from ssl_doctor import findings as F, netchecks
from ssl_doctor.analyze import diagnose

HANDSHAKE_OK = F.Finding("tls.handshake", "TLS handshake", F.PASS, F.SCOPE_REMOTE_NET,
                         ["negotiated protocol: TLSv1.3"])


class StalledValidation(unittest.TestCase):

    def test_regression_r5_verify_timeout(self):
        with FaultServer(get_pki(), "stall") as srv:
            verify = netchecks.check_tls_validation(srv.host, srv.port, HOSTNAME, 1.0)
            rootonly = netchecks.check_tls_rootonly_validation(
                srv.host, srv.port, HOSTNAME, 1.0, roots=[_any_root()])
        for f in (verify, rootonly):
            with self.subTest(check=f.check):
                self.assertEqual(f.status, F.NOT_TESTED)
                self.assertEqual(f.failure_kind, "negotiation-timeout")
                self.assertIn("no conclusion about it is drawn", " ".join(f.evidence))
        d = diagnose([HANDSHAKE_OK, verify, rootonly])
        self.assertEqual([c for c in d.causes if c.origin in ("certificate", "client")], [])
        self.assertTrue(any("could not be completed" in n for n in d.notes))

    def test_connect_timeout_is_not_tested(self):
        with mock.patch.object(netchecks, "_handshake",
                               side_effect=netchecks._ConnectTimeout("connect timed out")):
            f = netchecks.check_tls_validation("192.0.2.10", 443, HOSTNAME, 1.0)
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "connect-timeout"))

    def test_reset_is_not_tested(self):
        with mock.patch.object(netchecks, "_handshake",
                               side_effect=ConnectionResetError(104, "Connection reset by peer")):
            f = netchecks.check_tls_validation("192.0.2.10", 443, HOSTNAME, 1.0)
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "network-error"))

    def test_tls_alert_is_still_a_failure(self):
        with FaultServer(get_pki(), "alert") as srv:
            f = netchecks.check_tls_validation(srv.host, srv.port, HOSTNAME, 2.0)
        self.assertEqual((f.status, f.failure_kind), (F.FAIL, "tls-alert"))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class GenuineVerificationErrors(unittest.TestCase):

    def test_missing_intermediate_still_fails_rootonly(self):
        p = get_pki()
        root = _root(p)
        with TLSServer(p, "leaf-only") as srv:
            f = netchecks.check_tls_rootonly_validation(srv.host, srv.port, HOSTNAME,
                                                        3.0, roots=[root])
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("unable to get local issuer", " ".join(f.evidence))
        self.assertEqual(f.failure_kind, "")

    def test_validation_names_the_pinned_address(self):
        p = get_pki()
        with TLSServer(p, "full-chain") as srv:
            seen = []
            real = netchecks._handshake

            def spy(host, port, sni, ctx, timeout, connect_ip=None):
                seen.append(connect_ip)
                return real(host, port, sni, ctx, timeout, connect_ip=connect_ip)

            with mock.patch.object(netchecks, "_handshake", side_effect=spy):
                f = netchecks.check_tls_rootonly_validation(
                    "localhost", srv.port, HOSTNAME, 3.0, roots=[_root(p)],
                    connect_ip="127.0.0.1")
        self.assertEqual(seen, ["127.0.0.1"])
        self.assertEqual(f.status, F.PASS)
        self.assertIn("validated against 127.0.0.1", f.evidence)

    def test_run_remote_diagnostics_pins_both_validations(self):
        p = get_pki()
        with TLSServer(p, "full-chain") as srv:
            calls = []
            real = netchecks._handshake

            def spy(host, port, sni, ctx, timeout, connect_ip=None):
                calls.append((ctx.verify_mode, connect_ip))
                return real(host, port, sni, ctx, timeout, connect_ip=connect_ip)

            with mock.patch.object(netchecks, "_handshake", side_effect=spy):
                netchecks.run_remote_diagnostics(srv.host, srv.port, sni=HOSTNAME,
                                                 timeout=3.0)
        import ssl
        verified = [ip for mode, ip in calls if mode == ssl.CERT_REQUIRED]
        self.assertGreaterEqual(len(verified), 2)
        self.assertTrue(all(ip == "127.0.0.1" for ip in verified), verified)


def _root(p):
    from ssl_doctor import certs
    with open(p.root, "rb") as fh:
        return certs.decode_pem(fh.read(), enrich=False)


def _any_root():
    return _root(get_pki())


if __name__ == "__main__":
    unittest.main()
