"""SNI behaviour: a different default certificate is an observation, not a defect.

Regression cover for the scan where google.com's no-SNI certificate differed from
the SNI certificate, which matched the hostname and validated, and the tool
reported a possible SNI/virtual-host inconsistency.
"""

import unittest
from unittest import mock

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.tls_server import TLSServer

from ssl_doctor import certs, findings as F, netchecks
from ssl_doctor.analyze import diagnose

OTHER_FP = "b" * 64


def fake_cert(sha, hostname_ok=True):
    c = certs.CertInfo(subject=f"CN={HOSTNAME}", common_name=HOSTNAME,
                       sha256=sha)
    if hostname_ok:
        c.san_dns = [HOSTNAME]
    else:
        c.san_dns = ["other.example"]
    return c


def run(with_sni_cert, without_sni=None, raise_without=None):
    """check_sni_difference with the two probes replaced."""
    def fake(host, port, server_name, timeout):
        if server_name is None:
            if raise_without is not None:
                raise raise_without
            return without_sni
        return with_sni_cert

    with mock.patch.object(netchecks, "_sni_cert", fake):
        return netchecks.check_sni_difference("shop.test", 443, HOSTNAME, 2)


class SniObservationTests(unittest.TestCase):

    def test_identical_certificates_pass_without_observation(self):
        c = fake_cert("a" * 64)
        f = run(c, without_sni=c)
        self.assertEqual(f.status, F.PASS)
        self.assertEqual(f.observation, "")
        self.assertIn("same certificate", " ".join(f.evidence))

    def test_different_default_certificate_is_only_an_observation(self):
        f = run(fake_cert("a" * 64), without_sni=fake_cert(OTHER_FP))
        self.assertEqual(f.status, F.PASS)
        self.assertEqual(f.observation, "sni-certificate-differs")
        text = " ".join(f.evidence).lower()
        self.assertIn("legitimate", text)
        self.assertNotIn("wrong certificate", text)
        self.assertNotIn("misconfiguration", text)
        self.assertNotIn("virtual-host", f.recommendation.lower())
        self.assertEqual(f.failure_kind, "")

    def test_different_default_certificate_raises_no_cause(self):
        f = run(fake_cert("a" * 64), without_sni=fake_cert(OTHER_FP))
        hostname = F.Finding("tls.hostname", "Hostname match", F.PASS,
                             F.SCOPE_REMOTE_NET, ["certificate covers the name"])
        verify = F.Finding("tls.verify", "Certificate validation", F.PASS,
                           F.SCOPE_REMOTE_NET, ["chains to a trusted root"])
        d = diagnose([hostname, verify, f])
        self.assertEqual(d.causes, [])
        self.assertEqual(d.overall, "PASS")

    def test_observation_corroborates_an_independent_hostname_failure(self):
        f = run(fake_cert("a" * 64, hostname_ok=False), without_sni=fake_cert(OTHER_FP))
        hostname = F.Finding("tls.hostname", "Hostname match", F.FAIL,
                             F.SCOPE_REMOTE_NET,
                             ["certificate subjectAltName does not include shop.test"])
        d = diagnose([hostname, f])
        self.assertTrue(d.causes)
        self.assertEqual(d.causes[0].origin, "certificate")
        self.assertIn("different certificate", " ".join(d.causes[0].evidence).lower())

    def test_no_sni_probe_failure_is_inconclusive_not_a_warning(self):
        f = run(fake_cert("a" * 64), raise_without=ConnectionResetError(104, "reset"))
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.observation, "sni-without-probe-failed")
        text = " ".join(f.evidence).lower()
        self.assertIn("could not be determined", text)
        self.assertNotIn("very old clients", text)
        self.assertEqual(diagnose([f]).causes, [])

    def test_with_sni_handshake_failure_is_a_real_finding(self):
        def fake(host, port, server_name, timeout):
            if server_name is None:
                return fake_cert("a" * 64)
            raise ConnectionRefusedError(111, "refused")

        with mock.patch.object(netchecks, "_sni_cert", fake):
            f = netchecks.check_sni_difference("shop.test", 443, HOSTNAME, 2)
        self.assertEqual(f.status, F.FAIL)
        causes = diagnose([f]).causes
        self.assertTrue(causes)
        self.assertEqual(causes[0].origin, "server")
        self.assertIn(causes[0].certainty, ("probable", "confirmed"))

    def test_ip_target_is_not_applicable(self):
        f = netchecks.check_sni_difference("192.0.2.10", 443, HOSTNAME, 2)
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.observation, "")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class SniRealEndpointTests(unittest.TestCase):

    def test_real_endpoint_same_certificate_with_and_without_sni(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            f = netchecks.check_sni_difference(srv.host, srv.port, HOSTNAME, 4)
        self.assertIn(f.status, (F.PASS, F.NOT_TESTED))
        if f.status == F.PASS:
            self.assertIn(f.observation, ("", "sni-certificate-differs"))


if __name__ == "__main__":
    unittest.main()
