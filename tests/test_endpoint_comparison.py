"""Endpoint comparison: only comparable certificate evidence may be compared.

Regression cover for the report where one reachable IPv4 endpoint plus three
unreachable IPv6 endpoints produced "endpoints present DIFFERENT results" and a
probable server cause about load-balancing.
"""

import unittest
from unittest import mock

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.tls_server import TLSServer

from ssl_doctor import findings as F, netchecks
from ssl_doctor.analyze import diagnose

UNREACHABLE = "2001:db8::64"


def ep(ip, state, sha="", hostname_ok=None, chain="complete", detail=""):
    """One endpoint probe record, shaped like netchecks._probe_endpoint()."""
    return {"ip": ip, "state": state, "detail": detail, "sha256": sha,
            "hostname_ok": hostname_ok, "chain_status": chain, "sni": HOSTNAME}


def run(records, ips=None, facts=None, sni=HOSTNAME):
    """check_multi_ip with the probe seam replaced by `records` (ip -> record)."""
    facts = facts if facts is not None else {}
    ips = ips or list(records)

    def fake_probe(host, port, server_name, timeout, ip):
        return dict(records[ip])

    with mock.patch.object(netchecks, "_probe_endpoint", fake_probe):
        return netchecks.check_multi_ip("shop.test", 443, ips, 2, sni=sni,
                                        facts=facts), facts


class UnreachableEndpointsTests(unittest.TestCase):
    """A transport failure is not a certificate fact."""

    def test_unreachable_endpoints_never_imply_different_certificates(self):
        f, facts = run({UNREACHABLE_IP: ep(UNREACHABLE_IP, "tcp-unreachable",
                                           detail="[Errno 101] Network is unreachable"),
                        "192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                         hostname_ok=True)})
        text = " ".join(f.evidence).lower()
        self.assertNotIn("different certificates", text)
        self.assertNotIn("different results", text)
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.observation, "endpoint-comparison-inconclusive")
        self.assertEqual(f.failure_kind, "probe-inconclusive")
        self.assertIn("1 of 2 endpoints yielded a certificate", " ".join(f.evidence))
        self.assertIn("Network is unreachable", " ".join(f.evidence))
        # the transport failure stays visible, with its state
        states = {e["ip"]: e["state"] for e in facts["endpoints"]}
        self.assertEqual(states[UNREACHABLE_IP], "tcp-unreachable")

    def test_timeout_next_to_a_success_is_inconclusive(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64),
                    "192.0.2.11": ep("192.0.2.11", "timed-out",
                                     detail="probe timed out after 2s")})
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.observation, "endpoint-comparison-inconclusive")
        self.assertNotIn("different", " ".join(f.evidence).lower())

    def test_tls_rejection_is_not_a_certificate_mismatch(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64),
                    "192.0.2.11": ep("192.0.2.11", "tls-rejected",
                                     detail="sslv3 alert handshake failure")})
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertNotIn("different certificates", " ".join(f.evidence).lower())

    def test_no_endpoint_with_certificate_data(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "tcp-unreachable"),
                    "192.0.2.11": ep("192.0.2.11", "tcp-unreachable")})
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.failure_kind, "endpoint-unreachable")
        self.assertNotIn("different", " ".join(f.evidence).lower())

    def test_unreadable_certificate_is_not_a_difference(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64),
                    "192.0.2.11": ep("192.0.2.11", "probe-unavailable",
                                     detail="no certificate presented")})
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertNotIn("different certificates", " ".join(f.evidence).lower())


class ComparableEndpointsTests(unittest.TestCase):
    """Differences require two comparable, successful observations."""

    def test_two_identical_endpoints_pass(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                     hostname_ok=True),
                    "192.0.2.11": ep("192.0.2.11", "negotiated", sha="a" * 64,
                                     hostname_ok=True)})
        self.assertEqual(f.status, F.PASS)
        self.assertEqual(f.observation, "")
        self.assertIn("same certificate", " ".join(f.evidence))

    def test_two_different_certificates_are_reported(self):
        f, facts = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                         hostname_ok=True),
                        "192.0.2.11": ep("192.0.2.11", "negotiated", sha="b" * 64,
                                         hostname_ok=True)})
        self.assertEqual(f.status, F.WARNING)
        self.assertEqual(f.observation, "endpoint-certificate-difference")
        self.assertIn("certificate identity", " ".join(f.evidence))
        self.assertEqual(facts["endpoint_comparison"]["comparable"], 2)
        self.assertTrue(facts["endpoint_comparison"]["difference"])

    def test_same_leaf_with_different_chain_is_a_difference(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                     hostname_ok=True, chain="complete"),
                    "192.0.2.11": ep("192.0.2.11", "negotiated", sha="a" * 64,
                                     hostname_ok=True, chain="incomplete")})
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("chain status", " ".join(f.evidence))

    def test_different_hostname_coverage_is_a_difference(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                     hostname_ok=True),
                    "192.0.2.11": ep("192.0.2.11", "negotiated", sha="a" * 64,
                                     hostname_ok=False)})
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("hostname coverage", " ".join(f.evidence))

    def test_incomparable_server_name_is_not_compared(self):
        other = ep("192.0.2.11", "negotiated", sha="b" * 64, hostname_ok=True)
        other["sni"] = "other.example"
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                     hostname_ok=True),
                    "192.0.2.11": other})
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertNotIn("certificate identity", " ".join(f.evidence))

    def test_probe_cap_is_respected(self):
        ips = [f"192.0.2.{i}" for i in range(10, 16)]
        records = {ip: ep(ip, "negotiated", sha="a" * 64, hostname_ok=True) for ip in ips}
        f, facts = run(records, ips=ips)
        self.assertLessEqual(len(facts["endpoints"]), 4)
        self.assertEqual(f.status, F.PASS)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class RealSocketEndpointTests(unittest.TestCase):
    """One real reachable endpoint plus a genuinely unroutable IPv6 address."""

    def test_reachable_endpoint_plus_unreachable_ipv6(self):
        facts = {}
        with TLSServer(get_pki(), "full-chain") as srv:
            f = netchecks.check_multi_ip(srv.host, srv.port,
                                         [srv.host, UNREACHABLE], 2.0,
                                         sni=HOSTNAME, facts=facts)
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.observation, "endpoint-comparison-inconclusive")
        self.assertNotIn("different certificates", " ".join(f.evidence).lower())
        states = {e["ip"]: e["state"] for e in facts["endpoints"]}
        self.assertEqual(states[srv.host], "negotiated")
        self.assertIn(states[UNREACHABLE], ("tcp-unreachable", "timed-out"))


class EndpointDiagnosisTests(unittest.TestCase):
    """Diagnosis: no probable load-balancing cause from missing evidence."""

    def test_inconclusive_comparison_raises_no_cause(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64),
                    UNREACHABLE_IP: ep(UNREACHABLE_IP, "tcp-unreachable")})
        d = diagnose([f])
        self.assertEqual(d.causes, [])
        self.assertTrue(any("inconclusive" in n.lower() for n in d.notes),
                        f"expected an inconclusive note, got {d.notes}")

    def test_real_difference_raises_a_server_cause(self):
        f, _ = run({"192.0.2.10": ep("192.0.2.10", "negotiated", sha="a" * 64,
                                     hostname_ok=True),
                    "192.0.2.11": ep("192.0.2.11", "negotiated", sha="b" * 64,
                                     hostname_ok=True)})
        d = diagnose([f])
        self.assertTrue(d.causes)
        self.assertEqual(d.causes[0].origin, "server")
        self.assertIn(d.causes[0].certainty, ("probable", "confirmed"))
        self.assertTrue(d.causes[0].limitations)

    def test_transport_failure_is_never_confirmed_or_probable(self):
        f, _ = run({UNREACHABLE_IP: ep(UNREACHABLE_IP, "tcp-unreachable")})
        d = diagnose([f])
        self.assertFalse([c for c in d.causes if c.certainty in ("confirmed", "probable")])


UNREACHABLE_IP = UNREACHABLE

if __name__ == "__main__":
    unittest.main()
