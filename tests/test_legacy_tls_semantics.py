"""Legacy-TLS finding, diagnosis and uncertainty stay separate.

Regression cover for a google.com:443 scan: TLS 1.0/1.1 completed a handshake
only under `ALL:@SECLEVEL=0`, their default-policy probes failed locally with
`NO_PROTOCOLS_AVAILABLE`, and TLS 1.2/1.3 succeeded normally.  The remediation
told users to treat legacy TLS as enabled, the diagnosis hid the open warning
behind "some checks report warnings/failures", and the endpoint comparison of
four out of seven addresses read like all seven were verified.
"""

import ssl
import unittest
from unittest import mock

from ssl_doctor import contract, findings as F, netchecks, report
from ssl_doctor.analyze import diagnose

from test_endpoint_comparison import ep, run as run_endpoints
from test_protocol_policy import LOCAL, OK10, OK11, OK12, OK13, REJECT, matrix

GOOGLE_LIKE = {("TLS 1.0", "relaxed"): [OK10], ("TLS 1.1", "relaxed"): [OK11],
               ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.2", "default"): [OK12],
               ("TLS 1.3", "default"): [OK13],
               ("TLS 1.0", "default"): [LOCAL], ("TLS 1.1", "default"): [LOCAL]}


def google_like(facts=None):
    facts = facts if facts is not None else {}
    with mock.patch.object(netchecks, "_probe_version",
                           _fake_from(GOOGLE_LIKE)):
        f = netchecks.check_protocol_matrix("shop.test", 443, "shop.test", 1.0,
                                            negotiated="TLSv1.3", facts=facts)
    return f, facts


def _fake_from(table):
    queues = {k: list(v) for k, v in table.items()}

    def fake(host, port, name, label, version, timeout, connect_ip, relaxed):
        queue = queues.get((label, "relaxed" if relaxed else "default"))
        return queue.pop(0) if queue else REJECT
    return fake


class RelaxedOnlyEvidenceTests(unittest.TestCase):

    def test_relaxed_only_handshake_is_recorded_not_promoted(self):
        f, facts = google_like()
        self.assertEqual(f.status, F.WARNING)
        self.assertEqual(f.observation, "legacy-accepted-unverified")
        policy = facts["probe_policy"]
        self.assertEqual(policy["confirmed_legacy"], [])
        self.assertEqual(policy["unverified_legacy"], ["TLS 1.0", "TLS 1.1"])
        self.assertIn("ALL:@SECLEVEL=0", f.detail)

    def test_tls12_tls13_results_are_preserved(self):
        f, facts = google_like()
        support = facts["probe_policy"]["support"]
        self.assertEqual(support["TLS 1.2"], netchecks.SUPPORT_DEFAULT)
        self.assertEqual(support["TLS 1.3"], netchecks.SUPPORT_DEFAULT)
        self.assertEqual(facts["probe_policy"]["default_probe"]["TLS 1.2"], "accepted")
        self.assertIn("TLS 1.3: accepted (TLSv1.3)", f.evidence)


class ClientLimitationVersusRejectionTests(unittest.TestCase):

    def test_default_probe_client_limitation_is_recorded_as_such(self):
        f, facts = google_like()
        self.assertEqual(facts["probe_policy"]["default_probe"],
                         {"TLS 1.0": "client-limited", "TLS 1.1": "client-limited",
                          "TLS 1.2": "accepted"})
        rows = [r for r in f.evidence if "default-policy probe" in r]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertIn("not a server rejection", row)
            self.assertNotIn("refused", row)
        self.assertTrue(any("never sent" in u for u in f.uncertainty), f.uncertainty)

    def test_remote_rejection_is_distinguished_from_client_limitation(self):
        table = dict(GOOGLE_LIKE)
        table[("TLS 1.0", "default")] = [REJECT]          # the peer answered "no"
        facts = {}
        with mock.patch.object(netchecks, "_probe_version", _fake_from(table)):
            f = netchecks.check_protocol_matrix("shop.test", 443, "shop.test", 1.0,
                                                negotiated="TLSv1.3", facts=facts)
        policy = facts["probe_policy"]
        self.assertEqual(policy["default_probe"]["TLS 1.0"], "refused")
        self.assertEqual(policy["default_probe"]["TLS 1.1"], "client-limited")
        self.assertEqual(policy["support"]["TLS 1.0"], netchecks.SUPPORT_RELAXED_ONLY)
        self.assertEqual(policy["support"]["TLS 1.1"], netchecks.SUPPORT_UNVERIFIED)

    def test_probe_classifies_the_ssl_error_by_origin(self):
        local = ssl.SSLError("[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available")
        remote = ssl.SSLError("[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert "
                              "protocol version")
        for exc, expected in ((local, netchecks.CLIENT_LIMITED),
                              (remote, netchecks.REFUSED)):
            with self.subTest(error=str(exc)), \
                    mock.patch.object(netchecks, "_handshake", side_effect=exc):
                state, _ = netchecks._probe_version(
                    "shop.test", 443, "shop.test", "TLS 1.0", ssl.TLSVersion.TLSv1_2,
                    1.0, "192.0.2.10", False)
                self.assertEqual(state, expected)


class DiagnosisSeparationTests(unittest.TestCase):

    def test_warning_stays_visible_without_a_root_cause(self):
        f, _ = google_like()
        d = diagnose([f])
        self.assertEqual(d.causes, [])
        self.assertEqual(len(d.unresolved), 1)
        u = d.unresolved[0]
        self.assertEqual((u.check, u.status, u.observation),
                         ("tls.protocols", F.WARNING, "legacy-accepted-unverified"))
        # observed / conclusion / uncertainty are three different statements
        self.assertEqual(u.observed, f.detail)
        self.assertEqual(u.uncertainty, f.uncertainty)
        self.assertTrue(u.uncertainty)
        self.assertNotIn("some checks report warnings", " ".join(d.notes))

    def test_unexplained_warning_is_named_not_generic(self):
        other = F.Finding("tls.weakcipher", "Obsolete cipher acceptance", F.FAIL,
                          F.SCOPE_REMOTE_NET, ["x"])
        d = diagnose([other])
        joined = " ".join(d.notes)
        self.assertNotIn("some checks report warnings", joined)
        self.assertIn("Obsolete cipher acceptance (FAIL)", joined)

    def test_unresolved_entry_round_trips_through_the_contract(self):
        f, facts = google_like()
        payload = report.build_payload([f], diagnose([f]), {}, facts=facts)
        self.assertEqual(contract.validate(payload), [])
        html = report.html_from_payload(payload)
        self.assertIn("UNRESOLVED", html)
        self.assertIn("uncertainty:", html)


class RemediationTests(unittest.TestCase):

    def test_remediation_does_not_presume_legacy_is_enabled(self):
        f, _ = google_like()
        rec = f.recommendation.lower()
        self.assertNotIn("until proven otherwise", rec)
        self.assertNotIn("disable tls 1.0/1.1 (and", rec)   # the confirmed-case advice
        self.assertIn("not confirmed", rec)
        self.assertIn("controlled test", rec)
        self.assertIn("limitations", rec)

    def test_confirmed_default_acceptance_still_says_disable(self):
        table = dict(GOOGLE_LIKE)
        table[("TLS 1.0", "default")] = [OK10]
        f, _ = matrix(table)
        self.assertEqual(f.observation, "legacy-accepted-default")
        self.assertIn("Disable TLS 1.0/1.1", f.recommendation)


class PartialEndpointCoverageTests(unittest.TestCase):

    def test_four_of_seven_does_not_claim_all_addresses(self):
        ips = [f"192.0.2.{i}" for i in range(10, 17)]
        records = {ip: ep(ip, "negotiated", sha="a" * 64, hostname_ok=True)
                   for ip in ips}
        f, facts = run_endpoints(records, ips=ips)
        self.assertEqual(f.status, F.PASS)
        cmp_ = facts["endpoint_comparison"]
        self.assertEqual((cmp_["addresses"], cmp_["probed"], cmp_["comparable"]),
                         (7, 4, 4))
        headline = f.evidence[0]
        self.assertTrue(headline.startswith("the 4 comparable endpoint(s)"), headline)
        self.assertNotIn("all", headline.split()[:2])
        self.assertIn("3 of 7 DNS address(es) were not compared", headline)
        self.assertIn("4 of 7", " ".join(f.uncertainty))

    def test_full_coverage_has_no_coverage_caveat(self):
        ips = ["192.0.2.10", "192.0.2.11"]
        records = {ip: ep(ip, "negotiated", sha="a" * 64, hostname_ok=True)
                   for ip in ips}
        f, facts = run_endpoints(records, ips=ips)
        self.assertNotIn("not compared", f.evidence[0])
        self.assertEqual(f.uncertainty, [])


if __name__ == "__main__":
    unittest.main()
