"""TLS protocol support: what the probes prove, and what they only suggest.

Regression cover for a scan that reported TLS 1.0/1.1 "accepted by the server"
after probing them *only* with the relaxed cipher policy `ALL:@SECLEVEL=0`, and
then raised `[possible · server] Protocol configuration carries compatibility/
security risks` from that evidence alone.
"""

import ssl
import unittest
from unittest import mock

from ssl_doctor import findings as F, netchecks
from ssl_doctor.analyze import diagnose

REJECT = ("refused", "alert handshake failure")
OK10 = ("accepted", "TLSv1")
OK11 = ("accepted", "TLSv1.1")
OK12 = ("accepted", "TLSv1.2")
OK13 = ("accepted", "TLSv1.3")
STALL = ("inconclusive", "probe timed out: TLS negotiation stalled")
LOCAL = ("client-limited", "[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available")


def matrix(table, negotiated="TLSv1.3", timeout=1.0):
    """Run check_protocol_matrix with `_probe_version` fed from `table`.

    `table` maps (label, policy) -> list of results consumed in order; a missing
    key answers with a server refusal.
    """
    calls, queues = [], {k: list(v) for k, v in table.items()}

    def fake(host, port, server_name, label, version, timeout, connect_ip, relaxed):
        key = (label, "relaxed" if relaxed else "default")
        calls.append(key)
        queue = queues.get(key)
        return queue.pop(0) if queue else REJECT

    with mock.patch.object(netchecks, "_probe_version", fake):
        f = netchecks.check_protocol_matrix("shop.test", 443, "shop.test", timeout,
                                           connect_ip="192.0.2.10",
                                           negotiated=negotiated)
    return f, calls


class LegacyRelaxedOnlyTests(unittest.TestCase):
    """Relaxed acceptance alone must not claim ordinary-client support."""

    def test_reported_scan_no_longer_claims_legacy_for_ordinary_clients(self):
        f, calls = matrix({("TLS 1.0", "relaxed"): [OK10],
                           ("TLS 1.1", "relaxed"): [OK11],
                           ("TLS 1.2", "relaxed"): [OK12],
                           ("TLS 1.2", "default"): [OK12],
                           ("TLS 1.3", "default"): [OK13],
                           # the client cannot test legacy versions at default policy
                           ("TLS 1.0", "default"): [LOCAL],
                           ("TLS 1.1", "default"): [LOCAL]})
        # every legacy version was actually offered under the default policy
        self.assertIn(("TLS 1.0", "default"), calls)
        self.assertIn(("TLS 1.1", "default"), calls)
        self.assertEqual(f.observation, "legacy-accepted-unverified")
        self.assertIn("NOT established", f.detail)
        self.assertNotIn("accepted by the server", f.detail)
        self.assertIn("default-policy probe cannot establish",
                      " ".join(f.evidence))

    def test_unverified_legacy_raises_no_protocol_cause(self):
        f, _ = matrix({("TLS 1.0", "relaxed"): [OK10], ("TLS 1.1", "relaxed"): [OK11],
                       ("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12], ("TLS 1.3", "default"): [OK13],
                       ("TLS 1.0", "default"): [LOCAL], ("TLS 1.1", "default"): [LOCAL]})
        d = diagnose([f])
        self.assertFalse([c for c in d.causes if "protocol" in c.summary.lower()],
                         f"unexpected cause: {[c.summary for c in d.causes]}")
        # the open question is carried as an unresolved entry, not a free-text note
        self.assertEqual([u.check for u in d.unresolved], ["tls.protocols"])
        self.assertIn("may be enabled", d.unresolved[0].conclusion.lower())

    def test_unverified_legacy_is_still_visible_as_a_warning(self):
        f, _ = matrix({("TLS 1.0", "relaxed"): [OK10], ("TLS 1.1", "relaxed"): [OK11],
                       ("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12], ("TLS 1.3", "default"): [OK13],
                       ("TLS 1.0", "default"): [LOCAL], ("TLS 1.1", "default"): [LOCAL]})
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("relaxed cipher policy", " ".join(f.evidence))
        self.assertTrue(f.recommendation, "a limitation must still carry advice")


class LegacyConfirmedTests(unittest.TestCase):

    def test_legacy_accepted_with_default_policy_is_a_real_finding(self):
        f, _ = matrix({("TLS 1.0", "relaxed"): [OK10], ("TLS 1.0", "default"): [OK10],
                       ("TLS 1.1", "relaxed"): [OK11],
                       ("TLS 1.1", "default"): [OK11],
                       ("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12], ("TLS 1.3", "default"): [OK13]})
        self.assertEqual(f.observation, "legacy-accepted-default")
        self.assertIn("default cipher policy", " ".join(f.evidence))
        d = diagnose([f])
        cause = [c for c in d.causes if c.origin == "server"][0]
        self.assertIn("ordinary clients can negotiate", cause.summary)
        self.assertEqual(cause.certainty, "possible")

    def test_server_refusing_the_default_probe_is_relaxed_only(self):
        f, _ = matrix({("TLS 1.0", "relaxed"): [OK10], ("TLS 1.0", "default"): [REJECT],
                       ("TLS 1.1", "relaxed"): [REJECT],
                       ("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12], ("TLS 1.3", "default"): [OK13]})
        self.assertEqual(f.observation, "legacy-accepted-relaxed-only")
        self.assertIn("accepted only under the relaxed cipher policy",
                      " ".join(f.evidence))
        d = diagnose([f])
        cause = [c for c in d.causes if c.origin == "server"][0]
        self.assertIn("only when legacy cipher suites are offered", cause.summary)
        self.assertTrue(cause.limitations)

    def test_legacy_refused_outright_returns_to_pass(self):
        f, _ = matrix({("TLS 1.2", "relaxed"): [OK12], ("TLS 1.2", "default"): [OK12],
                       ("TLS 1.3", "default"): [OK13]})
        self.assertEqual(f.status, F.PASS)
        self.assertEqual(f.observation, "")
        self.assertEqual(f.recommendation, "")
        self.assertEqual(diagnose([f]).causes, [])


class ModernProtocolTests(unittest.TestCase):
    """TLS 1.2/1.3 findings stay accurate and are not called insecure."""

    def test_tls12_default_acceptance_is_plain_support(self):
        f, calls = matrix({("TLS 1.2", "relaxed"): [OK12],
                           ("TLS 1.2", "default"): [OK12],
                           ("TLS 1.3", "default"): [OK13]})
        self.assertEqual(f.status, F.PASS)
        self.assertIn(("TLS 1.2", "default"), calls)
        self.assertIn("default-configured modern client can negotiate it",
                      " ".join(f.evidence))

    def test_tls13_acceptance_is_plain_support(self):
        f, _ = matrix({("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12], ("TLS 1.3", "default"): [OK13]})
        self.assertIn("TLS 1.3: accepted (TLSv1.3)", f.evidence)
        self.assertNotIn("insecure", " ".join(f.evidence).lower())

    def test_tls12_requiring_legacy_ciphers_warns_about_interop(self):
        f, _ = matrix({("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [REJECT],
                       ("TLS 1.3", "default"): [OK13]})
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("TLS 1.2 is reachable only with legacy cipher suites", f.detail)
        self.assertIn("cannot connect", f.detail)
        self.assertEqual(f.observation, "tls12-relaxed-only")
        d = diagnose([f])
        cause = [c for c in d.causes if c.origin == "server"][0]
        self.assertEqual(cause.certainty, "possible")
        self.assertIn("only with legacy cipher suites", cause.summary)
        self.assertTrue(any("ALL:@SECLEVEL=0" in lim for lim in cause.limitations),
                        cause.limitations)
        self.assertIn("modern cipher suites", cause.recommendation)


class ProbeFailureTests(unittest.TestCase):

    def test_timeout_does_not_become_a_support_claim(self):
        f, _ = matrix({("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12],
                       ("TLS 1.3", "default"): [STALL, STALL]})
        row = [r for r in f.evidence if r.startswith("TLS 1.3")][0]
        self.assertIn("inconclusive", row)
        self.assertNotIn("refused", row)
        # an inconclusive probe is reported as such, never as support or refusal
        self.assertEqual(f.observation, "probe-inconclusive")
        self.assertEqual(f.failure_kind, "probe-inconclusive")

    def test_client_limitation_is_not_a_server_refusal(self):
        f, _ = matrix({("TLS 1.0", "relaxed"): [OK10],
                       ("TLS 1.0", "default"): [LOCAL],
                       ("TLS 1.1", "relaxed"): [LOCAL],
                       ("TLS 1.2", "relaxed"): [OK12],
                       ("TLS 1.2", "default"): [OK12], ("TLS 1.3", "default"): [OK13]})
        joined = " ".join(f.evidence).lower()
        self.assertIn("this client could not offer", joined)
        self.assertIn("limitation of the test", f.detail)
        self.assertNotIn("refused", [r for r in f.evidence
                                     if r.startswith("TLS 1.1")][0])

    def test_local_marker_detection(self):
        self.assertTrue(netchecks._is_local_probe_limitation(
            ssl.SSLError("[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available")))
        self.assertTrue(netchecks._is_local_probe_limitation(
            ssl.SSLError("[SSL: NO_CIPHERS_AVAILABLE] no ciphers available")))
        self.assertFalse(netchecks._is_local_probe_limitation(
            ssl.SSLError("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake "
                         "failure")))


class BudgetTests(unittest.TestCase):

    def test_default_policy_probes_stay_within_the_budget(self):
        table = {("TLS 1.0", "relaxed"): [OK10] * 2,
                 ("TLS 1.1", "relaxed"): [OK11] * 2,
                 ("TLS 1.2", "relaxed"): [OK12] * 2,
                 ("TLS 1.3", "default"): [OK13] * 2,
                 ("TLS 1.0", "default"): [STALL] * 2,
                 ("TLS 1.1", "default"): [STALL] * 2,
                 ("TLS 1.2", "default"): [STALL] * 2}
        f, calls = matrix(table, timeout=0.5)
        self.assertLessEqual(len(calls), netchecks.PROBE_BUDGET_FACTOR * 7)
        self.assertEqual(f.observation, "legacy-accepted-unverified")


class FactsTests(unittest.TestCase):

    def test_probe_policy_records_support_per_version(self):
        facts = {}
        queues = {("TLS 1.0", "relaxed"): [OK10], ("TLS 1.0", "default"): [LOCAL],
                  ("TLS 1.1", "relaxed"): [REJECT],
                  ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.2", "default"): [OK12],
                  ("TLS 1.3", "default"): [OK13]}

        def fake(host, port, name, label, version, timeout, connect_ip, relaxed):
            return queues.get((label, "relaxed" if relaxed else "default"),
                              [REJECT]).pop(0)

        with mock.patch.object(netchecks, "_probe_version", fake):
            netchecks.check_protocol_matrix("h", 443, "shop.test", 1.0, facts=facts)
        policy = facts["probe_policy"]
        self.assertEqual(policy["support"]["TLS 1.0"], "relaxed-only-unverified")
        self.assertEqual(policy["support"]["TLS 1.1"], "rejected")
        self.assertEqual(policy["support"]["TLS 1.2"], "default")
        self.assertEqual(policy["support"]["TLS 1.3"], "default")
        self.assertEqual(policy["unverified_legacy"], ["TLS 1.0"])


if __name__ == "__main__":
    unittest.main()
