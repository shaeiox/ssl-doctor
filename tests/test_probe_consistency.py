"""Protocol probes: reconciled with the primary handshake, inconclusive when unsure.

Regression cover for a scan whose primary handshake negotiated TLS 1.3 while the
dedicated TLS 1.3 probe timed out, and for relaxed-policy acceptance being read as
ordinary client compatibility.
"""

import time
import unittest
from unittest import mock

from ssl_doctor import findings as F, netchecks
from ssl_doctor.analyze import diagnose


def probe_matrix(outcomes, negotiated="TLSv1.3", facts=None, timeout=1.0):
    """Run check_protocol_matrix with `_probe_version` replaced.

    `outcomes` maps (version-label, policy) -> list of results consumed in order;
    a result is a tuple (state, detail) or an Exception instance.
    """
    calls = []
    queues = {k: list(v) for k, v in outcomes.items()}

    def fake(host, port, server_name, label, version, timeout, connect_ip, relaxed):
        key = (label, "relaxed" if relaxed else "default")
        calls.append(key)
        queue = queues.get(key)
        if not queue:
            return "refused", "alert handshake failure"
        result = queue.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    started = time.monotonic()
    with mock.patch.object(netchecks, "_probe_version", fake):
        f = netchecks.check_protocol_matrix("shop.test", 443, "shop.test", timeout,
                                            connect_ip="192.0.2.10",
                                            negotiated=negotiated, facts=facts)
    return f, calls, time.monotonic() - started


REJECT = ("refused", "alert handshake failure")
OK10 = ("accepted", "TLSv1")
OK11 = ("accepted", "TLSv1.1")
OK12 = ("accepted", "TLSv1.2")
OK13 = ("accepted", "TLSv1.3")
STALL = ("inconclusive", "probe timed out after 1s")
DROP = ("inconclusive", "network error: EOF occurred in violation of protocol")


def standard(over=None):
    """Default table: legacy accepted (relaxed), 1.3 accepted, TLS1.2 default accepted."""
    table = {("TLS 1.0", "relaxed"): [OK10], ("TLS 1.1", "relaxed"): [OK11],
             ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.2", "default"): [OK12],
             ("TLS 1.3", "default"): [OK13]}
    if over:
        table.update(over)
    return table


class PrimaryReconciliationTests(unittest.TestCase):

    def test_primary_tls13_success_with_timed_out_probe_is_inconclusive(self):
        f, calls, _ = probe_matrix(standard({("TLS 1.3", "default"): [STALL, STALL]}))
        row = [r for r in f.evidence if r.startswith("TLS 1.3")][0]
        self.assertIn("inconclusive", row)
        self.assertIn("primary handshake negotiated TLSv1.3", row)
        self.assertNotIn("refused", row)
        self.assertNotIn("unsupported", row.lower())
        self.assertEqual(f.status, F.WARNING)
        self.assertEqual(f.failure_kind, "probe-inconclusive")
        self.assertEqual(f.observation, "probe-inconclusive")
        self.assertIn("TLS 1.3", f.detail)
        # the retry happened once
        self.assertEqual(calls.count(("TLS 1.3", "default")), 2)

    def test_primary_success_with_probe_refusal_is_not_a_refusal(self):
        """A version the primary negotiated can never be reported refused."""
        f, _calls, _ = probe_matrix(
            standard({("TLS 1.2", "relaxed"): [REJECT, REJECT],
                        ("TLS 1.2", "default"): [REJECT]}),
            negotiated="TLSv1.2")
        row = [r for r in f.evidence if r.startswith("TLS 1.2")][0]
        self.assertIn("inconclusive", row)
        self.assertIn("primary handshake negotiated TLSv1.2", row)
        self.assertNotIn("refused", row)

    def test_both_probes_succeed(self):
        f, _calls, _ = probe_matrix(standard())
        self.assertEqual(f.status, F.WARNING)   # TLS 1.0/1.1 accepted: policy risk
        self.assertIn("TLS 1.3: accepted (TLSv1.3)", f.evidence)
        self.assertEqual(f.observation, "")
        self.assertEqual(f.failure_kind, "")

    def test_no_inconclusive_rows_means_no_inconclusive_observation(self):
        f, _calls, _ = probe_matrix(
            {("TLS 1.0", "relaxed"): [REJECT], ("TLS 1.1", "relaxed"): [REJECT],
             ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.3", "default"): [OK13]})
        self.assertEqual(f.observation, "")


class ProbeFailureTests(unittest.TestCase):

    def test_explicit_rejection_is_reported_as_refused(self):
        f, _calls, _ = probe_matrix(
            {("TLS 1.0", "relaxed"): [REJECT], ("TLS 1.1", "relaxed"): [REJECT],
             ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.3", "default"): [REJECT]},
            negotiated="TLSv1.2")
        row = [r for r in f.evidence if r.startswith("TLS 1.3")][0]
        self.assertIn("refused", row)
        self.assertNotIn("inconclusive", row)

    def test_connection_closed_without_handshake_is_inconclusive(self):
        f, _calls, _ = probe_matrix(standard({("TLS 1.3", "default"): [DROP, DROP]}))
        row = [r for r in f.evidence if r.startswith("TLS 1.3")][0]
        self.assertIn("inconclusive", row)
        self.assertNotIn("refused", row)

    def test_local_probe_error_is_inconclusive(self):
        f, _calls, _ = probe_matrix(
            standard({("TLS 1.3", "default"): [
                ("inconclusive", "local probe error: ValueError: cannot pin version"),
                ("inconclusive", "local probe error: ValueError: cannot pin version")]}))
        self.assertIn("local probe error", " ".join(f.evidence))
        self.assertEqual(f.observation, "probe-inconclusive")
        self.assertNotIn("refused", " ".join(f.evidence))

    def test_probe_seam_never_raises_for_local_limitations(self):
        """The real _probe_version turns an unusable context into inconclusive."""
        state, detail = netchecks._probe_version("127.0.0.1", 1, "shop.test",
                                                 "TLS 9.9", object(), 0.2, None, False)
        self.assertEqual(state, "inconclusive")
        self.assertIn("local probe error", detail)

    def test_retry_success_counts_as_accepted(self):
        f, _calls, _ = probe_matrix(
            {("TLS 1.0", "relaxed"): [REJECT], ("TLS 1.1", "relaxed"): [REJECT],
             ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.3", "default"): [STALL, OK13]})
        row = [r for r in f.evidence if r.startswith("TLS 1.3")][0]
        self.assertIn("accepted", row)
        self.assertIn("retry", row)
        self.assertEqual(f.observation, "")

    def test_probe_budget_bounds_retries_and_time(self):
        all_stall = {("TLS 1.0", "relaxed"): [STALL] * 4,
                     ("TLS 1.1", "relaxed"): [STALL] * 4,
                     ("TLS 1.2", "relaxed"): [STALL] * 4,
                     ("TLS 1.3", "default"): [STALL] * 4}
        f, calls, elapsed = probe_matrix(all_stall, timeout=0.6)
        self.assertLessEqual(len(calls), 2 * 4)
        self.assertEqual(f.status, F.FAIL)
        self.assertEqual(f.failure_kind, "no-version-answered")
        self.assertIn("timed out", " ".join(f.evidence))
        self.assertNotIn("refused", " ".join(f.evidence))


class RelaxedPolicyTests(unittest.TestCase):

    def test_relaxed_acceptance_with_default_refusal_states_the_limit(self):
        f, _calls, _ = probe_matrix(
            {("TLS 1.0", "relaxed"): [OK10], ("TLS 1.1", "relaxed"): [OK11],
             ("TLS 1.2", "relaxed"): [OK12], ("TLS 1.2", "default"): [REJECT],
             ("TLS 1.3", "default"): [OK13]})
        text = " ".join(f.evidence).lower()
        self.assertIn("only under the relaxed cipher policy", text)
        self.assertIn("default-configured", text)
        self.assertEqual(f.status, F.WARNING)

    def test_default_policy_acceptance_states_interoperability(self):
        f, _calls, _ = probe_matrix(standard())
        self.assertIn("default cipher policy", " ".join(f.evidence).lower())

    def test_relaxed_rows_are_labelled(self):
        f, _calls, _ = probe_matrix(standard())
        row = [r for r in f.evidence if r.startswith("TLS 1.0")][0]
        self.assertIn("relaxed cipher policy", row)

    def test_deprecated_version_still_warns_when_tls13_is_in_use(self):
        f, _calls, _ = probe_matrix(standard())
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("deprecated", f.detail.lower())
        self.assertTrue(f.recommendation)


class ProbeDiagnosisTests(unittest.TestCase):

    def test_inconclusive_probe_adds_no_server_cause(self):
        f, _calls, _ = probe_matrix(
            standard({("TLS 1.3", "default"): [STALL, STALL]}))
        primary = F.Finding("tls.handshake", "TLS handshake", F.PASS,
                            F.SCOPE_REMOTE_NET,
                            ["negotiated protocol: TLSv1.3"])
        d = diagnose([primary, f])
        # no cause may claim the server refuses or lacks a version
        for c in d.causes:
            joined = " ".join([c.summary] + c.evidence).lower()
            self.assertNotIn("lack", joined)
            self.assertNotIn("refused", joined)
        policy = [c for c in d.causes if "protocol configuration" in c.summary.lower()]
        self.assertTrue(policy, "the legacy-version security warning must survive")
        self.assertTrue(any("no definite result" in lim
                            for lim in policy[0].limitations))
        self.assertTrue(any("inconclusive" in n.lower() for n in d.notes), d.notes)

    def test_policy_warning_keeps_a_possible_cause_with_limitations(self):
        f, _calls, _ = probe_matrix(standard())
        d = diagnose([f])
        policy = [c for c in d.causes if "protocol" in c.summary.lower()]
        self.assertTrue(policy)
        self.assertEqual(policy[0].certainty, "possible")
        self.assertTrue(policy[0].limitations)


if __name__ == "__main__":
    unittest.main()
