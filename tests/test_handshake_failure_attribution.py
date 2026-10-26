"""Failure-mode attribution: a stalled handshake is never a protocol/cipher mismatch.

The reproduction is the report pair that exposed the defect: `tls.handshake` FAIL
("handshake/connect timed out after 8s") next to `tls.protocols` where TLS 1.0-1.3
were all "accepted", diagnosed as a probable *server* protocol/cipher mismatch.
"""

import unittest
from unittest import mock

from fixtures.fault_server import FaultServer
from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.tls_server import TLSServer

from ssl_doctor import findings as F, netchecks
from ssl_doctor.analyze import diagnose
from ssl_doctor.contract import FAILURE_KINDS

TIMEOUT_KINDS = ("connect-timeout", "negotiation-timeout")
MISMATCH = "protocol/cipher mismatch"

ACCEPTED_ROWS = ["TLS 1.0: accepted (TLSv1)", "TLS 1.1: accepted (TLSv1.1)",
                 "TLS 1.2: accepted (TLSv1.2)", "TLS 1.3: accepted (TLSv1.3)"]


def handshake_finding(kind, status=F.FAIL, accept_status=None):
    """A `tls.handshake` finding shaped like the probe emits it."""
    if status == F.PASS:
        return F.Finding("tls.handshake", "TLS handshake", F.PASS, F.SCOPE_REMOTE_NET,
                         ["negotiated protocol: TLSv1.3"])
    evidence = {
        "negotiation-timeout": ["TCP connected to 192.0.2.10:443, but the TLS "
                                "negotiation stalled with no server response",
                                "attempt 1: TLS negotiation stalled (8.0s elapsed)"],
        "connect-timeout": ["could not open a TCP connection to 192.0.2.10:443 within "
                            "the timeout"],
        "tls-alert": ["the peer at 192.0.2.10:443 rejected the TLS handshake",
                      "attempt 1: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert "
                      "handshake failure"],
        "network-error": ["the connection to 192.0.2.10:443 was reset or dropped during "
                          "TLS negotiation"],
    }.get(kind, ["handshake failed"])
    return F.Finding("tls.handshake", "TLS handshake", status, F.SCOPE_REMOTE_NET,
                     evidence, target="192.0.2.10:443", failure_kind=kind)


def items(kind, state, status=F.FAIL):
    """`[handshake, matrix?]` - the matrix is absent when nothing ran it."""
    out = [handshake_finding(kind, status=status)]
    m = matrix_finding(state)
    return out + ([m] if m else [])


def matrix_finding(state):
    if state == "accepted":
        return F.Finding("tls.protocols", "TLS protocol version support", F.WARNING,
                         F.SCOPE_REMOTE_NET, list(ACCEPTED_ROWS),
                         detail="deprecated TLS 1.0/1.1 are enabled")
    if state == "refused":
        return F.Finding("tls.protocols", "TLS protocol version support", F.FAIL,
                         F.SCOPE_REMOTE_NET,
                         ["TLS 1.0: refused (alert)", "TLS 1.1: refused (alert)",
                          "TLS 1.2: refused (alert)", "TLS 1.3: refused (alert)"],
                         failure_kind="no-version-accepted")
    if state == "silent":
        return F.Finding("tls.protocols", "TLS protocol version support", F.FAIL,
                         F.SCOPE_REMOTE_NET,
                         ["TLS 1.0: timed out after 8s (no response)",
                          "TLS 1.1: timed out after 8s (no response)",
                          "TLS 1.2: timed out after 8s (no response)",
                          "TLS 1.3: timed out after 8s (no response)"],
                         failure_kind="no-version-answered")
    return None


class TimeoutAttributionTests(unittest.TestCase):
    """The regression proper: timeout plus working version probes."""

    def test_reproduction_pair_is_not_a_server_protocol_cause(self):
        d = diagnose([handshake_finding("negotiation-timeout"),
                      matrix_finding("accepted")])
        summaries = " ".join(c.summary for c in d.causes)
        self.assertNotIn(MISMATCH, summaries)
        self.assertFalse([c for c in d.causes if c.origin == "server"
                          and "handshake" in c.summary.lower()])
        self.assertEqual(d.causes[0].origin, "network")
        self.assertEqual(d.causes[0].certainty, "probable")
        self.assertNotEqual(d.overall, "PASS")

    def test_connect_timeout_with_accepted_versions_is_a_path_cause(self):
        d = diagnose([handshake_finding("connect-timeout"), matrix_finding("accepted")])
        self.assertNotIn(MISMATCH, " ".join(c.summary for c in d.causes))
        self.assertEqual(d.causes[0].origin, "network")

    def test_recovered_stall_still_raises_a_network_cause(self):
        hs = handshake_finding("negotiation-timeout", status=F.WARNING)
        d = diagnose([hs, matrix_finding("accepted")])
        self.assertEqual(d.causes[0].origin, "network")
        self.assertIn("retry", d.causes[0].summary)
        self.assertEqual(d.overall, "WARNING")

    def test_reset_during_negotiation_is_a_path_cause(self):
        d = diagnose([handshake_finding("network-error"), matrix_finding("accepted")])
        self.assertEqual(d.causes[0].origin, "network")
        self.assertIn("reset", d.causes[0].summary)

    def test_nothing_answers(self):
        d = diagnose([handshake_finding("negotiation-timeout"), matrix_finding("silent")])
        self.assertEqual(d.causes[0].origin, "network")
        self.assertIn("no TLS version", d.causes[0].summary)

    def test_unclassified_failure_never_claims_a_mismatch(self):
        d = diagnose([handshake_finding(""), matrix_finding("accepted")])
        self.assertNotIn(MISMATCH, " ".join(c.summary for c in d.causes))
        self.assertEqual(d.causes[0].origin, "network")

    def test_missing_matrix_with_timeout_is_a_network_cause(self):
        d = diagnose(items("negotiation-timeout", None))
        self.assertEqual(d.causes[0].origin, "network")

    def test_rejection_with_accepted_versions_stays_a_server_cause(self):
        d = diagnose([handshake_finding("tls-alert"), matrix_finding("accepted")])
        self.assertEqual(d.causes[0].origin, "server")
        self.assertIn(MISMATCH, d.causes[0].summary)

    def test_rejection_without_matrix_stays_a_server_cause(self):
        d = diagnose(items("tls-alert", None))
        self.assertEqual(d.causes[0].origin, "server")

    def test_timeout_evidence_is_never_confirmed(self):
        for kind in TIMEOUT_KINDS + ("network-error", ""):
            for state in ("accepted", "refused", "silent", None):
                with self.subTest(kind=kind, state=state):
                    d = diagnose(items(kind, state))
                    self.assertFalse([c for c in d.causes if c.certainty == "confirmed"])

    def test_cause_evidence_names_the_failure_kind(self):
        d = diagnose([handshake_finding("negotiation-timeout"),
                      matrix_finding("accepted")])
        joined = " ".join(d.causes[0].evidence)
        self.assertIn("negotiation-timeout", joined)
        self.assertIn("TLS 1.3: accepted", joined)

    def test_stall_does_not_suppress_server_chain_cause(self):
        chain = F.Finding("tls.chain", "Chain sent by server", F.WARNING,
                          F.SCOPE_REMOTE_NET,
                          ["presented chain: intermediate certificate(s) not sent"],
                          recommendation="Serve the full chain.")
        d = diagnose([handshake_finding("negotiation-timeout"),
                      matrix_finding("accepted"), chain])
        origins = {c.origin for c in d.causes}
        self.assertIn("network", origins)
        self.assertIn("server", origins)

    def test_protocol_mismatch_requires_rejection_evidence(self):
        # every non-alert failure mode must be unable to produce the mismatch cause
        for kind in TIMEOUT_KINDS + ("network-error", ""):
            with self.subTest(kind=kind):
                d = diagnose([handshake_finding(kind), matrix_finding("accepted")])
                self.assertNotIn(MISMATCH, " ".join(c.summary for c in d.causes))


class ErrorClassificationTests(unittest.TestCase):

    def test_alert_is_a_rejection(self):
        import ssl
        for exc in (ssl.SSLError("sslv3 alert handshake failure"),
                    ssl.SSLError("no shared cipher"),
                    ssl.SSLError("[SSL: WRONG_VERSION_NUMBER] wrong version number")):
            with self.subTest(exc=str(exc)):
                self.assertEqual(netchecks._classify_negotiation_error(exc), "tls-alert")

    def test_dropped_connection_is_a_path_problem(self):
        import ssl
        for exc in (ssl.SSLEOFError("EOF occurred in violation of protocol"),
                    ConnectionResetError(104, "Connection reset by peer"),
                    OSError(110, "Connection timed out")):
            with self.subTest(exc=str(exc)):
                self.assertEqual(netchecks._classify_negotiation_error(exc), "network-error")


class FailureKindContractTests(unittest.TestCase):

    def test_registry_values_are_the_documented_ones(self):
        self.assertEqual(set(FAILURE_KINDS), {
            "connect-timeout", "negotiation-timeout", "tls-alert", "network-error",
            "no-version-accepted", "no-version-answered",
            # 1.3: an inconclusive probe and an unreachable endpoint are failures
            # to obtain evidence, not findings about the server
            "probe-inconclusive", "endpoint-unreachable",
            # 1.7: why a certificate or key question stayed open
            "verifier-unavailable", "key-encrypted", "key-unreadable",
            "command-failed", "permission-denied",
            # 1.7: chain defect classes
            "chain-signature", "chain-misordered", "chain-incomplete",
            "chain-unverified", "chain-hygiene", "chain-wrong-leaf"})

    def test_finding_defaults_to_unclassified(self):
        self.assertEqual(F.Finding("tls.chain", "t", F.PASS, F.SCOPE_REMOTE_NET
                                  ).to_dict()["failure_kind"], "")


class StallFixtureTests(unittest.TestCase):
    """Probe behaviour against a socket that misbehaves on purpose."""

    def test_stall_is_a_negotiation_timeout_with_two_attempts(self):
        with FaultServer(get_pki(), "stall") as srv:
            f, facts = netchecks.check_tls_basic(srv.host, srv.port, HOSTNAME, 0.5)
            self.assertEqual(f.status, F.FAIL)
            self.assertEqual(f.failure_kind, "negotiation-timeout")
            self.assertEqual(facts["handshake_attempts"], 2)
            joined = " ".join(f.evidence)
            self.assertIn(f"{srv.host}:{srv.port}", joined)
            self.assertIn("attempt 2", joined)
            self.assertIn("stalled", joined)
            self.assertNotIn("timed out", joined)

    def test_recovered_stall_is_a_warning_with_a_usable_handshake(self):
        if not openssl_available():
            self.skipTest("openssl binary not available")
        with FaultServer(get_pki(), "stall-once") as srv:
            f, facts = netchecks.check_tls_basic(srv.host, srv.port, HOSTNAME, 0.5)
            self.assertEqual(f.status, F.WARNING)
            self.assertEqual(f.failure_kind, "negotiation-timeout")
            self.assertEqual(facts["handshake_attempts"], 2)
            self.assertTrue(facts["cert"], "recovered handshake lost its certificate")
            self.assertEqual(len(facts["chain"]), 2)
            self.assertIn("recovered on attempt 2", " ".join(f.evidence))

    def test_rejection_is_a_single_attempt(self):
        with FaultServer(get_pki(), "alert") as srv:
            f, facts = netchecks.check_tls_basic(srv.host, srv.port, HOSTNAME, 2)
            self.assertEqual(f.status, F.FAIL)
            self.assertEqual(f.failure_kind, "tls-alert")
            self.assertEqual(srv.tls_attempts, 1, "a rejection must not be retried")
            self.assertEqual(facts["handshake_attempts"], 1)
            self.assertIn("alert", " ".join(f.evidence).lower())

    def test_matrix_reports_no_answer_not_refusal(self):
        with FaultServer(get_pki(), "stall") as srv:
            f = netchecks.check_protocol_matrix(srv.host, srv.port, HOSTNAME, 0.35)
            self.assertEqual(f.status, F.FAIL)
            self.assertEqual(f.failure_kind, "no-version-answered")
            joined = " ".join(f.evidence)
            self.assertIn("timed out", joined)
            self.assertNotIn("refused", joined)

    def test_recovered_stall_keeps_downstream_checks(self):
        if not openssl_available():
            self.skipTest("openssl binary not available")
        with FaultServer(get_pki(), "stall-once") as srv:
            items, facts = netchecks.run_remote_diagnostics(
                srv.host, srv.port, sni=HOSTNAME, timeout=1)
        by_check = {f.check: f for f in items}
        self.assertEqual(by_check["tls.handshake"].status, F.WARNING)
        for check in ("tls.certvalid", "tls.hostname", "tls.chain", "tls.verify"):
            self.assertIn(check, by_check, f"{check} did not run after a recovered stall")
        self.assertEqual(facts["handshake_failure"], "negotiation-timeout")


class ProbeAddressTests(unittest.TestCase):
    """Every handshake probe must use the address the TCP check verified."""

    def test_handshake_and_matrix_pin_the_verified_address(self):
        seen = []
        original = netchecks._handshake

        def spy(host, port, server_hostname, ctx, timeout, connect_ip=None):
            seen.append(connect_ip)
            return original(host, port, server_hostname, ctx, timeout, connect_ip)

        with FaultServer(get_pki(), "stall") as srv, \
                mock.patch.object(netchecks, "_handshake", spy):
            netchecks.run_remote_diagnostics(srv.host, srv.port, sni=HOSTNAME,
                                             timeout=0.4)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {srv.host},
                         f"a probe ignored the verified address: {seen}")

    def test_facts_record_the_probed_address(self):
        with FaultServer(get_pki(), "stall") as srv:
            f, facts = netchecks.check_tls_basic(srv.host, srv.port, HOSTNAME, 0.4)
        self.assertEqual(facts["handshake_ip"], srv.host)
        self.assertEqual(facts["handshake_failure"], "negotiation-timeout")
        self.assertEqual(netchecks.export_facts(facts)["handshake_failure"],
                         "negotiation-timeout")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class MatrixPolicyDisclosureTests(unittest.TestCase):

    def test_legacy_acceptance_discloses_the_relaxed_policy(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            f = netchecks.check_protocol_matrix(srv.host, srv.port, HOSTNAME, 4)
        accepted = [r for r in f.evidence if ": accepted" in r]
        self.assertTrue(accepted)
        if any(r.startswith(("TLS 1.0", "TLS 1.1", "TLS 1.2")) for r in accepted):
            self.assertIn("relaxed cipher policy", " ".join(f.evidence))

    def test_matrix_reports_accepted_versions(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            f = netchecks.check_protocol_matrix(srv.host, srv.port, HOSTNAME, 4)
        self.assertIn(f.status, (F.PASS, F.WARNING))
        self.assertEqual(f.failure_kind, "")
        self.assertIn("TLS 1.2: accepted", " ".join(f.evidence))


if __name__ == "__main__":
    unittest.main()
