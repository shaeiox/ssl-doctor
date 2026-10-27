"""diagnosis-correlation: every FAIL counts toward the overall verdict.

R2: a live endpoint serving an expired intermediate gave `tls.verify` FAIL, yet
the diagnosis was `overall: PASS` because no cause rule matched.
"""

import unittest

from ssl_doctor import contract
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose


def finding(check, status, *evidence, scope=F.SCOPE_REMOTE_NET, **kw):
    return F.Finding(check, check, status, scope, list(evidence), **kw)


HANDSHAKE = finding("tls.handshake", F.PASS, "negotiated protocol: TLSv1.3")
CHAIN_OK = finding("tls.chain", F.PASS, "2 certificate(s), linked")
LEAF_OK = finding("tls.certvalid", F.PASS, "valid until 2027-06-01 (219 days remaining)")
EXPIRED_INTERMEDIATE = finding("tls.verify", F.FAIL, "validation failed: certificate has expired",
                               "openssl verify detail: certificate has expired")


class VerdictTable(unittest.TestCase):

    def check(self, items, overall, unexplained=()):
        d = diagnose(items)
        self.assertEqual(d.overall, overall, [u.check for u in d.unexplained])
        self.assertEqual(sorted({u.check for u in d.unexplained}), sorted(unexplained))
        doc = {"schema_version": contract.SCHEMA_VERSION, "tool": "t", "generated_utc": "t",
               "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")},
               "findings": [], "diagnosis": d.to_dict()}
        self.assertEqual(contract.validate(doc), [])
        return d

    def test_regression_r2_expired_intermediate_is_fail(self):
        d = self.check([HANDSHAKE, CHAIN_OK, LEAF_OK, EXPIRED_INTERMEDIATE], F.FAIL,
                       unexplained=["tls.verify"])
        self.assertTrue(any("still count toward the overall result" in n for n in d.notes))

    def test_expired_leaf_is_explained_by_the_validity_cause(self):
        leaf = finding("tls.certvalid", F.FAIL, "server presents an EXPIRED certificate")
        d = self.check([HANDSHAKE, CHAIN_OK, leaf, EXPIRED_INTERMEDIATE], F.FAIL)
        self.assertTrue(any("outside its validity period" in c.summary for c in d.causes))

    def test_hostname_mismatch_without_a_hostname_finding_stays_unexplained(self):
        mismatch = finding("tls.verify", F.FAIL,
                           "validation failed: hostname mismatch (certificate does not "
                           "cover this name)")
        self.check([HANDSHAKE, CHAIN_OK, LEAF_OK, mismatch], F.FAIL,
                   unexplained=["tls.verify"])

    def test_transport_only_unexplained_failure_is_warning(self):
        stalled = finding("https.response", F.FAIL, "HTTPS request reset",
                          failure_kind="network-error")
        self.check([HANDSHAKE, stalled], F.WARNING, unexplained=["https.response"])

    def test_ssh_authentication_failure_is_warning_without_server_cause(self):
        auth = finding("ssh.auth", F.FAIL, "Permission denied (password)",
                       scope=F.SCOPE_SERVER)
        d = self.check([HANDSHAKE, auth], F.WARNING, unexplained=["ssh.auth"])
        self.assertEqual([c for c in d.causes if c.origin == "server"], [])

    def test_observation_only_is_not_fail(self):
        sni = finding("tls.sni", F.PASS, "observation: without SNI a different certificate",
                      observation="sni-certificate-differs")
        self.check([HANDSHAKE, sni], F.PASS)

    def test_not_tested_only_is_pass_with_notes(self):
        verify = finding("tls.verify", F.NOT_TESTED, "TLS negotiation stalled",
                         failure_kind="negotiation-timeout")
        d = self.check([HANDSHAKE, verify], F.PASS)
        self.assertTrue(any(n.startswith("Not tested:") and "tls.verify" in n
                            for n in d.notes))
        self.assertTrue(any("could not be completed" in n for n in d.notes))

    def test_path_resolution_failure_reaches_the_verdict(self):
        missing = finding("nginx.path_resolution", F.FAIL,
                          "certificate: /etc/nginx/ssl/site.pem", "  missing",
                          scope=F.SCOPE_SERVER)
        # since P5 a confirmed server cause names it (it was unexplained in P0)
        d = self.check([HANDSHAKE, missing], F.FAIL)
        self.assertTrue(any("cannot be used" in c.summary and c.certainty == "confirmed"
                            for c in d.causes))

    def test_unexplained_warning_gives_warning(self):
        soon = finding("tls.certvalid", F.WARNING, "certificate expires in 12 days")
        self.check([HANDSHAKE, soon], F.WARNING, unexplained=["tls.certvalid"])

    def test_explained_findings_are_not_listed(self):
        leaf_only = finding("tls.chain", F.WARNING,
                            "intermediate certificate(s) not sent: the chain ends at a "
                            "non-CA certificate")
        d = self.check([HANDSHAKE, leaf_only], F.FAIL)
        self.assertTrue(any("full chain" in c.summary for c in d.causes))

    def test_unresolved_entries_are_not_duplicated(self):
        conf = finding("nginx.conf", F.WARNING, "evidence level: candidate",
                       scope=F.SCOPE_SERVER)
        d = self.check([HANDSHAKE, conf], F.PASS)
        self.assertEqual([u.check for u in d.unresolved], ["nginx.conf"])

    def test_html_report_shows_the_same_verdict(self):
        import os
        import tempfile
        from ssl_doctor import report
        items = [HANDSHAKE, CHAIN_OK, LEAF_OK, EXPIRED_INTERMEDIATE]
        d = diagnose(items)
        path = os.path.join(tempfile.mkdtemp(prefix="ssldoctor-verdict-"), "r.html")
        report.write_html(path, items, d, {"tool": "t"})
        with open(path, encoding="utf-8") as fh:
            page = fh.read()
        payload = report.build_payload(items, d, {"tool": "t"})
        self.assertEqual(payload["diagnosis"]["overall"], "FAIL")
        self.assertEqual(report._diagnosis_from(payload["diagnosis"]).overall, "FAIL")
        self.assertIn("still count toward the overall result", page)

    def test_all_pass(self):
        d = self.check([HANDSHAKE, CHAIN_OK, LEAF_OK], F.PASS)
        self.assertTrue(any(n.startswith("All executed checks passed") for n in d.notes))


class ClientMachineWeighting(unittest.TestCase):
    """U1: an unexplained FAIL about the machine running SSL Doctor describes the
    client, not the endpoint, so it weighs as WARNING; rule causes keep theirs."""

    ENDPOINT_OK = [HANDSHAKE, CHAIN_OK, LEAF_OK, finding("tls.verify", F.PASS, "verified")]

    def test_unexplained_clock_skew_is_warning(self):
        skew = finding("local.clockskew", F.FAIL, "this machine is 400s ahead",
                       scope=F.SCOPE_LOCAL)
        d = diagnose(self.ENDPOINT_OK + [skew])
        self.assertEqual(d.overall, F.WARNING)
        self.assertEqual([u.check for u in d.unexplained], ["local.clockskew"])

    def test_probable_certutil_cause_is_warning(self):
        certutil = finding("local.certutil", F.FAIL, "CertUtil: -verify command FAILED",
                           scope=F.SCOPE_LOCAL)
        d = diagnose(self.ENDPOINT_OK + [certutil])
        self.assertEqual(d.overall, F.WARNING)
        self.assertTrue(any(c.origin == "client" and c.certainty == "probable"
                            for c in d.causes))

    def test_confirmed_cause_next_to_a_client_failure_is_still_fail(self):
        skew = finding("local.clockskew", F.FAIL, "this machine is 400s ahead",
                       scope=F.SCOPE_LOCAL)
        leaf = finding("tls.certvalid", F.FAIL, "server presents an EXPIRED certificate")
        d = diagnose([HANDSHAKE, CHAIN_OK, leaf, EXPIRED_INTERMEDIATE, skew])
        self.assertTrue(any(c.certainty == "confirmed" for c in d.causes))
        self.assertEqual(d.overall, F.FAIL)


if __name__ == "__main__":
    unittest.main()
