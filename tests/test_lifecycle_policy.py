"""certificate-lifecycle-policy and certificate-trust-classification (#7):
every certificate's dates, the expiry threshold, key/signature policy, and the
configured certificate judged like the presented one.

R4: an expired certificate configured on the server gave srv.cert PASS.
"""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import agent, certpolicy, certs, cli, netchecks, server
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose


def chain(sample):
    return certs.parse_cert_file(get_pki().sample(sample)).certs


def cert_expiring_in(days):
    now = datetime.now(timezone.utc)
    return certs.CertInfo(not_before=now - timedelta(days=10),
                          not_after=now + timedelta(days=days, hours=1))


class Threshold(unittest.TestCase):

    def tearDown(self):
        certpolicy.set_warn_days(certpolicy.DEFAULT_WARN_DAYS)

    def test_default_threshold(self):
        status, line, _ = certpolicy.leaf_validity(cert_expiring_in(20))
        self.assertEqual(status, F.WARNING)
        self.assertIn("warning threshold 30 days", line)

    def test_custom_threshold(self):
        certpolicy.set_warn_days(14)
        status, line, _ = certpolicy.leaf_validity(cert_expiring_in(20))
        self.assertEqual(status, F.PASS)
        self.assertIn("20 days remaining (warning threshold 14 days)", line)

    def test_boundaries(self):
        for value in ("1", "30", "365"):
            self.assertEqual(certpolicy.parse_warn_days(value), int(value))
        for value in ("0", "400", "-3", "soon", ""):
            with self.subTest(value=value), self.assertRaises(ValueError) as cm:
                certpolicy.parse_warn_days(value)
            self.assertIn("1-365", str(cm.exception))

    def test_cli_refuses_an_out_of_range_threshold_and_runs_nothing(self):
        err = io.StringIO()
        with mock.patch.object(cli.SSLDoctorCLI, "execute") as execute, \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            status = cli.main(["--expiry-warn-days", "400", "-c", "/version"])
        self.assertEqual(status, 2)
        execute.assert_not_called()
        self.assertIn("1-365", err.getvalue())

    def test_cli_sets_the_threshold(self):
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--no-tui", "--expiry-warn-days", "14", "-c", "/version"])
        self.assertEqual(certpolicy.warn_days(), 14)

    def test_agent_job_option(self):
        client = mock.Mock()
        seen = []
        runner = lambda host, port, sni: seen.append(certpolicy.warn_days()) or {}  # noqa: E731
        job = {"job_id": "j1", "kind": "client", "target": {"host": "h", "port": 443},
               "options": {"expiry_warn_days": 10}}
        with mock.patch.dict(agent.RUNNERS, {"client": runner}):
            self.assertEqual(agent.handle_job(client, "client", job), "done")
            self.assertEqual(seen, [10])
            self.assertEqual(certpolicy.warn_days(), 30, "restored after the job")
            job["options"]["expiry_warn_days"] = 0
            self.assertEqual(agent.handle_job(client, "client", job), "declined")
        client.decline.assert_called_once()
        self.assertIn("1-365", client.decline.call_args[0][1])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class EveryCertificate(unittest.TestCase):

    def test_not_yet_valid_leaf(self):
        status, line, rec = certpolicy.leaf_validity(chain("future-leaf.pem")[0])
        self.assertEqual(status, F.FAIL)
        self.assertIn("not valid until 2099-01-01", line)
        self.assertIn("clock", rec)

    def test_expired_and_not_yet_valid_intermediates(self):
        p = get_pki()
        expired = certs.parse_cert_file(p.expired_intermediate_chain).certs
        f = certpolicy.chain_validity_finding(expired, F.SCOPE_LOCAL, "x")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("position 2 ('SSLDoctor Test Intermediate'): expired", f.evidence[0])
        f = certpolicy.chain_validity_finding(chain("future-int-chain.pem"), F.SCOPE_LOCAL, "x")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("not valid until 2099-01-01", f.evidence[0])

    def test_intermediate_expiring_before_the_leaf(self):
        f = certpolicy.chain_validity_finding(chain("short-int-chain.pem"), F.SCOPE_LOCAL, "x")
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("the chain stops validating on", f.evidence[0])
        self.assertIn("within the warning threshold", f.evidence[0])

    def test_live_expired_intermediate_is_named(self):
        with TLSServer(get_pki(), "expired-intermediate") as srv, trust_env(("root",)):
            items, _ = netchecks.run_remote_diagnostics(srv.host, srv.port, sni=HOSTNAME,
                                                        timeout=4)
        by = {f.check: f for f in items}
        self.assertEqual(by["chain.validity"].status, F.FAIL)
        d = diagnose(items)
        self.assertEqual(d.overall, F.FAIL)
        self.assertTrue(any("outside its validity period" in c.summary for c in d.causes))

    def test_live_not_yet_valid_intermediate(self):
        p = get_pki()
        p.sample("future-int-chain.pem")
        with TLSServer(p, "full-chain", chain=p.path("int_future.pem")) as srv, \
                trust_env(("root",)):
            items, _ = netchecks.run_remote_diagnostics(srv.host, srv.port, sni=HOSTNAME,
                                                        timeout=4)
        self.assertEqual({f.check: f for f in items}["chain.validity"].status, F.FAIL)

    def test_configured_chain_validity(self):
        from fixtures.fake_server import FakeSession
        p = get_pki()
        by = {f.check: f for f in FakeSession(f"""http {{ server {{ listen 443 ssl;
            server_name shop.test; ssl_certificate {p.expired_intermediate_chain};
            ssl_certificate_key {p.leaf_key}; }} }}""").nginx_scan("shop.test")}
        self.assertEqual(by["chain.validity"].status, F.FAIL)

    def test_problems_do_not_hide_each_other(self):
        by = {f.check: f for f in certs.inspect_cert_file(get_pki().sample("sha1-int-chain.pem"))}
        self.assertEqual(by["cert.validity"].status, F.WARNING)     # leaf within 30 days
        self.assertEqual(by["cert.policy"].status, F.FAIL)         # SHA-1 intermediate


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Policy(unittest.TestCase):

    def policy(self, sample):
        c = chain(sample)
        return certpolicy.policy_finding(c, F.SCOPE_LOCAL, "x", certpolicy.anchor_ids(c))

    def test_rsa_1024_fails(self):
        f = self.policy("rsa1024-leaf.pem")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("below the 2048-bit minimum", " ".join(f.evidence))
        self.assertTrue(f.evidence[0].startswith("policy 1:"))

    def test_p256_and_ed25519_pass(self):
        for sample in ("ec-aia.pem", "ed25519.pem"):
            with self.subTest(sample=sample):
                self.assertEqual(self.policy(sample).status, F.PASS)

    def test_sha1_intermediate_fails(self):
        f = self.policy("sha1-int-chain.pem")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("position 2 ('SSLDoctor Test Intermediate'): signature algorithm "
                      "sha1WithRSAEncryption is deprecated", " ".join(f.evidence))

    def test_sha1_root_self_signature_is_not_judged(self):
        f = self.policy("sha1-root.pem")
        self.assertEqual(f.status, F.PASS)
        self.assertIn("not judged", " ".join(f.evidence))

    def test_policy_failure_is_a_cause(self):
        d = diagnose([self.policy("rsa1024-leaf.pem")])
        self.assertTrue(any("weak key or a deprecated signature" in c.summary
                            for c in d.causes))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ConfiguredCertificate(unittest.TestCase):

    def scan(self, sample, domain=HOSTNAME):
        path = get_pki().sample(sample)
        items = server.LocalSession(tls_host=domain).scan_cert(
            path, states={path: "readable"})
        return {f.check: f for f in items}["srv.cert"], items

    def test_regression_r4_expired_on_disk_leaf(self):
        f, items = self.scan("expired-leaf.pem")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("expired", " ".join(f.evidence))
        self.assertTrue(any("configured on the server is unusable" in c.summary
                            for c in diagnose(items).causes))

    def test_configured_certificate_not_covering_the_domain(self):
        f, _ = self.scan("ec-aia.pem", domain=HOSTNAME)
        self.assertEqual(f.status, F.FAIL)
        self.assertIn(f"does not cover '{HOSTNAME}'", " ".join(f.evidence))

    def test_valid_configured_certificate(self):
        certpolicy.set_warn_days(7)
        try:
            path = get_pki().leaf
            items = server.LocalSession(tls_host=HOSTNAME).scan_cert(
                path, states={path: "readable"})
        finally:
            certpolicy.set_warn_days(certpolicy.DEFAULT_WARN_DAYS)
        f = {i.check: i for i in items}["srv.cert"]
        self.assertEqual(f.status, F.PASS)
        self.assertIn(f"covers '{HOSTNAME}'", " ".join(f.evidence))


if __name__ == "__main__":
    unittest.main()
