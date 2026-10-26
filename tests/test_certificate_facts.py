"""certificate-evidence-model + diagnosis-correlation (P4): structured
certificate facts, a named cause for every validation reason, and reports
that show unexplained findings."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from fixtures.fake_server import FakeSession
from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import cli_session, trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import certs, chainval, cli, contract, netchecks, report
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def export_json(app):
    path = os.path.join(tempfile.mkdtemp(prefix="ssldoctor-facts-"), "r.json")
    with contextlib.redirect_stdout(io.StringIO()):
        app.execute(f"/report json {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def key_lines():
    with open(get_pki().leaf_key) as fh:
        return [ln for ln in fh.read().splitlines() if ln and "-----" not in ln]


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class CertificateFacts(unittest.TestCase):

    def test_presented_chain_facts(self):
        app = cli_session("full-chain")
        with trust_env(("root",)):                # the store the scan was judged against
            doc = export_json(app)
        self.assertEqual(contract.validate(doc), [])
        presented = doc["facts"]["certificates"]["presented"]
        self.assertEqual(presented["source"], "presented")
        self.assertEqual(presented["status"], "complete")
        self.assertEqual(presented["trust_class"], "public")
        self.assertEqual([c["role"] for c in presented["certificates"]],
                         ["leaf", "intermediate"])
        self.assertEqual(presented["certificates"][0]["link"], "verified")
        self.assertEqual(presented["certificates"][0]["extended_key_usage"], ["serverAuth"])
        text = json.dumps(doc)
        for line in key_lines():
            self.assertNotIn(line, text)

    def test_configured_and_supplied_chain_facts(self):
        p = get_pki()
        app = cli.SSLDoctorCLI()
        app.server = FakeSession(f"""http {{ server {{ listen 443 ssl;
            server_name shop.test; ssl_certificate {p.fullchain};
            ssl_certificate_key {p.leaf_key}; }} }}""")
        app.store.extend(app.server.nginx_scan("shop.test"))
        with contextlib.redirect_stdout(io.StringIO()):
            app.execute(f"/cert inspect {p.sample('forged-chain.pem')}")
        doc = export_json(app)
        self.assertEqual(contract.validate(doc), [])
        facts = doc["facts"]["certificates"]
        self.assertEqual(facts[f"configured:{p.fullchain}"]["status"], "complete")
        forged = facts[f"supplied:{p.sample('forged-chain.pem')}"]
        self.assertEqual(forged["status"], "broken")
        self.assertEqual(forged["certificates"][0]["link"], "signature-failed")

    def test_server_agent_document_carries_configured_chains_only(self):
        from ssl_doctor import agent, server
        p = get_pki()
        with mock.patch.object(server.LocalSession, "nginx_scan",
                                        lambda self, domain, port=443:
                                        FakeSession(f"""http {{ server {{ listen 443 ssl;
            server_name shop.test; ssl_certificate {p.fullchain};
            ssl_certificate_key {p.leaf_key}; }} }}""").nginx_scan(domain)), \
                mock.patch.object(server.LocalSession, "overview", lambda self: []), \
                mock.patch.object(server.LocalSession, "webserver_detection",
                                           lambda self: []), \
                mock.patch.object(server.LocalSession, "log_scan", lambda self: []), \
                mock.patch.object(netchecks, "check_tls_basic",
                                           return_value=(None, {})):
            doc = agent.run_server_checks("127.0.0.1", 443, HOSTNAME)
        self.assertNotIn("leaf", doc.get("facts", {}))

    def test_forged_presented_chain_opens_the_chain_alert(self):
        sys.path.insert(0, os.path.join(ROOT, "service"))
        try:
            from ssldoctor_service import monitor
        except ImportError as exc:
            self.skipTest(f"service package not importable: {exc}")
        p = get_pki()
        with TLSServer(p, "full-chain", chain=p.sample("forged-int.pem")) as srv, \
                trust_env(("root",)):
            items, facts = netchecks.run_remote_diagnostics(srv.host, srv.port,
                                                            sni=HOSTNAME, timeout=4)
        doc = report.build_payload(items, diagnose(items), {},
                                   facts=netchecks.export_facts(facts))
        self.assertEqual(doc["facts"]["chain_status"], "broken")
        conditions = monitor.conditions_of(doc, 30, datetime.now(timezone.utc))
        self.assertIn("chain_incomplete", conditions)

    def test_expired_intermediate_opens_its_own_alert(self):
        sys.path.insert(0, os.path.join(ROOT, "service"))
        try:
            from ssldoctor_service import monitor
        except ImportError as exc:
            self.skipTest(f"service package not importable: {exc}")
        with TLSServer(get_pki(), "expired-intermediate") as srv, trust_env(("root",)):
            items, facts = netchecks.run_remote_diagnostics(srv.host, srv.port,
                                                            sni=HOSTNAME, timeout=4)
        doc = report.build_payload(items, diagnose(items), {},
                                   facts=netchecks.export_facts(facts))
        self.assertIn("chain_certificate_invalid",
                      monitor.conditions_of(doc, 30, datetime.now(timezone.utc)))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ValidationCauses(unittest.TestCase):

    def summaries(self, items):
        return [c.summary for c in diagnose(items).causes]

    def test_non_ca_issuer_has_a_named_cause(self):
        f = FakeSession("")._chainfile_finding(get_pki().sample("nonca-chain.pem"))
        self.assertTrue(any("not allowed to issue certificates" in s
                            for s in self.summaries([f])))

    def test_failed_signature_has_a_named_cause(self):
        f = FakeSession("")._chainfile_finding(get_pki().sample("forged-chain.pem"))
        self.assertTrue(any("does not verify" in s for s in self.summaries([f])))

    def test_expired_anchor_has_a_named_cause(self):
        p = get_pki()
        later = datetime.now(timezone.utc) + timedelta(days=60)
        f = chainval.trust_finding(certs.parse_cert_file(p.fullchain).certs,
                                   F.SCOPE_REMOTE_NET, "x",
                                   certs.parse_cert_file(p.root).certs, now=later)
        self.assertTrue(any("anchors at an expired root" in s for s in self.summaries([f])))

    def test_unknown_trust_for_a_configured_chain_is_unresolved_not_blamed(self):
        p = get_pki()
        f = chainval.trust_finding(certs.parse_cert_file(p.fullchain).certs,
                                   F.SCOPE_SERVER, "x",
                                   certs.parse_cert_file(p.sample("old-root.pem")).certs)
        d = diagnose([f])
        self.assertEqual(d.causes, [])
        self.assertEqual([u.check for u in d.unresolved], ["chain.trust"])

    def test_encrypted_key_is_named_in_the_notes(self):
        f = F.Finding("srv.keymatch", "pairing", F.NOT_TESTED, F.SCOPE_SERVER,
                      ["private key /etc/ssl/site.key: the private key is "
                       "passphrase-encrypted; it was not read"], failure_kind="key-encrypted")
        d = diagnose([f])
        self.assertEqual(d.causes, [])
        self.assertTrue(any("passphrase-encrypted" in n and "no mismatch is concluded" in n
                            for n in d.notes))


class ReportsShowUnexplained(unittest.TestCase):

    ITEMS = [F.Finding("tls.handshake", "TLS handshake", F.PASS, F.SCOPE_REMOTE_NET, ["ok"]),
             F.Finding("nginx.path_resolution", "Certificate and key file paths", F.FAIL,
                       F.SCOPE_SERVER, ["certificate: /etc/nginx/site.pem", "missing"])]

    def test_html_lists_unexplained_findings(self):
        d = diagnose(self.ITEMS)
        path = os.path.join(tempfile.mkdtemp(prefix="ssldoctor-html-"), "r.html")
        report.write_html(path, self.ITEMS, d, {"tool": "t"})
        with open(path, encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn("[UNEXPLAINED · nginx.path_resolution · FAIL]", page)

    def test_agent_markdown_lists_unexplained_findings(self):
        d = diagnose(self.ITEMS)
        payload = report.build_payload(self.ITEMS, d, {"tool": "t"})
        md = report.agent_markdown(payload)
        self.assertIn("### 5.8 Unexplained findings", md)
        self.assertIn("FAIL · `nginx.path_resolution`", md)
        self.assertIn("unexplained findings: 1", md)
        self.assertNotIn("derived from causes only", md)


if __name__ == "__main__":
    unittest.main()
