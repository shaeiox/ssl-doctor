"""findings-contract: schema validity, version gate, check-id registry, redaction."""

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available
from fixtures.scan import cli_session

from ssl_doctor import contract
from ssl_doctor import findings as F

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def export(app, fmt="json"):
    d = tempfile.mkdtemp(prefix="ssldoctor-report-")
    path = os.path.join(d, "r." + fmt)
    with contextlib.redirect_stdout(io.StringIO()):
        app.execute(f"/report {fmt} {path}")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class SchemaTests(unittest.TestCase):

    def test_exported_report_validates(self):
        app = cli_session("full-chain")
        doc = json.loads(export(app))
        self.assertEqual(doc["schema_version"], contract.SCHEMA_VERSION)
        self.assertEqual(contract.validate(doc), [])
        try:
            import jsonschema  # optional cross-check with a reference validator
        except ImportError:
            return
        jsonschema.validate(doc, contract.SCHEMA)

    def test_every_emitted_check_id_is_registered(self):
        p = get_pki()
        emitted = set()
        for mode in ("leaf-only", "full-chain", "wrong-chain", "cn-only"):
            emitted |= {f.check for f in cli_session(mode).store.all()}
        emitted |= {f.check for f in FakeSession(f"""http {{ server {{ listen 443 ssl;
            server_name shop.test; ssl_certificate {p.fullchain};
            ssl_certificate_key {p.leaf_key}; }} }}""").nginx_scan("shop.test")}
        self.assertEqual(emitted - set(contract.CHECK_IDS), set())

    def test_published_schema_and_docs_match_source(self):
        with open(os.path.join(ROOT, "schemas",
                               f"findings-{contract.SCHEMA_VERSION}.schema.json")) as fh:
            self.assertEqual(json.load(fh), contract.SCHEMA)
        # earlier minor versions remain published
        self.assertTrue(os.path.exists(os.path.join(ROOT, "schemas", "findings-1.0.schema.json")))
        with open(os.path.join(ROOT, "docs", "findings-contract.md")) as fh:
            docs = fh.read()
        for check in contract.CHECK_IDS:
            self.assertIn(f"`{check}`", docs)


class VersionGateTests(unittest.TestCase):

    def doc(self, version):
        return {"schema_version": version, "tool": "x", "generated_utc": "t",
                "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")},
                "findings": []}

    def test_major_2_rejected_naming_both_versions(self):
        with self.assertRaises(contract.ContractError) as cm:
            contract.load_document(json.dumps(self.doc("2.0")))
        self.assertIn("2.0", str(cm.exception))
        self.assertIn("1.x", str(cm.exception))

    def test_newer_minor_accepted(self):
        self.assertEqual(contract.load_document(self.doc("1.7"))["schema_version"], "1.7")

    def test_missing_version_rejected(self):
        d = self.doc("1.0")
        del d["schema_version"]
        with self.assertRaises(contract.ContractError):
            contract.load_document(d)

    def test_structural_error_rejected(self):
        d = self.doc("1.0")
        d["findings"] = [{"check": "tls.chain", "title": "t", "status": "MAYBE",
                          "scope": "remote-net", "evidence": []}]
        with self.assertRaises(contract.ContractError) as cm:
            contract.load_document(d)
        self.assertIn("MAYBE", str(cm.exception))


class FailureKindTests(unittest.TestCase):
    """1.2 adds an optional, enumerated failure classification."""

    def doc(self, **finding):
        base = {"check": "tls.handshake", "title": "TLS handshake", "status": "FAIL",
                "scope": "remote-net", "evidence": ["stalled"]}
        base.update(finding)
        return {"schema_version": "1.2", "tool": "x", "generated_utc": "t",
                "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")},
                "findings": [base]}

    def test_document_without_the_field_still_validates(self):
        self.assertEqual(contract.validate(self.doc()), [])
        self.assertEqual(contract.load_document(self.doc())["schema_version"], "1.2")

    def test_every_registered_failure_kind_validates(self):
        for kind in contract.FAILURE_KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(contract.validate(self.doc(failure_kind=kind)), [])

    def test_empty_failure_kind_validates(self):
        self.assertEqual(contract.validate(self.doc(failure_kind="")), [])

    def test_unregistered_failure_kind_is_rejected(self):
        errs = contract.validate(self.doc(failure_kind="probably-fine"))
        self.assertTrue(errs)
        self.assertIn("probably-fine", " ".join(errs))

    def test_facts_carry_address_and_classification(self):
        doc = self.doc()
        doc["facts"] = {"leaf": None, "chain_status": "unread",
                        "handshake_ip": "192.0.2.10",
                        "handshake_failure": "negotiation-timeout"}
        self.assertEqual(contract.validate(doc), [])
        doc["facts"]["handshake_failure"] = "not-a-kind"
        self.assertTrue(contract.validate(doc))

    def test_earlier_minor_schema_does_not_declare_the_field(self):
        with open(os.path.join(ROOT, "schemas", "findings-1.1.schema.json")) as fh:
            old = json.load(fh)
        self.assertNotIn(
            "failure_kind", old["properties"]["findings"]["items"]["properties"],
            "1.1 must stay unchanged; the field is new in 1.2")
        self.assertIn("failure_kind", contract.SCHEMA["properties"]["findings"]["items"]
                      ["properties"])
        self.assertEqual(contract.SCHEMA_VERSION, "1.2")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class RedactionTests(unittest.TestCase):

    PASSWORD = "S3cr3t-Pa55!word"

    def test_password_auth_export_has_no_password(self):
        app = cli_session("full-chain")
        app.server = FakeSession("")
        app.server.cfg.auth = "password"
        app.server._password = self.PASSWORD
        b64 = base64.b64encode(self.PASSWORD.encode()).decode()
        # simulate tools echoing secrets into evidence (worst case)
        app.store.add(F.Finding("ssh.auth", "SSH authentication", F.FAIL, F.SCOPE_SERVER,
                                [f"sshpass -p {self.PASSWORD} failed", f"auth={b64}"]))
        with open(get_pki().leaf_key) as fh:
            app.store.add(F.Finding("srv.cert", "x", F.FAIL, F.SCOPE_SERVER, [fh.read()]))
        for fmt in ("json", "html"):
            with self.subTest(fmt=fmt):
                text = export(app, fmt)
                self.assertNotIn(self.PASSWORD, text)
                self.assertNotIn(b64, text)
                self.assertNotIn("PRIVATE KEY", text)
                self.assertIn(contract.REDACTED, text)


if __name__ == "__main__":
    unittest.main()
