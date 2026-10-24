"""`/report agent`: an AI-ready export that is faithful to the scan it exports.

The session below is built from the real check functions behind their probe
seams (no network): the google.com-like protocol matrix (TLS 1.0/1.1 relaxed
only, default probes client-limited), a 4-of-7 endpoint comparison, a NOT
TESTED SNI check and the client's `local.os` record.
"""

from __future__ import annotations

import base64
import contextlib
import glob
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available
from fixtures.scan import cli_session

from ssl_doctor import cli, contract, findings as F, report

from test_endpoint_comparison import ep, run as run_endpoints
from test_legacy_tls_semantics import google_like

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IPS = [f"192.0.2.{i}" for i in range(10, 17)]


def google_session() -> cli.SSLDoctorCLI:
    matrix, matrix_facts = google_like()
    records = {ip: ep(ip, "negotiated", sha="a" * 64, hostname_ok=True) for ip in IPS}
    multi, ep_facts = run_endpoints(records, ips=IPS)
    app = cli.SSLDoctorCLI()
    app.store.extend([
        F.Finding("net.dns", "DNS resolution of shop.test", F.PASS, F.SCOPE_REMOTE_NET,
                  [f"A {ip}" for ip in IPS], target="shop.test:443"),
        F.Finding("net.tcp", "TCP connectivity to 192.0.2.10:443", F.PASS,
                  F.SCOPE_REMOTE_NET, ["connected to 192.0.2.10:443 within the timeout"],
                  target="shop.test:443"),
        F.Finding("tls.handshake", "TLS handshake with shop.test:443", F.PASS,
                  F.SCOPE_REMOTE_NET, ["negotiated TLSv1.3 / TLS_AES_256_GCM_SHA384"],
                  target="shop.test:443"),
        matrix,
        F.Finding("tls.sni", "Behaviour with and without SNI", F.NOT_TESTED,
                  F.SCOPE_REMOTE_NET, ["the no-SNI probe could not be completed"],
                  target="shop.test:443", observation="sni-without-probe-failed"),
        multi,
        F.Finding("local.os", "Operating system and clock", F.PASS, F.SCOPE_LOCAL,
                  ["OS: Linux-test", "Python: 3.12.0 / OpenSSL 3.0.13 30 Jan 2024"]),
    ])
    app.remote_facts = {"host": "shop.test", "port": 443, "sni": "shop.test",
                        "ips": IPS, "handshake_ip": IPS[0], "protocol": "TLSv1.3",
                        "cipher": "TLS_AES_256_GCM_SHA384", **matrix_facts, **ep_facts}
    return app


class AgentDocument(unittest.TestCase):
    """agent-report.json is the `/report json` document plus agent `meta`."""

    def setUp(self):
        self.app = google_session()
        self.items = self.app.store.all()
        self.payload = self.app._agent_payload(self.items)

    def test_it_is_a_valid_findings_contract_document(self):
        self.assertEqual(self.payload["schema_version"], contract.SCHEMA_VERSION)
        self.assertEqual(contract.validate(self.payload), [])
        with open(os.path.join(ROOT, "schemas",
                               f"findings-{contract.SCHEMA_VERSION}.schema.json")) as fh:
            published = json.load(fh)
        try:
            import jsonschema
        except ImportError:
            return
        jsonschema.validate(self.payload, published)

    def test_findings_diagnosis_and_facts_equal_report_json(self):
        diag, meta, secrets, facts = self.app._report_inputs(self.items)
        plain = report.build_payload(self.items, diag, meta, secrets, facts)
        for key in ("summary", "findings", "diagnosis", "facts"):
            with self.subTest(key=key):
                self.assertEqual(self.payload[key], plain[key])

    def test_probe_policy_and_endpoint_coverage_are_kept(self):
        facts = self.payload["facts"]
        self.assertEqual(facts["probe_policy"]["default_probe"],
                         {"TLS 1.0": "client-limited", "TLS 1.1": "client-limited",
                          "TLS 1.2": "accepted"})
        self.assertEqual(facts["probe_policy"]["unverified_legacy"], ["TLS 1.0", "TLS 1.1"])
        coverage = facts["endpoint_comparison"]
        self.assertEqual((coverage["addresses"], coverage["probed"], coverage["comparable"]),
                         (7, 4, 4))

    def test_finding_classifications_are_kept(self):
        by_check = {f["check"]: f for f in self.payload["findings"]}
        self.assertEqual(by_check["tls.protocols"]["observation"], "legacy-accepted-unverified")
        self.assertTrue(by_check["tls.protocols"]["uncertainty"])
        self.assertEqual(by_check["tls.sni"]["status"], F.NOT_TESTED)
        for f in self.payload["findings"]:
            self.assertIn("failure_kind", f)
            self.assertIn("uncertainty", f)

    def test_meta_carries_scan_and_environment_context(self):
        meta = self.payload["meta"]
        self.assertEqual(meta["report_kind"], "agent")
        scan = meta["agent_report"]["scan"]
        self.assertEqual((scan["host"], scan["port"], scan["sni"]), ("shop.test", 443, "shop.test"))
        self.assertEqual(scan["ips"], IPS)
        self.assertEqual((scan["protocol"], scan["cipher"]),
                         ("TLSv1.3", "TLS_AES_256_GCM_SHA384"))
        self.assertIsNone(scan["final_url"])          # not recorded -> null
        self.assertIn("shop.test:443", scan["targets"])
        env = meta["agent_report"]["environment"]
        for key in ("tool", "python", "openssl", "platform"):
            self.assertTrue(env[key], key)
        self.assertEqual(env["local_os_evidence"][0], "OS: Linux-test")
        self.assertEqual(meta["agent_report"]["configuration"]["network_timeout"], 8.0)
        # the base run context is untouched
        self.assertEqual(meta["network_timeout"], 8.0)

    def test_missing_local_record_is_null_not_guessed(self):
        app = google_session()
        app.store.clear()
        app.store.extend([f for f in self.items if f.check != "local.os"])
        meta = app._agent_payload(app.store.all())["meta"]
        self.assertIsNone(meta["agent_report"]["environment"]["local_os_evidence"])


SECTIONS = ("## 1. Report metadata", "## 2. Executive summary",
            "## 3. Target and environment", "## 4. Detailed evidence",
            "## 5. Findings and diagnosis", "## 6. Recommended next steps",
            "## 7. AI analysis instructions")


def section(md: str, heading: str) -> str:
    """The text of one `##`/`###` section, up to the next heading of that level."""
    level = heading.split(" ", 1)[0]
    start = md.index(heading)
    rest = md[start + len(heading):]
    ends = [rest.find(f"\n{level} ")] + ([rest.find("\n## ")] if level == "###" else [])
    ends = [e for e in ends if e >= 0]
    return rest[:min(ends)] if ends else rest


class AgentMarkdown(unittest.TestCase):
    """agent-report.md: fixed structure, rendered only from the JSON document."""

    def setUp(self):
        self.app = google_session()
        self.payload = self.app._agent_payload(self.app.store.all())
        self.md = report.agent_markdown(self.payload)

    def test_sections_appear_in_order(self):
        positions = [self.md.index(heading) for heading in SECTIONS]
        self.assertEqual(positions, sorted(positions))

    def test_summary_counts_and_status_equal_the_json(self):
        summary = section(self.md, "## 2. Executive summary")
        counts = self.payload["summary"]
        self.assertIn(f"**{self.payload['diagnosis']['overall']}**", summary)
        self.assertIn(f"{counts['PASS']} PASS · {counts['FAIL']} FAIL · "
                      f"{counts['WARNING']} WARNING · {counts['NOT TESTED']} NOT TESTED",
                      summary)
        self.assertIn("unresolved findings: 1", summary)

    def test_metadata_names_versions_target_and_environment(self):
        meta = section(self.md, "## 1. Report metadata")
        self.assertIn(self.payload["tool"], meta)
        self.assertIn(f"findings/{contract.SCHEMA_VERSION}", meta)
        self.assertIn("`shop.test:443`", meta)
        self.assertIn(self.payload["generated_utc"], meta)

    def test_every_evidence_area_has_a_heading(self):
        evidence = section(self.md, "## 4. Detailed evidence")
        for heading, _, empty in report._AGENT_AREAS:
            with self.subTest(area=heading):
                self.assertIn(f"### {heading}", evidence)
        self.assertIn("cipher acceptance was not tested in this session", evidence)
        self.assertIn("no server-side checks were run", evidence)

    def test_protocol_probes_carry_policy_and_client_limit_labels(self):
        probes = section(self.md, "### Protocol-version probes")
        self.assertIn("`ALL:@SECLEVEL=0`", probes)
        self.assertIn("| TLS 1.0 | `relaxed-only-unverified`", probes)
        self.assertIn("`client-limited` - not sent", probes)
        self.assertIn("not a server rejection", probes)
        self.assertIn("confirmed for ordinary clients: none", probes)

    def test_endpoint_coverage_is_partial_not_all(self):
        endpoints = section(self.md, "### Endpoint comparison")
        self.assertIn("7 address(es) resolved, 4 probed, 4 reachable, 4 comparable",
                      endpoints)
        self.assertIn("apply to the comparable endpoints only", endpoints)
        self.assertNotIn("all 7", endpoints)

    def test_not_tested_stays_not_tested(self):
        self.assertIn("**NOT TESTED** · `tls.sni`", self.md)
        self.assertIn("NOT TESTED · `tls.sni`", section(self.md, "### 5.1 Observations"))
        self.assertIn("`tls.sni` was NOT TESTED", section(self.md, "### Missing evidence"))
        self.assertNotRegex(self.md, r"\*\*(PASS|FAIL)\*\* · `tls\.sni`")

    def test_unverified_legacy_tls_is_unresolved_never_confirmed(self):
        self.assertIn("- none recorded", section(self.md, "### 5.2 Confirmed causes"))
        unresolved = section(self.md, "### 5.5 Unresolved findings")
        self.assertIn("`tls.protocols` (WARNING", unresolved)
        self.assertIn("uncertainty:", unresolved)
        self.assertNotRegex(self.md.lower(), r"legacy tls (is )?confirmed")

    def test_next_steps_reproduce_recorded_guidance_only(self):
        steps = section(self.md, "## 6. Recommended next steps")
        recorded = {f["recommendation"] for f in self.payload["findings"] if f["recommendation"]}
        recorded |= {u["recommendation"] for u in self.payload["diagnosis"]["unresolved"]}
        numbered = [line.split(". ", 1)[1] for line in steps.splitlines()
                    if line[:1].isdigit() and ". " in line]
        self.assertTrue(numbered)
        self.assertEqual(set(numbered) - recorded, set())   # nothing invented

    def test_no_finding_or_cause_is_invented(self):
        titles = {(f["check"], f["title"]) for f in self.payload["findings"]}
        for check, title in re.findall(r"· `([a-z.]+)` · ([^(\n]+?)(?: \(scope|$)",
                                       self.md, re.M):
            with self.subTest(check=check):
                self.assertIn((check, title.strip()), titles)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class AgentMarkdownWithCauses(unittest.TestCase):
    """A real fixture session whose diagnosis has a cause."""

    def setUp(self):
        self.app = cli_session("leaf-only")
        self.payload = self.app._agent_payload(self.app.store.all())
        self.md = report.agent_markdown(self.payload)

    def test_causes_keep_certainty_evidence_and_recorded_remediation(self):
        causes = self.payload["diagnosis"]["causes"]
        self.assertTrue(causes)
        diagnosis = section(self.md, "## 5. Findings and diagnosis")
        for c in causes:
            with self.subTest(cause=c["summary"][:40]):
                self.assertIn(f"**{c['certainty'].upper()}** (rank {c['rank']}", diagnosis)
                self.assertIn(c["summary"], diagnosis)
        self.assertIn("SSL Doctor did not record contradicting evidence", diagnosis)

    def test_client_only_scan_says_no_server_checks_ran(self):
        self.assertIn("no server-side checks were run",
                      section(self.md, "### Server-side checks (authorized, read-only)"))


class ReportAgentCommand(unittest.TestCase):
    """`/report agent [dir]`: output, refusals and failure handling."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agent-report-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)
        self.out = io.StringIO()
        self.quiet = lambda: contextlib.redirect_stdout(self.out)
        original = cli._MODE
        self.addCleanup(cli.set_color_mode, original)
        cli.set_color_mode(cli.ColorMode.PLAIN)

    def run_cmd(self, app, line):
        with self.quiet():
            app.execute(line)
        return self.out.getvalue()

    def snapshot(self, app):
        return [f.to_dict() for f in app.store.all()]

    def test_writes_both_files_and_prints_paths_and_summary(self):
        app = google_session()
        before = self.snapshot(app)
        text = self.run_cmd(app, "/report agent")
        [folder] = os.listdir(self.tmp)
        self.assertRegex(folder, r"^ssl-doctor-agent-report-\d{8}-\d{6}$")
        md_path, json_path = (os.path.join(self.tmp, folder, name)
                              for name in report.AGENT_REPORT_FILES)
        self.assertIn(os.path.abspath(md_path), text)
        self.assertIn(os.path.abspath(json_path), text)
        self.assertIn("shop.test:443 - overall PASS - 5 pass, 0 fail, 1 warning, "
                      "1 not tested", text)
        with open(json_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        with open(md_path, encoding="utf-8") as fh:
            md = fh.read()
        self.assertEqual(contract.validate(doc), [])
        # the Markdown is the rendering of exactly this JSON document
        self.assertEqual(md, report.agent_markdown(doc))
        self.assertTrue(md.endswith(report.AGENT_ANALYSIS_PROMPT))
        # the scan itself is untouched
        self.assertEqual(self.snapshot(app), before)

    def test_an_explicit_directory_is_used_and_created(self):
        app = google_session()
        self.run_cmd(app, "/report agent out/case-42")
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, "out", "case-42"))),
                         sorted(report.AGENT_REPORT_FILES))

    def test_no_completed_scan_writes_nothing(self):
        for setup in ("fresh", "local-only", "cleared"):
            with self.subTest(setup=setup):
                app = cli.SSLDoctorCLI()
                if setup == "local-only":
                    app.store.add(F.Finding("local.os", "OS", F.PASS, F.SCOPE_LOCAL, []))
                if setup == "cleared":
                    app = google_session()
                    self.run_cmd(app, "/clear")
                text = self.run_cmd(app, "/report agent")
                self.assertIn("no completed scan in this session", text)
                self.assertIn("/scan <target> or /tls <target>", text)
                self.assertEqual(os.listdir(self.tmp), [])

    def test_existing_report_is_never_overwritten(self):
        os.makedirs("out")
        with open(os.path.join("out", "agent-report.md"), "w") as fh:
            fh.write("keep me")
        text = self.run_cmd(google_session(), "/report agent out")
        self.assertIn("could not write the agent report", text)
        self.assertIn("agent-report.md", text)
        self.assertEqual(os.listdir("out"), ["agent-report.md"])
        with open(os.path.join("out", "agent-report.md")) as fh:
            self.assertEqual(fh.read(), "keep me")

    def test_a_failing_second_file_leaves_no_partial_report(self):
        real_replace = os.replace
        calls = []

        def flaky(src, dst):
            calls.append(dst)
            if dst.endswith(".json"):
                raise OSError(28, "No space left on device", dst)
            return real_replace(src, dst)

        app = google_session()
        with mock.patch.object(os, "replace", flaky):
            text = self.run_cmd(app, "/report agent out")
        self.assertTrue(any(d.endswith(".md") for d in calls))   # the first file was placed
        self.assertIn("could not write the agent report", text)
        self.assertIn("No space left on device", text)
        self.assertFalse(os.path.exists("out"))                 # directory it made is gone
        self.assertIn("SSL Doctor v", self.run_cmd(app, "/version"))  # still usable

    def test_an_unwritable_location_is_reported(self):
        with open("blocker", "w") as fh:
            fh.write("a file, not a directory")
        text = self.run_cmd(google_session(), "/report agent blocker/out")
        self.assertIn("could not write the agent report", text)
        self.assertEqual(sorted(os.listdir(self.tmp)), ["blocker"])

    def test_a_serialisation_failure_writes_nothing(self):
        app = google_session()
        with mock.patch.object(
                report, "agent_markdown", side_effect=ValueError("bad value")):
            text = self.run_cmd(app, "/report agent")
        self.assertIn("could not serialise the agent report: ValueError: bad value", text)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_other_report_modes_are_unchanged(self):
        app = google_session()
        self.run_cmd(app, "/report both r")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["r.html", "r.json"])
        with open("r.json") as fh:
            doc = json.load(fh)
        self.assertNotIn("report_kind", doc["meta"])      # no agent context leaks in


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class AgentReportRedaction(unittest.TestCase):
    """Same redaction conventions as `/report json` and `/report html`."""

    PASSWORD = "S3cr3t-Pa55!word"

    def test_neither_file_contains_secrets(self):
        app = cli_session("full-chain")
        app.server = FakeSession("")
        app.server.cfg.auth = "password"
        app.server._password = self.PASSWORD
        b64 = base64.b64encode(self.PASSWORD.encode()).decode()
        app.store.add(F.Finding("ssh.auth", "SSH authentication", F.FAIL, F.SCOPE_SERVER,
                                [f"sshpass -p {self.PASSWORD} failed", f"auth={b64}"]))
        with open(get_pki().leaf_key) as fh:
            app.store.add(F.Finding("srv.cert", "x", F.FAIL, F.SCOPE_SERVER, [fh.read()]))
        out = tempfile.mkdtemp(prefix="agent-redact-")
        self.addCleanup(shutil.rmtree, out, True)
        with contextlib.redirect_stdout(io.StringIO()):
            app.execute(f"/report agent {out}/r")
        for name in report.AGENT_REPORT_FILES:
            with self.subTest(file=name), open(os.path.join(out, "r", name),
                                               encoding="utf-8") as fh:
                text = fh.read()
                self.assertNotIn(self.PASSWORD, text)
                self.assertNotIn(b64, text)
                self.assertNotIn("PRIVATE KEY", text)
                self.assertIn(contract.REDACTED, text)


class AnalysisPrompt(unittest.TestCase):
    """The prompt is specified text: it must reach the report unchanged."""

    FIXTURE = os.path.join(ROOT, "tests", "fixtures", "agent_prompt.txt")

    def test_the_constant_is_the_specified_text(self):
        with open(self.FIXTURE, encoding="utf-8") as fh:
            self.assertEqual(report.AGENT_ANALYSIS_PROMPT, fh.read())

    def test_the_fixture_matches_the_change_design(self):
        """While the OpenSpec change (or its archive) is present, pin the
        fixture to the design's appendix so neither copy can drift."""
        designs = glob.glob(os.path.join(ROOT, "openspec", "changes", "add-agent-report",
                                         "design.md")) + \
            glob.glob(os.path.join(ROOT, "openspec", "changes", "archive",
                                   "*add-agent-report", "design.md"))
        if not designs:
            self.skipTest("add-agent-report design not present")
        with open(designs[0], encoding="utf-8") as fh:
            appendix = fh.read().split("## Appendix: AI analysis prompt (verbatim)", 1)[1]
        with open(self.FIXTURE, encoding="utf-8") as fh:
            self.assertEqual(appendix.split("\n---\n", 2)[1].strip("\n") + "\n", fh.read())

    def test_key_rules_are_present(self):
        for phrase in ("`NO_PROTOCOLS_AVAILABLE`", "relaxed OpenSSL security policy",
                       "Three prioritized next actions",
                       "Never fabricate command output"):
            self.assertIn(phrase, report.AGENT_ANALYSIS_PROMPT)


if __name__ == "__main__":
    unittest.main()
