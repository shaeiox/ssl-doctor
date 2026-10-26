"""certificate-revocation + endpoint-comparison (P7): stapled OCSP by default,
online OCSP/CRL on request, explicit states, and both address families."""

import contextlib
import io
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import agent, certs, cli, netchecks, report, revocation as rv
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cert(path):
    return certs.parse_cert_file(path).certs[0]


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


class ModeReset(unittest.TestCase):
    def tearDown(self):
        rv.set_mode("staple")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Stapled(ModeReset):

    def test_stapled_response_is_fetched_exactly(self):
        p = get_pki()
        with TLSServer(p, "full-chain", status_file=p.ocsp_response("good")) as srv:
            der, detail = rv.fetch_stapled(srv.host, srv.port, HOSTNAME, 4)
        self.assertEqual(der, read(p.ocsp_response("good")))
        self.assertIn("stapled response received", detail)

    def test_nothing_stapled(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            der, detail = rv.fetch_stapled(srv.host, srv.port, HOSTNAME, 4)
        self.assertIsNone(der)
        self.assertIn("staples no OCSP response", detail)

    def test_good_and_revoked(self):
        p = get_pki()
        leaf, inter = cert(p.leaf), cert(p.intermediate)
        good = rv.evaluate(read(p.ocsp_response("good")), leaf, inter, "stapled")
        self.assertEqual((good.state, good.source), (rv.GOOD, "stapled"))
        bad = rv.evaluate(read(p.ocsp_response("revoked")), leaf, inter, "stapled")
        self.assertEqual(bad.state, rv.REVOKED)
        self.assertIn("keyCompromise", bad.evidence[0])

    def test_stale_stapled_response(self):
        p = get_pki()
        later = datetime.now(timezone.utc) + timedelta(days=3)
        r = rv.evaluate(read(p.ocsp_response("good")), cert(p.leaf), cert(p.intermediate),
                        "stapled", now=later)
        self.assertEqual(r.state, rv.INCONCLUSIVE)
        self.assertTrue(r.stapled_defect)
        self.assertIn("stapled response expired", r.evidence[0])

    def test_response_for_another_issuer(self):
        p = get_pki()
        r = rv.evaluate(read(p.ocsp_response("good")), cert(p.leaf), cert(p.root), "stapled")
        self.assertEqual(r.state, rv.INCONCLUSIVE)

    def test_response_signed_by_an_unauthorised_key(self):
        # same certificate ID, but signed by a CA that is not the leaf's issuer
        p = get_pki()
        out = p.path("ocsp-forged.der")
        subprocess.run(["openssl", "ocsp", "-index", p._revocation_index(False),
                        "-rsigner", "other_int.pem", "-rkey", "other_int.key",
                        "-CA", "int.pem", "-issuer", "int.pem", "-cert", "leaf.pem",
                        "-respout", out, "-ndays", "1"],
                       cwd=p.dir, check=True, capture_output=True)
        r = rv.evaluate(read(out), cert(p.leaf), cert(p.intermediate), "stapled")
        self.assertEqual(r.state, rv.INCONCLUSIVE)
        self.assertIn("signature does not verify", r.evidence[0])

    def test_not_yet_valid_response(self):
        p = get_pki()
        earlier = datetime.now(timezone.utc) - timedelta(days=1)
        r = rv.evaluate(read(p.ocsp_response("good")), cert(p.leaf), cert(p.intermediate),
                        "stapled", now=earlier)
        self.assertEqual(r.state, rv.INCONCLUSIVE)
        self.assertIn("not yet valid", r.evidence[0])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class States(ModeReset):

    def chain(self, leaf_path):
        return [cert(leaf_path), cert(get_pki().intermediate)]

    def test_off_is_not_checked(self):
        rv.set_mode("off")
        r = rv.check_chain(self.chain(get_pki().leaf), "127.0.0.1", 9, HOSTNAME, 1)
        self.assertEqual(r.state, rv.NOT_CHECKED)

    def test_no_revocation_information_is_unavailable(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            r = rv.check_chain(self.chain(get_pki().leaf), srv.host, srv.port, HOSTNAME, 3)
        self.assertEqual(r.state, rv.UNAVAILABLE)

    def test_urls_but_staple_mode_is_not_checked_and_names_the_option(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            r = rv.check_chain(self.chain(get_pki().sample("ocsp-leaf.pem")),
                               srv.host, srv.port, HOSTNAME, 3)
        self.assertEqual(r.state, rv.NOT_CHECKED)
        self.assertIn("--revocation=online", " ".join(r.evidence))

    def test_unreachable_responder_is_inconclusive(self):
        rv.set_mode("online")
        with TLSServer(get_pki(), "full-chain") as srv:
            r = rv.check_chain(self.chain(get_pki().sample("ocsp-leaf.pem")),
                               srv.host, srv.port, HOSTNAME, 2)
        self.assertEqual(r.state, rv.INCONCLUSIVE)
        text = " ".join(r.evidence)
        self.assertIn("OCSP responder http://127.0.0.1:9/ did not answer", text)
        self.assertIn("CRL http://127.0.0.1:9/int.crl could not be fetched", text)

    def test_crl_revoked_and_good(self):
        p = get_pki()
        leaf, inter = cert(p.leaf), cert(p.intermediate)
        with mock.patch.object(rv, "_download", return_value=read(p.crl(True))):
            self.assertEqual(rv.query_crl(leaf, inter, "http://x/int.crl", 2).state, rv.REVOKED)
        with mock.patch.object(rv, "_download", return_value=read(p.crl(False))):
            self.assertEqual(rv.query_crl(leaf, inter, "http://x/int.crl", 2).state, rv.GOOD)

    def test_crl_signed_by_someone_else_is_inconclusive(self):
        p = get_pki()
        with mock.patch.object(rv, "_download", return_value=read(p.crl(True))):
            r = rv.query_crl(cert(p.leaf), cert(p.root), "http://x/int.crl", 2)
        self.assertEqual(r.state, rv.INCONCLUSIVE)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class InTheScan(ModeReset):

    def scan(self, status_file=""):
        with TLSServer(get_pki(), "full-chain", status_file=status_file) as srv, \
                trust_env(("root",)):
            items, facts = netchecks.run_remote_diagnostics(srv.host, srv.port,
                                                            sni=HOSTNAME, timeout=4)
        return {f.check: f for f in items}, items, facts

    def test_good_staple_by_default_sends_nothing_to_the_ca(self):
        with mock.patch.object(rv, "query_ocsp", side_effect=AssertionError("CA queried")), \
                mock.patch.object(rv, "query_crl", side_effect=AssertionError("CA queried")):
            by, _items, facts = self.scan(get_pki().ocsp_response("good"))
        self.assertEqual(by["tls.revocation"].status, F.PASS)
        self.assertIn("source: stapled", by["tls.revocation"].evidence[0])
        doc = netchecks.export_facts(facts)
        self.assertEqual(doc["certificates"]["presented"]["revocation"], "good")

    def test_revoked_leaf_is_a_confirmed_cause_and_an_alert(self):
        by, items, facts = self.scan(get_pki().ocsp_response("revoked"))
        self.assertEqual(by["tls.revocation"].status, F.FAIL)
        d = diagnose(items)
        self.assertTrue(any(c.certainty == "confirmed" and "revoked" in c.summary
                            for c in d.causes))
        sys.path.insert(0, os.path.join(ROOT, "service"))
        try:
            from ssldoctor_service import monitor
        except ImportError as exc:
            self.skipTest(f"service package not importable: {exc}")
        doc = report.build_payload(items, d, {}, facts=netchecks.export_facts(facts))
        self.assertIn("revoked", monitor.conditions_of(doc, 30, datetime.now(timezone.utc)))

    def test_good_revocation_does_not_upgrade_an_incomplete_chain(self):
        p = get_pki()
        with TLSServer(p, "leaf-only", status_file=p.ocsp_response("good")) as srv, \
                trust_env(("root",)):
            items, _facts = netchecks.run_remote_diagnostics(srv.host, srv.port,
                                                             sni=HOSTNAME, timeout=4)
        by = {f.check: f for f in items}
        self.assertEqual(by["tls.chain"].status, F.WARNING)
        # leaf-only: the issuer is not sent, so the staple cannot be checked
        self.assertNotEqual(by["tls.revocation"].status, F.PASS)

    def test_cli_and_agent_options(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--revocation=sometimes", "-c", "/version"]), 2)
            cli.main(["--no-tui", "--revocation=off", "-c", "/version"])
        self.assertEqual(rv.mode(), "off")
        self.assertIn("staple, online, off", err.getvalue())
        rv.set_mode("staple")
        client, seen = mock.Mock(), []
        job = {"job_id": "j", "kind": "client", "target": {"host": "h", "port": 443},
               "options": {"revocation": "online"}}
        with mock.patch.dict(agent.RUNNERS, {"client": lambda *a: seen.append(rv.mode()) or {}}):
            agent.handle_job(client, "client", job)
            job["options"]["revocation"] = "always"
            self.assertEqual(agent.handle_job(client, "client", job), "declined")
        self.assertEqual((seen, rv.mode()), (["online"], "staple"))


class AddressFamilies(unittest.TestCase):

    def fake_probe(self, certs_by_ip, unreachable=()):
        def probe(host, port, sni, timeout, ip):
            family = "ipv6" if ":" in ip else "ipv4"
            if ip in unreachable:
                return {"ip": ip, "state": netchecks.EP_UNREACHABLE, "detail": "no route",
                        "sha256": "", "hostname_ok": None, "chain_status": "", "sni": sni,
                        "family": family}
            return {"ip": ip, "state": netchecks.EP_NEGOTIATED, "detail": "",
                    "sha256": certs_by_ip.get(ip, "a" * 64), "hostname_ok": True,
                    "chain_status": "complete", "sni": sni, "family": family}
        return probe

    V4 = [f"192.0.2.{i}" for i in range(1, 6)]
    V6 = ["2001:db8::1", "2001:db8::2"]

    def test_both_families_are_probed_and_labelled(self):
        facts = {}
        with mock.patch.object(netchecks, "_probe_endpoint", side_effect=self.fake_probe({})):
            f = netchecks.check_multi_ip("shop.test", 443, self.V4 + self.V6, 4, facts=facts)
        families = [r["family"] for r in facts["endpoints"]]
        self.assertEqual(len(families), 4)
        self.assertIn("ipv6", families)
        self.assertIn("DNS published 5 IPv4 and 2 IPv6 address(es)", f.evidence)

    def test_ipv6_only_difference(self):
        certs_by_ip = {ip: "b" * 64 for ip in self.V6}
        with mock.patch.object(netchecks, "_probe_endpoint",
                               side_effect=self.fake_probe(certs_by_ip)):
            f = netchecks.check_multi_ip("shop.test", 443, self.V4[:2] + self.V6[:1], 4)
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("IPv6 endpoints differ from IPv4 endpoints in: certificate identity",
                      f.evidence)

    def test_ipv6_unreachable_is_not_a_difference(self):
        with mock.patch.object(netchecks, "_probe_endpoint",
                               side_effect=self.fake_probe({}, unreachable=self.V6)):
            f = netchecks.check_multi_ip("shop.test", 443, self.V4[:2] + self.V6, 4)
        self.assertEqual(f.status, F.PASS)
        self.assertIn("IPv6 not reachable from this network", f.evidence)

    def test_single_family(self):
        with mock.patch.object(netchecks, "_probe_endpoint", side_effect=self.fake_probe({})):
            f = netchecks.check_multi_ip("shop.test", 443, self.V4[:2], 4)
        self.assertIn("no IPv6 address was published", f.evidence)

    @unittest.skipUnless(openssl_available(), "openssl binary not available")
    def test_real_ipv6_loopback(self):
        if not socket.has_ipv6:
            self.skipTest("this Python has no IPv6 support")
        try:
            with socket.socket(socket.AF_INET6) as s:
                s.bind(("::1", 0))
                port = s.getsockname()[1]
        except OSError as exc:
            self.skipTest(f"no IPv6 loopback on this host: {exc}")
        p = get_pki()
        proc = subprocess.Popen(["openssl", "s_server", "-quiet", "-www", "-no-CAfile",
                                 "-no-CApath", "-accept", f"[::1]:{port}", "-cert", p.leaf,
                                 "-key", p.leaf_key, "-cert_chain", p.intermediate],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    socket.create_connection(("::1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            rec = netchecks._probe_endpoint("localhost", port, HOSTNAME, 4, "::1")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
        self.assertEqual((rec["state"], rec["family"]), (netchecks.EP_NEGOTIATED, "ipv6"))


if __name__ == "__main__":
    unittest.main()
