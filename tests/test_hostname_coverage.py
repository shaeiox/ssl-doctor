"""certificate-hostname-coverage: one matcher, modern-client rules."""

import unittest
from unittest import mock

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import certs, hostnames, netchecks


class Matrix(unittest.TestCase):

    CASES = [
        # (SAN DNS, SAN IP, host, covered, matching entry)
        (["shop.example"], [], "shop.example", True, "shop.example"),
        (["shop.example"], [], "SHOP.Example.", True, "shop.example"),
        (["xn--bcher-kva.example"], [], "bücher.example", True, "xn--bcher-kva.example"),
        (["bücher.example"], [], "xn--bcher-kva.example", True, "bücher.example"),
        (["*.shop.example"], [], "a.shop.example", True, "*.shop.example"),
        (["*.shop.example"], [], "shop.example", False, ""),
        (["*.shop.example"], [], "a.b.shop.example", False, ""),
        (["w*.shop.example"], [], "www.shop.example", False, ""),
        (["www.*.example"], [], "www.shop.example", False, ""),
        (["*.co.uk"], [], "example.co.uk", False, ""),
        (["*.com"], [], "example.com", False, ""),
        (["192.0.2.10"], [], "192.0.2.10", False, ""),
        ([], ["192.0.2.10"], "192.0.2.10", True, "192.0.2.10"),
        ([], ["2001:db8::1"], "[2001:db8:0::1]", True, "2001:db8::1"),
        (["shop.example"], [], "other.example", False, ""),
        ([], [], "shop.example", False, ""),
    ]

    def test_hostname_matrix(self):
        for dns, ips, host, covered, entry in self.CASES:
            with self.subTest(san=dns or ips, host=host):
                self.assertEqual(hostnames.covers(dns, ips, host), (covered, entry))

    def test_reasons_are_given(self):
        self.assertIn("partial-label", hostnames.why_not(["w*.shop.example"], "www.shop.example"))
        self.assertIn("public suffix", hostnames.why_not(["*.co.uk"], "a.co.uk"))
        self.assertIn("bare domain", hostnames.why_not(["*.shop.example"], "shop.example"))
        self.assertIn("one label only", hostnames.why_not(["*.shop.example"], "a.b.shop.example"))

    def test_cn_only_certificate_is_not_covered(self):
        c = certs.CertInfo(subject="CN=shop.example", common_name="shop.example")
        self.assertEqual(c.matches_hostname("shop.example")[0], False)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class OneMatcher(unittest.TestCase):

    def test_every_coverage_check_uses_the_matcher(self):
        seen = []
        real = hostnames.covers

        def spy(dns, ips, host):
            import traceback
            seen.append({f.name for f in traceback.extract_stack()})
            return real(dns, ips, host)

        with TLSServer(get_pki(), "full-chain") as srv, trust_env(("root",)), \
                mock.patch.object(hostnames, "covers", side_effect=spy):
            items, facts = netchecks.run_remote_diagnostics(srv.host, srv.port,
                                                            sni=HOSTNAME, timeout=4)
            netchecks.domain_profile(srv.host, srv.port, ["127.0.0.1"],
                                     {**facts, "sni": HOSTNAME})
            netchecks._probe_endpoint(srv.host, srv.port, HOSTNAME, 4, "127.0.0.1")
            # by name: the SNI comparison does not apply to an IP literal target
            netchecks.check_sni_difference("localhost", srv.port, HOSTNAME, 4)
        callers = set().union(*seen)
        for name in ("run_remote_diagnostics", "check_sni_difference", "domain_profile",
                     "_probe_endpoint"):
            self.assertIn(name, callers)
        hostname = {f.check: f for f in items}["tls.hostname"]
        self.assertIn(f"subjectAltName entry '{HOSTNAME}'", hostname.evidence[0])


if __name__ == "__main__":
    unittest.main()
