"""nginx-config-analysis: block selection, http{} inheritance, chain-file linkage."""

import contextlib
import io
import unittest

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available

from ssl_doctor import cli
from ssl_doctor import findings as F
from ssl_doctor import server


def blocks_of(config):
    nodes = server._parse_nginx_nodes(config)
    return [server._block_directives(b) for b in server._collect_server_blocks(nodes)]


SELECTION_CONFIG = r"""
http {
    server { listen 80;              server_name shop.test; ssl_certificate /plain; }
    server { listen 443 ssl;         server_name shop.test; ssl_certificate /first; }
    server { listen 443 ssl;         server_name shop.test; ssl_certificate /second; }
    server { listen 8443 ssl default_server; server_name other.test; ssl_certificate /alt; }
    server { listen 443 ssl;         server_name *.test;    ssl_certificate /leading; }
    server { listen 443 ssl;         server_name www.*;     ssl_certificate /trailing; }
    server { listen [::]:443 ssl;    server_name ~^api\d+\.example$; ssl_certificate /regex; }
}
"""


def selected(domain, port=443):
    cand, how, notes = server._match_nginx_server(blocks_of(SELECTION_CONFIG), domain, port)
    return cand[0]["ssl_certificate"][0][0], how, notes


class BlockSelectionTests(unittest.TestCase):

    def test_duplicate_exact_first_wins_with_warning(self):
        cert, how, notes = selected("shop.test")
        self.assertEqual(cert, "/first")
        self.assertIn("exact", how)
        self.assertTrue(any("conflicting server name" in n for n in notes))

    def test_default_server_on_other_port_not_used(self):
        cert, how, _ = selected("nomatch.example", 443)
        self.assertEqual(cert, "/first")
        self.assertIn("first-block fallback", how)

    def test_default_server_used_on_its_port(self):
        cert, how, _ = selected("nomatch.example", 8443)
        self.assertEqual(cert, "/alt")
        self.assertIn("default_server", how)

    def test_precedence_leading_trailing_regex(self):
        self.assertEqual(selected("a.test")[0], "/leading")
        self.assertEqual(selected("www.example")[0], "/trailing")
        self.assertEqual(selected("api7.example")[0], "/regex")

    def test_port_80_block_never_selected_for_443(self):
        self.assertNotEqual(selected("shop.test")[0], "/plain")


def nginx_findings(config, domain="shop.test", port=443):
    return {f.check: f for f in FakeSession(config).nginx_scan(domain, port)}


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class InheritanceTests(unittest.TestCase):

    def test_http_level_certificate_is_inherited(self):
        p = get_pki()
        by = nginx_findings(f"""
            http {{
                ssl_certificate {p.fullchain};
                ssl_certificate_key {p.leaf_key};
                server {{ listen 443 ssl; server_name shop.test; }}
            }}""")
        self.assertIn(f"ssl_certificate {p.fullchain} (inherited from http{{}})",
                      by["nginx.certref"].evidence)
        self.assertEqual(by["nginx.chainfile"].status, F.PASS)
        self.assertEqual(by["srv.keymatch"].status, F.PASS)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ChainFileTests(unittest.TestCase):

    def chainfile(self, path):
        return FakeSession("")._chainfile_finding(path)

    def test_leaf_only_file_warns(self):
        f = self.chainfile(get_pki().leaf)
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("intermediate certificate(s) not sent", " ".join(f.evidence))

    def test_wrong_intermediate_file_warns(self):
        f = self.chainfile(get_pki().wrongchain)
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("position 1", " ".join(f.evidence))

    def test_full_chain_file_passes(self):
        self.assertEqual(self.chainfile(get_pki().fullchain).status, F.PASS)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class CliPortTests(unittest.TestCase):

    def test_server_nginx_selects_443_block(self):
        p = get_pki()
        app = cli.SSLDoctorCLI()
        app.server = FakeSession(f"""
            http {{
                server {{ listen 8443 ssl; server_name shop.test;
                          ssl_certificate {p.leaf}; ssl_certificate_key {p.leaf_key}; }}
                server {{ listen 443 ssl; server_name shop.test;
                          ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }}
            }}""")
        with contextlib.redirect_stdout(io.StringIO()):
            app.execute("/server nginx shop.test")
        by = {f.check: f for f in app.store.all()}
        self.assertIn("listen: 443 ssl", by["nginx.domain"].evidence)
        self.assertEqual(by["nginx.chainfile"].target, p.fullchain)


if __name__ == "__main__":
    unittest.main()
