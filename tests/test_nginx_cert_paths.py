"""Certificate path resolution with nginx's rule, and gated certificate checks.

Covers openspec change `nginx-cert-path-resolution`, capability
`nginx-cert-path-resolution`. nginx resolves a relative `ssl_certificate` /
`ssl_certificate_key` against its configuration prefix -- the directory of the
main configuration file (`ngx_cycle->conf_prefix`, nginx src/core/nginx.c and
src/event/ngx_event_openssl.c) -- not against `-p`. SSL Doctor used the value
verbatim, so a relative path was looked up in the SSH account's home directory
and reported as a broken certificate or chain.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from fixtures.nginx_host import Exe, File, HostSession, NginxHost, master_line, version

from ssl_doctor import findings as F
from ssl_doctor import nginx_discovery as nd
from ssl_doctor import server

PVM = "/opt/pvm/nginx"
START = 10_000 - 3600
CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUVb2h0RkEA1V0
-----END CERTIFICATE-----
"""
SITE = """
server {
    listen 443 ssl;
    server_name files.example.com;
    ssl_certificate ssl/fullchain.pem;
    ssl_certificate_key ssl/private.key;
}
"""


def host_with(site=SITE, main_dir="conf", files=None, prefix=f"{PVM}/", conf="conf/nginx.conf"):
    main = f"{PVM}/{main_dir}/nginx.conf".replace("//", "/")
    host = NginxHost(
        ps=master_line(812, f"{PVM}/sbin/nginx -p {prefix} -c {conf}"),
        proc={812: {"exe": f"{PVM}/sbin/nginx"}},
        executables={f"{PVM}/sbin/nginx": Exe(version_output=version(f"{PVM}/", main))},
        files={main: File("http { include site.conf; }", START - 100),
               posixpath_join(main, "site.conf"): File(site, START - 100)})
    host.files.update(files or {})
    return host


def posixpath_join(main, name):
    return main.rsplit("/", 1)[0] + "/" + name


def scan(host, settings=None):
    session = HostSession(host)
    if settings is not None:
        session.set_nginx_settings(settings)
    by = {}
    for f in session.nginx_scan("files.example.com"):
        by.setdefault(f.check, f)
    return session, by


# ------------------------------------------------------------- the resolver

class Resolver(unittest.TestCase):

    def test_relative_path_uses_the_configuration_prefix(self):
        resolved, method, problem = nd.resolve_cert_path("ssl/fullchain.pem",
                                                          f"{PVM}/conf/")
        self.assertEqual(resolved, f"{PVM}/conf/ssl/fullchain.pem")
        self.assertIn("configuration prefix", method)
        self.assertEqual(problem, "")

    def test_main_config_at_the_prefix_root(self):
        d = nd.Discovery(main_path=f"{PVM}/nginx.conf")
        resolved, _, _ = nd.resolve_cert_path("ssl/fullchain.pem", nd.conf_prefix(d))
        self.assertEqual(resolved, f"{PVM}/ssl/fullchain.pem")

    def test_prefix_and_configuration_directory_are_not_conflated(self):
        d = nd.Discovery(main_path="/etc/nginx-www/nginx.conf", prefix="/srv/www/")
        resolved, _, _ = nd.resolve_cert_path("certs/site.pem", nd.conf_prefix(d))
        self.assertEqual(resolved, "/etc/nginx-www/certs/site.pem")

    def test_absolute_path_is_unchanged(self):
        resolved, method, _ = nd.resolve_cert_path("/etc/ssl/site/fullchain.pem", f"{PVM}/conf/")
        self.assertEqual((resolved, method), ("/etc/ssl/site/fullchain.pem", "absolute path"))

    def test_variables_and_data_are_not_guessed(self):
        for value in ("/etc/ssl/$ssl_server_name.pem", "data:$cert_pem"):
            resolved, _, problem = nd.resolve_cert_path(value, f"{PVM}/conf/")
            self.assertEqual(resolved, "")
            self.assertTrue(problem)


class Provenance(unittest.TestCase):

    def test_file_and_line_of_the_directive(self):
        d = nd.discover(host_with())
        self.assertEqual(nd.directive_source(d, "ssl_certificate", "ssl/fullchain.pem"),
                         f"{PVM}/conf/site.conf:5")

    def test_inherited_key(self):
        host = host_with(site="server { listen 443 ssl; server_name files.example.com; "
                              "ssl_certificate ssl/c.pem; }")
        host.files[f"{PVM}/conf/nginx.conf"] = File(
            "http {\n    ssl_certificate_key ssl/k.key;\n    include site.conf;\n}", START - 100)
        d = nd.discover(host)
        self.assertEqual(nd.directive_source(d, "ssl_certificate_key", "ssl/k.key", inherited=True),
                         f"{PVM}/conf/nginx.conf:2 (inherited from http{{}})")


class Overrides(unittest.TestCase):

    def test_operator_main_config_when_no_master_is_visible(self):
        host = host_with()
        host.ps = ""
        d = nd.discover(host, conf_override=f"{PVM}/conf/nginx.conf")
        self.assertEqual(d.main_path, f"{PVM}/conf/nginx.conf")
        self.assertIn("operator-specified", d.main_how)
        self.assertEqual(d.level, nd.LEVEL_CANDIDATE)

    def test_override_equal_to_the_runtime_config_keeps_the_runtime_level(self):
        d = nd.discover(host_with(), conf_override=f"{PVM}/conf/nginx.conf")
        self.assertEqual(d.level, nd.LEVEL_VERIFIED)

    def test_override_different_from_the_runtime_config_is_a_candidate(self):
        host = host_with()
        host.files["/srv/other/nginx.conf"] = File("http {}", START - 100)
        d = nd.discover(host, conf_override="/srv/other/nginx.conf")
        self.assertEqual(d.main_path, "/srv/other/nginx.conf")
        self.assertEqual(d.level, nd.LEVEL_CANDIDATE)

    def test_prefix_is_recorded(self):
        self.assertEqual(nd.discover(host_with()).prefix, f"{PVM}/")
        self.assertEqual(nd.discover(host_with(), prefix_override="/srv/x/").prefix, "/srv/x/")


# ---------------------------------------------- path resolution in nginx_scan

class PathResolutionFinding(unittest.TestCase):

    def test_regression_relative_paths_resolve_under_the_configuration_prefix(self):
        host = host_with(files={f"{PVM}/conf/ssl/fullchain.pem": File(CERT_PEM),
                                f"{PVM}/conf/ssl/private.key": File("KEY")})
        _, by = scan(host)
        pr = by["nginx.path_resolution"]
        text = "\n".join(pr.evidence)
        self.assertEqual(pr.status, F.PASS)
        self.assertIn("ssl/fullchain.pem", text)
        self.assertIn(f"{PVM}/conf/ssl/fullchain.pem", text)
        self.assertIn(f"{PVM}/conf/ssl/private.key", text)
        self.assertIn("configuration prefix", text)
        self.assertIn(f"{PVM}/conf/site.conf:5", text)

    def test_missing_certificate_is_fail_and_validation_not_tested(self):
        host = host_with(files={f"{PVM}/conf/ssl/private.key": File("KEY")})
        _, by = scan(host)
        self.assertEqual(by["nginx.path_resolution"].status, F.FAIL)
        self.assertIn("missing", " ".join(by["nginx.path_resolution"].evidence))
        self.assertEqual(by["nginx.chainfile"].status, F.NOT_TESTED)
        self.assertIn("could not be opened", " ".join(by["nginx.chainfile"].evidence))
        self.assertEqual(by["srv.cert"].status, F.NOT_TESTED)

    def test_missing_key(self):
        host = host_with(files={f"{PVM}/conf/ssl/fullchain.pem": File(CERT_PEM)})
        _, by = scan(host)
        pr = by["nginx.path_resolution"]
        self.assertEqual(pr.status, F.FAIL)
        self.assertIn(f"{PVM}/conf/ssl/private.key", " ".join(pr.evidence))

    def test_root_only_key_is_not_a_fault(self):
        host = host_with(files={f"{PVM}/conf/ssl/fullchain.pem": File(CERT_PEM),
                                f"{PVM}/conf/ssl/private.key": File("KEY", readable=False)})
        _, by = scan(host)
        self.assertEqual(by["nginx.path_resolution"].status, F.PASS)
        self.assertIn("not readable by this account", " ".join(by["nginx.path_resolution"].evidence))
        self.assertEqual(by["srv.keymatch"].status, F.NOT_TESTED)

    def test_unreadable_certificate_is_not_tested(self):
        host = host_with(files={f"{PVM}/conf/ssl/fullchain.pem": File(CERT_PEM, readable=False),
                                f"{PVM}/conf/ssl/private.key": File("KEY")})
        _, by = scan(host)
        self.assertEqual(by["nginx.path_resolution"].status, F.NOT_TESTED)
        self.assertEqual(by["nginx.chainfile"].status, F.NOT_TESTED)

    def test_prefix_relative_file_is_pointed_out_but_not_used(self):
        host = host_with(files={f"{PVM}/ssl/fullchain.pem": File(CERT_PEM),
                                f"{PVM}/ssl/private.key": File("KEY")})
        _, by = scan(host)
        text = " ".join(by["nginx.path_resolution"].evidence)
        self.assertIn(f"{PVM}/ssl/fullchain.pem exists", text)
        self.assertIn("would not open", text)
        self.assertEqual(by["nginx.chainfile"].status, F.NOT_TESTED)

    def test_invalid_pem_is_distinct_from_an_incomplete_chain(self):
        host = host_with(files={f"{PVM}/conf/ssl/fullchain.pem": File("not a certificate"),
                                f"{PVM}/conf/ssl/private.key": File("KEY")})
        _, by = scan(host)
        self.assertEqual(by["nginx.chainfile"].status, F.FAIL)
        self.assertIn("no PEM certificate in the file", " ".join(by["nginx.chainfile"].evidence))

    def test_variable_certificate_is_not_tested(self):
        site = SITE.replace("ssl/fullchain.pem", "/etc/ssl/$ssl_server_name.pem")
        _, by = scan(host_with(site=site))
        self.assertEqual(by["nginx.path_resolution"].status, F.NOT_TESTED)
        self.assertIn("variable", " ".join(by["nginx.path_resolution"].evidence))

    def test_unconfirmed_configuration_downgrades_missing_to_warning(self):
        host = host_with()
        host.ps = ""                                  # nothing running: candidate config
        host.files["/etc/nginx/nginx.conf"] = host.files.pop(f"{PVM}/conf/nginx.conf")
        host.files["/etc/nginx/site.conf"] = host.files.pop(f"{PVM}/conf/site.conf")
        _, by = scan(host)
        self.assertEqual(by["nginx.path_resolution"].status, F.WARNING)
        self.assertTrue(by["nginx.path_resolution"].uncertainty)

    def test_failed_resolution_suggests_the_manual_setting(self):
        _, by = scan(host_with())
        self.assertIn("/server config set", by["nginx.path_resolution"].recommendation)


class ManualSettings(unittest.TestCase):

    def test_manual_paths_work_when_discovery_fails(self):
        host = NginxHost(ps=None, files={"/srv/tls/site.pem": File(CERT_PEM),
                                         "/srv/tls/site.key": File("KEY")})
        settings = server.NginxSettings(mode="manual", cert="/srv/tls/site.pem",
                                        key="/srv/tls/site.key", origin="saved for files")
        _, by = scan(host, settings)
        pr = by["nginx.path_resolution"]
        self.assertEqual(pr.status, F.PASS)
        self.assertIn("saved manual setting", " ".join(pr.evidence))
        self.assertIn("nginx.chainfile", by)

    def test_manual_and_automatic_disagree(self):
        host = host_with(files={f"{PVM}/conf/ssl/fullchain.pem": File(CERT_PEM),
                                f"{PVM}/conf/ssl/private.key": File("KEY"),
                                "/etc/ssl/old.pem": File(CERT_PEM)})
        settings = server.NginxSettings(mode="manual", cert="/etc/ssl/old.pem",
                                        origin="saved for files")
        session, by = scan(host, settings)
        pr = by["nginx.path_resolution"]
        self.assertEqual(pr.status, F.WARNING)
        self.assertIn("automatic discovery resolves", " ".join(pr.evidence))
        self.assertEqual(session.nginx_cert_path, "/etc/ssl/old.pem")    # never substituted

    def test_failing_manual_path_is_reported_and_kept(self):
        settings = server.NginxSettings(mode="manual", cert="/etc/ssl/gone.pem",
                                        origin="saved for files")
        session, by = scan(host_with(), settings)
        self.assertNotEqual(by["nginx.path_resolution"].status, F.PASS)
        self.assertIn("/server config", by["nginx.path_resolution"].recommendation)
        self.assertEqual(session.nginx_settings.cert, "/etc/ssl/gone.pem")


# ----------------------------------------------- the real file-state script

class FileStatesScript(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="certpaths")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.probe = server._SshNginxProbe(server.LocalSession())

    def test_states(self):
        f = os.path.join(self.root, "c.pem")
        open(f, "w").close()
        d = os.path.join(self.root, "dir.pem")
        os.mkdir(d)
        states = self.probe.file_states([f, d, os.path.join(self.root, "gone.pem"),
                                         "/etc/$(id).pem"])
        self.assertEqual(states[f], "readable")
        self.assertEqual(states[d], "notfile")
        self.assertEqual(states[os.path.join(self.root, "gone.pem")], "missing")
        self.assertEqual(states["/etc/$(id).pem"], "unsupported")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads everything")
    def test_denied_and_unreachable(self):
        f = os.path.join(self.root, "k.key")
        open(f, "w").close()
        os.chmod(f, 0)
        locked = os.path.join(self.root, "locked")
        os.mkdir(locked)
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o700)
        states = self.probe.file_states([f, os.path.join(locked, "x.pem")])
        self.assertEqual(states[f], "denied")
        self.assertEqual(states[os.path.join(locked, "x.pem")], "unreachable")


class DirectCertCommand(unittest.TestCase):

    def test_missing_file_is_not_tested_not_fail(self):
        session = HostSession(NginxHost(ps=""))
        [finding] = session.scan_cert("/etc/ssl/missing.pem")
        self.assertEqual(finding.status, F.NOT_TESTED)
        self.assertIn("not found", " ".join(finding.evidence))

    def test_unreadable_key_makes_pairing_not_tested(self):
        host = NginxHost(ps="", files={"/etc/ssl/c.pem": File(CERT_PEM),
                                       "/etc/ssl/k.key": File("KEY", readable=False)})
        session = HostSession(host)
        found = {f.check: f for f in session.scan_cert("/etc/ssl/c.pem", "/etc/ssl/k.key")}
        self.assertEqual(found["srv.keymatch"].status, F.NOT_TESTED)


if __name__ == "__main__":
    unittest.main()


class SessionSettings(unittest.TestCase):

    def test_overrides_reach_discovery_and_changes_clear_the_cache(self):
        host = host_with()
        host.ps = ""                                         # nothing visible
        session = HostSession(host)
        first = session.discover_nginx()
        self.assertIn("bounded search", first.main_how)        # found by the fallback
        session.set_nginx_settings(server.NginxSettings(conf=f"{PVM}/conf/nginx.conf",
                                                        prefix=f"{PVM}/"))
        second = session.discover_nginx()
        self.assertIsNot(second, first)
        self.assertEqual(second.main_path, f"{PVM}/conf/nginx.conf")
        self.assertIn("operator-specified", second.main_how)
        self.assertEqual(second.prefix, f"{PVM}/")
