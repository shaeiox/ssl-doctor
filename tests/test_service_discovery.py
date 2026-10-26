"""tls-service-discovery (P6): who serves the TLS port, the native
configuration test, Apache/HAProxy certificate paths, reload state, renewal
tooling - and that none of it ever changes the server."""

import re
import unittest
from unittest import mock

from fixtures.nginx_host import (Exe, File, HostSession, NginxHost, master_line, version,
                                 worker_line)

from ssl_doctor import server, services
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose

PVM = "/opt/pvm/nginx"
NGINX = f"{PVM}/sbin/nginx"
NOW = 10_000
START = NOW - 3600
CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
SITE = """
server {
    listen 443 ssl;
    server_name files.example.com;
    ssl_certificate ssl/fullchain.pem;
    ssl_certificate_key ssl/private.key;
}
"""
FORBIDDEN = re.compile(r"-s\s+(reload|stop|quit|reopen)|\breload\b|\brestart\b|"
                       r"\bgraceful\b|\bkill\b|systemctl\s+(start|stop|restart|reload)|"
                       r"\bsudo\b")


def nginx_host(cert_mtime=START - 100, exe=None, extra_ps="", worker_etimes=100):
    main = f"{PVM}/conf/nginx.conf"
    return NginxHost(
        ps=master_line(812, f"{NGINX} -p {PVM}/ -c conf/nginx.conf", etimes=3600) + "\n"
        + worker_line(813, 812, etimes=worker_etimes) + ("\n" + extra_ps if extra_ps else ""),
        now=NOW,
        proc={812: {"exe": NGINX}},
        executables={NGINX: exe or Exe(version_output=version(f"{PVM}/", main))},
        files={main: File("http { include site.conf; }", START - 100),
               f"{PVM}/conf/site.conf": File(SITE, START - 100),
               f"{PVM}/conf/ssl/fullchain.pem": File(CERT_PEM, cert_mtime),
               f"{PVM}/conf/ssl/private.key": File("KEY", START - 100, readable=False)},
        sockets='LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))')


def service_scan(host):
    session = HostSession(host)
    session.nginx_scan("files.example.com")
    items = session.service_scan("files.example.com", 443)
    out = {}
    for f in items:
        out.setdefault(f.check, f)
    return session, out, items


class Listener(unittest.TestCase):

    def finding(self, sockets, **kw):
        host = nginx_host()
        host.sockets = sockets
        return service_scan(host)[1]["srv.service"]

    def test_nginx_owns_the_port(self):
        f = self.finding('LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))')
        self.assertEqual(f.status, F.PASS)
        self.assertIn("nginx (pid 812) listens on :443", f.evidence[0])

    def test_unsupported_terminator(self):
        host = nginx_host()
        host.sockets = 'LISTEN 0 4096 *:443 *:* users:(("caddy",pid=77,fd=9))'
        _s, b, items = service_scan(host)
        f = b["srv.service"]
        self.assertEqual((f.status, f.observation), (F.WARNING, "listener-unsupported"))
        self.assertIn("served by caddy, which SSL Doctor does not analyse", f.evidence[0])
        causes = [c.summary for c in diagnose(items).causes]
        self.assertTrue(any("not served by the analysed" in c for c in causes))
        self.assertFalse(any("nginx server block" in c for c in causes))

    def test_owner_not_visible(self):
        f = self.finding("LISTEN 0 511 0.0.0.0:443 0.0.0.0:*")
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "permission-denied"))
        self.assertIn("listener owner is not visible to this account", f.evidence[0])
        self.assertTrue(any("nginx master pid 812" in e for e in f.evidence))

    def test_nothing_listens(self):
        f = self.finding("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")
        self.assertEqual((f.status, f.observation), (F.WARNING, "no-local-listener"))
        self.assertIn("no local listener on :443", f.evidence[0])

    def test_no_socket_tool(self):
        self.assertEqual(self.finding(None).status, F.NOT_TESTED)

    def test_netstat_format(self):
        state, owners = services.parse_listeners(
            "tcp 0 0 0.0.0.0:443 0.0.0.0:* LISTEN 812/nginx: master pro", 443)
        self.assertEqual((state, owners), (services.LISTENER_OWNED, [("nginx", 812)]))


NONROOT_NGINX_T = (
    'nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" '
    "failed (13: Permission denied)\n"
    f"nginx: the configuration file {PVM}/conf/nginx.conf syntax is ok\n"
    '2026/10/26 10:00:00 [emerg] 4242#4242: open() "/run/nginx.pid" failed '
    "(13: Permission denied)\n"
    f"nginx: configuration file {PVM}/conf/nginx.conf test failed")


class ConfigTest(unittest.TestCase):

    def run_test(self, result, exe=None):
        host = nginx_host(exe=exe)
        if result is not None:
            host.config_tests[NGINX] = result
        session, b, items = service_scan(host)
        return b["srv.configtest"], items, host

    def test_failing_test_keeps_status_and_message(self):
        f, items, host = self.run_test(
            (1, 'nginx: [emerg] cannot load certificate "/x.pem": BIO_new_file() failed\n'
                f"nginx: configuration file {PVM}/conf/nginx.conf test failed"))
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("exit status 1", f.evidence[0])
        self.assertIn("cannot load certificate", " ".join(f.evidence))
        self.assertIn(("config_test", (NGINX, "-p", f"{PVM}/", "-c", "conf/nginx.conf", "-t")),
                      host.calls)
        self.assertTrue(any(c.certainty == "confirmed" and "configuration test fails"
                            in c.summary for c in diagnose(items).causes))

    def test_passing_test(self):
        f, _items, _h = self.run_test((0, "nginx: configuration file test is successful"))
        self.assertEqual(f.status, F.PASS)
        self.assertIn("exit status 0", f.evidence[0])

    def test_permission_only_failure_is_not_tested(self):
        # nginx always ends a failed test with "configuration file ... test failed"
        f, _items, _h = self.run_test(
            (1, 'nginx: [alert] could not open error log file: open() '
                '"/var/log/nginx/error.log" failed (13: Permission denied)\n'
                'nginx: [emerg] open() "/run/nginx.pid" failed (13: Permission denied)\n'
                f"nginx: configuration file {PVM}/conf/nginx.conf test failed"))
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "permission-denied"))
        self.assertIn("configuration test needs read access", " ".join(f.evidence))

    def test_regression_b_unprivileged_nginx_t(self):
        # captured shape of `nginx -t` run by a non-root account (audit B)
        f, items, _h = self.run_test((1, NONROOT_NGINX_T))
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "permission-denied"))
        text = " ".join(f.evidence)
        self.assertIn("syntax is ok", text)
        self.assertIn("/run/nginx.pid", text)
        d = diagnose(items)
        self.assertFalse([c for c in d.causes if "configuration test" in c.summary])
        self.assertNotIn("srv.configtest", [u.check for u in d.unexplained])

    def test_unreadable_certificate_key_is_not_tested(self):
        f, _items, _h = self.run_test(
            (1, 'nginx: [emerg] cannot load certificate key "/etc/ssl/private/site.key": '
                "BIO_new_file() failed (SSL: error:8000000D:system library::Permission "
                "denied:calling fopen(/etc/ssl/private/site.key, r) error:10080002:BIO "
                "routines::system lib)\n"
                f"nginx: configuration file {PVM}/conf/nginx.conf test failed"))
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "permission-denied"))
        self.assertIn("/etc/ssl/private/site.key", " ".join(f.evidence))

    def test_genuine_error_next_to_a_permission_error_fails(self):
        f, items, _h = self.run_test(
            (1, 'nginx: [alert] could not open error log file: open() '
                '"/var/log/nginx/error.log" failed (13: Permission denied)\n'
                'nginx: [emerg] unknown directive "ssl_certificat" in '
                f"{PVM}/conf/site.conf:12\n"
                f"nginx: configuration file {PVM}/conf/nginx.conf test failed"))
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("unknown directive", " ".join(f.evidence))
        self.assertTrue(any(c.certainty == "confirmed" and "configuration test fails"
                            in c.summary for c in diagnose(items).causes))

    def test_nonzero_exit_without_error_lines_is_not_tested(self):
        f, _items, _h = self.run_test((1, "nginx: something unexpected happened"))
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "command-failed"))

    def test_untrusted_binary_is_not_run(self):
        f, _items, host = self.run_test((0, "ok"), exe=Exe(mode=0o777))
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("not trusted", " ".join(f.evidence))
        self.assertFalse([c for c in host.calls if c[0] == "config_test"])


class ConfigTestOutputs(unittest.TestCase):
    """classify_config_test on captured Apache and HAProxy output."""

    def test_apache_syntax_error(self):
        verdict, lines = services.classify_config_test(
            1, "AH00526: Syntax error on line 12 of /etc/apache2/sites-enabled/site.conf:\n"
               "Invalid command 'SSLCertificatFile', perhaps misspelled\n"
               "Action '-t' failed.")
        self.assertEqual(verdict, "fail")
        self.assertIn("AH00526", " ".join(lines))

    def test_apache_syntax_ok(self):
        self.assertEqual(services.classify_config_test(0, "Syntax OK")[0], "pass")

    def test_haproxy_alert(self):
        verdict, lines = services.classify_config_test(
            1, "[NOTICE]   (1234) : haproxy version is 2.8.5\n"
               "[ALERT]    (1234) : config : parsing [/etc/haproxy/haproxy.cfg:40] : "
               "'bind *:443' : unable to load SSL certificate file '/etc/ssl/x.pem'.\n"
               "[ALERT]    (1234) : config : Fatal errors found in configuration.")
        self.assertEqual(verdict, "fail")

    def test_haproxy_permission_only(self):
        verdict, _ = services.classify_config_test(
            1, "[ALERT]    (1234) : config : parsing [/etc/haproxy/haproxy.cfg:40] : "
               "'bind *:443' : unable to stat SSL certificate from file "
               "'/etc/ssl/private/x.pem' : Permission denied.\n"
               "[ALERT]    (1234) : config : Fatal errors found in configuration.")
        # the summary ALERT carries no access error itself
        self.assertEqual(verdict, "permission")


class ApacheAndHaproxy(unittest.TestCase):

    def test_apache_vhost_from_a_custom_configuration(self):
        host = nginx_host()
        host.ps += "\n" + "   900      1 root 3600 /usr/sbin/httpd -f /opt/web/conf/httpd.conf"
        host.executables["/usr/sbin/httpd"] = Exe()
        host.config_tests["/usr/sbin/httpd"] = (0, "Syntax OK")
        host.files.update({
            "/opt/web/conf/httpd.conf": File('ServerRoot "/opt/web"\n'
                                             "IncludeOptional conf.d/*.conf\n"),
            "/opt/web/conf.d/site.conf": File(
                "<VirtualHost *:443>\n  ServerName files.example.com\n"
                "  SSLCertificateFile /opt/web/ssl/site.crt\n"
                "  SSLCertificateKeyFile /opt/web/ssl/site.key\n</VirtualHost>\n"),
            "/opt/web/ssl/site.crt": File(CERT_PEM)})
        _s, _b, items = service_scan(host)
        apache = [f for f in items if f.check == "srv.tlsconf"]
        self.assertEqual(len(apache), 1)
        text = " ".join(apache[0].evidence)
        self.assertIn("[/opt/web/conf.d/site.conf:1]", text)
        self.assertIn("certificate: /opt/web/ssl/site.crt (exists and is readable)", text)
        self.assertIn("key: /opt/web/ssl/site.key (missing", text)
        self.assertEqual(apache[0].status, F.WARNING)
        tests = [f for f in items if f.check == "srv.configtest"]
        self.assertIn("/usr/sbin/httpd -t -f /opt/web/conf/httpd.conf: exit status 0",
                      [f.evidence[0] for f in tests])
        self.assertTrue([f for f in items if f.check == "srv.cert"
                         and f.target == "/opt/web/ssl/site.crt"])

    def test_haproxy_crt_with_crt_base(self):
        host = nginx_host()
        host.ps += "\n" + ("   950      1 root 3600 /usr/sbin/haproxy -Ws -f "
                           "/etc/haproxy/haproxy.cfg -p /run/haproxy.pid")
        host.executables["/usr/sbin/haproxy"] = Exe()
        host.config_tests["/usr/sbin/haproxy"] = (0, "Configuration file is valid")
        host.files.update({
            "/etc/haproxy/haproxy.cfg": File("global\n    crt-base /etc/haproxy/certs\n"
                                             "frontend fe\n    bind :443 ssl crt site.pem\n"),
            "/etc/haproxy/certs/site.pem": File(CERT_PEM)})
        _s, _b, items = service_scan(host)
        [conf] = [f for f in items if f.check == "srv.tlsconf"]
        self.assertIn("certificate: /etc/haproxy/certs/site.pem (exists and is readable)",
                      " ".join(conf.evidence))
        self.assertIn("/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg: exit status 0",
                      [f.evidence[0] for f in items if f.check == "srv.configtest"])

    def test_untrusted_haproxy_binary_is_not_run(self):
        host = nginx_host()
        host.ps += "\n   950      1 root 3600 /usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg"
        host.executables["/usr/sbin/haproxy"] = Exe(mode=0o775)
        service_scan(host)
        self.assertFalse([c for c in host.calls
                          if c[0] == "config_test" and c[1][0] == "/usr/sbin/haproxy"])


class Reload(unittest.TestCase):

    def test_certificate_newer_than_the_workers(self):
        _s, b, items = service_scan(nginx_host(cert_mtime=NOW - 50, worker_etimes=100))
        f = b["srv.reload"]
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("a reload is needed for nginx to serve it", " ".join(f.evidence))

    def test_reloaded_after_renewal(self):
        _s, b, _items = service_scan(nginx_host(cert_mtime=NOW - 500, worker_etimes=100))
        self.assertEqual(b["srv.reload"].status, F.PASS)

    def test_journal_errors(self):
        host = nginx_host()
        session = HostSession(host)
        host.journals["nginx.service"] = [
            'Oct 26 nginx[812]: nginx: [emerg] cannot load certificate "/x.pem"',
            "Oct 26 systemd[1]: nginx.service: Control process exited",
            "Oct 26 systemd[1]: Reload failed for A high performance web server."]
        f = session._reload_finding(host, "nginx", NOW, [100],
                                    [f"{PVM}/conf/ssl/fullchain.pem"], "nginx.service")
        self.assertEqual(f.status, F.WARNING)
        text = " ".join(f.evidence)
        self.assertIn("cannot load certificate", text)
        self.assertIn("Reload failed", text)

    def test_times_unknown(self):
        host = nginx_host()
        f = HostSession(host)._reload_finding(host, "nginx", None, [],
                                              [f"{PVM}/conf/ssl/fullchain.pem"], "")
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("reload state unknown", f.evidence[0])


class Renewal(unittest.TestCase):

    LIVE = "/etc/letsencrypt/live/files.example.com/fullchain.pem"

    def finding(self, output, paths=None):
        host = NginxHost(renewal_output=output, files={self.LIVE: File(CERT_PEM)})
        return HostSession(host)._renewal_finding(host, paths or [self.LIVE])

    def test_certbot_manages_the_certificate(self):
        f = self.finding("@@SSLDOCTOR tools\n/usr/bin/certbot\n@@SSLDOCTOR certbot\n"
                         "/etc/letsencrypt/renewal/files.example.com.conf:fullchain = "
                         f"{self.LIVE}\n@@SSLDOCTOR timers\n"
                         "Mon 2026-10-27 00:00:00 UTC 10h left certbot.timer certbot.service\n")
        self.assertEqual(f.status, F.PASS)
        self.assertIn("managed by certbot", f.evidence[0])

    def test_installed_but_not_linked(self):
        f = self.finding("@@SSLDOCTOR tools\n/usr/bin/certbot\n@@SSLDOCTOR certbot\n")
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("certbot installed, but no renewal configuration names", f.evidence[0])

    def test_nothing_found_does_not_claim_manual_renewal(self):
        f = self.finding("@@SSLDOCTOR tools\n@@SSLDOCTOR certbot\n")
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("no renewal tooling found", f.evidence[0])
        self.assertNotIn("manual", " ".join(f.evidence).lower())

    LINKED = ("@@SSLDOCTOR tools\n/usr/bin/certbot\n@@SSLDOCTOR certbot\n"
              "/etc/letsencrypt/renewal/files.example.com.conf:fullchain = "
              "/etc/letsencrypt/live/files.example.com/fullchain.pem\n")

    @staticmethod
    def visibility(hidden=()):
        sources = ["timers", "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
                   "/var/spool/cron/crontabs", "/var/spool/cron", "/root/.acme.sh",
                   "/home/audit/.acme.sh", "/etc/letsencrypt/renewal"]
        return "@@SSLDOCTOR visibility\n" + "".join(
            f"{src} {'no' if src in hidden else 'yes'}\n" for src in sources)

    def test_regression_g_hidden_root_crontab_is_not_tested(self):
        f = self.finding(self.visibility(hidden=("/var/spool/cron/crontabs",))
                         + self.LINKED + "@@SSLDOCTOR timers\n@@SSLDOCTOR cron\n")
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "permission-denied"))
        self.assertIn("/var/spool/cron/crontabs", " ".join(f.evidence))
        self.assertFalse([c for c in diagnose([f]).causes if "Renewal" in c.summary])

    def test_every_source_visible_and_no_schedule_warns(self):
        f = self.finding(self.visibility() + self.LINKED + "@@SSLDOCTOR timers\n"
                         "@@SSLDOCTOR cron\n")
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("no systemd timer or cron entry for it was found", " ".join(f.evidence))

    def test_another_tools_schedule_does_not_count(self):
        f = self.finding(self.visibility() + self.LINKED + "@@SSLDOCTOR timers\n"
                         "@@SSLDOCTOR cron\nlego: /etc/cron.d/lego-other-site\n")
        self.assertNotEqual(f.status, F.PASS)
        self.assertIn("certbot", " ".join(f.evidence))

    def test_root_crontab_naming_the_tool_counts(self):
        f = self.finding(self.visibility() + self.LINKED + "@@SSLDOCTOR timers\n"
                         "@@SSLDOCTOR cron\ncertbot: /var/spool/cron/crontabs/root\n")
        self.assertEqual(f.status, F.PASS)

    def test_hidden_acme_home_is_named_when_nothing_is_found(self):
        f = self.finding(self.visibility(hidden=("/root/.acme.sh",))
                         + "@@SSLDOCTOR tools\n@@SSLDOCTOR certbot\n")
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("/root/.acme.sh could not be inspected", " ".join(f.evidence))

    def test_real_probe_reports_every_source(self):
        out = server.LocalSession().nginx_probe().renewal()
        section = out.split("@@SSLDOCTOR visibility\n", 1)[1].split("@@SSLDOCTOR", 1)[0]
        names = [line.rsplit(" ", 1)[0] for line in section.splitlines() if line.strip()]
        for source in ("timers", "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
                       "/var/spool/cron/crontabs", "/var/spool/cron", "/root/.acme.sh",
                       "/etc/letsencrypt/renewal"):
            self.assertIn(source, names)
        self.assertTrue(all(line.endswith((" yes", " no")) for line in section.splitlines()
                            if line.strip()), section)


class NeverAStateChange(unittest.TestCase):

    def test_command_audit_over_a_full_server_scan(self):
        host = nginx_host(cert_mtime=NOW - 50)
        host.config_tests[NGINX] = (0, "ok")
        session = HostSession(host)
        session.nginx_scan("files.example.com")
        session.service_scan("files.example.com", 443)
        session.compare_configured_vs_presented("ab" * 32)
        executed = list(session.commands) + [" ".join(c[1]) for c in host.calls
                                             if c[0] == "config_test"]
        self.assertTrue(executed)
        for command in executed:
            self.assertIsNone(FORBIDDEN.search(command), command)
        tests = [c for c in host.calls if c[0] == "config_test"]
        self.assertTrue(all(c[1][-1] in ("-t", "-c") or "-c" in c[1] for c in tests))

    def test_real_probe_commands_are_read_only(self):
        session = server.LocalSession(tls_host="files.example.com")
        commands = []
        real = session.run
        with mock.patch.object(session, "run",
                               side_effect=lambda c: commands.append(c) or real(c)):
            session.nginx_scan("files.example.com")
            session.service_scan("files.example.com", 443)
        self.assertTrue(commands)
        for command in commands:
            self.assertIsNone(FORBIDDEN.search(command), command)


if __name__ == "__main__":
    unittest.main()
