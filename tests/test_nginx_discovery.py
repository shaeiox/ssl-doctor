"""Nginx configuration discovery: runtime first, include graph, evidence levels.

Regression cover for openspec change `fix-nginx-config-discovery`: SSL Doctor
analysed whatever `nginx -T` from PATH or a fixed `/etc/nginx` file list
returned, so a custom installation (`/opt/pvm/nginx/sbin/nginx -p … -c …`)
produced "no server block listens on port 443" and then a diagnosis of
"several server blocks claim this domain" while HTTPS worked.
"""

from __future__ import annotations

import unittest

from fixtures.nginx_host import (Exe, File, HostSession, NginxHost, master_line,
                                 version, worker_line)

from ssl_doctor import analyze, findings as F
from ssl_doctor import nginx_discovery as nd

PVM = "/opt/pvm/nginx"
TLS_SITE = """
server {
    listen 443 ssl;
    server_name files.example.com;
    ssl_certificate /opt/pvm/nginx/ssl/files.crt;
    ssl_certificate_key /opt/pvm/nginx/ssl/files.key;
    ssl_protocols TLSv1.2 TLSv1.3;
}
"""
PVM_MAIN = """
worker_processes auto;
events { worker_connections 1024; }
http {
    include mime.types;
    include ../conf.d/*.conf;
}
"""
ETC_DEFAULT = """
http {
    server { listen 80 default_server; server_name _; root /var/www/html; }
}
"""
START = 10_000 - 3600          # host.now - etimes


def custom_host(**over):
    """A custom installation under /opt/pvm/nginx, plus an unrelated /etc/nginx."""
    host = NginxHost(
        ps="\n".join([
            master_line(812, f"{PVM}/sbin/nginx -p {PVM}/ -c conf/nginx.conf"),
            worker_line(813, 812), worker_line(814, 812),
            "  900      1 root 50 /usr/sbin/sshd -D",
        ]),
        proc={812: {"exe": f"{PVM}/sbin/nginx",
                    "cgroup": "0::/system.slice/pvm-nginx.service"}},
        units={"pvm-nginx.service":
               "Id=pvm-nginx.service\nMainPID=812\n"
               f"ExecStart={{ path={PVM}/sbin/nginx ; argv[]={PVM}/sbin/nginx -p {PVM}/ "
               "-c conf/nginx.conf ; ignore_errors=no }\n"
               "FragmentPath=/etc/systemd/system/pvm-nginx.service"},
        executables={f"{PVM}/sbin/nginx": Exe(
            version_output=version(f"{PVM}/", f"{PVM}/conf/nginx.conf"))},
        files={
            f"{PVM}/conf/nginx.conf": File(PVM_MAIN, mtime=START - 500),
            f"{PVM}/conf/mime.types": File("types { text/html html; }", mtime=START - 900),
            f"{PVM}/conf.d/files.conf": File(TLS_SITE, mtime=START - 400),
            f"{PVM}/ssl/files.crt": File("not a real certificate", mtime=START - 400),
            "/etc/nginx/nginx.conf": File(ETC_DEFAULT, mtime=START - 9000),
        })
    for key, value in over.items():
        setattr(host, key, value)
    return host


def scan(host, domain="files.example.com"):
    session = HostSession(host)
    found = session.nginx_scan(domain)
    return session, {f.check: f for f in found}


def https_ok():
    return [F.Finding("tls.handshake", "TLS handshake", F.PASS, F.SCOPE_REMOTE_NET,
                      ["TLSv1.3 negotiated"]),
            F.Finding("tls.verify", "Validation", F.PASS, F.SCOPE_REMOTE_NET, ["ok"]),
            F.Finding("tls.hostname", "Hostname", F.PASS, F.SCOPE_REMOTE_NET, ["ok"]),
            F.Finding("tls.chain", "Chain", F.PASS, F.SCOPE_REMOTE_NET, ["complete"]),
            F.Finding("https.status", "HTTPS", F.PASS, F.SCOPE_REMOTE_NET, ["HTTP 200"])]


# ----------------------------------------------------------------- regression

class Regression(unittest.TestCase):
    """The field report: custom install, unrelated /etc/nginx, HTTPS fine."""

    def test_no_false_no_tls_vhost_and_no_invented_conflict(self):
        host = custom_host(executables={})     # executable unknown: worst case
        host.proc = {812: {"denied": ["/proc/812/exe: Permission denied"]}}
        host.ps = "\n".join([master_line(812, "nginx -p /opt/pvm/nginx/ -c conf/nginx.conf")])
        _, by = scan(host)
        self.assertNotEqual(by["nginx.domain"].status, F.WARNING)
        diagnosis = analyze.diagnose(https_ok() + list(by.values()), {})
        self.assertFalse(any("Several nginx server blocks" in c.summary
                             for c in diagnosis.causes))


# ------------------------------------------------------------- pure functions

class ParseMasters(unittest.TestCase):

    def test_custom_master_with_prefix_and_conf(self):
        [m] = nd.parse_masters("\n".join([
            master_line(812, f"{PVM}/sbin/nginx -p {PVM}/ -c conf/nginx.conf"),
            worker_line(813, 812), worker_line(814, 812)]))
        self.assertEqual((m.pid, m.exe, m.prefix, m.conf, m.workers),
                         (812, f"{PVM}/sbin/nginx", f"{PVM}/", "conf/nginx.conf", 2))

    def test_debian_master_with_globals(self):
        [m] = nd.parse_masters(master_line(
            700, '/usr/sbin/nginx -g "daemon on; master_process on;"'))
        self.assertEqual((m.exe, m.globals, m.conf), ("/usr/sbin/nginx",
                                                      "daemon on; master_process on;", ""))

    def test_garbage_and_other_processes_are_ignored(self):
        self.assertEqual(nd.parse_masters("garbage\n  1 0 root 9 /sbin/init\n"), [])

    def test_several_masters(self):
        masters = nd.parse_masters("\n".join([master_line(1, "/a/nginx"),
                                              master_line(2, "/b/nginx -c /b/x.conf")]))
        self.assertEqual([m.pid for m in masters], [1, 2])


class BuildInfoAndSystemd(unittest.TestCase):

    def test_build_info(self):
        info = nd.parse_build_info(version("/usr/share/nginx", "/etc/nginx/nginx.conf"))
        self.assertEqual(info, {"version": "nginx/1.24.0", "prefix": "/usr/share/nginx",
                                "conf_path": "/etc/nginx/nginx.conf"})
        self.assertEqual(nd.parse_build_info("nginx version: nginx/1.25.3\n"),
                         {"version": "nginx/1.25.3"})

    def test_systemd_exec_start_argv(self):
        props = nd.parse_systemd_show(
            "Id=nginx.service\nMainPID=700\nExecStart={ path=/usr/sbin/nginx ; "
            "argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no }\n")
        self.assertEqual(props["MainPID"], "700")
        self.assertTrue(props["ExecStartArgv"].startswith("/usr/sbin/nginx -g daemon"))

    def test_unit_from_cgroup(self):
        self.assertEqual(nd.unit_from_cgroup("0::/system.slice/pvm-nginx.service\n"),
                         "pvm-nginx.service")
        self.assertEqual(nd.unit_from_cgroup("0::/user.slice/session-3.scope"), "")


class PathSemantics(unittest.TestCase):

    def test_relative_conf_with_prefix_beats_build_default(self):
        path, how, _ = nd.resolve_main_config(f"{PVM}/", "conf/nginx.conf",
                                              {"conf_path": "/etc/nginx/nginx.conf"})
        self.assertEqual(path, f"{PVM}/conf/nginx.conf")
        self.assertIn("-c", how)

    def test_build_default_without_c(self):
        path, how, _ = nd.resolve_main_config("", "", {
            "prefix": "/usr/local/nginx/", "conf_path": "/usr/local/nginx/conf/nginx.conf"})
        self.assertEqual(path, "/usr/local/nginx/conf/nginx.conf")
        self.assertIn("build default", how)

    def test_relative_prefix_needs_the_cwd(self):
        path, _, limitation = nd.resolve_main_config("nginx/", "conf/nginx.conf", {})
        self.assertEqual(path, "")
        self.assertIn("working directory", limitation)
        path, _, _ = nd.resolve_main_config("nginx/", "conf/nginx.conf", {}, cwd="/opt")
        self.assertEqual(path, "/opt/nginx/conf/nginx.conf")

    def test_include_resolution_and_safety(self):
        self.assertEqual(nd.resolve_include("conf.d/*.conf", "/etc/nginx"),
                         "/etc/nginx/conf.d/*.conf")
        self.assertEqual(nd.resolve_include("../conf.d/x.conf", f"{PVM}/conf"),
                         f"{PVM}/conf.d/x.conf")
        self.assertTrue(nd.safe_pattern("/etc/nginx/sites-enabled/*"))
        for bad in ("/etc/$(id).conf", "/etc/a;b", "/etc/a b.conf", "/etc/`x`"):
            self.assertFalse(nd.safe_pattern(bad), bad)


class Graph(unittest.TestCase):

    def reader(self, host):
        return host.read

    def test_nested_wildcard_include_each_file_once(self):
        host = NginxHost(files={
            "/etc/nginx/nginx.conf": File("http { include conf.d/*.conf; include conf.d/*.conf; }"),
            "/etc/nginx/conf.d/site.conf": File("server { listen 443 ssl; include snippets/tls.conf; }"),
            "/etc/nginx/snippets/tls.conf": File("ssl_protocols TLSv1.3;")})
        records, complete, source = nd.build_graph("/etc/nginx/nginx.conf", host.read)
        self.assertTrue(complete)
        self.assertEqual(sorted(r.path for r in records if r.state == nd.READ),
                         ["/etc/nginx/conf.d/site.conf", "/etc/nginx/nginx.conf",
                          "/etc/nginx/snippets/tls.conf"])
        self.assertIn("ssl_protocols TLSv1.3", source)
        self.assertLess(source.index("listen 443"), source.index("ssl_protocols"))

    def test_include_order_is_preserved(self):
        host = NginxHost(files={
            "/etc/nginx/nginx.conf": File("http { server { listen 443; server_name a; } "
                                          "include b.conf; server { listen 443; server_name c; } }"),
            "/etc/nginx/b.conf": File("server { listen 443; server_name b; }")})
        _, _, source = nd.build_graph("/etc/nginx/nginx.conf", host.read)
        self.assertLess(source.index("server_name a"), source.index("server_name b"))
        self.assertLess(source.index("server_name b"), source.index("server_name c"))

    def test_cycle_is_read_once(self):
        host = NginxHost(files={
            "/etc/nginx/nginx.conf": File("include a.conf;"),
            "/etc/nginx/a.conf": File("include b.conf;"),
            "/etc/nginx/b.conf": File("include a.conf;")})
        records, complete, _ = nd.build_graph("/etc/nginx/nginx.conf", host.read)
        self.assertTrue(complete)
        self.assertEqual(len([r for r in records if r.state == nd.READ]), 3)

    def test_denied_missing_nomatch_unsupported(self):
        host = NginxHost(files={
            "/etc/nginx/nginx.conf": File("include secret.conf; include gone.conf; "
                                          "include sites-enabled/*; include /etc/$(id).conf;"),
            "/etc/nginx/secret.conf": File("x", readable=False)})
        records, complete, _ = nd.build_graph("/etc/nginx/nginx.conf", host.read)
        states = {r.path: r.state for r in records}
        self.assertEqual(states["/etc/nginx/secret.conf"], nd.DENIED)
        self.assertEqual(states["/etc/nginx/gone.conf"], nd.MISSING)
        self.assertEqual(states["/etc/nginx/sites-enabled/*"], nd.NOMATCH)
        self.assertEqual(states["/etc/$(id).conf"], nd.UNSUPPORTED)
        self.assertFalse(complete)
        self.assertNotIn(("read", ("/etc/$(id).conf",)), host.calls)

    def test_wildcard_matching_nothing_keeps_the_graph_complete(self):
        host = NginxHost(files={"/etc/nginx/nginx.conf": File("include sites-enabled/*;")})
        _, complete, _ = nd.build_graph("/etc/nginx/nginx.conf", host.read)
        self.assertTrue(complete)

    def test_dump_is_turned_into_an_expanded_graph(self):
        dump = ("# configuration file /etc/nginx/nginx.conf:\nhttp { include conf.d/*.conf; }\n"
                "# configuration file /etc/nginx/conf.d/a.conf:\nserver { listen 443 ssl; }\n")
        records, source = nd.graph_from_dump(dump, "/etc/nginx/nginx.conf")
        self.assertEqual([r.path for r in records],
                         ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/a.conf"])
        self.assertIn("http { server { listen 443 ssl; }", " ".join(source.split()))


class EvidenceLevels(unittest.TestCase):

    def test_unchanged_since_start_is_verified(self):
        d = nd.discover(custom_host())
        self.assertEqual(d.level, nd.LEVEL_VERIFIED)
        self.assertTrue(d.complete)

    def test_changed_after_start_is_associated(self):
        host = custom_host()
        host.files[f"{PVM}/conf.d/files.conf"].mtime = START + 60
        d = nd.discover(host)
        self.assertEqual(d.level, nd.LEVEL_ASSOCIATED)
        self.assertTrue(any("modified after the master started" in u for u in d.uncertainty))

    def test_linked_but_incomplete_is_associated(self):
        host = custom_host()
        host.files[f"{PVM}/conf/mime.types"].readable = False
        d = nd.discover(host)
        self.assertEqual(d.level, nd.LEVEL_ASSOCIATED)
        self.assertFalse(d.complete)

    def test_search_result_is_a_candidate(self):
        host = custom_host(ps="", proc={}, units={})
        d = nd.discover(host)
        self.assertEqual(d.level, nd.LEVEL_CANDIDATE)
        self.assertEqual(d.main_path, "/etc/nginx/nginx.conf")
        self.assertIn(f"{PVM}/conf/nginx.conf", d.discovered_only)


class Stages(unittest.TestCase):

    def test_spoofed_title_is_never_executed(self):
        host = NginxHost(ps=master_line(66, "/tmp/x/nginx -c /tmp/x/n.conf", user="mallory"),
                         executables={"/tmp/x/nginx": Exe(uid=1001, mode=0o777)},
                         files={"/tmp/x/n.conf": File("http {}")})
        d = nd.discover(host)
        self.assertEqual(host.executed(), [])
        self.assertTrue(any("not trusted" in lim for lim in d.limitations))

    def test_path_nginx_is_not_run_while_a_master_is_visible(self):
        host = custom_host(path_nginx_dump="# configuration file /etc/nginx/nginx.conf:\n")
        nd.discover(host)
        self.assertFalse(any(c[0] == "PATH -T" for c in host.calls))
        self.assertEqual(set(host.executed()), {f"{PVM}/sbin/nginx"})

    def test_unit_owning_the_master_is_linked(self):
        d = nd.discover(custom_host())
        self.assertTrue(d.unit_linked)
        self.assertTrue(any("pvm-nginx.service" in f for f in d.facts))

    def test_unrelated_unit_only_gives_a_candidate(self):
        host = custom_host(ps="", proc={})
        host.units = {"nginx.service": "Id=nginx.service\nMainPID=0\nExecStart={ path=/usr/sbin/nginx ; "
                                       f"argv[]=/usr/sbin/nginx -c {PVM}/conf/nginx.conf ; }}\n"}
        d = nd.discover(host)
        self.assertEqual(d.level, nd.LEVEL_CANDIDATE)
        self.assertEqual(d.main_path, f"{PVM}/conf/nginx.conf")

    def test_restricted_account_records_every_refusal(self):
        host = custom_host(ps=None, systemd=False, proc={})
        d = nd.discover(host)
        self.assertTrue(any("process list not available" in lim for lim in d.limitations))
        self.assertEqual(d.level, nd.LEVEL_CANDIDATE)


# ---------------------------------------------------- findings (brief tests 1-7)

class Findings(unittest.TestCase):

    def test_1_standard_installation(self):
        host = NginxHost(
            ps=master_line(700, '/usr/sbin/nginx -g "daemon on; master_process on;"'),
            proc={700: {"exe": "/usr/sbin/nginx",
                        "cgroup": "0::/system.slice/nginx.service"}},
            units={"nginx.service": "Id=nginx.service\nMainPID=700\n"},
            executables={"/usr/sbin/nginx": Exe(version_output=version(
                "/usr/share/nginx", "/etc/nginx/nginx.conf"))},
            files={"/etc/nginx/nginx.conf": File("http { include /etc/nginx/sites-enabled/*; }", 1),
                   "/etc/nginx/sites-enabled/files": File(TLS_SITE, 1)})
        _, by = scan(host)
        self.assertEqual(by["nginx.conf"].status, F.PASS)
        self.assertIn("TLS-enabled: 1", " ".join(by["nginx.blocks"].evidence))
        self.assertEqual(by["nginx.domain"].status, F.PASS)

    def test_2_custom_installation(self):
        session, by = scan(custom_host())
        conf = by["nginx.conf"]
        self.assertEqual(conf.status, F.PASS)
        text = " ".join(conf.evidence)
        self.assertIn(f"{PVM}/sbin/nginx", text)
        self.assertIn(f"{PVM}/conf/nginx.conf", text)
        self.assertIn("runtime-verified", text)
        self.assertEqual(by["nginx.domain"].status, F.PASS)
        self.assertNotIn("/etc/nginx/nginx.conf", " ".join(by["nginx.blocks"].evidence))

    def test_3_explicit_c_and_p_beat_build_defaults(self):
        host = custom_host()
        host.executables[f"{PVM}/sbin/nginx"].version_output = version(
            "/usr/share/nginx", "/etc/nginx/nginx.conf")
        d = nd.discover(host)
        self.assertEqual(d.main_path, f"{PVM}/conf/nginx.conf")

    def test_4_default_conf_on_disk_but_not_included(self):
        host = custom_host()
        host.files[f"{PVM}/conf/nginx.conf"] = File("http { include site/*.conf; }", START - 500)
        host.files[f"{PVM}/conf/site/plain.conf"] = File("server { listen 80; server_name x; }",
                                                         START - 500)
        host.files[f"{PVM}/conf.d/default.conf"] = File(TLS_SITE, START - 500)
        del host.files[f"{PVM}/conf.d/files.conf"]
        _, by = scan(host)
        blocks = " ".join(by["nginx.blocks"].evidence)
        self.assertIn("TLS-enabled: 0", blocks)
        self.assertIn(f"{PVM}/conf.d/default.conf", blocks)      # listed, not counted
        self.assertIn("not part of the configuration graph", blocks)

    def test_5_runtime_cannot_be_determined(self):
        host = custom_host(ps=None, proc={}, units={}, systemd=False)
        _, by = scan(host)
        self.assertEqual(by["nginx.conf"].status, F.WARNING)
        self.assertEqual(by["nginx.domain"].status, F.NOT_TESTED)
        self.assertTrue(by["nginx.domain"].uncertainty)
        self.assertTrue(by["nginx.conf"].uncertainty)

    def test_6_https_works_but_discovery_incomplete(self):
        host = custom_host(ps=None, proc={}, units={}, systemd=False)
        _, by = scan(host)
        d = analyze.diagnose(https_ok() + list(by.values()), {})
        self.assertTrue(any(u.check == "nginx.conf" for u in d.unresolved))
        self.assertFalse(any(c.origin == "server" for c in d.causes))
        self.assertFalse(any("server block" in (c.recommendation or "").lower()
                             or "server_name" in (c.recommendation or "") for c in d.causes))

    def test_7_missing_and_unreadable_files_are_told_apart(self):
        host = custom_host()
        host.files[f"{PVM}/conf/nginx.conf"] = File(
            "http { include mime.types; include gone.conf; include ../conf.d/*.conf; }", START - 500)
        host.files[f"{PVM}/conf.d/files.conf"].readable = False
        _, by = scan(host)
        text = " ".join(by["nginx.conf"].evidence)
        self.assertIn(f"{PVM}/conf/gone.conf: missing", text)
        self.assertIn(f"{PVM}/conf.d/files.conf: not readable", text)
        self.assertEqual(by["nginx.conf"].status, F.WARNING)
        self.assertEqual(by["nginx.domain"].status, F.NOT_TESTED)

    def test_verified_graph_without_443_block_warns(self):
        host = custom_host()
        host.files[f"{PVM}/conf.d/files.conf"] = File("server { listen 80; server_name x; }",
                                                      START - 400)
        _, by = scan(host)
        self.assertEqual(by["nginx.domain"].status, F.WARNING)
        self.assertIn("no server block listens on port 443", " ".join(by["nginx.domain"].evidence))

    def test_nothing_readable_is_not_tested(self):
        host = NginxHost(ps="", files={})
        _, by = scan(host)
        self.assertEqual(by["nginx.conf"].status, F.NOT_TESTED)
        self.assertIn("/etc/nginx", " ".join(by["nginx.conf"].evidence))

    def test_suspected_custom_path_is_uncertainty_not_a_cause(self):
        host = custom_host(executables={})
        host.proc = {812: {"exe": f"{PVM}/sbin/nginx"}}
        host.ps = master_line(812, f"{PVM}/sbin/nginx")         # no -c, -V not trusted
        _, by = scan(host)
        d = analyze.diagnose(https_ok() + list(by.values()), {})
        self.assertTrue(any("outside" in u for u in by["nginx.conf"].uncertainty))
        self.assertFalse(any("non-standard" in c.summary or "custom" in c.summary
                             for c in d.causes))


class Diagnosis(unittest.TestCase):

    def finding(self, evidence, status=F.WARNING):
        return F.Finding("nginx.domain", "Nginx vhost", status, F.SCOPE_SERVER, evidence)

    def conf(self, status=F.PASS):
        return F.Finding("nginx.conf", "Nginx TLS configuration", status, F.SCOPE_SERVER,
                         ["evidence level: runtime-verified"])

    def test_no_block_on_port_is_not_a_conflict(self):
        d = analyze.diagnose([self.conf(), self.finding(
            ["no server block found: no server block listens on port 443"])], {})
        titles = [c.summary for c in d.causes]
        self.assertFalse(any("Several" in t for t in titles))
        self.assertTrue(any("listens on port 443" in t for t in titles))

    def test_real_duplicate_is_a_conflict(self):
        d = analyze.diagnose([self.conf(), self.finding(
            ["selected by: exact server_name match",
             "conflicting server name 'shop.test' on port 443: nginx ignores every block "
             "after the first"])], {})
        self.assertTrue(any("Several nginx server blocks" in c.summary for c in d.causes))

    def test_fallback_keeps_its_cause(self):
        d = analyze.diagnose([self.conf(), self.finding(
            ["selected by: default_server fallback", "nginx answered with a FALLBACK server block"])], {})
        self.assertTrue(any("no dedicated nginx server block" in c.summary for c in d.causes))

    def test_no_server_cause_without_a_confirmed_configuration(self):
        d = analyze.diagnose([self.conf(F.WARNING), self.finding(
            ["selected by: default_server fallback", "nginx answered with a FALLBACK server block"])], {})
        self.assertFalse(any(c.origin == "server" for c in d.causes))


if __name__ == "__main__":
    unittest.main()


# --------------------------------------------- the real remote scripts (sh)

import os
import shutil
import sys
import tempfile

from ssl_doctor import server


class SshProbeScripts(unittest.TestCase):
    """The probe's shell scripts, run by /bin/sh on this machine (LocalSession)."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="nginxroot")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.probe = server._SshNginxProbe(server.LocalSession())

    def write(self, rel, text, mtime=1_000_000):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        os.utime(path, (mtime, mtime))
        return path

    def test_read_frames_states_and_content(self):
        main = self.write("conf/nginx.conf", "http { include conf.d/*.conf; }\n# é ünïcode\n")
        a = self.write("conf/conf.d/a.conf", "server { listen 443 ssl; }\n@@SSLDOCTOR fake\n")
        big = self.write("conf/big.conf", "x" * (nd.MAX_FILE_BYTES + 1))
        records = self.probe.read([main, f"{self.root}/conf/conf.d/*.conf",
                                   f"{self.root}/conf/gone.conf",
                                   f"{self.root}/conf/empty/*", big])
        by = {(r.pattern, r.path): r for r in records}
        self.assertEqual(by[(main, main)].state, nd.READ)
        self.assertEqual(by[(main, main)].content, open(main).read())
        self.assertEqual(by[(main, main)].mtime, 1_000_000)
        glob_rec = by[(f"{self.root}/conf/conf.d/*.conf", a)]
        self.assertEqual(glob_rec.content, open(a).read())       # framing survives @@ lines
        gone = f"{self.root}/conf/gone.conf"
        self.assertEqual(by[(gone, gone)].state, nd.MISSING)
        empty = f"{self.root}/conf/empty/*"
        self.assertEqual(by[(empty, empty)].state, nd.NOMATCH)
        self.assertEqual(by[(big, big)].state, nd.TOOLARGE)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads everything")
    def test_unreadable_file_is_denied_not_missing(self):
        path = self.write("conf/secret.conf", "x")
        os.chmod(path, 0)
        [rec] = self.probe.read([path])
        self.assertEqual(rec.state, nd.DENIED)

    def test_graph_through_the_real_script(self):
        self.write("conf/nginx.conf", "http { include ../sites/*.conf; }")
        self.write("sites/files.conf", "server { listen 443 ssl; server_name files; }")
        records, complete, source = nd.build_graph(f"{self.root}/conf/nginx.conf",
                                                   self.probe.read)
        self.assertTrue(complete)
        self.assertIn("server_name files", source)

    def test_roots_find_and_list(self):
        self.write("opt/pvm/nginx/conf/nginx.conf", "events {}")
        self.write("opt/pvm/nginx/conf.d/default.conf", "server {}")
        states = dict(self.probe.root_states([f"{self.root}/opt", f"{self.root}/nope"]))
        self.assertEqual(states, {f"{self.root}/opt": "ok", f"{self.root}/nope": "missing"})
        self.assertEqual(self.probe.find_main([f"{self.root}/opt"]),
                         [f"{self.root}/opt/pvm/nginx/conf/nginx.conf"])
        self.assertEqual(self.probe.list_conf([f"{self.root}/opt/pvm/nginx/conf.d"]),
                         [f"{self.root}/opt/pvm/nginx/conf.d/default.conf"])

    def test_mtimes(self):
        path = self.write("conf/nginx.conf", "x", mtime=1_234_567)
        self.assertEqual(self.probe.mtimes([path]), {path: 1_234_567})

    def test_processes_proc_and_stat(self):
        text, now, why = self.probe.processes()
        self.assertIsNotNone(text, why)
        self.assertIsInstance(now, int)
        self.assertIn(str(os.getpid()), text)
        info = self.probe.proc_details(os.getpid())
        self.assertTrue(info.get("exe"), info)
        uid, mode, kind = self.probe.exe_stat(os.path.realpath(sys.executable))
        self.assertEqual(kind, "regular file")
        self.assertIsNone(self.probe.exe_stat(f"{self.root}/no-such-binary"))

    def test_missing_unit_and_non_nginx_binary(self):
        self.assertIsNone(self.probe.systemd_show("ssl-doctor-no-such-unit.service"))
        self.assertIsNone(self.probe.build_info("/bin/true"))


class OtherServerChecks(unittest.TestCase):

    def test_web_detection_reports_the_running_master_without_path_nginx(self):
        session = HostSession(custom_host())
        [finding] = session.webserver_detection()
        text = " ".join(finding.evidence)
        self.assertEqual(finding.status, F.PASS)
        self.assertIn(f"running nginx master pid 812: {PVM}/sbin/nginx", text)

    def test_tls_config_inventory_uses_the_discovered_graph(self):
        session = HostSession(custom_host())
        [finding] = session.tls_config_scan()
        text = " ".join(finding.evidence)
        self.assertIn(f"{PVM}/conf/nginx.conf", text)
        self.assertIn(f"ssl_certificate {PVM}/ssl/files.crt;", text)
        self.assertNotIn("/etc/nginx", text)
        self.assertFalse(any("/etc/nginx" in c for c in session.commands))


class ContractAndAgentReport(unittest.TestCase):
    """Same check ids, documents still valid findings 1.5, report shows the scope."""

    def scan_items(self, host):
        _, by = scan(host)
        return https_ok() + list(by.values())

    def test_ids_registered_and_document_valid(self):
        from ssl_doctor import contract, report
        for host in (custom_host(), custom_host(ps=None, proc={}, units={}, systemd=False)):
            items = self.scan_items(host)
            nginx_ids = {f.check for f in items if f.check.startswith("nginx.")}
            self.assertLessEqual(nginx_ids, set(contract.CHECK_IDS))
            payload = report.build_payload(items, analyze.diagnose(items, {}),
                                           {"target": "files.example.com:443"}, [], {})
            self.assertEqual(payload["schema_version"], contract.SCHEMA_VERSION)
            self.assertEqual(contract.validate(payload), [])

    def test_agent_report_carries_level_and_unresolved_entry(self):
        from ssl_doctor import report
        items = self.scan_items(custom_host(ps=None, proc={}, units={}, systemd=False))
        meta = report.agent_meta({"target": "files.example.com:443"},
                                 {"host": "files.example.com", "port": 443}, items)
        payload = report.build_payload(items, analyze.diagnose(items, {}), meta, [], {})
        markdown = report.agent_markdown(payload)
        self.assertIn("evidence level: candidate", markdown)
        self.assertIn("not linked to a running nginx master", markdown)
