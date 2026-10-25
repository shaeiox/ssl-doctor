"""A ServerSession whose 'remote' is this machine plus a canned nginx config."""

from __future__ import annotations

import subprocess

from ssl_doctor import server


class FakeSession(server.ServerSession):
    """A running nginx whose `-T` returns `config`; other commands run locally."""

    def __init__(self, config: str, tls_host: str = "shop.test", tls_port: int = 443):
        super().__init__(server.SSHConfig(host="fake-host", username="tester",
                                          tls_host=tls_host, tls_port=tls_port))
        self.config = config
        self.connected = True

    def nginx_probe(self):
        # a running root master whose trusted executable dumps `config` with -T
        from fixtures.nginx_host import Exe, File, NginxHost, master_line, version
        dump = "# configuration file /etc/nginx/nginx.conf:\n" + self.config
        return NginxHost(
            ps=master_line(700, '/usr/sbin/nginx -g "daemon on; master_process on;"'),
            proc={700: {"exe": "/usr/sbin/nginx"}},
            executables={"/usr/sbin/nginx": Exe(
                version_output=version("/usr/share/nginx", "/etc/nginx/nginx.conf"),
                dump=dump)},
            files={"/etc/nginx/nginx.conf": File(self.config, mtime=1)})

    def run(self, remote_cmd: str):
        if remote_cmd.startswith("nginx -T"):
            return 0, self.config, "", ""
        proc = subprocess.run(["bash", "-c", remote_cmd], capture_output=True,
                              text=True, timeout=30)
        return proc.returncode, proc.stdout, proc.stderr, ""
