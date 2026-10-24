"""A ServerSession whose 'remote' is this machine plus a canned nginx config."""

from __future__ import annotations

import subprocess

from ssl_doctor import server


class FakeSession(server.ServerSession):
    """`nginx -T` returns `config`; every other command runs locally (read-only)."""

    def __init__(self, config: str, tls_host: str = "shop.test", tls_port: int = 443):
        super().__init__(server.SSHConfig(host="fake-host", username="tester",
                                          tls_host=tls_host, tls_port=tls_port))
        self.config = config
        self.connected = True

    def run(self, remote_cmd: str):
        if remote_cmd.startswith("nginx -T"):
            return 0, self.config, "", ""
        proc = subprocess.run(["bash", "-c", remote_cmd], capture_output=True,
                              text=True, timeout=30)
        return proc.returncode, proc.stdout, proc.stderr, ""
