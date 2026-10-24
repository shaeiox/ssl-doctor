"""Running control plane for tests: fresh database, two orgs, uvicorn in a thread."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

# reuse the CLI suite's PKI / TLS server fixtures
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tests"))

import httpx  # noqa: E402
import uvicorn  # noqa: E402

import pgfixture  # noqa: E402
from ssldoctor_service import db as dbmod  # noqa: E402
from ssldoctor_service.app import create_app  # noqa: E402


class Service:
    def __init__(self) -> None:
        self.admin_dsn = pgfixture.fresh_database()
        dbmod.migrate(self.admin_dsn)
        self.app_dsn = dbmod.connect_info(self.admin_dsn, user="ssldoctor_app")
        self.db = dbmod.Database(self.app_dsn)
        self.tokens = {}
        self.orgs = {}
        for org in ("A", "B"):
            for role in ("owner", "engineer", "viewer"):
                tok = f"tok-{org}-{role}-" + os.urandom(8).hex()
                if role == "owner":
                    self.orgs[org] = dbmod.bootstrap_org(self.admin_dsn, f"org {org}", tok)
                else:
                    dbmod.add_user_with_token(self.admin_dsn, self.orgs[org],
                                              f"{role}@{org.lower()}.example", role, tok)
                self.tokens[(org, role)] = tok
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        cfg = uvicorn.Config(create_app(self.db), host="127.0.0.1", port=self.port,
                             log_level="warning", access_log=False)
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("service did not start")
            time.sleep(0.02)

    def client(self, org: str = "A", role: str = "owner") -> httpx.Client:
        return httpx.Client(base_url=self.url, timeout=60,
                            headers={"Authorization": f"Bearer {self.tokens[(org, role)]}"})

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)
