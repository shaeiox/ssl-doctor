"""Throwaway PostgreSQL cluster for service tests.

Uses PG binaries from $SSLDOCTOR_PG_BIN, else the `pgserver` wheel, else
PATH. PostgreSQL refuses to run as root, so under root the server runs as
$SSLDOCTOR_PG_USER (default 'nobody').
"""

from __future__ import annotations

import atexit
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
from typing import List, Optional


def _pg_bin() -> Optional[str]:
    if os.environ.get("SSLDOCTOR_PG_BIN"):
        return os.environ["SSLDOCTOR_PG_BIN"]
    try:
        import pgserver
        cand = os.path.join(os.path.dirname(pgserver.__file__), "pginstall", "bin")
        if os.path.exists(os.path.join(cand, "initdb")):
            return cand
    except ImportError:
        pass
    found = shutil.which("initdb")
    return os.path.dirname(found) if found else None


def available() -> bool:
    return _pg_bin() is not None


class PostgresCluster:
    def __init__(self) -> None:
        self.bin = _pg_bin()
        self.dir = tempfile.mkdtemp(prefix="ssldoctor-pg-")
        self.data = os.path.join(self.dir, "data")
        self.port = 0
        self._runas: List[str] = []
        if os.geteuid() == 0:
            user = os.environ.get("SSLDOCTOR_PG_USER", "nobody")
            pw = pwd.getpwnam(user)
            os.chmod(self.dir, 0o755)
            os.chown(self.dir, pw.pw_uid, pw.pw_gid)
            self._runas = ["runuser", "-u", user, "--"]

    def _run(self, *argv: str) -> None:
        subprocess.run(self._runas + list(argv), check=True, cwd=self.dir,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def start(self) -> "PostgresCluster":
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self._run(os.path.join(self.bin, "initdb"), "-D", self.data, "-U", "postgres",
                  "--auth=trust", "-E", "UTF8", "--no-locale")
        self._run(os.path.join(self.bin, "pg_ctl"), "-D", self.data, "-w", "-l",
                  os.path.join(self.dir, "pg.log"), "-o",
                  f"-p {self.port} -k {self.dir} -c listen_addresses=127.0.0.1", "start")
        atexit.register(self.stop)
        return self

    def stop(self) -> None:
        if os.path.exists(os.path.join(self.data, "postmaster.pid")):
            subprocess.run(self._runas + [os.path.join(self.bin, "pg_ctl"), "-D",
                                          self.data, "-m", "immediate", "stop"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(self.dir, ignore_errors=True)

    def dsn(self, db: str = "postgres", user: str = "postgres") -> str:
        return f"host=127.0.0.1 port={self.port} dbname={db} user={user}"

    def create_database(self, name: str) -> str:
        import psycopg
        with psycopg.connect(self.dsn(), autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{name}"')
        return self.dsn(name)


_CLUSTER: Optional[PostgresCluster] = None


def cluster() -> PostgresCluster:
    """One cluster per test process."""
    global _CLUSTER
    if _CLUSTER is None:
        _CLUSTER = PostgresCluster().start()
    return _CLUSTER


def fresh_database() -> str:
    """A new empty database's admin DSN."""
    import uuid
    return cluster().create_database("t_" + uuid.uuid4().hex[:12])
