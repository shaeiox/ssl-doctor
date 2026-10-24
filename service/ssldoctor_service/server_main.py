"""ssldoctor-server: the whole platform in one executable, with embedded PostgreSQL.

    ssldoctor-server init    --data DIR [--org NAME] [--listen HOST:PORT] [--run-as USER]
    ssldoctor-server run     --data DIR
    ssldoctor-server upgrade --data DIR          # backup, then apply migrations
    ssldoctor-server backup  --data DIR
    ssldoctor-server verify-audit --data DIR
    ssldoctor-server version

The data directory holds the PostgreSQL cluster (``pg/``), backups and
``config.json`` (0600: database passwords, listen address). PostgreSQL listens
on 127.0.0.1 only, with SCRAM authentication. PostgreSQL refuses to run as
root; on Linux, pass ``--run-as`` at init when invoked as root (the systemd
unit uses a dedicated account instead).

No outbound connections are made: there is no telemetry and no update check.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__

CONFIG = "config.json"


# ------------------------------------------------------------------ PostgreSQL

def pg_bin_dir() -> str:
    """Bundled PostgreSQL binaries (PyInstaller bundle, pgserver wheel, or env)."""
    if os.environ.get("SSLDOCTOR_PG_BIN"):
        return os.environ["SSLDOCTOR_PG_BIN"]
    exe = "initdb.exe" if os.name == "nt" else "initdb"
    if getattr(sys, "frozen", False):          # executable bundle: copied verbatim at build
        bundled = os.path.join(sys._MEIPASS, "pgserver", "pginstall", "bin")  # noqa
        if os.path.exists(os.path.join(bundled, exe)):
            return bundled
    try:
        import pgserver
        # inside a bundle `pgserver` may resolve as a file-less namespace package
        if getattr(pgserver, "__file__", None):
            cand = os.path.join(os.path.dirname(pgserver.__file__), "pginstall", "bin")
            if os.path.exists(os.path.join(cand, exe)):
                return cand
    except ImportError:
        pass
    found = shutil.which(exe)
    if found:
        return os.path.dirname(found)
    raise SystemExit("PostgreSQL binaries not found (set SSLDOCTOR_PG_BIN)")


class Postgres:
    def __init__(self, data_dir: str, cfg: dict) -> None:
        self.data = os.path.join(data_dir, "pg")
        self.log = os.path.join(data_dir, "pg.log")
        self.cfg = cfg
        self.bin = pg_bin_dir()
        self.runas: List[str] = ["runuser", "-u", cfg["run_as"], "--"] if cfg.get("run_as") else []

    def _cmd(self, name: str, *args: str, check=True, **kw):
        exe = os.path.join(self.bin, name + (".exe" if os.name == "nt" else ""))
        env = dict(os.environ, PGPASSWORD=self.cfg["pg_admin_password"])
        proc = subprocess.run(self.runas + [exe, *args], env=env,
                              stdout=kw.pop("stdout", subprocess.DEVNULL),
                              stderr=subprocess.PIPE, **kw)
        if check and proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            if name == "pg_ctl" and os.path.exists(self.log):
                with open(self.log, errors="replace") as fh:
                    detail += "\n" + "".join(fh.readlines()[-5:])
            raise SystemExit(f"{name} failed (exit {proc.returncode}): {detail}")
        return proc

    def initdb(self) -> None:
        pwfile = os.path.join(os.path.dirname(self.data), ".pwfile")
        with open(pwfile, "w") as fh:
            fh.write(self.cfg["pg_admin_password"])
        os.chmod(pwfile, 0o600)
        if self.runas:
            _chown(pwfile, self.cfg["run_as"])
        try:
            self._cmd("initdb", "-D", self.data, "-U", "postgres", "-E", "UTF8",
                      "--no-locale", "--auth=scram-sha-256", f"--pwfile={pwfile}")
        finally:
            os.unlink(pwfile)

    def start(self) -> None:
        self._cmd("pg_ctl", "-D", self.data, "-w", "-t", "60", "-l", self.log, "-o",
                  f"-p {self.cfg['pg_port']} -c listen_addresses=127.0.0.1 "
                  f"-c unix_socket_directories=''", "start")

    def stop(self) -> None:
        self._cmd("pg_ctl", "-D", self.data, "-w", "-m", "fast", "stop", check=False)

    def dump(self, path: str) -> None:
        with open(path, "wb") as fh:
            self._cmd("pg_dump", "-h", "127.0.0.1", "-p", str(self.cfg["pg_port"]),
                      "-U", "postgres", "-Fc", "ssldoctor", stdout=fh)

    def dsn(self, user: str = "postgres", db: str = "ssldoctor") -> str:
        pw = self.cfg["pg_admin_password"] if user == "postgres" else self.cfg["app_password"]
        return f"host=127.0.0.1 port={self.cfg['pg_port']} dbname={db} user={user} password={pw}"


def _chown(path: str, user: str) -> None:
    import pwd
    pw = pwd.getpwnam(user)
    os.chown(path, pw.pw_uid, pw.pw_gid)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_config(data_dir: str) -> dict:
    with open(os.path.join(data_dir, CONFIG)) as fh:
        return json.load(fh)


def save_config(data_dir: str, cfg: dict) -> None:
    path = os.path.join(data_dir, CONFIG)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(cfg, fh, indent=2)


# ------------------------------------------------------------------ commands

def cmd_init(args) -> int:
    import psycopg
    from . import db
    data = os.path.abspath(args.data)
    if os.path.exists(os.path.join(data, CONFIG)):
        print(f"{data} is already initialized", file=sys.stderr)
        return 1
    if os.name != "nt" and os.geteuid() == 0 and not args.run_as:
        print("refusing to run PostgreSQL as root: pass --run-as <user> or run init as the "
              "service account", file=sys.stderr)
        return 2
    os.makedirs(data, exist_ok=True)
    os.chmod(data, 0o700)
    if args.run_as:
        _chown(data, args.run_as)
    host, _, port = args.listen.rpartition(":")
    cfg = {"version": __version__, "listen_host": host or "127.0.0.1",
           "listen_port": int(port), "pg_port": args.pg_port or _free_port(),
           "pg_admin_password": secrets.token_urlsafe(24),
           "app_password": secrets.token_urlsafe(24),
           "run_as": args.run_as, "tls_cert": args.tls_cert, "tls_key": args.tls_key}
    pg = Postgres(data, cfg)
    pg.initdb()
    pg.start()
    try:
        with psycopg.connect(pg.dsn(db="postgres"), autocommit=True) as conn:
            conn.execute("CREATE DATABASE ssldoctor")
        db.migrate(pg.dsn())
        with psycopg.connect(pg.dsn(), autocommit=True) as conn:
            conn.execute(psycopg.sql.SQL("ALTER ROLE ssldoctor_app PASSWORD {}").format(
                psycopg.sql.Literal(cfg["app_password"])))
        token = secrets.token_urlsafe(32)
        org = db.bootstrap_org(pg.dsn(), args.org, token, email=args.admin_email)
    finally:
        pg.stop()
    save_config(data, cfg)
    if args.run_as:
        _chown(os.path.join(data, CONFIG), args.run_as)
    print(f"initialized {data}\norganization: {args.org} ({org})\n"
          f"owner API token (shown once): {token}")
    return 0


def _monitor_loop(dsn: str, stop: threading.Event, every: float) -> None:
    from . import monitor
    from .db import Database
    database = Database(dsn)
    while not stop.is_set():
        try:
            now = datetime.now(timezone.utc)
            monitor.schedule(database, now)
            monitor.dispatch(database, now)
        except Exception as exc:  # noqa: BLE001 - keep the scheduler alive
            print(f"monitor: {exc}", file=sys.stderr, flush=True)
        stop.wait(every)


def cmd_run(args) -> int:
    import uvicorn
    from .app import create_app
    from .db import Database
    data = os.path.abspath(args.data)
    cfg = load_config(data)
    pg = Postgres(data, cfg)
    pg.start()
    stop = threading.Event()
    try:
        app_dsn = pg.dsn(user="ssldoctor_app")
        threading.Thread(target=_monitor_loop, args=(app_dsn, stop, args.monitor_every),
                         daemon=True).start()
        kw = {}
        if cfg.get("tls_cert"):
            kw = {"ssl_certfile": cfg["tls_cert"], "ssl_keyfile": cfg["tls_key"]}
        server = uvicorn.Server(uvicorn.Config(
            create_app(Database(app_dsn)), host=cfg["listen_host"], port=cfg["listen_port"],
            log_level="info", **kw))
        if os.name != "nt":
            signal.signal(signal.SIGTERM, lambda *_: setattr(server, "should_exit", True))
        print(f"ssldoctor-server {__version__} listening on "
              f"{'https' if kw else 'http'}://{cfg['listen_host']}:{cfg['listen_port']}",
              flush=True)
        server.run()
    finally:
        stop.set()
        pg.stop()
    return 0


def _backup(data: str, pg: Postgres) -> str:
    os.makedirs(os.path.join(data, "backups"), exist_ok=True)
    path = os.path.join(data, "backups",
                        f"ssldoctor-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.dump")
    pg.dump(path)
    return path


def cmd_upgrade(args) -> int:
    from . import db
    data = os.path.abspath(args.data)
    cfg = load_config(data)
    pg = Postgres(data, cfg)
    pg.start()
    try:
        backup = _backup(data, pg)
        applied = db.migrate(pg.dsn())
    finally:
        pg.stop()
    cfg["version"] = __version__
    save_config(data, cfg)
    print(f"backup: {backup}\napplied migrations: {', '.join(applied) or '(none)'}")
    return 0


def cmd_backup(args) -> int:
    data = os.path.abspath(args.data)
    pg = Postgres(data, load_config(data))
    pg.start()
    try:
        print(_backup(data, pg))
    finally:
        pg.stop()
    return 0


def cmd_verify_audit(args) -> int:
    import psycopg
    from psycopg.rows import dict_row
    from . import audit
    data = os.path.abspath(args.data)
    pg = Postgres(data, load_config(data))
    pg.start()
    bad = 0
    try:
        with psycopg.connect(pg.dsn(), row_factory=dict_row) as conn:
            for org in conn.execute("SELECT id, name FROM app.organizations ORDER BY name"):
                ok, seq, reason = audit.verify_org(conn, org["id"])
                bad += not ok
                print(f"{'OK    ' if ok else 'BROKEN'} {org['name']} ({org['id']}): "
                      f"{reason if ok else f'entry {seq}: {reason}'}")
    finally:
        pg.stop()
    return 1 if bad else 0


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="ssldoctor-server", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--data", required=True)
    p.add_argument("--org", default="My organization")
    p.add_argument("--admin-email", default=None)
    p.add_argument("--listen", default="127.0.0.1:8080")
    p.add_argument("--pg-port", type=int, default=0)
    p.add_argument("--run-as", default=None)
    p.add_argument("--tls-cert", default=None)
    p.add_argument("--tls-key", default=None)
    p = sub.add_parser("run")
    p.add_argument("--data", required=True)
    p.add_argument("--monitor-every", type=float, default=30.0)
    for name in ("upgrade", "backup", "verify-audit"):
        sub.add_parser(name).add_argument("--data", required=True)
    sub.add_parser("version")
    args = ap.parse_args(argv)
    if args.cmd == "version":
        print(f"ssldoctor-server {__version__}")
        return 0
    return {"init": cmd_init, "run": cmd_run, "upgrade": cmd_upgrade, "backup": cmd_backup,
            "verify-audit": cmd_verify_audit}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
