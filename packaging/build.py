"""Build the native executables with PyInstaller (run on the target OS).

    python packaging/build.py [--out dist/<os>]

Produces:
    ssl-doctor[.exe]          single file  (CLI)
    ssl-doctor-agent[.exe]    single file  (agent; Windows service host on Windows)
    ssldoctor-server/         one-dir      (server + embedded PostgreSQL binaries)

PyInstaller does not cross-compile: build Windows .exe files on Windows.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WIN = sys.platform == "win32"


def pyinstaller(name: str, entry: str, out: str, work: str, onefile: bool, extra=()) -> None:
    argv = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level",
            "WARN", "--name", name, "--distpath", out, "--workpath", work,
            "--specpath", work, "--paths", ROOT, "--paths", os.path.join(ROOT, "service"),
            "--paths", HERE, "--onefile" if onefile else "--onedir", *extra,
            os.path.join(HERE, entry)]
    if WIN:
        argv[-1:-1] = ["--hidden-import", "winsvc", "--hidden-import", "win32timezone"]
    subprocess.run(argv, check=True)


def bundle_postgres(server_dir: str) -> None:
    """Copy the PostgreSQL install tree verbatim (bin/lib/share; no headers).

    It must not go through PyInstaller's binary analysis: that relocates the
    server's extension modules and breaks PostgreSQL's fixed $libdir layout.
    """
    import pgserver
    src = os.path.join(os.path.dirname(pgserver.__file__), "pginstall")
    dst = os.path.join(server_dir, "_internal", "pgserver", "pginstall")
    shutil.rmtree(dst, ignore_errors=True)
    for part in ("bin", "lib", "share"):
        shutil.copytree(os.path.join(src, part), os.path.join(dst, part), symlinks=True)
    # vendored client libs (libpq...), found via RPATH $ORIGIN/../../../pgserver.libs
    libs = os.path.join(os.path.dirname(os.path.dirname(pgserver.__file__)), "pgserver.libs")
    if os.path.isdir(libs):
        target = os.path.join(server_dir, "_internal", "pgserver.libs")
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(libs, target, symlinks=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "dist",
                                                  "windows" if WIN else sys.platform))
    args = ap.parse_args()
    out = os.path.abspath(args.out)
    work = os.path.join(ROOT, "build", "pyinstaller")
    shutil.rmtree(out, ignore_errors=True)
    pyinstaller("ssl-doctor", "entry_cli.py", out, work, onefile=True)
    # the agent must stay minimal: never pull the server stack in through winsvc
    agent_excludes = ["--exclude-module", "ssldoctor_service"]
    for mod in ("fastapi", "starlette", "pydantic", "uvicorn", "psycopg", "psycopg_binary",
                "lxml", "xmlsec", "onelogin", "authlib", "cryptography"):
        agent_excludes += ["--exclude-module", mod]
    if not WIN:
        agent_excludes += ["--exclude-module", "winsvc"]
    pyinstaller("ssl-doctor-agent", "entry_agent.py", out, work, onefile=True,
                extra=agent_excludes)

    pyinstaller("ssldoctor-server", "entry_server.py", out, work, onefile=False, extra=[
        "--exclude-module", "pgserver",         # PostgreSQL is copied verbatim below
        "--add-data", os.path.join(ROOT, "service", "ssldoctor_service", "migrations")
        + os.pathsep + "ssldoctor_service/migrations",       # SQL migrations
        "--hidden-import", "psycopg_binary", "--hidden-import", "psycopg_binary.pq",
        "--hidden-import", "psycopg_binary._psycopg",
        "--collect-submodules", "uvicorn",
        "--collect-data", "onelogin",           # SAML XML schemas
        "--collect-all", "xmlsec",
        "--hidden-import", "multipart",
    ])
    bundle_postgres(os.path.join(out, "ssldoctor-server"))
    print(f"built into {out}:")
    for name in sorted(os.listdir(out)):
        print("  ", name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
