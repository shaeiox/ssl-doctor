"""Assemble and sign the offline (air-gap) release bundle.

    python packaging/release.py --dist dist/linux --key release-ed25519.pem [--out release/]
    python packaging/release.py --dist dist/linux --dev-key            # throwaway key (CI/tests)

Bundle layout (``ssl-doctor-<version>-<os>/``):

    bin/ssl-doctor[.exe]  bin/ssl-doctor-agent[.exe]  ssldoctor-server/...
    systemd/*.service     docs/INSTALL.md  VERIFY.md
    sbom.cdx.json         CycloneDX SBOM of the build environment
    RELEASE-KEY.pub       Ed25519 public key
    SHA256SUMS            sha256 of every file above
    SHA256SUMS.sig        Ed25519 signature of SHA256SUMS

Verification needs only ``openssl`` and ``sha256sum`` (see VERIFY.md).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

VERIFY_MD = """# Verifying this release (offline)

Run inside the extracted bundle directory. Only `openssl` (1.1.1+) and
`sha256sum` are needed. No network access, no transparency log.

```bash
# 1. the checksum list was signed by the release key
openssl pkeyutl -verify -pubin -inkey RELEASE-KEY.pub -rawin \\
        -in SHA256SUMS -sigfile SHA256SUMS.sig
# -> "Signature Verified Successfully"

# 2. every file matches the signed list
sha256sum -c --strict SHA256SUMS
```

Compare the fingerprint of `RELEASE-KEY.pub` with the one published by your
vendor through a separate channel:

```bash
openssl pkey -pubin -in RELEASE-KEY.pub -outform DER | sha256sum
```

On Windows hosts without OpenSSL, verify the bundle on any Linux/macOS
machine (or with Git for Windows' `openssl`) before copying it over.
"""


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)


def write_sums(bundle: str) -> None:
    lines = []
    for dirpath, dirnames, filenames in os.walk(bundle):
        dirnames.sort()
        for f in sorted(filenames):
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, bundle).replace(os.sep, "/")
            if rel in ("SHA256SUMS", "SHA256SUMS.sig") or os.path.islink(full):
                continue
            lines.append(f"{sha256(full)}  {rel}\n")
    with open(os.path.join(bundle, "SHA256SUMS"), "w", newline="\n") as fh:
        fh.writelines(lines)


def sign(bundle: str, key: str) -> None:
    openssl("pkey", "-in", key, "-pubout", "-out", os.path.join(bundle, "RELEASE-KEY.pub"))
    write_sums(bundle)
    openssl("pkeyutl", "-sign", "-inkey", key, "-rawin",
            "-in", os.path.join(bundle, "SHA256SUMS"),
            "-out", os.path.join(bundle, "SHA256SUMS.sig"))


def verify(bundle: str) -> tuple:
    """(signature_ok, files_ok, detail) — the same checks VERIFY.md documents."""
    sig = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                          "RELEASE-KEY.pub", "-rawin", "-in", "SHA256SUMS",
                          "-sigfile", "SHA256SUMS.sig"], cwd=bundle, capture_output=True,
                         text=True)
    sums = subprocess.run(["sha256sum", "-c", "--strict", "--quiet", "SHA256SUMS"],
                          cwd=bundle, capture_output=True, text=True)
    return sig.returncode == 0, sums.returncode == 0, (sig.stdout + sig.stderr +
                                                       sums.stdout + sums.stderr).strip()


def sbom(path: str) -> None:
    subprocess.run([sys.executable, "-m", "cyclonedx_py", "environment", sys.executable,
                    "--of", "JSON", "-o", path], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)


def build(dist: str, key: str, out: str) -> str:
    from ssl_doctor import __version__
    osname = "windows" if any(f.endswith(".exe") for f in os.listdir(dist)) else "linux"
    name = f"ssl-doctor-{__version__}-{osname}"
    bundle = os.path.join(out, name)
    shutil.rmtree(bundle, ignore_errors=True)
    os.makedirs(os.path.join(bundle, "bin"))
    for f in os.listdir(dist):
        src = os.path.join(dist, f)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(bundle, f), symlinks=True)
        else:
            shutil.copy2(src, os.path.join(bundle, "bin", f))
    shutil.copytree(os.path.join(HERE, "systemd"), os.path.join(bundle, "systemd"))
    os.makedirs(os.path.join(bundle, "docs"))
    shutil.copy2(os.path.join(HERE, "INSTALL.md"), os.path.join(bundle, "docs", "INSTALL.md"))
    shutil.copy2(os.path.join(ROOT, "docs", "agents.md"), os.path.join(bundle, "docs"))
    with open(os.path.join(bundle, "VERIFY.md"), "w") as fh:
        fh.write(VERIFY_MD)
    sbom(os.path.join(bundle, "sbom.cdx.json"))
    sign(bundle, key)
    if osname == "windows":
        archive = bundle + ".zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for dirpath, _d, files in os.walk(bundle):
                for f in files:
                    full = os.path.join(dirpath, f)
                    z.write(full, os.path.relpath(full, out))
    else:
        archive = bundle + ".tar.gz"
        with tarfile.open(archive, "w:gz") as t:
            t.add(bundle, arcname=name)
    return archive


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", required=True)
    ap.add_argument("--key", help="Ed25519 private key (PEM)")
    ap.add_argument("--dev-key", action="store_true", help="generate a throwaway key")
    ap.add_argument("--out", default=os.path.join(ROOT, "release"))
    args = ap.parse_args()
    if not args.key and not args.dev_key:
        ap.error("--key or --dev-key is required")
    key = args.key
    if args.dev_key:
        key = os.path.join(tempfile.mkdtemp(), "dev-ed25519.pem")
        openssl("genpkey", "-algorithm", "ed25519", "-out", key)
    os.makedirs(args.out, exist_ok=True)
    print(build(os.path.abspath(args.dist), key, os.path.abspath(args.out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
