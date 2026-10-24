"""Throwaway test PKI built with the openssl binary.

Layout (all under one temp directory, created once per test run):

    root.pem                       self-signed "SSLDoctor Test Root"
    int.pem / int.key              intermediate issued by root
    other_int.pem                  a second intermediate (did NOT issue the leaf)
    leaf.pem / leaf.key            CN=shop.test, SAN DNS:shop.test, issued by int
    cn_only.pem / cn_only.key      CN=shop.test, no subjectAltName, issued by int
    fullchain.pem                  leaf + int
    wrongchain.pem                 leaf + other_int
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

HOSTNAME = "shop.test"

_CA_EXT = "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" \
          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
_LEAF_EXT = "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" \
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


@dataclass
class PKI:
    dir: str

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    @property
    def root(self) -> str: return self.path("root.pem")
    @property
    def intermediate(self) -> str: return self.path("int.pem")
    @property
    def other_intermediate(self) -> str: return self.path("other_int.pem")
    @property
    def leaf(self) -> str: return self.path("leaf.pem")
    @property
    def leaf_key(self) -> str: return self.path("leaf.key")
    @property
    def cn_only(self) -> str: return self.path("cn_only.pem")
    @property
    def cn_only_key(self) -> str: return self.path("cn_only.key")
    @property
    def fullchain(self) -> str: return self.path("fullchain.pem")
    @property
    def wrongchain(self) -> str: return self.path("wrongchain.pem")

    def bundle(self, *names: str) -> str:
        """Concatenate PEM files (by attribute name) into a trust bundle file."""
        out = self.path("bundle-" + "-".join(names) + ".pem")
        with open(out, "w") as fh:
            for n in names:
                with open(getattr(self, n)) as src:
                    fh.write(src.read())
        return out


def _run(*args: str, cwd: str) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _issue(d: str, name: str, subject: str, ca: str, ext: str) -> None:
    _run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
         "-out", f"{name}.csr", "-subj", subject, cwd=d)
    with open(os.path.join(d, f"{name}.ext"), "w") as fh:
        fh.write(ext)
    _run("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key",
         "-CAcreateserial", "-out", f"{name}.pem", "-days", "30",
         "-extfile", f"{name}.ext", cwd=d)


def _build(d: str) -> None:
    _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key",
         "-out", "root.pem", "-days", "30", "-subj", "/CN=SSLDoctor Test Root",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash", cwd=d)
    _issue(d, "int", "/CN=SSLDoctor Test Intermediate", "root", _CA_EXT)
    _issue(d, "other_int", "/CN=SSLDoctor Other Intermediate", "root", _CA_EXT)
    _issue(d, "leaf", f"/CN={HOSTNAME}", "int",
           _LEAF_EXT + f"subjectAltName=DNS:{HOSTNAME}\n")
    _issue(d, "cn_only", f"/CN={HOSTNAME}", "int", _LEAF_EXT)
    for out, parts in (("fullchain.pem", ("leaf.pem", "int.pem")),
                       ("wrongchain.pem", ("leaf.pem", "other_int.pem"))):
        with open(os.path.join(d, out), "w") as fh:
            for p in parts:
                with open(os.path.join(d, p)) as src:
                    fh.write(src.read())


_PKI: Optional[PKI] = None


def get_pki() -> PKI:
    """Build the PKI once per process and remove it at exit."""
    global _PKI
    if _PKI is None:
        d = tempfile.mkdtemp(prefix="ssldoctor-pki-")
        atexit.register(shutil.rmtree, d, True)
        _build(d)
        _PKI = PKI(d)
    return _PKI
