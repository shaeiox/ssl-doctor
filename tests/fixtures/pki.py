"""Throwaway test PKI built with the openssl binary.

Layout (all under one temp directory, created once per test run):

    root.pem                       self-signed "SSLDoctor Test Root"
    int.pem / int.key              intermediate issued by root
    other_int.pem                  a second intermediate (did NOT issue the leaf)
    leaf.pem / leaf.key            CN=shop.test, SAN DNS:shop.test, issued by int
    cn_only.pem / cn_only.key      CN=shop.test, no subjectAltName, issued by int
    fullchain.pem                  leaf + int
    wrongchain.pem                 leaf + other_int

Built on first use (``openssl ca`` with explicit dates):

    int_expired.pem                the intermediate (same subject and key)
                                   re-issued for 2020-01-01..2021-01-01
    expired_int_chain.pem          leaf + int_expired

Malformed and unusual inputs (``pki.sample(name)``, built on first use; a
sample this openssl cannot build skips the calling test with the reason):

    truncated.pem    leaf + an unterminated intermediate block
    corrupt.pem      leaf, intermediate with invalid Base64, root (3 blocks)
    duplicate.pem    leaf, intermediate, leaf
    mixed.pem        leaf + its private key
    der-as.pem       the leaf DER-encoded, named .pem
    pkcs7.crt        leaf + intermediate as a PEM PKCS#7 bundle
    pkcs12.bin       leaf + key as PKCS#12, no telling extension
    key-only.crt     only the leaf's private key
    csr.pem          a certificate signing request
    empty.pem        whitespace only
    reversed.pem     intermediate, leaf
    full-root.pem    leaf, intermediate, root
    unrelated.pem    leaf, intermediate, other intermediate
    ca-bundle.pem    root + intermediate (a "root file" holding a non-root)
    name-only-root.pem  subject == issuer, CA:TRUE, signed by another key
    ec-aia.pem       self-signed P-256 leaf with AIA, CRL, KU and EKU extensions
    ed25519.pem      self-signed Ed25519 certificate
    forged-int.pem   the intermediate's subject and SKI on another key, signed by root
    same-name-int.pem   the intermediate's subject on another key (own SKI)
    leaf-issued.pem  a certificate issued (and signed) by the CA:FALSE leaf
    self-signed-leaf.pem  self-signed, CA:FALSE, digitalSignature only
    nonca-chain.pem  leaf-issued.pem + the leaf that signed it (non-CA issuer)
    pathlen-chain.pem    leaf below a sub-CA below the pathlen:0 intermediate
    client-leaf.pem  EKU clientAuth only, issued by the intermediate
    nosign-chain.pem leaf + an intermediate whose Key Usage lacks keyCertSign
    root2.pem        a second root with the test root's name and another key
    cross-root.pem   the test root's subject and key, cross-signed by old-root.pem
    old-root.pem     a different self-signed root ("SSLDoctor Old Root")
    case-chain.pem   child of "CN=Case CA" + the same key re-issued as "CN=CASE ca"
    aia-leaf.pem     leaf issued by the intermediate with an AIA caIssuers URL
    forged-chain.pem leaf + forged-int.pem
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

    @property
    def expired_intermediate(self) -> str:
        path = self.path("int_expired.pem")
        if not os.path.exists(path):
            _issue_dated(self.dir, "int", "root", _CA_EXT, path,
                         "20200101000000Z", "20210101000000Z")
        return path

    @property
    def expired_intermediate_chain(self) -> str:
        out = self.path("expired_int_chain.pem")
        if not os.path.exists(out):
            with open(out, "w") as fh:
                for part in (self.leaf, self.expired_intermediate):
                    with open(part) as src:
                        fh.write(src.read())
        return out

    def sample(self, name: str) -> str:
        """Path of a malformed/unusual sample file (see module docstring)."""
        path = self.path(name)
        if not os.path.exists(path):
            build = _SAMPLES[name]
            try:
                build(self, path)
            except (subprocess.CalledProcessError, OSError) as exc:
                import unittest
                raise unittest.SkipTest(f"this openssl cannot build {name}: {exc}")
        return path

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


def _issue_dated(d: str, name: str, ca: str, ext: str, out: str,
                 start: str, end: str) -> None:
    """Re-issue `<name>.csr` signed by `ca`, valid from `start` to `end` (UTC).

    `openssl x509 -req` before 3.4 cannot set past dates; `openssl ca` can.
    """
    work = tempfile.mkdtemp(prefix="ca-", dir=d)
    open(os.path.join(work, "index.txt"), "w").close()
    with open(os.path.join(work, "serial"), "w") as fh:
        fh.write("1000\n")
    with open(os.path.join(work, "ext"), "w") as fh:
        fh.write(ext)
    with open(os.path.join(work, "ca.cnf"), "w") as fh:
        fh.write("[ca]\ndefault_ca = dated\n[dated]\n"
                 f"database = {work}/index.txt\nserial = {work}/serial\n"
                 f"new_certs_dir = {work}\ndefault_md = sha256\n"
                 "policy = anything\nunique_subject = no\n"
                 "[anything]\ncommonName = supplied\n")
    _run("ca", "-batch", "-notext", "-config", f"{work}/ca.cnf",
         "-cert", f"{ca}.pem", "-keyfile", f"{ca}.key", "-in", f"{name}.csr",
         "-startdate", start, "-enddate", end, "-extfile", f"{work}/ext",
         "-out", out, cwd=d)


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


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _cat(*parts):
    """Builder writing the concatenation of `parts` (callables of the PKI)."""
    def build(pki: "PKI", out: str) -> None:
        with open(out, "wb") as fh:
            fh.write(b"".join(part(pki) for part in parts))
    return build


def _file(attr: str):
    return lambda pki: _read(getattr(pki, attr))


def _truncated_int(pki: "PKI") -> bytes:
    return _read(pki.intermediate)[:400]


def _corrupt_int(pki: "PKI") -> bytes:
    lines = _read(pki.intermediate).split(b"\n")
    lines[3] = b"!!!!" + lines[3][4:]          # invalid Base64 inside the block
    return b"\n".join(lines)


def _der_leaf(pki: "PKI", out: str) -> None:
    import ssl
    with open(out, "wb") as fh:
        fh.write(ssl.PEM_cert_to_DER_cert(_read(pki.leaf).decode()))


def _pkcs7(pki: "PKI", out: str) -> None:
    _run("crl2pkcs7", "-nocrl", "-certfile", pki.fullchain, "-out", out, cwd=pki.dir)


def _pkcs12(pki: "PKI", out: str) -> None:
    _run("pkcs12", "-export", "-in", pki.leaf, "-inkey", pki.leaf_key,
         "-passout", "pass:secret", "-out", out, cwd=pki.dir)


def _csr(pki: "PKI", out: str) -> None:
    _run("req", "-new", "-key", pki.leaf_key, "-subj", f"/CN={HOSTNAME}", "-out", out,
         cwd=pki.dir)


def _empty(pki: "PKI", out: str) -> None:
    with open(out, "w") as fh:
        fh.write("  \n\n")


def _name_only_root(pki: "PKI", out: str) -> None:
    # issuer == subject because the signer's subject is reused, but the
    # signature is the other intermediate's, not the certificate's own
    d = pki.dir
    _run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "name_only.key",
         "-out", "name_only.csr", "-subj", "/CN=SSLDoctor Other Intermediate", cwd=d)
    with open(os.path.join(d, "name_only.ext"), "w") as fh:
        fh.write("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n")
    _run("x509", "-req", "-in", "name_only.csr", "-CA", "other_int.pem",
         "-CAkey", "other_int.key", "-CAcreateserial", "-out", out, "-days", "30",
         "-extfile", "name_only.ext", cwd=d)


def _ec_aia(pki: "PKI", out: str) -> None:
    _run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", out + ".key", "-out", out, "-subj", "/CN=ec.test",
         "-days", "30",
         "-addext", "authorityInfoAccess=caIssuers;URI:http://ca.test/int.crt,"
                    "OCSP;URI:http://ocsp.test",
         "-addext", "crlDistributionPoints=URI:http://crl.test/ca.crl",
         "-addext", "keyUsage=critical,digitalSignature",
         "-addext", "extendedKeyUsage=serverAuth,clientAuth",
         "-addext", "basicConstraints=critical,CA:FALSE", cwd=pki.dir)


def _ed25519(pki: "PKI", out: str) -> None:
    _run("req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", out + ".key",
         "-out", out, "-subj", "/CN=ed.test", "-days", "30", cwd=pki.dir)


def _forged_int(pki: "PKI", out: str) -> None:
    import ssl
    from ssl_doctor import certs
    ski = certs.decode_pem(ssl.DER_cert_to_PEM_cert(ssl.PEM_cert_to_DER_cert(
        _read(pki.intermediate).decode())).encode()).ski
    d = pki.dir
    _run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "forged.key", "-out",
         "forged.csr", "-subj", "/CN=SSLDoctor Test Intermediate", cwd=d)
    with open(os.path.join(d, "forged.ext"), "w") as fh:
        fh.write("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n"
                 f"subjectKeyIdentifier={ski}\nauthorityKeyIdentifier=keyid\n")
    _run("x509", "-req", "-in", "forged.csr", "-CA", "root.pem", "-CAkey", "root.key",
         "-CAcreateserial", "-out", out, "-days", "30", "-extfile", "forged.ext", cwd=d)


def _same_name_int(pki: "PKI", out: str) -> None:
    d = pki.dir
    _run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "same_name.key", "-out",
         "same_name.csr", "-subj", "/CN=SSLDoctor Test Intermediate", cwd=d)
    _run("x509", "-req", "-in", "same_name.csr", "-CA", "root.pem", "-CAkey", "root.key",
         "-CAcreateserial", "-out", out, "-days", "30", "-extfile", "int.ext", cwd=d)


def _leaf_issued(pki: "PKI", out: str) -> None:
    d = pki.dir
    _run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf_issued.key", "-out",
         "leaf_issued.csr", "-subj", "/CN=www.shop.test", cwd=d)
    _run("x509", "-req", "-in", "leaf_issued.csr", "-CA", "leaf.pem", "-CAkey", "leaf.key",
         "-CAcreateserial", "-out", out, "-days", "30", cwd=d)


def _self_signed_leaf(pki: "PKI", out: str) -> None:
    _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", out + ".key",
         "-out", out, "-subj", "/CN=self.test", "-days", "30",
         "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature",
         "-addext", "subjectAltName=DNS:self.test", cwd=pki.dir)


def _issue_sample(pki: "PKI", name: str, subject: str, ca_pem: str, ca_key: str,
                  ext: str, key: str = "") -> str:
    """Issue `<name>.pem` under `ca_pem`/`ca_key`; returns its path."""
    d = pki.dir
    keyopt = ["-key", key] if key else ["-newkey", "rsa:2048", "-nodes",
                                        "-keyout", f"{name}.key"]
    _run("req", "-new", *keyopt, "-out", f"{name}.csr", "-subj", subject, cwd=d)
    with open(os.path.join(d, f"{name}.ext"), "w") as fh:
        fh.write(ext)
    _run("x509", "-req", "-in", f"{name}.csr", "-CA", ca_pem, "-CAkey", ca_key,
         "-CAcreateserial", "-out", f"{name}.pem", "-days", "30",
         "-extfile", f"{name}.ext", cwd=d)
    return pki.path(f"{name}.pem")


def _nonca_chain(pki: "PKI", out: str) -> None:
    _cat(lambda p: _read(p.sample("leaf-issued.pem")), _file("leaf"))(pki, out)


def _pathlen_chain(pki: "PKI", out: str) -> None:
    sub = _issue_sample(pki, "sub_int", "/CN=SSLDoctor Sub CA", "int.pem", "int.key",
                        _CA_EXT.replace(",pathlen:0", ""))
    leaf = _issue_sample(pki, "deep_leaf", "/CN=deep.shop.test", "sub_int.pem",
                         "sub_int.key", _LEAF_EXT + "subjectAltName=DNS:deep.shop.test\n")
    _cat(lambda p: _read(leaf), lambda p: _read(sub), _file("intermediate"))(pki, out)


def _client_leaf(pki: "PKI", out: str) -> None:
    path = _issue_sample(pki, "client_leaf", f"/CN={HOSTNAME}", "int.pem", "int.key",
                         "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n"
                         f"subjectAltName=DNS:{HOSTNAME}\n")
    _cat(lambda p: _read(path), _file("intermediate"))(pki, out)


def _nosign_chain(pki: "PKI", out: str) -> None:
    inter = _issue_sample(pki, "nosign_int", "/CN=SSLDoctor NoSign CA", "root.pem",
                          "root.key", "basicConstraints=critical,CA:TRUE\n"
                          "keyUsage=critical,digitalSignature\n")
    leaf = _issue_sample(pki, "nosign_leaf", f"/CN={HOSTNAME}", "nosign_int.pem",
                         "nosign_int.key", _LEAF_EXT + f"subjectAltName=DNS:{HOSTNAME}\n")
    _cat(lambda p: _read(leaf), lambda p: _read(inter))(pki, out)


def _root2(pki: "PKI", out: str) -> None:
    _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root2.key",
         "-out", out, "-days", "30", "-subj", "/CN=SSLDoctor Test Root",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=pki.dir)


def _old_root(pki: "PKI", out: str) -> None:
    _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "old_root.key",
         "-out", out, "-days", "30", "-subj", "/CN=SSLDoctor Old Root",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=pki.dir)


def _cross_root(pki: "PKI", out: str) -> None:
    pki.sample("old-root.pem")
    path = _issue_sample(pki, "cross_root", "/CN=SSLDoctor Test Root", "old-root.pem",
                         "old_root.key", "basicConstraints=critical,CA:TRUE\n"
                         "keyUsage=critical,keyCertSign,cRLSign\n"
                         "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
                         key="root.key")
    os.replace(path, out)


def _case_chain(pki: "PKI", out: str) -> None:
    d = pki.dir
    _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "case.key",
         "-out", "case_ca.pem", "-days", "30", "-subj", "/CN=Case CA",
         "-addext", "basicConstraints=critical,CA:TRUE", cwd=d)
    child = _issue_sample(pki, "case_child", "/CN=case.test", "case_ca.pem", "case.key",
                          "basicConstraints=CA:FALSE\n")
    _run("req", "-x509", "-key", "case.key", "-out", "case_variant.pem", "-days", "30",
         "-subj", "/CN=CASE   ca", "-addext", "basicConstraints=critical,CA:TRUE", cwd=d)
    _cat(lambda p: _read(child), lambda p: _read(p.path("case_variant.pem")))(pki, out)


def _aia_leaf(pki: "PKI", out: str) -> None:
    path = _issue_sample(pki, "aia_leaf", f"/CN={HOSTNAME}", "int.pem", "int.key",
                         _LEAF_EXT + f"subjectAltName=DNS:{HOSTNAME}\n"
                         "authorityInfoAccess=caIssuers;URI:http://ca.test/int.crt\n")
    os.replace(path, out)


_SAMPLES = {
    "truncated.pem": _cat(_file("leaf"), _truncated_int),
    "corrupt.pem": _cat(_file("leaf"), _corrupt_int, _file("root")),
    "duplicate.pem": _cat(_file("leaf"), _file("intermediate"), _file("leaf")),
    "mixed.pem": _cat(_file("leaf"), _file("leaf_key")),
    "der-as.pem": _der_leaf,
    "pkcs7.crt": _pkcs7,
    "pkcs12.bin": _pkcs12,
    "key-only.crt": _cat(_file("leaf_key")),
    "csr.pem": _csr,
    "empty.pem": _empty,
    "reversed.pem": _cat(_file("intermediate"), _file("leaf")),
    "full-root.pem": _cat(_file("leaf"), _file("intermediate"), _file("root")),
    "unrelated.pem": _cat(_file("leaf"), _file("intermediate"), _file("other_intermediate")),
    "ca-bundle.pem": _cat(_file("root"), _file("intermediate")),
    "name-only-root.pem": _name_only_root,
    "ec-aia.pem": _ec_aia,
    "ed25519.pem": _ed25519,
    "forged-int.pem": _forged_int,
    "same-name-int.pem": _same_name_int,
    "leaf-issued.pem": _leaf_issued,
    "self-signed-leaf.pem": _self_signed_leaf,
    "nonca-chain.pem": _nonca_chain,
    "pathlen-chain.pem": _pathlen_chain,
    "client-leaf.pem": _client_leaf,
    "nosign-chain.pem": _nosign_chain,
    "root2.pem": _root2,
    "old-root.pem": _old_root,
    "cross-root.pem": _cross_root,
    "case-chain.pem": _case_chain,
    "aia-leaf.pem": _aia_leaf,
    "forged-chain.pem": _cat(_file("leaf"), lambda p: _read(p.sample("forged-int.pem"))),
}


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
