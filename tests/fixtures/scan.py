"""Run ssl-doctor checks against fixture servers with a controlled trust store."""

from __future__ import annotations

import contextlib
import io
import os
import ssl
from typing import Iterable, Optional
from unittest import mock

from ssl_doctor import cli, findings as F, local, netchecks

from .pki import HOSTNAME, get_pki
from .tls_server import TLSServer


def trust_env(trust: Iterable[str]):
    """Patch the system trust store to the given PKI members (e.g. root + intermediate)."""
    pki = get_pki()
    return mock.patch.dict(os.environ, {"SSL_CERT_FILE": pki.bundle(*trust),
                                        "SSL_CERT_DIR": pki.dir})


def scan(mode: str, trust: Iterable[str] = ("root",), readers: Optional[tuple] = None):
    """Run the remote suite against a fixture server; returns (by_check, facts)."""
    pki = get_pki()
    with contextlib.ExitStack() as stack:
        stack.enter_context(trust_env(trust))
        if readers is not None:
            stack.enter_context(mock.patch.object(netchecks, "CHAIN_READERS", readers))
        srv = stack.enter_context(TLSServer(pki, mode))
        items, facts = netchecks.run_remote_diagnostics(
            srv.host, srv.port, sni=HOSTNAME, timeout=4)
    return {f.check: f for f in items}, facts


@contextlib.contextmanager
def windows_client(root_pems: Iterable[str]):
    """Simulate a Windows client whose ROOT store holds exactly `root_pems`.

    `ssl.enum_certificates` yields real-shaped (der, encoding, trust) 3-tuples.
    Yields a list collecting the files passed to the certutil check.
    """
    ders = []
    for path in root_pems:
        with open(path) as fh:
            ders.append(ssl.PEM_cert_to_DER_cert(fh.read()))
    certutil_calls = []

    def fake_certutil(path):
        with open(path, "rb") as fh:
            certutil_calls.append(fh.read())
        return F.Finding("local.certutil", "certutil (simulated)", F.PASS,
                         F.SCOPE_LOCAL, ["simulated"])

    stub = lambda check: (lambda *a, **k: F.Finding(  # noqa: E731
        check, check, F.NOT_TESTED, F.SCOPE_LOCAL, ["simulated"]))
    with mock.patch.object(local, "IS_WINDOWS", True), \
            mock.patch.object(ssl, "enum_certificates", create=True,
                              new=lambda store: [(d, "x509_asn", True) for d in ders]
                              if store == "ROOT" else []), \
            mock.patch.object(local, "check_proxy_config", stub("local.proxy")), \
            mock.patch.object(local, "check_schannel_events", stub("local.events")), \
            mock.patch.object(local, "check_certutil_verify", fake_certutil):
        yield certutil_calls


def cli_session(mode: str, trust: Iterable[str] = ("root",), windows_roots=None,
                extra_findings=()):
    """Run '/tls' then '/local' as the CLI would; returns the CLI object."""
    app = cli.SSLDoctorCLI()
    by, facts = scan(mode, trust)
    app.store.extend(list(by.values()))
    app.remote_facts = facts
    with contextlib.ExitStack() as stack:
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(trust_env(trust))
        if windows_roots is not None:
            app.certutil_calls = stack.enter_context(windows_client(windows_roots))
        app.cmd_local([])
    app.store.extend(list(extra_findings))
    return app
