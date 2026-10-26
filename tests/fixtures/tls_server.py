"""Local TLS endpoints backed by `openssl s_server`.

Modes:
    leaf-only   server sends only the leaf certificate
    full-chain  server sends leaf + issuing intermediate
    wrong-chain server sends leaf + an intermediate that did not issue it
    cn-only     server sends a CN-only leaf (no SAN) + intermediate
    expired-intermediate  server sends leaf + an expired copy of its intermediate
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from typing import List

from .pki import PKI

MODES = ("leaf-only", "full-chain", "wrong-chain", "cn-only", "expired-intermediate")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TLSServer:
    """Context manager: `with TLSServer(pki, "leaf-only") as srv: srv.port`."""

    def __init__(self, pki: PKI, mode: str, chain: str = "", status_file: str = "") -> None:
        """`chain`: a PEM file of extra certificates to send after the leaf,
        replacing the mode's intermediates.  `status_file`: a DER OCSP
        response the server staples."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        self.pki, self.mode, self.chain = pki, mode, chain
        self.status_file = status_file
        self.host = "127.0.0.1"
        self.port = 0
        self._proc = None

    def _argv(self) -> List[str]:
        p = self.pki
        cert, key, chain = p.leaf, p.leaf_key, None
        if self.mode == "full-chain":
            chain = p.intermediate
        elif self.mode == "wrong-chain":
            chain = p.other_intermediate
        elif self.mode == "expired-intermediate":
            chain = p.expired_intermediate
        elif self.mode == "cn-only":
            cert, key, chain = p.cn_only, p.cn_only_key, p.intermediate
        # -no-CAfile/-no-CApath: otherwise OpenSSL completes the chain from its
        # trust store and a "leaf-only" server silently sends intermediates.
        argv = ["openssl", "s_server", "-quiet", "-www", "-no-CAfile", "-no-CApath",
                "-accept", f"{self.host}:{self.port}", "-cert", cert, "-key", key]
        chain = self.chain or chain
        if chain:
            argv += ["-cert_chain", chain]
        if self.status_file:
            argv += ["-status_file", self.status_file]
        return argv

    def __enter__(self) -> "TLSServer":
        self.port = _free_port()
        env = {k: v for k, v in os.environ.items()
               if k not in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
        self._proc = subprocess.Popen(self._argv(), env=env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"openssl s_server exited ({self.mode})")
            try:
                socket.create_connection((self.host, self.port), timeout=0.5).close()
                return self
            except OSError:
                time.sleep(0.05)
        self.__exit__()
        raise RuntimeError(f"openssl s_server did not start ({self.mode})")

    def __exit__(self, *exc) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
