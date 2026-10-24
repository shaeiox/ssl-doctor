"""TCP endpoints that misbehave in a specific, reproducible way.

Modes:
    stall       accept every connection and never answer (TLS negotiation stall)
    stall-once  stall the first TLS attempt, serve real TLS (full chain) afterwards
    alert       answer the ClientHello with a fatal handshake_failure alert

These are pure-socket fixtures: they need no `openssl` binary, except
`stall-once`, which proxies to an `openssl s_server` upstream so that the
recovered connection carries a real certificate and chain.

A connection that closes without sending any bytes (for example the TCP
reachability check) is not counted as a TLS attempt, so the counters describe
what a TLS client observed.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from typing import List, Optional

from .pki import PKI
from .tls_server import _free_port

FAULT_MODES = ("stall", "stall-once", "alert")

# TLS record: alert (21), legacy version 0x0303, length 2, fatal(2) handshake_failure(40)
_HANDSHAKE_FAILURE_ALERT = b"\x15\x03\x03\x00\x02\x02\x28"
_CLIENT_HELLO_READ_TIMEOUT = 5.0


class FaultServer:
    """Context manager: `with FaultServer(pki, "stall") as srv: srv.port`."""

    def __init__(self, pki: PKI, mode: str, upstream_chain: bool = True) -> None:
        if mode not in FAULT_MODES:
            raise ValueError(f"unknown fault mode {mode!r}")
        self.pki, self.mode = pki, mode
        self.upstream_chain = upstream_chain
        self.host = "127.0.0.1"
        self.port = 0
        self.tls_attempts = 0          # connections that sent a ClientHello
        self.tcp_connections = 0       # every accepted connection
        self._srv: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._workers: List[threading.Thread] = []
        self._upstream: Optional[subprocess.Popen] = None
        self._upstream_port = 0

    # ---------------------------------------------------------------- upstream
    def _start_upstream(self) -> None:
        self._upstream_port = _free_port()
        argv = ["openssl", "s_server", "-quiet", "-www", "-no-CAfile", "-no-CApath",
                "-accept", f"{self.host}:{self._upstream_port}",
                "-cert", self.pki.leaf, "-key", self.pki.leaf_key]
        if self.upstream_chain:
            argv += ["-cert_chain", self.pki.intermediate]
        self._upstream = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._upstream.poll() is not None:
                raise RuntimeError("upstream openssl s_server exited")
            try:
                socket.create_connection((self.host, self._upstream_port),
                                         timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("upstream openssl s_server did not start")

    # --------------------------------------------------------------- lifecycle
    def __enter__(self) -> "FaultServer":
        if self.mode == "stall-once":
            self._start_upstream()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self.host, 0))
        self.port = self._srv.getsockname()[1]
        self._srv.listen(16)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
            self._srv = None
        for worker in self._workers:
            worker.join(timeout=2)
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self._upstream is not None:
            if self._upstream.poll() is None:
                self._upstream.terminate()
                try:
                    self._upstream.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._upstream.kill()
            self._upstream = None

    # ----------------------------------------------------------------- serving
    def _accept_loop(self) -> None:
        assert self._srv is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.tcp_connections += 1
            worker = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            worker.start()
            self._workers.append(worker)

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(_CLIENT_HELLO_READ_TIMEOUT)
            try:
                hello = conn.recv(65536)
            except (socket.timeout, OSError):
                hello = b""
            if not hello:
                conn.close()               # plain reachability probe: not an attempt
                return
            self.tls_attempts += 1
            attempt = self.tls_attempts
            if self.mode == "alert":
                conn.sendall(_HANDSHAKE_FAILURE_ALERT)
                conn.close()
                return
            if self.mode == "stall" or (self.mode == "stall-once" and attempt == 1):
                while not self._stop.is_set():   # never answer: the client must time out
                    time.sleep(0.05)
                conn.close()
                return
            self._proxy(conn, hello)
        except OSError:
            try:
                conn.close()
            except OSError:
                pass

    def _proxy(self, conn: socket.socket, first_bytes: bytes) -> None:
        upstream = socket.create_connection((self.host, self._upstream_port), timeout=5)
        try:
            upstream.sendall(first_bytes)

            def pump(src: socket.socket, dst: socket.socket) -> None:
                try:
                    while not self._stop.is_set():
                        chunk = src.recv(65536)
                        if not chunk:
                            break
                        dst.sendall(chunk)
                except OSError:
                    pass
                finally:
                    for s in (src, dst):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            t = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
            t.start()
            pump(conn, upstream)
            t.join(timeout=3)
        finally:
            for s in (upstream, conn):
                try:
                    s.close()
                except OSError:
                    pass
