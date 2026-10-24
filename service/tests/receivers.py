"""Local alert receivers: an HTTP webhook sink and a minimal SMTP sink."""

from __future__ import annotations

import http.server
import socketserver
import threading
import time


class WebhookSink:
    def __init__(self) -> None:
        self.requests = []
        sink = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                sink.requests.append((dict(self.headers), body))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *a):
                pass

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}/hook"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self._srv.shutdown()


class SMTPSink:
    """Just enough SMTP (HELO/EHLO, MAIL, RCPT, DATA, QUIT) to capture messages."""

    def __init__(self) -> None:
        self.messages = []
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def reply(self, line):
                self.wfile.write((line + "\r\n").encode())

            def handle(self):
                self.reply("220 sink ESMTP")
                rcpt, data = [], None
                for raw in self.rfile:
                    line = raw.decode().rstrip("\r\n")
                    if data is not None:
                        if line == ".":
                            sink.messages.append({"to": rcpt, "data": "\n".join(data)})
                            data, rcpt = None, []
                            self.reply("250 queued")
                        else:
                            data.append(line[1:] if line.startswith("..") else line)
                        continue
                    cmd = line[:4].upper()
                    if cmd in ("HELO", "EHLO"):
                        self.reply("250 sink")
                    elif cmd == "MAIL":
                        self.reply("250 ok")
                    elif cmd == "RCPT":
                        rcpt.append(line.split(":", 1)[1].strip(" <>"))
                        self.reply("250 ok")
                    elif cmd == "DATA":
                        data = []
                        self.reply("354 end with .")
                    elif cmd == "QUIT":
                        self.reply("221 bye")
                        return
                    else:
                        self.reply("250 ok")

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._srv = Server(("127.0.0.1", 0), Handler)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self._srv.shutdown()


def wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()
