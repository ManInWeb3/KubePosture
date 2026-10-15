"""Tiny stdlib reverse proxy between the real importer process and
pytest-django's live_server, able to break the transfer in the ways a
real network does.

Rules are matched as a SUBSTRING of the request path — bundle paths embed
a fresh import_id, so `"/bundles/trivy.SbomReport/"` is the natural key.

  fail_paths      {rule: status}  answer with this status, never reach the server
  delay_paths     {rule: seconds} hold the request, then forward it
  cut_request     {rule: n}       first n matching requests: read HALF the body,
                                  then drop the connection (client sees a reset /
                                  disconnect mid-upload; the server never sees it)
  drop_response   {rule: n}       first n matching requests: forward to the server,
                                  let it fully process, then drop the connection
                                  without answering (lost response)
  hold_paths      {rule}          read the whole body, never forward, never answer —
                                  the upload "hangs" until the proxy closes (use it to
                                  freeze an importer at a known point, then kill it)
  watch(rule)     Event set when a matching request arrives
"""
from __future__ import annotations

import http.client
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class ChaosProxy:
    def __init__(
        self,
        upstream_url: str,
        *,
        fail_paths: dict[str, int] | None = None,
        delay_paths: dict[str, float] | None = None,
        cut_request: dict[str, int] | None = None,
        drop_response: dict[str, int] | None = None,
        hold_paths: set[str] | None = None,
    ):
        split = urlsplit(upstream_url)
        self.upstream_host = split.hostname
        self.upstream_port = split.port
        self.fail_paths = dict(fail_paths or {})
        self.delay_paths = dict(delay_paths or {})
        self.cut_request = dict(cut_request or {})
        self.drop_response = dict(drop_response or {})
        self.hold_paths = set(hold_paths or ())
        self.seen: list[str] = []
        self.events: dict[str, threading.Event] = {}
        self.release = threading.Event()
        self._lock = threading.Lock()
        proxy = self

        def _match(rules, path):
            return next((r for r in rules if r in path), None)

        def _consume(counter: dict[str, int], path: str) -> bool:
            with proxy._lock:
                rule = _match(counter, path)
                if rule is not None and counter[rule] > 0:
                    counter[rule] -= 1
                    return True
            return False

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # quiet
                pass

            def _drop(self):
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()

            def _handle(self):
                path = self.path
                with proxy._lock:
                    proxy.seen.append(path)
                for rule, ev in proxy.events.items():
                    if rule in path:
                        ev.set()
                length = int(self.headers.get("Content-Length") or 0)

                if _match(proxy.hold_paths, path) is not None:
                    if length:
                        self.rfile.read(length)
                    proxy.release.wait()
                    return self._drop()

                if _consume(proxy.cut_request, path):
                    if length:
                        self.rfile.read(length // 2)
                    return self._drop()

                body = self.rfile.read(length) if length else b""
                for rule, seconds in proxy.delay_paths.items():
                    if rule in path:
                        threading.Event().wait(seconds)
                for rule, status in proxy.fail_paths.items():
                    if rule in path:
                        payload = b'{"error":"chaos"}'
                        self.send_response(status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return

                conn = http.client.HTTPConnection(proxy.upstream_host, proxy.upstream_port, timeout=60)
                headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "transfer-encoding")}
                conn.request(self.command, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                conn.close()

                if _consume(proxy.drop_response, path):
                    return self._drop()

                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def watch(self, rule: str) -> threading.Event:
        return self.events.setdefault(rule, threading.Event())

    def count(self, rule: str) -> int:
        return sum(1 for p in self.seen if rule in p)

    def __enter__(self) -> "ChaosProxy":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.release.set()
        self._server.shutdown()
        self._server.server_close()
