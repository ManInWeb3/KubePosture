"""Tiny stdlib reverse proxy between the real importer process and
pytest-django's live_server, able to fail or delay chosen paths.

Rules (`fail_paths`, `delay_paths`, `watch`) match when the rule string
is a SUBSTRING of the request path — bundle paths embed a fresh
import_id, so `"/bundles/trivy.SbomReport/"` is the natural key."""
from __future__ import annotations

import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class ChaosProxy:
    def __init__(self, upstream_url: str, *, fail_paths: dict[str, int] | None = None,
                 delay_paths: dict[str, float] | None = None):
        split = urlsplit(upstream_url)
        self.upstream_host = split.hostname
        self.upstream_port = split.port
        self.fail_paths = dict(fail_paths or {})
        self.delay_paths = dict(delay_paths or {})
        self.seen: list[str] = []
        self.events: dict[str, threading.Event] = {}
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # quiet
                pass

            def _handle(self):
                path = self.path
                proxy.seen.append(path)
                for rule, ev in proxy.events.items():
                    if rule in path:
                        ev.set()
                length = int(self.headers.get("Content-Length") or 0)
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
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                conn.close()

            do_GET = do_POST = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def watch(self, rule: str) -> threading.Event:
        return self.events.setdefault(rule, threading.Event())

    def __enter__(self) -> "ChaosProxy":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
