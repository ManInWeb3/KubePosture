"""Thin urllib client with retries, fail-fast on client errors, and a
wall-clock deadline so a slow central can't push the importer past its
Job's activeDeadlineSeconds without a clean abort.

Retry (with exponential backoff): connection-level errors
(`OSError` covers URLError / timeouts / ConnectionResetError;
`http.client.HTTPException` covers RemoteDisconnected), 5xx, 408, 429.
Fail fast: any other 4xx — a 409/400 won't fix itself by retrying.
"""
from __future__ import annotations

import http.client
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HTTP_TIMEOUT_DEFAULT = 60
HTTP_MAX_ATTEMPTS = 3
HTTP_RETRY_BASE_DELAY = 2.5
GET_MAX_ATTEMPTS = 3
GET_RETRY_BASE_DELAY = 0.5
_RETRY_STATUSES = frozenset({408, 429})


@dataclass(frozen=True)
class HttpResult:
    ok: bool
    status: int
    body: str
    retryable: bool = False

    def json(self) -> dict | None:
        try:
            doc = json.loads(self.body)
        except (ValueError, TypeError):
            return None
        return doc if isinstance(doc, dict) else None


class HttpClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: int = HTTP_TIMEOUT_DEFAULT,
        max_attempts: int = HTTP_MAX_ATTEMPTS,
        base_delay: float = HTTP_RETRY_BASE_DELAY,
        deadline_at: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        urlopen_fn: Callable = urlopen,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.deadline_at = deadline_at
        self._sleep = sleep
        self._urlopen = urlopen_fn
        self._clock = clock

    # ── public ─────────────────────────────────────────────────────

    def post_json(self, path: str, body: dict) -> HttpResult:
        data = json.dumps(body).encode("utf-8")
        req = Request(
            self.base_url + path, data=data, method="POST",
            headers={**self._auth(), "Content-Type": "application/json"},
        )
        return self._request(req, max_attempts=self.max_attempts, base_delay=self.base_delay)

    def post_file(self, path: str, fileobj: BinaryIO, *, content_length: int,
                  headers: dict[str, str]) -> HttpResult:
        """Stream `fileobj` as the body. Content-Length is set explicitly
        so urllib never falls back to chunked transfer encoding (which
        some ingress controllers reject); the file is rewound before
        every attempt."""
        req = Request(
            self.base_url + path, data=fileobj, method="POST",
            headers={**self._auth(), **headers, "Content-Length": str(content_length)},
        )
        return self._request(
            req, max_attempts=self.max_attempts, base_delay=self.base_delay,
            rewind=lambda: fileobj.seek(0),
        )

    def get(self, path: str) -> HttpResult:
        req = Request(self.base_url + path, method="GET", headers=self._auth())
        return self._request(req, max_attempts=GET_MAX_ATTEMPTS, base_delay=GET_RETRY_BASE_DELAY)

    # ── internals ──────────────────────────────────────────────────

    def _auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def _past_deadline(self) -> bool:
        return self.deadline_at is not None and self._clock() >= self.deadline_at

    def _request(self, req: Request, *, max_attempts: int, base_delay: float,
                 rewind: Callable[[], object] | None = None) -> HttpResult:
        last = HttpResult(False, 0, "no attempt made", retryable=True)
        for attempt in range(1, max_attempts + 1):
            if self._past_deadline():
                return HttpResult(False, 0, "upload deadline exceeded", retryable=False)
            if rewind is not None:
                rewind()
            try:
                with self._urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode(errors="replace")
                    return HttpResult(True, resp.status, body)
            except HTTPError as e:
                try:
                    body = e.read().decode(errors="replace")
                except Exception:  # pragma: no cover - defensive
                    body = ""
                retryable = e.code >= 500 or e.code in _RETRY_STATUSES
                last = HttpResult(False, e.code, body[:2000], retryable=retryable)
                if not retryable:
                    return last
            except (OSError, http.client.HTTPException) as e:
                last = HttpResult(False, 0, f"connection error: {e}", retryable=True)
            if attempt < max_attempts:
                self._sleep(base_delay * (2 ** (attempt - 1)))
        return last
