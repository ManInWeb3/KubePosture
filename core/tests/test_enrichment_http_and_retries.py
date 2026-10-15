"""The enrichment paths every other test patches out: the deadlock-retry
wrapper around the bulk Finding UPDATEs, the streaming HTTP helpers, and
the conditional (ETag) download."""
from __future__ import annotations

import io
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest
from django.db import OperationalError

from core.models import FeedFetchState
from core.services import enrichment


# ── _exec_with_deadlock_retry ─────────────────────────────────────


class _Deadlock(Exception):
    sqlstate = "40P01"


class _Other(Exception):
    sqlstate = "23505"


def _cursor_raising(exc_types, rows=()):
    """`connection.cursor()` context manager whose execute() raises the
    next exception type in `exc_types` (None = succeed)."""
    calls = iter(exc_types)
    cur = MagicMock()
    cur.description = [("id",)] if rows else None
    cur.fetchall.return_value = list(rows)

    def execute(sql):
        cause = next(calls)
        if cause is not None:
            raise OperationalError("boom") from cause()
    cur.execute.side_effect = execute
    cm = MagicMock()
    cm.__enter__.return_value = cur
    return cm, cur


def test_deadlock_is_retried_with_backoff_then_returns_the_rows():
    cm, cur = _cursor_raising([_Deadlock, _Deadlock, None], rows=[(7,), (9,)])
    with patch.object(enrichment.connection, "cursor", return_value=cm), \
         patch.object(enrichment.time, "sleep") as sleep:
        assert enrichment._exec_with_deadlock_retry("UPDATE x") == [7, 9]
    assert cur.execute.call_count == 3
    assert [c.args[0] for c in sleep.call_args_list] == [0.5, 1.0]


def test_non_deadlock_error_is_raised_immediately():
    cm, cur = _cursor_raising([_Other])
    with patch.object(enrichment.connection, "cursor", return_value=cm), \
         patch.object(enrichment.time, "sleep") as sleep, pytest.raises(OperationalError):
        enrichment._exec_with_deadlock_retry("UPDATE x")
    assert cur.execute.call_count == 1 and sleep.call_count == 0


def test_persistent_deadlock_gives_up_after_the_attempt_cap():
    cm, cur = _cursor_raising([_Deadlock] * enrichment._DEADLOCK_MAX_ATTEMPTS)
    with patch.object(enrichment.connection, "cursor", return_value=cm), \
         patch.object(enrichment.time, "sleep"), pytest.raises(OperationalError):
        enrichment._exec_with_deadlock_retry("UPDATE x")
    assert cur.execute.call_count == enrichment._DEADLOCK_MAX_ATTEMPTS


# ── _http_open ────────────────────────────────────────────────────


class _Resp(io.BytesIO):
    def __init__(self, body=b"ok", headers=None):
        super().__init__(body)
        self.headers = headers or {}
        self.status = 200


def _http_error(code):
    return HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


def test_http_open_does_not_retry_client_errors():
    with patch.object(enrichment, "urlopen", side_effect=[_http_error(404)]) as uo, \
         patch.object(enrichment.time, "sleep") as sleep:
        with enrichment._http_open("https://x") as resp:
            assert resp is None
    assert uo.call_count == 1 and sleep.call_count == 0


def test_http_open_retries_transport_errors_then_gives_up():
    with patch.object(enrichment, "urlopen", side_effect=[URLError("down")] * 3) as uo, \
         patch.object(enrichment.time, "sleep") as sleep:
        with enrichment._http_open("https://x") as resp:
            assert resp is None
    assert uo.call_count == 3 and sleep.call_count == 2


def test_http_open_yields_the_response_after_a_retried_5xx():
    with patch.object(enrichment, "urlopen", side_effect=[_http_error(503), _Resp(b"body")]) as uo, \
         patch.object(enrichment.time, "sleep"):
        with enrichment._http_open("https://x") as resp:
            assert resp.read() == b"body"
    assert uo.call_count == 2


# ── _http_download_conditional ────────────────────────────────────


@pytest.mark.django_db
def test_conditional_download_sends_validators_and_returns_none_on_304():
    FeedFetchState.objects.create(state_key="osv:npm", etag='"e1"', last_modified="Wed, 01 Jan 2025 00:00:00 GMT")
    with patch.object(enrichment, "urlopen", side_effect=[_http_error(304)]) as uo:
        assert enrichment._http_download_conditional("https://x/all.zip", state_key="osv:npm", suffix=".zip") is None
    req = uo.call_args.args[0]
    assert req.get_header("If-none-match") == '"e1"'
    assert req.get_header("If-modified-since") == "Wed, 01 Jan 2025 00:00:00 GMT"


@pytest.mark.django_db
def test_conditional_download_streams_to_a_temp_file_and_carries_the_validators():
    resp = _Resp(b"zipbytes", headers={"ETag": '"e2"', "Last-Modified": "Thu, 02 Jan 2025 00:00:00 GMT"})
    with patch.object(enrichment, "urlopen", return_value=resp):
        path = enrichment._http_download_conditional("https://x/all.zip", state_key="osv:npm", suffix=".zip")
    try:
        assert isinstance(path, enrichment._DownloadPath)
        assert open(path, "rb").read() == b"zipbytes"
        assert path.fetch_state == {"etag": '"e2"', "last_modified": "Thu, 02 Jan 2025 00:00:00 GMT"}
        assert not FeedFetchState.objects.filter(state_key="osv:npm").exists(), "persisted only after apply"
    finally:
        import os
        os.unlink(path)


@pytest.mark.django_db
def test_fetch_kev_returns_zero_when_the_stream_dies_mid_body():
    broken = MagicMock()
    broken.read.side_effect = ConnectionResetError("mid-body")
    with patch.object(enrichment, "urlopen", return_value=broken), \
         patch.object(enrichment, "load_kev_from_file") as load:
        assert enrichment.fetch_kev() == 0
    load.assert_not_called()
