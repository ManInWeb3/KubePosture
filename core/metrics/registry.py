"""TTL cache for the business collector — bounds DB load.

Without a cache, a 15s scrape interval means 4 round-trips/minute per
worker; with the default 300s TTL it's 12/hour regardless of scrape
rate. Tune via ``METRICS_BUSINESS_TTL_SECONDS``.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable

DEFAULT_TTL_SECONDS = 300
DEFAULT_QUEUE_TTL_SECONDS = 15

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, Any]] = {}


def _ttl_seconds() -> float:
    return _env_ttl("METRICS_BUSINESS_TTL_SECONDS", DEFAULT_TTL_SECONDS)


def queue_ttl_seconds() -> float:
    """Short TTL for the cheap ingest-queue gauges. Each gunicorn worker
    holds its own cache, so with the business TTL a scrape could land on a
    worker serving a 5-minute-old snapshot — the queue line flip-flopped
    between workers' values. Tune via ``METRICS_QUEUE_TTL_SECONDS``."""
    return _env_ttl("METRICS_QUEUE_TTL_SECONDS", DEFAULT_QUEUE_TTL_SECONDS)


def _env_ttl(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return float(default)
    try:
        return max(0.0, float(raw))
    except ValueError:
        return float(default)


def cached(key: str, fn: Callable[[], Any], ttl: float | None = None) -> Any:
    """Return ``fn()`` cached for ``ttl`` seconds (default
    ``METRICS_BUSINESS_TTL_SECONDS``)."""
    now = time.monotonic()
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] > now:
            return hit[1]
    value = fn()
    expires = time.monotonic() + (_ttl_seconds() if ttl is None else ttl)
    with _LOCK:
        _CACHE[key] = (expires, value)
    return value


def reset() -> None:
    """Test helper — clears all cached entries."""
    with _LOCK:
        _CACHE.clear()
