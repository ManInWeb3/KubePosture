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

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, Any]] = {}


def _ttl_seconds() -> float:
    raw = os.environ.get("METRICS_BUSINESS_TTL_SECONDS")
    if raw is None:
        return float(DEFAULT_TTL_SECONDS)
    try:
        return max(0.0, float(raw))
    except ValueError:
        return float(DEFAULT_TTL_SECONDS)


def cached(key: str, fn: Callable[[], Any]) -> Any:
    """Return ``fn()`` cached for ``METRICS_BUSINESS_TTL_SECONDS`` seconds."""
    now = time.monotonic()
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] > now:
            return hit[1]
    value = fn()
    expires = time.monotonic() + _ttl_seconds()
    with _LOCK:
        _CACHE[key] = (expires, value)
    return value


def reset() -> None:
    """Test helper — clears all cached entries."""
    with _LOCK:
        _CACHE.clear()
