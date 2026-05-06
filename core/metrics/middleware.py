"""Django request counter + latency histogram.

Skips ``/metrics``, ``/healthz``, ``/readyz`` so those don't pollute
the latency baseline. Labels stay narrow on purpose: putting the raw
URL ``path`` in here would explode cardinality on routes like
``/api/v1/findings/<id>/``.
"""
from __future__ import annotations

import time

from prometheus_client import Counter, Histogram

_REQUESTS = Counter(
    "django_http_requests_total",
    "HTTP requests handled by Django.",
    ["view", "method", "status"],
)
_LATENCY = Histogram(
    "django_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["view", "method"],
)

_SKIP_PREFIXES = ("/metrics", "/healthz", "/readyz")


class PrometheusMetricsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(_SKIP_PREFIXES):
            return self.get_response(request)
        start = time.monotonic()
        response = self.get_response(request)
        elapsed = time.monotonic() - start
        match = getattr(request, "resolver_match", None)
        view = getattr(match, "view_name", None) if match else None
        view = view or "unmatched"
        _REQUESTS.labels(view=view, method=request.method, status=str(response.status_code)).inc()
        _LATENCY.labels(view=view, method=request.method).observe(elapsed)
        return response
