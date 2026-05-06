"""``GET /metrics`` — Prometheus exposition.

Single registry instance of ``KubePostureCollector`` is registered to
the default REGISTRY at import time so it's picked up in single-process
mode (e.g. ``runserver`` and tests). In multi-process mode (gunicorn
with ``PROMETHEUS_MULTIPROC_DIR`` set) we build a fresh registry per
request that combines ``MultiProcessCollector`` (aggregates middleware
counters across workers via mmap) with the same business collector
(queries DB directly — no IPC needed).
"""
from __future__ import annotations

import os

from django.http import HttpResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    generate_latest,
    multiprocess,
)

from .collectors import KubePostureCollector

_BUSINESS_COLLECTOR = KubePostureCollector()
try:
    REGISTRY.register(_BUSINESS_COLLECTOR)
except ValueError:
    # Already registered — happens with module reloads in tests.
    pass


def metrics_view(request):
    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        registry.register(_BUSINESS_COLLECTOR)
        body = generate_latest(registry)
    else:
        body = generate_latest(REGISTRY)
    return HttpResponse(body, content_type=CONTENT_TYPE_LATEST)
