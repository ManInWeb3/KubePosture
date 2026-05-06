"""Prometheus metrics surface — runtime + Django + business gauges.

The endpoint is mounted at ``/metrics`` (see ``kubeposture/urls.py``).
Multi-process (gunicorn) mode is opt-in via ``PROMETHEUS_MULTIPROC_DIR``.
Business gauges are computed by ``KubePostureCollector`` with a TTL cache
(``METRICS_BUSINESS_TTL_SECONDS``, default 300) so a tight scrape interval
doesn't translate into a tight DB-query interval.
"""
