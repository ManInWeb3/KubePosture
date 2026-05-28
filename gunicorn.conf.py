"""Gunicorn config — wires prometheus-client multi-process mode.

Each worker writes its Counter / Histogram samples to mmap files in
``PROMETHEUS_MULTIPROC_DIR``; the ``/metrics`` view aggregates across
workers with ``MultiProcessCollector``. We clean stale shards on boot
(gunicorn does not GC them — leftover state from a previous container
generation would inflate counter values) and reap per-worker shards
on clean exit via the ``child_exit`` hook.

The ``worker_abort`` hook counts arbiter-triggered SIGABRT kills (when
a worker exceeds ``timeout``). Sync workers were vulnerable to slow /
half-open client connections starving the whole pod; we switched to
``gthread`` in values.yaml, but this counter stays as the canonical
signal — any non-zero rate means the new headroom isn't enough.
"""
import os
import shutil

from prometheus_client import Counter

_MULTIPROC_DIR = os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", "/tmp/prom_multiproc")

if os.path.isdir(_MULTIPROC_DIR):
    shutil.rmtree(_MULTIPROC_DIR, ignore_errors=True)
os.makedirs(_MULTIPROC_DIR, exist_ok=True)


# Created at config-load time so the metric is registered in every worker
# (gunicorn re-executes this file on fork). prometheus_client keys mmap
# shards by PID lazily, so the per-worker file is created on first ``inc()``
# inside the worker; counters survive worker exit because MultiProcessCollector
# reads dead shards too.
_WORKER_ABORTS = Counter(
    "kubeposture_gunicorn_worker_aborts_total",
    "Gunicorn workers killed by the arbiter after exceeding `timeout` (SIGABRT).",
)


def worker_abort(worker):
    # Runs inside the dying worker (it's the SIGABRT signal handler),
    # so the inc() lands in that worker's shard before sys.exit.
    _WORKER_ABORTS.inc()


def child_exit(server, worker):
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(worker.pid)
