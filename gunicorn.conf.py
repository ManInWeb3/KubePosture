"""Gunicorn config — wires prometheus-client multi-process mode.

Each worker writes its Counter / Histogram samples to mmap files in
``PROMETHEUS_MULTIPROC_DIR``; the ``/metrics`` view aggregates across
workers with ``MultiProcessCollector``. We clean stale shards on boot
(gunicorn does not GC them — leftover state from a previous container
generation would inflate counter values) and reap per-worker shards
on clean exit via the ``child_exit`` hook.
"""
import os
import shutil

_MULTIPROC_DIR = os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", "/tmp/prom_multiproc")

if os.path.isdir(_MULTIPROC_DIR):
    shutil.rmtree(_MULTIPROC_DIR, ignore_errors=True)
os.makedirs(_MULTIPROC_DIR, exist_ok=True)


def child_exit(server, worker):
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(worker.pid)
