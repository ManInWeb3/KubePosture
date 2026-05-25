"""Integration tests for `manage.py prune_stale_data`."""
from __future__ import annotations

import io
from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from core.constants import IngestQueueStatus
from core.models import IngestQueue


def _bump(obj, **fields):
    type(obj).objects.filter(pk=obj.pk).update(**fields)
    obj.refresh_from_db()
    return obj


def _stale_queue_row():
    q = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i", raw_json={},
        status=IngestQueueStatus.DONE.value,
    )
    _bump(q, processed_at=timezone.now() - timedelta(days=30))
    return q


@pytest.mark.django_db
def test_command_runs_end_to_end_default_flags():
    stale = _stale_queue_row()
    out = io.StringIO()
    call_command("prune_stale_data", stdout=out, stderr=io.StringIO())
    body = out.getvalue()
    assert "ingest_queue: scanned=1 deleted=1" in body
    assert "deleted 1 of 1 scanned" in body
    assert not IngestQueue.objects.filter(pk=stale.pk).exists()


@pytest.mark.django_db
def test_command_dry_run_does_not_delete():
    stale = _stale_queue_row()
    out = io.StringIO()
    call_command("prune_stale_data", "--dry-run", stdout=out, stderr=io.StringIO())
    body = out.getvalue()
    assert "ingest_queue: scanned=1 deleted=0" in body
    assert "would delete 0 of 1 scanned" in body
    assert IngestQueue.objects.filter(pk=stale.pk).exists()


@pytest.mark.django_db
def test_command_skip_flag_excludes_target():
    stale = _stale_queue_row()
    out = io.StringIO()
    call_command(
        "prune_stale_data", "--skip-ingest-queue",
        stdout=out, stderr=io.StringIO(),
    )
    body = out.getvalue()
    assert "ingest_queue: skipped" in body
    assert IngestQueue.objects.filter(pk=stale.pk).exists()


@pytest.mark.django_db
def test_command_custom_retention_per_target():
    """A 60-day retention shouldn't prune a 30-day-old DONE row."""
    stale = _stale_queue_row()   # 30 days old
    out = io.StringIO()
    call_command(
        "prune_stale_data", "--ingest-queue-days", "60",
        stdout=out, stderr=io.StringIO(),
    )
    body = out.getvalue()
    assert "ingest_queue: scanned=0 deleted=0" in body
    assert IngestQueue.objects.filter(pk=stale.pk).exists()


@pytest.mark.django_db
def test_command_is_idempotent():
    """Run twice; second run reports zero scanned across all targets."""
    _stale_queue_row()
    call_command("prune_stale_data", stdout=io.StringIO(), stderr=io.StringIO())
    out = io.StringIO()
    call_command("prune_stale_data", stdout=out, stderr=io.StringIO())
    body = out.getvalue()
    assert "ingest_queue: scanned=0 deleted=0" in body
    assert "deleted 0 of 0 scanned" in body
