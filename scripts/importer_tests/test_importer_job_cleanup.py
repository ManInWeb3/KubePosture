"""cleanup_failed_sibling_jobs: deletes only the failed Jobs of the
calling CronJob, and never raises."""
from __future__ import annotations

from types import SimpleNamespace as NS

from kubeposture_importer.sources.kube import cleanup_failed_sibling_jobs

MINE, OTHER = "uid-trigger", "uid-main"


def _job(name, owner_uid, *, failed=0, succeeded=0):
    refs = [NS(kind="CronJob", uid=owner_uid)] if owner_uid else []
    return NS(metadata=NS(name=name, owner_references=refs), status=NS(failed=failed, succeeded=succeeded))


class FakeBatch:
    def __init__(self, jobs, *, fail_read=False, fail_delete=()):
        self.jobs, self.fail_read, self.fail_delete, self.deleted = jobs, fail_read, set(fail_delete), []

    def read_namespaced_cron_job(self, name, namespace, **_):
        if self.fail_read:
            raise RuntimeError("forbidden")
        return NS(metadata=NS(uid=MINE))

    def list_namespaced_job(self, namespace, **_):
        return NS(items=self.jobs)

    def delete_namespaced_job(self, name, namespace, **_):
        if name in self.fail_delete:
            raise RuntimeError("conflict")
        self.deleted.append(name)


def _run(batch):
    cleanup_failed_sibling_jobs(NS(BatchV1Api=lambda: batch), namespace="ns", cronjob_name="imp-trigger")
    return batch.deleted


def test_deletes_only_failed_jobs_of_its_own_cronjob():
    batch = FakeBatch([
        _job("t-1", MINE, failed=1),             # deleted
        _job("t-2", MINE, failed=2),             # deleted
        _job("t-3", MINE, succeeded=1),          # kept: succeeded
        _job("t-4", MINE),                       # kept: running (this pod's own Job)
        _job("t-5", MINE, failed=1, succeeded=1),  # kept: eventually succeeded
        _job("m-1", OTHER, failed=1),            # kept: the main CronJob's failure
        _job("x-1", None, failed=1),             # kept: not owned by a CronJob (init Job)
    ])
    assert _run(batch) == ["t-1", "t-2"]


def test_api_errors_are_swallowed(capsys):
    assert _run(FakeBatch([_job("t-1", MINE, failed=1)], fail_read=True)) == []
    batch = FakeBatch([_job("t-1", MINE, failed=1), _job("t-2", MINE, failed=1)], fail_delete={"t-1"})
    assert _run(batch) == ["t-2"], "one failed delete must not stop the rest"
    err = capsys.readouterr().err
    assert "could not read CronJob" in err and "failed to delete Job t-1" in err


def test_nothing_to_delete_is_silent(capsys):
    assert _run(FakeBatch([_job("t-1", MINE, succeeded=1)])) == []
    assert capsys.readouterr().out == "", "idle trigger ticks run this every minute"
