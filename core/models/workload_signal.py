"""WorkloadSignal — registry-keyed exploitability fact on a Workload.

One row per `(workload, signal_id)`, where `signal_id` is a stable
string from `core.signals.SIGNALS` (e.g.
`kyverno:disallow-privileged-containers`, `ksv:KSV-0017`,
`kp:has-nodeport-service`).

No canonical-ID dedup: if Kyverno and Trivy both report the same
underlying fact (privileged container) they get TWO rows with two
distinct `signal_id`s. They flip `currently_active=false` together
once both scanners stop reporting them — the natural lifecycle when
the issue is fixed. This keeps the ingest path trivial: the worker
upserts by `signal_id` and never has to canonicalise.

Rows are append-only — never deleted. The reap flips
`currently_active=false` when the source for this signal_id stops
observing it; recompute fan-out runs for every Finding attached to
the workload.
"""
from django.db import models


class WorkloadSignalManager(models.Manager):
    def upsert(self, workload, signal_id: str, *, active: bool = True):
        """Record that `signal_id` is currently active (or not) on
        `workload`, creating the row on first sight. An active observation
        always bumps `last_seen_at` (auto_now); a clearing one only writes
        when it actually flips the flag, so a signal never seen stays
        absent. Shared by the inventory parser and the scan ingest path."""
        obj = self.filter(workload=workload, signal_id=signal_id).first()
        if obj is None:
            if not active:
                return None
            return self.create(workload=workload, signal_id=signal_id, currently_active=True)
        if active or obj.currently_active:
            obj.currently_active = active
            obj.save(update_fields=["currently_active", "last_seen_at"])
        return obj


class WorkloadSignal(models.Model):
    workload = models.ForeignKey(
        "core.Workload",
        on_delete=models.CASCADE,
        related_name="signals",
    )
    signal_id = models.CharField(
        max_length=128,
        help_text="Registry key from core.signals.SIGNALS.",
    )

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    currently_active = models.BooleanField(
        default=True,
        help_text=(
            "True iff the source still reports this signal at last reap. "
            "False after the reap observes silence."
        ),
    )

    objects = WorkloadSignalManager()

    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Source-specific context (e.g. capability name, CRB granting admin).",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workload", "signal_id"],
                name="unique_workload_signal",
            ),
        ]
        indexes = [
            models.Index(
                fields=["workload", "currently_active"],
                name="workload_signal_active",
            ),
            models.Index(fields=["signal_id"], name="workload_signal_id"),
        ]
        ordering = ["workload_id", "signal_id"]

    def __str__(self) -> str:
        return f"{self.workload}: {self.signal_id}"
