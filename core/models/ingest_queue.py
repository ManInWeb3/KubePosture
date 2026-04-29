"""IngestQueue — DB-backed queue for raw scan payloads.

Worker claim is gated on the matching ImportMark being in
`state='draining'` — items posted during an open import sit pending
but uncllaimed until the importer signals finish. This eliminates
the partial-import race where a scan payload would be processed
before the inventory payload that creates its workload row.

`created_at` doubles as `observation_time` so that
`Finding.last_seen = max(last_seen, observation_time)` is monotonic
regardless of the order in which workers process items.
"""
from django.db import models

from core.constants import IngestQueueStatus


class IngestQueue(models.Model):
    cluster_name = models.CharField(
        max_length=253,
        help_text="String — matched against Cluster.name during dispatch.",
    )
    kind = models.CharField(max_length=64)
    import_id = models.CharField(max_length=32)
    raw_json = models.JSONField()
    complete_snapshot = models.BooleanField(
        default=False,
        help_text="Set by the importer on the final inventory payload of a cycle.",
    )

    status = models.CharField(
        max_length=16,
        choices=IngestQueueStatus.choices,
        default=IngestQueueStatus.PENDING,
    )
    attempts = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(
                fields=["cluster_name", "kind", "import_id"],
                name="ingest_queue_tuple",
            ),
            models.Index(
                fields=["status", "created_at"],
                name="ingest_queue_status_created",
            ),
        ]
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"#{self.pk} {self.kind} for {self.cluster_name} [{self.status}]"
