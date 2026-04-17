"""
Async ingest queue — PostgreSQL-backed queue for decoupling webhook
acceptance from processing.

Webhook INSERTs raw JSON → returns 202. Queue processor claims items
via SELECT FOR UPDATE SKIP LOCKED → calls ingest_scan() → marks done.

See: docs/architecture.md § Async Ingest Queue
"""
from django.db import models


class QueueStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    PROCESSING = "processing", "Processing"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


class IngestQueue(models.Model):
    """Raw CRD JSON waiting to be processed.

    cluster_name is a CharField (not FK) because the cluster may not
    exist yet — it gets auto-registered during processing.
    """

    cluster_name = models.CharField(
        max_length=253,
        help_text="From X-Cluster-Name header or CRD metadata",
    )
    raw_json = models.JSONField()
    status = models.CharField(
        max_length=20,
        choices=QueueStatus.choices,
        default=QueueStatus.PENDING,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    attempts = models.PositiveSmallIntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(
                fields=["status", "created_at"],
                name="queue_status_created",
            ),
        ]
        ordering = ["created_at"]

    def __str__(self):
        kind = self.raw_json.get("kind", "?") if isinstance(self.raw_json, dict) else "?"
        return f"#{self.pk} {kind} for {self.cluster_name} [{self.status}]"
