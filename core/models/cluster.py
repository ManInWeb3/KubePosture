"""Cluster — identity + environment classification for one K8s cluster.

Cluster rows are pre-created by an admin via the in-app "Add cluster"
flow (per dev_docs/02-architecture.md *Cluster onboarding*); ingest
posts are matched to an existing row via bearer token. Auto-detected
fields (environment, provider, region, k8s_version) come in via
`/api/v1/cluster-metadata/sync/` and are skipped on subsequent
detect runs once the corresponding `*_is_manual` flag is set.

`consecutive_incomplete_inventories` is bumped by the inventory reap
whenever a cycle's mark has no `complete_snapshot=true` payload, and
reset to 0 on the next successful reap. A non-zero value means the
tool is preserving stale `deployed` flags — Scan Health surfaces this
as a data-quality incident past a configurable threshold.
"""
from django.db import models

from core.constants import Environment


class Cluster(models.Model):
    name = models.CharField(max_length=253, unique=True)

    environment = models.CharField(
        max_length=20,
        choices=Environment.choices,
        default=Environment.DEV,
        help_text="dev / staging / prod — auto-detected from cluster name regex.",
    )
    environment_is_manual = models.BooleanField(default=False)

    provider = models.CharField(
        max_length=20,
        default="onprem",
        help_text="aws / eks / gcp / gke / azure / aks / onprem — derived from node providerID.",
    )
    provider_is_manual = models.BooleanField(default=False)

    region = models.CharField(
        max_length=64,
        blank=True,
        help_text="From topology.kubernetes.io/region on a worker node.",
    )
    region_is_manual = models.BooleanField(default=False)

    k8s_version = models.CharField(max_length=32, blank=True)

    consecutive_incomplete_inventories = models.PositiveIntegerField(
        default=0,
        help_text=(
            "Incremented by the inventory reap when complete_snapshot=true is "
            "absent for a cycle; reset to 0 on a complete reap. Threshold "
            "crossing emits reap.inventory.persistent_incomplete."
        ),
    )

    last_complete_inventory_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "`mark.started_at` of the most recent COMPLETE inventory cycle "
            "(carrying `complete_snapshot=true`). Anchor for "
            "`Image.objects.currently_running()`: an image observation is "
            "considered current iff its `last_seen_at` is at or after this "
            "timestamp. NULL until the first complete cycle reaps. Partial "
            "cycles do NOT advance this field — that's what protects partial "
            "imports from causing false negatives in image-deployment queries."
        ),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Bumped on every successful inventory sync.",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name
