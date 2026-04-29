"""WorkloadImageObservation — M:N between Workload and Image.

Records that an image was observed in a workload at a given container
slot. `currently_deployed` is the source of truth for "is this image
running in this workload right now"; it mirrors `Workload.deployed`
and is set by the inventory reaper at end of each complete cycle.

Stale rows (currently_deployed=False) are kept for a retention window
(see `core.constants.WORKLOAD_OBSERVATION_RETENTION_DAYS`) and then
deleted by the same reaper.
"""
from django.db import models


class WorkloadImageObservation(models.Model):
    workload = models.ForeignKey(
        "core.Workload",
        on_delete=models.CASCADE,
        related_name="image_observations",
    )
    image = models.ForeignKey(
        "core.Image",
        on_delete=models.CASCADE,
        related_name="observations",
    )
    container_name = models.CharField(
        max_length=253,
        help_text="Disambiguates multi-container Pods.",
    )
    init_container = models.BooleanField(
        default=False,
        help_text="True if the container came from pod.spec.initContainers.",
    )
    currently_deployed = models.BooleanField(
        default=False,
        db_index=True,
        help_text=(
            "True iff this (workload, image, container) was observed in the "
            "most recent COMPLETE inventory cycle. Set by the inventory "
            "reaper (core.services.reaper). Mirrors Workload.deployed. "
            "Default False because new rows are created mid-cycle and only "
            "the reaper has authority to mark them deployed at end of a "
            "complete cycle."
        ),
    )
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(
        auto_now=True,
        help_text=(
            "Bumped by the parser on every cycle that re-observes this "
            "(workload, image, container) combination. Reaper diffs against "
            "ImportMark.started_at to flip currently_deployed."
        ),
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workload", "image", "container_name"],
                name="unique_workload_image_container",
            ),
        ]
        indexes = [
            models.Index(fields=["image"], name="wio_image"),
        ]
        ordering = ["workload_id", "container_name"]

    def __str__(self) -> str:
        return f"{self.workload}/{self.container_name} → {self.image}"
