"""SbomComponent — one package observed inside an Image, keyed by (image, purl).

Sourced from Trivy Operator `SbomReport` CRDs. Stored once per Image — same
image deployed across many clusters / workloads doesn't duplicate component
rows, because `Image` is content-addressed by `digest` (globally unique).

There is no `active` flag on the row. A component is considered active iff
its image is currently deployed somewhere — derived via the existing
`WorkloadImageObservation.currently_deployed` machinery. Use
`SbomComponent.objects.active(cluster=..., namespace=...)`.

The `/components/` UI groups rows by `purl` (one display row per unique purl,
summing image/workload/cluster counts across images). Aggregation lives in
`core.services.components`, not in queryset annotations — `with_deployment_counts`
would be misleading on a per-row basis since each row is one (image, purl).
"""
from __future__ import annotations

from django.contrib.postgres.indexes import GinIndex
from django.db import models


class SbomComponentQuerySet(models.QuerySet):
    def active(self, *, cluster=None, namespace=None):
        """Filter to components whose image is currently deployed.

        Mirrors `ImageQuerySet.currently_running(cluster=..., namespace=...)`.
        """
        from core.models import Image

        running_images = Image.objects.currently_running(
            cluster=cluster, namespace=namespace,
        )
        return self.filter(image__in=running_images)


class SbomComponent(models.Model):
    image = models.ForeignKey(
        "core.Image",
        on_delete=models.CASCADE,
        related_name="sbom_components",
        help_text="Lifecycle anchor. Cluster is derived via observations.",
    )

    purl = models.CharField(
        max_length=512,
        db_index=True,
        help_text="Canonical package URL, e.g. pkg:npm/lodash@4.17.21.",
    )
    name = models.CharField(max_length=255, db_index=True)
    version = models.CharField(max_length=128, blank=True)
    ecosystem = models.CharField(
        max_length=32,
        blank=True,
        db_index=True,
        help_text="npm, pypi, gomod, golang, cargo, deb, rpm, apk, maven, …",
    )
    component_type = models.CharField(
        max_length=32,
        blank=True,
        help_text="CycloneDX `type`: library, application, framework, …",
    )
    supplier = models.CharField(max_length=255, blank=True)
    license = models.CharField(max_length=255, blank=True)
    layer_digest = models.CharField(
        max_length=80,
        blank=True,
        help_text="aquasecurity:trivy:LayerDigest property, if present.",
    )

    raw = models.JSONField(
        default=dict,
        blank=True,
        help_text="Full CycloneDX component object for future-proofing.",
    )

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    objects = SbomComponentQuerySet.as_manager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["image", "purl"], name="unique_image_purl",
            ),
        ]
        indexes = [
            GinIndex(fields=["raw"], name="sbomcomp_raw_gin"),
            models.Index(fields=["name", "version"], name="sbomcomp_name_ver"),
        ]
        ordering = ["name", "version"]

    def __str__(self) -> str:
        return self.purl or f"{self.name}@{self.version}"
