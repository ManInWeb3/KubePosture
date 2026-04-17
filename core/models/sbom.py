"""
SBOM models — Component inventory from Trivy SbomReport.

Convention D4: Latest state only. Each ingest replaces the previous
component list for that cluster+image. Raw SbomReport JSON is stored
in RawReport (Phase 1) or Snapshot raw_json for historical reference.

See: docs/architecture.md § F13, F14
"""
from django.db import models


class ComponentType(models.TextChoices):
    LIBRARY = "library", "Library"
    FRAMEWORK = "framework", "Framework"
    OS = "os", "OS Package"
    CONTAINER = "container", "Container"
    APPLICATION = "application", "Application"
    OTHER = "other", "Other"


class Component(models.Model):
    """Software component from Trivy SbomReport CycloneDX BOM.

    Tracks what software is running across clusters. Enables:
    - "Which clusters run log4j?" (F13)
    - "Do we have GPL software in production?" (F14)
    """

    cluster = models.ForeignKey(
        "core.Cluster", on_delete=models.CASCADE, related_name="components"
    )
    namespace = models.CharField(max_length=253, blank=True)
    resource_name = models.CharField(max_length=253, blank=True)
    image = models.CharField(
        max_length=500,
        help_text="Full image reference (registry/repo:tag)",
    )

    # Component identity
    name = models.CharField(max_length=500)
    version = models.CharField(max_length=200)
    component_type = models.CharField(
        max_length=30,
        choices=ComponentType.choices,
        default=ComponentType.LIBRARY,
    )
    purl = models.CharField(
        max_length=1000,
        blank=True,
        help_text="Package URL (pkg:deb/debian/openssl@1.1.1k)",
    )

    # License data (F14)
    licenses = models.JSONField(
        default=list,
        blank=True,
        help_text="List of SPDX license identifiers",
    )

    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "image", "name", "version"],
                name="unique_component_per_cluster_image",
            ),
        ]
        indexes = [
            models.Index(fields=["name"], name="component_name"),
            models.Index(fields=["purl"], name="component_purl"),
            models.Index(fields=["cluster", "image"], name="component_cluster_image"),
        ]
        ordering = ["name", "version"]

    def __str__(self):
        return f"{self.name}@{self.version}"
