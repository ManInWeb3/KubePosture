"""Image — content-addressed by digest, append-only.

Once observed in any cluster, an Image row is never deleted.

There is NO `deployed` column. An image is just a content-addressed
artefact (`sha256:...`). Whether an image is "currently running" is
answered via `WorkloadImageObservation.currently_deployed` — a stored
boolean maintained by the inventory reaper.

`ref` reflects the most-recently-seen tag (`registry/repo:tag`); it's
display-only. The dedup hash for Findings excludes `ref` — different
refs pointing at the same digest collapse to the same Image row and
the same Finding.
"""
from django.db import models
from django.db.models import Exists, OuterRef


class ImageQuerySet(models.QuerySet):
    """Helpers for the "is this image currently running anywhere?"
    question. For the per-(workload, container) version of the
    question, query `WorkloadImageObservation` directly with
    `currently_deployed=True`.
    """

    def with_currently_deployed(self, *, cluster=None, namespace=None):
        """Annotate each Image with `currently_deployed: bool`.

        Optional scoping: `cluster` and/or `namespace` narrow the
        observation join. Pass nothing to ask "deployed in *any*
        cluster".
        """
        from core.models import WorkloadImageObservation

        obs_q = WorkloadImageObservation.objects.filter(
            image=OuterRef("pk"),
            currently_deployed=True,
        )
        if cluster is not None:
            obs_q = obs_q.filter(workload__cluster=cluster)
        if namespace is not None:
            obs_q = obs_q.filter(workload__namespace=namespace)
        return self.annotate(currently_deployed=Exists(obs_q))

    def currently_running(self, *, cluster=None, namespace=None):
        """Filter to images currently running in scope.

        Use this from views, admin, and tests instead of
        re-deriving the join.
        """
        return self.with_currently_deployed(
            cluster=cluster, namespace=namespace,
        ).filter(currently_deployed=True)


class Image(models.Model):
    digest = models.CharField(
        max_length=80,
        unique=True,
        help_text="sha256:... canonical identity.",
    )
    ref = models.CharField(
        max_length=512,
        blank=True,
        help_text="Most-recently-seen full image reference, as received.",
    )
    registry = models.CharField(max_length=253, blank=True)
    repository = models.CharField(max_length=253, blank=True)

    os_family = models.CharField(max_length=32, blank=True)
    os_version = models.CharField(max_length=32, blank=True)
    base_eosl = models.BooleanField(default=False)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    objects = ImageQuerySet.as_manager()

    class Meta:
        ordering = ["ref"]

    def __str__(self) -> str:
        return self.ref or self.digest[:20]
