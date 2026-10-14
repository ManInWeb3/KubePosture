"""Image-digest normalisation.

Mirrors the server's `core/parsers/inventory.py::_digest_from_ref` /
`_digest_from_pod_status` so the importer's idea of "which digests are
deployed" is a superset of the server's. Everything is normalised to
`sha256:<64 lowercase hex>`; anything else is treated as no digest.
"""
from __future__ import annotations

import re

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalize_digest(value: str) -> str:
    """`SHA256:ABC…` → `sha256:abc…`; "" when not a sha256 digest."""
    if not value:
        return ""
    value = value.strip().lower()
    if not value.startswith("sha256:"):
        return ""
    hexpart = value[len("sha256:"):]
    return value if _HEX64.match(hexpart) else ""


def digest_from_image_id(image_id: str) -> str:
    """Pod `status.containerStatuses[].imageID`:
    `repo@sha256:…`, `docker-pullable://repo@sha256:…`, or bare `sha256:…`."""
    if not image_id:
        return ""
    if "@" in image_id:
        _, _, tail = image_id.partition("@")
        return normalize_digest(tail)
    return normalize_digest(image_id)


def digest_from_ref(ref: str) -> str:
    """A container `image` reference: only a `@sha256:` pin counts."""
    if not ref or "@" not in ref:
        return ""
    _, _, tail = ref.partition("@")
    return normalize_digest(tail)
