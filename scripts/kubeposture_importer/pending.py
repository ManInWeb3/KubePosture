"""On-demand ("Re-import" button) pull trigger — poll and clear."""
from __future__ import annotations

import sys
from urllib.parse import quote

from .http import HttpClient


def check_pending(client: HttpClient, *, cluster: str) -> dict | None:
    """Parsed pending-poll JSON, or None if the GET failed."""
    result = client.get(f"/api/v1/imports/pending/?cluster={quote(cluster)}")
    if not result.ok:
        print(f"  pending poll FAILED ({result.status}): {result.body[:200]}", file=sys.stderr)
        return None
    doc = result.json()
    if doc is None:
        print(f"  pending poll: unparseable response: {result.body[:200]}", file=sys.stderr)
        return None
    return doc


def clear_pending(client: HttpClient, *, cluster: str, satisfied_at: str) -> bool:
    result = client.post_json(
        "/api/v1/imports/pending/clear/", {"cluster": cluster, "satisfied_at": satisfied_at},
    )
    if not result.ok:
        print(f"  pending/clear FAILED ({result.status}): {result.body[:200]}", file=sys.stderr)
    return result.ok
