"""Small iteration helpers shared across services."""
from __future__ import annotations

from collections.abc import Iterable, Iterator


def chunked(items: Iterable, size: int) -> Iterator[list]:
    """Consecutive lists of at most `size` items, in order. Lazy: `items`
    may be a generator or a queryset iterator and is consumed one chunk at
    a time."""
    chunk: list = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
