"""Package URL (purl) utilities.

Centralised so parsers, fetchers, and search endpoints all normalise
the same way before reading or writing the DB.
"""
from __future__ import annotations


def purl_ecosystem(purl: str) -> str:
    """Extract the type segment of a purl: `pkg:<type>/...` → `<type>`.

    Returns "" for malformed input. Examples:
        pkg:npm/lodash@4.17.21          → npm
        pkg:pypi/requests@2.28.0        → pypi
        pkg:deb/debian/libc6@2.36-9     → deb
        pkg:npm/@types/node@20.0.0      → npm
    """
    if not purl.startswith("pkg:"):
        return ""
    tail = purl[4:]
    slash = tail.find("/")
    return tail[:slash] if slash > 0 else tail


def parse_purl_name_version(purl: str) -> tuple[str, str]:
    """Extract `(name, version)` from a purl.

    Handles `@`-scoped names that would break a naive `split("@")[0]`:
        pkg:npm/@types/node@20.0.0   → ("@types/node", "20.0.0")
        pkg:pypi/@ctx@0.1.2          → ("@ctx", "0.1.2")
        pkg:npm/lodash@4.17.21       → ("lodash", "4.17.21")
        pkg:pypi/requests            → ("requests", "")          # no version
        pkg:deb/debian/libc6@2.36-9  → ("debian/libc6", "2.36-9")

    The rule: split on the LAST `@` for the version separator, and treat
    everything after the first `/` (the type prefix) as the name path.
    """
    if not purl:
        return "", ""
    path = purl[4:] if purl.startswith("pkg:") else purl
    first_slash = path.find("/")
    name_part = path[first_slash + 1:] if first_slash >= 0 else path
    # Strip qualifiers / subpath if present — they shouldn't carry @.
    for sep in ("?", "#"):
        if sep in name_part:
            name_part = name_part.split(sep, 1)[0]
    last_at = name_part.rfind("@")
    # last_at > 0 (not >= 0) so a leading `@` in a scope isn't mistaken
    # for the version separator.
    if last_at > 0:
        return name_part[:last_at], name_part[last_at + 1:]
    return name_part, ""


def normalize_purl(purl: str) -> str:
    """Normalise a purl received from external sources.

    Some scanners URL-encode the `@` version separator as `%40` — that's
    a producer bug (the purl spec doesn't allow `%XX` for the `@`
    separator), but it slips into real-world data. Our IoC feeds (OSV,
    Aikido) use literal `@`, so mismatched encoding silently breaks
    purl-equality matching.

    This function does a targeted fix: only the `@` separator is
    decoded. We deliberately don't full-`unquote()` the string because
    qualifiers (e.g. `?arch=amd64&distro=debian-12`) can carry
    intentional percent-encoded values that we'd over-decode.

    Idempotent: already-normalised purls pass through unchanged.
    """
    if not purl:
        return purl
    # %40 is case-insensitive at the hex digits, but both digits here
    # are numeric so a single replace covers both encoder styles.
    return purl.replace("%40", "@")
