"""OSV `affected[]` evaluation — pure functions, no DB.

An OSV affected block says which versions of one package are vulnerable
in two ways: an explicit `versions[]` list (OSV enumerates it for the
ECOSYSTEM-ranged ecosystems — PyPI, Maven, RubyGems…) and `ranges[]`.
A SEMVER range is a *set* of intervals: every `introduced` event opens
one, the next `fixed` (exclusive) or `last_affected` (inclusive) closes
it, and a version is affected when it falls in any of them. npm, Go and
crates.io advisories carry only SEMVER ranges, so exact-version matching
alone would miss them entirely.

Ordering is python-semver's SemVer 2.0: Go pseudo-versions
(`0.0.0-20201216223049-8b5274cf687f`) are prereleases of their base
version — below the release, above nothing else — and build metadata
(`+incompatible`) is ignored. A leading `v` (Go, as Trivy emits it) is
stripped. ECOSYSTEM ranges are *not* interpreted when `versions[]` is
missing: we don't guess Maven or PEP 440 ordering, the evaluation is
reported as unsupported instead.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import semver

from core.purl import normalize_purl, parse_purl_name_version


@dataclass(frozen=True)
class Evaluation:
    affected: bool
    fixed_version: str = ""
    # Nothing could be decided: unparsable version, or only ECOSYSTEM /
    # GIT ranges without an enumerated versions[] list.
    unsupported: bool = False


NOT_AFFECTED = Evaluation(False)


def parse_version(version: str) -> semver.Version | None:
    """SemVer parse tolerant of the shapes Trivy and OSV actually emit:
    optional leading `v`, and `1.20` / `1` padded to three components
    (Go toolchain versions in OSV ranges)."""
    s = version.strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    try:
        return semver.Version.parse(s)
    except ValueError:
        pass
    core, sep, rest = s.partition("-")
    core, bsep, build = core.partition("+")
    parts = core.split(".")
    if 1 <= len(parts) < 3 and all(p.isdigit() for p in parts):
        padded = ".".join(parts + ["0"] * (3 - len(parts))) + sep + rest + bsep + build
        try:
            return semver.Version.parse(padded)
        except ValueError:
            return None
    return None


def _intervals(events: list[dict]) -> list[tuple[str, str | None, bool]]:
    """`[(lo, hi, hi_inclusive)]` — lo "0" means unbounded below, hi None
    means open-ended (no fix known)."""
    out: list[tuple[str, str | None, bool]] = []
    lo: str | None = None
    for ev in events:
        if "introduced" in ev:
            if lo is not None:
                out.append((lo, None, False))
            lo = str(ev["introduced"])
        elif "fixed" in ev:
            out.append((lo if lo is not None else "0", str(ev["fixed"]), False))
            lo = None
        elif "last_affected" in ev:
            out.append((lo if lo is not None else "0", str(ev["last_affected"]), True))
            lo = None
    if lo is not None:
        out.append((lo, None, False))
    return out


def _semver_hit(version: semver.Version, events: list[dict]) -> tuple[bool, str]:
    for lo, hi, inclusive in _intervals(events):
        if lo != "0":
            lo_v = parse_version(lo)
            if lo_v is None or version < lo_v:
                continue
        if hi is None:
            return True, ""
        hi_v = parse_version(hi)
        if hi_v is None:
            continue
        if version < hi_v or (inclusive and version == hi_v):
            return True, "" if inclusive else hi
    return False, ""


def _single_fixed(ranges: list[dict]) -> str:
    """The fix version to report for an enumerated-versions match: the one
    `fixed` event of the block's SEMVER / ECOSYSTEM ranges, or "" when
    there isn't exactly one (no fix, or several intervals)."""
    fixed = {
        str(ev["fixed"])
        for r in ranges if r.get("type") in ("SEMVER", "ECOSYSTEM")
        for ev in (r.get("events") or []) if "fixed" in ev
    }
    return next(iter(fixed)) if len(fixed) == 1 else ""


def evaluate(version: str, *, versions: list[str], ranges: list[dict]) -> Evaluation:
    """Is `version` affected by one OSV affected block?"""
    v = version.strip()
    bare = v[1:] if v[:1] in ("v", "V") else v
    if versions and ({v, bare, "v" + bare} & set(versions)):
        return Evaluation(True, _single_fixed(ranges))

    parsed = parse_version(v)
    unsupported = False
    for r in ranges:
        if r.get("type") != "SEMVER":
            continue
        if parsed is None:
            unsupported = True
            continue
        hit, fixed = _semver_hit(parsed, r.get("events") or [])
        if hit:
            return Evaluation(True, fixed)
    if not versions and any(r.get("type") == "ECOSYSTEM" for r in ranges):
        unsupported = True
    return Evaluation(False, "", unsupported) if unsupported else NOT_AFFECTED


# ── Malicious-package blocks (the IoC lane) ─────────────────────────
#
# Malicious-package advisories (MAL-*) use the same `affected[]` shape,
# but the IoC lane matches purls, not ranges: a block is first turned into
# `SupplyChainIoc` purls (`ioc_purls`), and a block that only has ranges
# is stored as a name-only purl whose version is checked at match time
# (`covers_version`).


def ioc_purls(affected: dict, purl_type: str) -> list[str]:
    """`SupplyChainIoc` purls for one `affected[]` block of a malicious
    advisory:

    - a `package.purl` that carries a version → that purl;
    - an enumerated `versions[]` → one exact purl per version;
    - otherwise (ranges only, typically `introduced: "0"`) → the name-only
      purl, meaning "some versions of this package": the matcher decides
      per component with `covers_version`.

    "Carries a version" is decided by parsing the purl, never by looking
    for an `@`: a scoped npm name (`pkg:npm/@scope/pkg`, which is how OSV
    publishes `%40scope`) has one, and mistaking it for a version
    separator stored the name-only purl for advisories that list their
    compromised versions — flagging every version of the package.

    Empty when the block names no package.
    """
    pkg = affected.get("package") or {}
    name = pkg.get("name") or ""
    explicit = normalize_purl(pkg.get("purl") or "")
    if explicit and parse_purl_name_version(explicit)[1]:
        return [explicit]
    if not (purl_type and name):
        return []
    versions = [v for v in affected.get("versions") or [] if isinstance(v, str) and v]
    if versions:
        return [normalize_purl(f"pkg:{purl_type}/{name}@{v}") for v in dict.fromkeys(versions)]
    return [normalize_purl(f"pkg:{purl_type}/{name}")]


def covers_version(version: str, affected: dict) -> bool:
    """Is `version` inside a malicious-package block? Fails open: a block
    with nothing this module can interpret (no `versions[]`, no SEMVER
    range — ECOSYSTEM/GIT only), or a version that doesn't parse, counts
    as covered, because for malware the cost of a miss outweighs a false
    alarm, and the name-only IoC always meant "every version"."""
    versions = [v for v in affected.get("versions") or [] if isinstance(v, str)]
    ranges = [r for r in affected.get("ranges") or [] if isinstance(r, dict)]
    if not versions and not any(r.get("type") == "SEMVER" for r in ranges):
        return True
    res = evaluate(version, versions=versions, ranges=ranges)
    return res.affected or res.unsupported


def _interval_text(lo: str, hi: str | None, inclusive: bool) -> str:
    if lo == "0":
        return "all versions" if hi is None else f"{'<=' if inclusive else '<'} {hi}"
    if hi is None:
        return f">= {lo}"
    return f">= {lo}, {'<=' if inclusive else '<'} {hi}"


def _version_sort_key(version: str):
    parsed = parse_version(version)
    return (0, parsed, version) if parsed is not None else (1, semver.Version(0), version)


def describe_blocks(blocks: Iterable[dict]) -> tuple[list[str], list[str]]:
    """`(versions, ranges)` of the blocks as a person reads them: the
    enumerated versions (semver order, unparsable ones last) and one text
    per interval (`>= 1.95.6, < 1.95.8`, `all versions`)."""
    versions: dict[str, None] = {}
    ranges: dict[str, None] = {}
    for block in blocks:
        for v in block.get("versions") or []:
            if isinstance(v, str) and v:
                versions[v] = None
        for r in block.get("ranges") or []:
            if isinstance(r, dict) and r.get("type") in ("SEMVER", "ECOSYSTEM"):
                for lo, hi, inclusive in _intervals(r.get("events") or []):
                    ranges[_interval_text(lo, hi, inclusive)] = None
    return sorted(versions, key=_version_sort_key), list(ranges)
