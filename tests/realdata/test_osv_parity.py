"""OSV lane vs Trivy on the anonymised real captures — the regression
guard for the range evaluator and the alias-based Trivy dedup.

Pure Python, no DB: the capture's SbomReports go through the real SBOM
parser, its VulnerabilityReports through the vuln parser, and the frozen
OSV subset under fixtures/osv/realdata (advisories for the captured
packages, published on or before the capture date) through the loader's
row builder and the matcher's per-image evaluation.

Per image with both reports, every (package@version, vuln) is counted
as found by both, OSV only, or Trivy only (language packages present in
the SBOM). The numbers are pinned in fixtures/osv/realdata/parity.json;
`OSV_PARITY_WRITE=1 pytest tests/realdata/test_osv_parity.py` rewrites
it after a deliberate change. Two invariants hold regardless of the
pin: Trivy finds nothing OSV misses on the same package, and OSV adds
only a few percent — the lane is gap-fill, not a second scanner.
"""
from __future__ import annotations

import gzip
import json
import os
import zipfile
from collections import defaultdict
from pathlib import Path

import pytest

from core.models import SbomComponent
from core.parsers.trivy import parse_sbom_report, parse_vulnerability_report
from core.services.enrichment import _advisory_rows
from core.services.osv_vuln_matcher import SUPPORTED_PURL_TYPES, _matches_for_image

pytestmark = pytest.mark.realdata

REPO = Path(__file__).resolve().parents[2]
OSV_SUBSET = REPO / "fixtures" / "osv" / "realdata"
PARITY = OSV_SUBSET / "parity.json"


def _affected_index() -> dict:
    index: dict = defaultdict(list)
    for zip_path in sorted(OSV_SUBSET.glob("*.zip")):
        eco = zip_path.stem
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                adv, rows = _advisory_rows(json.loads(zf.read(name)), eco)
                if adv.withdrawn_at:
                    continue
                for row in rows:
                    index[(row.purl_type, row.name)].append(row)
    return index


def _capture(fixture_dir: Path):
    sboms = json.load(gzip.open(fixture_dir / "trivy" / "sbomreports.json.gz"))["items"]
    vulns = json.load(gzip.open(fixture_dir / "trivy" / "vulnerabilityreports.json.gz"))["items"]
    comps: dict[str, list[SbomComponent]] = {}
    for item in sboms:
        parsed = parse_sbom_report(item)
        comps[parsed["image_digest"]] = [
            SbomComponent(purl=c["purl"], name=c["name"], version=c["version"],
                          ecosystem=c["ecosystem"])
            for c in parsed["components"] if c["ecosystem"] in SUPPORTED_PURL_TYPES
        ]
    trivy: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for item in vulns:
        parsed = parse_vulnerability_report(item)
        for f in parsed["findings"]:
            trivy[parsed["image_digest"]].add((f["vuln_id"], f["pkg_name"], f["installed_version"]))
    return comps, trivy


def _parity(fixture_dir: Path) -> dict[str, int]:
    index = _affected_index()
    comps, trivy = _capture(fixture_dir)
    both = osv_only = trivy_only = images = 0
    for digest, components in comps.items():
        if digest not in trivy:
            continue
        images += 1
        covered = trivy[digest]
        matches = _matches_for_image(components, index)
        osv_ids_by_pkg: dict[tuple[str, str], set[str]] = defaultdict(set)
        for m in matches:
            key = (m["pkg_name"], m["installed_version"])
            osv_ids_by_pkg[key] |= m["_ids"]
            if any((i, *key) in covered for i in m["_ids"]):
                both += 1
            else:
                osv_only += 1
        in_sbom = {(c.name, c.version) for c in components}
        for vuln_id, pkg, ver in covered:
            if (pkg, ver) in in_sbom and vuln_id not in osv_ids_by_pkg[(pkg, ver)]:
                trivy_only += 1
    return {"images": images, "both": both, "osv_only": osv_only, "trivy_only": trivy_only}


def test_osv_matches_agree_with_trivy(fixture_dir):
    if not OSV_SUBSET.is_dir() or not any(OSV_SUBSET.glob("*.zip")):
        pytest.skip("no OSV subset under fixtures/osv/realdata/")
    got = _parity(fixture_dir)
    assert got["images"] > 0
    assert got["trivy_only"] == 0, got
    assert got["osv_only"] <= 0.05 * got["both"], got

    pinned = json.loads(PARITY.read_text()) if PARITY.is_file() else {}
    if os.environ.get("OSV_PARITY_WRITE"):
        pinned[fixture_dir.name] = got
        PARITY.write_text(json.dumps(pinned, indent=2, sort_keys=True) + "\n")
    assert pinned.get(fixture_dir.name) == got, (
        f"parity drifted for {fixture_dir.name}: {got} (pinned {pinned.get(fixture_dir.name)}); "
        "rerun with OSV_PARITY_WRITE=1 if the change is intended"
    )
