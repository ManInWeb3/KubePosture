# OSV fixtures

Real OSV.dev records, frozen for the tests of the OSV lane (docs/osv.md).

- `advisories/<ecosystem>/<id>.json` — 12 complete advisories as served by
  `osv-vulnerabilities.storage.googleapis.com/<ecosystem>/<id>.json`
  (2026-10-23): multi-interval Go ranges (GO-2023-1571, GHSA-m425-mq94-257g,
  GO-2026-5158, GHSA-6vch-q96h-7gc3), an open-ended one (GO-2025-3521),
  `last_affected` (GHSA-35jh-r3h4-6jhm), enumerated Maven / PyPI versions
  (GHSA-jfh8-c2jp-5v3q, GHSA-j8r2-6x86-q33q + PYSEC-2023-74), crates.io
  (RUSTSEC-2023-0001), a withdrawn advisory (GHSA-24r3-p3x6-cqvx) and a
  malicious package (MAL-2026-18187). `core/tests/test_osv_*` zip them per
  ecosystem at test time.
- `realdata/<ecosystem>.zip` — slimmed advisories (id, aliases, dates,
  severity, affected package / versions / ranges) for every package in
  `fixtures/real` SBOMs, published on or before those captures. Drives
  `tests/realdata/test_osv_parity.py`; `parity.json` holds the pinned
  numbers. Rebuild from the full bulk zips when the real captures change.
