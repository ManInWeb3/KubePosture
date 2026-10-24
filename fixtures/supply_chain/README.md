# Supply-chain IoC fixtures

Real data, frozen for `core/tests/test_supply_chain_scoped_npm.py` and
`core/tests/test_migration_0016_scoped_iocs.py` (docs/supply-chain.md).

- `advisories/npm/<id>.json` — the ten malicious-package advisories that name
  a package the image below carries, exactly as served by
  `osv-vulnerabilities.storage.googleapis.com/npm/<id>.json` (2026-10-24),
  found by asking OSV about every package of its SBOM: the five `@tanstack/*`
  entries of the "Mini Shai-Hulud" compromise (MAL-2026-3463, -3465, -3466,
  -3473, -3475 — they enumerate `versions[]`), `@solana/web3.js`
  (MAL-2024-11183 — only the range `introduced 1.95.6 / fixed 1.95.8`), and
  four unscoped ones with enumerated versions: `debug` (MAL-2025-46974),
  `supports-color` (MAL-2025-46981), `axios` (MAL-2026-2307),
  `react-hook-form` (MAL-2026-2853).
- `frontend.sbom.cdx.json` — the CycloneDX component entries (Trivy 0.76.1)
  of an image that carries those six packages at *non-compromised*
  versions, plus three unscoped ones. Trimmed to those components; the
  image metadata is dropped. Before the fix every one of the six was
  reported as a malicious package.
- `frontend-full.sbom.cdx.json` — the same SBOM whole: all 737 component
  entries (700+ npm packages, plus OS packages), `components` only — the image
  name, registry host and dependency graph are dropped. The image carries
  none of the compromised versions (its `debug@4.4.3` sits next to the
  compromised 4.4.2, `supports-color@10.2.2` next to 10.2.1, …), so the whole
  image must come out clean.
