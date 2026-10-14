# Real-cluster fixtures

Anonymised captures of real clusters, one directory per cluster alias.
They drive `tests/realdata/` (parsers, relevance filter, bundle hashes,
PII scan) and `tests/integration/test_import_e2e_realdata.py` (the real
`scripts/import-cluster.py --from-folder` against a live test server).
Both suites skip when this directory holds no capture.

## Layout

```
fixtures/real/<alias>/
  README.md                       # provenance: date, k8s / trivy / kyverno versions, namespaces kept
  capture-meta.json               # written by the capture script (no hostnames / URLs)
  kubeapi/*.json.gz  trivy/*.json.gz  kyverno/*.json.gz
  golden/filter_stats.json        # relevance-filter stats + coverage per kind (exact match expected)
  golden/bundles.json             # per-kind count / sha256 / sizes of the bundles the importer builds
  golden/unfiltered_counts.json   # the same with the relevance filter disabled
  golden/expectations.yaml        # assertion-DSL list the e2e evaluates after the first cycle (optional)
```

Budget per cluster: **≤ 3 MB compressed, ≤ 25 MB uncompressed**
(`tests/realdata/test_realdata_bundles.py` enforces it). No git-LFS —
gzip plus a namespace subset chosen to cover every topology
(Deployment with ReplicaSet history, StatefulSet, DaemonSet, CronJob
with a Job and Pod, standalone Pod / Job, scaled-to-zero, digest-pinned
image, init container, LoadBalancer Service + Ingress, a namespace with
and one without NetworkPolicy).

## Producing one

```bash
# 1. Capture everything from the cluster (skips CRDs that aren't installed).
scripts/capture-cluster-fixture.sh /tmp/capture --context prod-1

# 2. Anonymise, verify faithfulness, write golden files. Keep the salt private.
python scripts/anonymize-fixture.py /tmp/capture fixtures/real/prod-a \
    --salt-file ~/.kubeposture-fixture-salt --keep-namespaces payments,platform --slim \
    --verify --write-golden

# 3. Review, then describe the capture.
$EDITOR fixtures/real/prod-a/README.md      # date, versions, namespaces kept, anonymiser version
$EDITOR fixtures/real/prod-a/golden/expectations.yaml   # optional DSL assertions, see below

# 4. Run the suites.
pytest -m realdata
pytest tests/integration/test_import_e2e_realdata.py
```

`--verify` fails if the importer's relevance-filter statistics differ
between the raw and the anonymised capture, or if any original
namespace, workload, host, registry, repository or digest string survives
— so a passing verify is the proof the fixture is both faithful and
clean. Re-run step 2 with `--write-golden` whenever the capture changes.

## `golden/expectations.yaml`

A list of assertion-DSL entries (`core/services/test_assertions.py`),
evaluated after the first import cycle:

```yaml
- kind: workload_count
  filter: {cluster: prod-a, deployed: true}
  expect: 42
- kind: finding_count
  filter: {cluster: prod-a, severity: critical}
  expect: 17
- kind: signal_present
  workload: ns-1a2b3c4d/wl-9f8e7d6c
  signal_id: kyverno:disallow-host-namespaces
```

Use the anonymised names (read them from the capture).
