"""KubePosture importer — runs inside each workload cluster.

Collect (kube-api or a captured folder) → relevance filter → coverage →
one gzip NDJSON bundle per kind → upload → commit. Stdlib only; the
`kubernetes` client is imported lazily in `sources.kube` for live mode.
See `cli.py` for the orchestration and the repo README ("Import API
contract") for the server side.
"""

IMPORTER_VERSION = "2.0.0"
