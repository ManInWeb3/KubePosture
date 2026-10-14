#!/usr/bin/env bash
# Capture a cluster snapshot in the layout scripts/import-cluster.py
# --from-folder reads (and scripts/anonymize-fixture.py consumes):
#
#   <outdir>/kubeapi/{namespaces,deployments,...,nodes,version}.json
#   <outdir>/trivy/{vulnerabilityreports,...,sbomreports}.json
#   <outdir>/kyverno/{policyreports,clusterpolicyreports}.json
#   <outdir>/capture-meta.json
#
# Always captures everything (all namespaces); choosing a subset is the
# anonymiser's job (--keep-namespaces) so referential closure is
# computed in one place. CRDs the cluster doesn't have are skipped, which
# the importer reads as "kind absent" (not "kind empty").
#
# Usage: capture-cluster-fixture.sh <outdir> [--context <kubectl-context>]
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <outdir> [--context <ctx>]" >&2
  exit 2
fi
OUT="$1"; shift
KCTL=(kubectl)
if [[ "${1:-}" == "--context" ]]; then
  KCTL+=(--context "$2"); shift 2
fi

mkdir -p "$OUT/kubeapi" "$OUT/trivy" "$OUT/kyverno"

# plural → file, namespaced?
declare -a KUBEAPI=(
  "namespaces:namespaces.json:cluster"
  "deployments:deployments.json:ns"
  "statefulsets:statefulsets.json:ns"
  "daemonsets:daemonsets.json:ns"
  "cronjobs:cronjobs.json:ns"
  "jobs:jobs.json:ns"
  "replicasets:replicasets.json:ns"
  "pods:pods.json:ns"
  "services:services.json:ns"
  "ingresses:ingresses.json:ns"
  "networkpolicies:networkpolicies.json:ns"
  "nodes:nodes.json:cluster"
)
declare -a TRIVY=(
  "vulnerabilityreports.aquasecurity.github.io:vulnerabilityreports.json:ns"
  "configauditreports.aquasecurity.github.io:configauditreports.json:ns"
  "exposedsecretreports.aquasecurity.github.io:exposedsecretreports.json:ns"
  "rbacassessmentreports.aquasecurity.github.io:rbacassessmentreports.json:ns"
  "clusterrbacassessmentreports.aquasecurity.github.io:clusterrbacassessmentreports.json:cluster"
  "infraassessmentreports.aquasecurity.github.io:infraassessmentreports.json:ns"
  "clustercompliancereports.aquasecurity.github.io:clustercompliancereports.json:cluster"
  "sbomreports.aquasecurity.github.io:sbomreports.json:ns"
)
declare -a KYVERNO=(
  "policyreports.wgpolicyk8s.io:policyreports.json:ns"
  "clusterpolicyreports.wgpolicyk8s.io:clusterpolicyreports.json:cluster"
)

API_RESOURCES="$("${KCTL[@]}" api-resources --verbs=list -o name 2>/dev/null || true)"

have_resource() {
  # exact plural, or plural.group
  grep -qx "$1" <<<"$API_RESOURCES" || grep -q "^$1\." <<<"$API_RESOURCES"
}

capture() {
  local dir="$1" spec="$2"
  local res="${spec%%:*}" rest="${spec#*:}"
  local file="${rest%%:*}" scope="${rest#*:}"
  if ! have_resource "$res"; then
    echo "  skip  $res (not installed)"
    return
  fi
  local args=(get "$res" -o json)
  [[ "$scope" == "ns" ]] && args+=(-A)
  "${KCTL[@]}" "${args[@]}" > "$OUT/$dir/$file"
  local n
  n=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("items", [])))' "$OUT/$dir/$file")
  printf '  %-6s %-45s %6s items  %8s bytes\n' "ok" "$res" "$n" "$(wc -c < "$OUT/$dir/$file" | tr -d ' ')"
}

echo "kubeapi:";  for s in "${KUBEAPI[@]}"; do capture kubeapi "$s"; done
echo "trivy:";    for s in "${TRIVY[@]}";   do capture trivy "$s"; done
echo "kyverno:";  for s in "${KYVERNO[@]}"; do capture kyverno "$s"; done

"${KCTL[@]}" version -o json > "$OUT/kubeapi/version.json" 2>/dev/null || echo '{}' > "$OUT/kubeapi/version.json"

python3 - "$OUT" <<'EOF'
import datetime, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
counts = {}
for sub in ("kubeapi", "trivy", "kyverno"):
    for p in sorted((out / sub).glob("*.json")):
        if p.name == "version.json":
            continue
        counts[f"{sub}/{p.name}"] = len(json.loads(p.read_text()).get("items", []))
ver = json.loads((out / "kubeapi/version.json").read_text())
images = set()
for p in ((out / "kubeapi/pods.json"),):
    if p.exists():
        for pod in json.loads(p.read_text()).get("items", []):
            for c in (pod.get("spec") or {}).get("containers") or []:
                img = c.get("image") or ""
                if "trivy-operator" in img or "kyverno" in img:
                    images.add(img.rsplit("/", 1)[-1])
meta = {
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "server_version": (ver.get("serverVersion") or {}).get("gitVersion", ""),
    "kubectl_version": (ver.get("clientVersion") or {}).get("gitVersion", ""),
    "scanner_images": sorted(images),
    "item_counts": counts,
}
(out / "capture-meta.json").write_text(json.dumps(meta, indent=2) + "\n")
print("\ncapture-meta.json written; total items:", sum(counts.values()))
EOF

echo
echo "Next: python scripts/anonymize-fixture.py $OUT fixtures/real/<alias> --salt-file <salt> --verify --write-golden"
