"""The anonymiser must be deterministic, leak nothing, and — crucially —
leave the importer's relevance-filter behaviour unchanged, so the
anonymised capture is still a faithful test fixture."""
from __future__ import annotations

import gzip
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
from kubeposture_importer.sources.folder import collect_from_folder

from .fixtures_builders import (
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_OLD,
    cronjob,
    kyverno_result,
    namespace,
    pod,
    replicaset,
    subject,
)

_SCRIPT = Path(__file__).resolve().parents[1] / "anonymize-fixture.py"


@pytest.fixture(scope="module")
def anon_mod():
    spec = importlib.util.spec_from_file_location("anonymize_fixture", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["anonymize_fixture"] = mod
    spec.loader.exec_module(mod)
    return mod


SALT = b"test-salt-0123456789"


def _deployment(name, ns, image, *, replicas=1):
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns, "uid": "11111111-2222-3333-4444-555555555555",
                     "labels": {"app": name, "team": "payments-core", "version": "v1.2.3"},
                     "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{secret}",
                                     "posture.io/contains-sensitive-data": "true"},
                     "creationTimestamp": "2026-01-01T00:00:00Z", "resourceVersion": "123", "managedFields": [{}]},
        "spec": {"replicas": replicas, "selector": {"matchLabels": {"app": name}},
                 "template": {"metadata": {"labels": {"app": name}},
                              "spec": {"serviceAccountName": "payments-sa", "nodeName": "ip-10-0-1-23.eu-west-1.compute.internal",
                                       "imagePullSecrets": [{"name": "regcred"}],
                                       "containers": [{"name": "app", "image": image,
                                                       "env": [{"name": "DB_PASSWORD", "value": "hunter2"},
                                                               {"name": "X", "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "p"}}}],
                                                       "command": ["/bin/sh", "-c", "curl http://internal"]}],
                                       "volumes": [{"name": "s", "secret": {"secretName": "tls-cert"}}]}}},
    }


def _service(name, ns, selector_app):
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns},
            "spec": {"type": "LoadBalancer", "selector": {"app": selector_app}, "clusterIP": "10.1.2.3",
                     "ports": [{"port": 80}]}}


def _ingress(name, ns, host, svc):
    return {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": name, "namespace": ns},
            "spec": {"ingressClassName": "nginx", "rules": [{"host": host, "http": {"paths": [
                {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": svc, "port": {"number": 80}}}}]}}],
                "tls": [{"hosts": [host], "secretName": "payments-tls"}]}}


def _node():
    return {"apiVersion": "v1", "kind": "Node", "metadata": {"name": "ip-10-0-1-23.eu-west-1.compute.internal",
            "labels": {"topology.kubernetes.io/region": "eu-west-1", "eks.amazonaws.com/nodegroup": "ng-prod-1",
                       "kubernetes.io/hostname": "ip-10-0-1-23.eu-west-1.compute.internal"}},
            "spec": {"providerID": "aws:///eu-west-1a/i-0123456789abcdef0"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.1.23"}],
                       "nodeInfo": {"kubeletVersion": "v1.30.2", "machineID": "abc", "osImage": "Bottlerocket"}}}


def _trivy(kind, ns, subject_kind, subject_name, digest, repo="123456789012.dkr.ecr.eu-west-1.amazonaws.com/payments/api",
           extra_report=None):
    report = {"artifact": {"repository": repo, "tag": "1.2.3", "digest": digest},
              "registry": {"server": repo.split("/")[0]}, "summary": {"criticalCount": 1}}
    report.update(extra_report or {})
    return {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": kind,
            "metadata": {"name": f"{subject_kind.lower()}-{subject_name}-app", "namespace": ns,
                         "labels": {"trivy-operator.resource.kind": subject_kind, "trivy-operator.resource.name": subject_name,
                                    "trivy-operator.resource.namespace": ns, "trivy-operator.container.name": "app"}},
            "report": report}


def _write(root: Path, rel: str, items: list[dict]) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"kind": "List", "items": items}))


def _capture(root: Path) -> Path:
    ns, kube = "payments", "kube-system"
    api_img = "123456789012.dkr.ecr.eu-west-1.amazonaws.com/payments/api:1.2.3"
    chain_rs = replicaset("api-7d9f5b6c8d", ns, owner_name="api", image=api_img)
    chain_pod = pod("api-7d9f5b6c8d-x1", ns, owner_ref={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9f5b6c8d", "controller": True},
                    image=api_img, digest=SHA_A, image_id_style="docker-pullable")
    old_rs = replicaset("api-5555555555", ns, owner_name="api", image="123456789012.dkr.ecr.eu-west-1.amazonaws.com/payments/api:1.2.2", replicas=0)
    agent_pod = pod("agent-abc12", kube, image="docker.io/library/busybox:1.36", digest=SHA_B)
    _write(root, "kubeapi/namespaces.json", [namespace(ns), namespace(kube), namespace("other-team")])
    _write(root, "kubeapi/deployments.json", [_deployment("api", ns, api_img), _deployment("legacy", "other-team", "r/legacy:1")])
    _write(root, "kubeapi/replicasets.json", [chain_rs, old_rs])
    _write(root, "kubeapi/pods.json", [chain_pod, agent_pod])
    _write(root, "kubeapi/services.json", [_service("api-svc", ns, "api")])
    _write(root, "kubeapi/ingresses.json", [_ingress("api-ing", ns, "api.payments.corp.example.com", "api-svc")])
    _write(root, "kubeapi/cronjobs.json", [cronjob("nightly", ns, image="123456789012.dkr.ecr.eu-west-1.amazonaws.com/payments/cron:2.0")])
    _write(root, "kubeapi/nodes.json", [_node()])
    _write(root, "trivy/vulnerabilityreports.json", [
        _trivy("VulnerabilityReport", ns, "ReplicaSet", "api-7d9f5b6c8d", SHA_A,
               extra_report={"vulnerabilities": [{"vulnerabilityID": "CVE-2024-1", "description": "long text", "severity": "HIGH"}]}),
        _trivy("VulnerabilityReport", ns, "ReplicaSet", "api-5555555555", SHA_OLD),
        _trivy("VulnerabilityReport", "other-team", "ReplicaSet", "legacy-aaa", SHA_C, repo="r/legacy"),
    ])
    _write(root, "trivy/sbomreports.json", [
        _trivy("SbomReport", ns, "ReplicaSet", "api-7d9f5b6c8d", SHA_A, extra_report={"components": {
            "bomFormat": "CycloneDX", "serialNumber": "urn:uuid:abc",
            "metadata": {"component": {"name": "123456789012.dkr.ecr.eu-west-1.amazonaws.com/payments/api:1.2.3", "type": "container"}},
            "components": [{"name": "openssl", "version": "3.0.1", "purl": "pkg:deb/debian/openssl@3.0.1",
                            "properties": [{"name": "aquasecurity:trivy:LayerDigest", "value": SHA_B}]}]}}),
    ])
    _write(root, "trivy/exposedsecretreports.json", [
        _trivy("ExposedSecretReport", ns, "ReplicaSet", "api-7d9f5b6c8d", SHA_A,
               extra_report={"secrets": [{"ruleID": "aws-key", "target": "/app/.env", "match": "AKIA1234567890SECRET"}]}),
    ])
    _write(root, "kyverno/policyreports.json", [{
        "apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
        "metadata": {"name": "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f", "namespace": ns},
        "scope": {"kind": "Pod", "name": "api-7d9f5b6c8d-x1", "namespace": ns, "uid": "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f"},
        "results": [kyverno_result(subjects=[subject("Pod", "api-7d9f5b6c8d-x1", ns)]) | {"message": "validation error: pod api-7d9f5b6c8d-x1 in payments"}],
    }])
    (root / "kubeapi/version.json").write_text(json.dumps({"serverVersion": {"gitVersion": "v1.30.2"}}))
    (root / "capture-meta.json").write_text(json.dumps({"captured_at": "2026-10-01", "kubectl_version": "x"}))
    return root


def _load_out(out: Path) -> dict:
    return collect_from_folder(out)


@pytest.fixture
def run(anon_mod, tmp_path):
    def _run(**kw):
        src = _capture(tmp_path / "src")
        out = tmp_path / "out"
        anon = anon_mod.anonymize(src, out, salt=SALT, **kw)
        return anon, out, _load_out(out)
    return _run


def test_deterministic_same_salt_differs_with_other_salt(anon_mod, tmp_path):
    src = _capture(tmp_path / "src")
    a = anon_mod.anonymize(src, tmp_path / "a", salt=SALT)
    anon_mod.anonymize(src, tmp_path / "b", salt=SALT)
    anon_mod.anonymize(src, tmp_path / "c", salt=b"other")
    read = lambda d: {p.relative_to(d): p.read_bytes() for p in sorted(d.rglob("*.gz"))}  # noqa: E731
    assert read(tmp_path / "a") == read(tmp_path / "b")
    assert read(tmp_path / "a") != read(tmp_path / "c")
    assert a.ns("payments") == anon_mod.Anonymizer(SALT).ns("payments")


def test_namespaces_renamed_everywhere_system_kept(run):
    anon, _, out = run()
    new_ns = anon.ns("payments")
    assert new_ns.startswith("ns-") and new_ns != "payments"
    assert {n["metadata"]["name"] for n in out["Namespace"]} == {new_ns, "kube-system", anon.ns("other-team")}
    dep = next(d for d in out["Deployment"] if d["metadata"]["name"].startswith("wl-") and d["metadata"]["namespace"] == new_ns)
    assert dep["metadata"]["namespace"] == new_ns
    vuln = out["VulnerabilityReport"][0]
    assert vuln["metadata"]["namespace"] == new_ns
    assert vuln["metadata"]["labels"]["trivy-operator.resource.namespace"] == new_ns
    polr = out["PolicyReport"][0]
    assert polr["results"][0]["subjects"][0]["namespace"] == new_ns and polr["scope"]["namespace"] == new_ns
    assert out["Pod"][1]["metadata"]["namespace"] == "kube-system"


def test_suffix_structure_preserved_through_deployment_rs_pod_and_reports(run):
    anon, _, out = run()
    dep_new = anon.obj_name("payments", "api")
    rs_new = next(r["metadata"]["name"] for r in out["ReplicaSet"] if r["metadata"]["name"].endswith("-7d9f5b6c8d"))
    assert rs_new == f"{dep_new}-7d9f5b6c8d"
    assert out["ReplicaSet"][0]["metadata"]["ownerReferences"][0]["name"] == dep_new
    pod_ = next(p for p in out["Pod"] if p["metadata"]["namespace"] != "kube-system")
    assert pod_["metadata"]["name"] == f"{rs_new}-x1"
    assert pod_["metadata"]["ownerReferences"][0]["name"] == rs_new
    vuln = next(v for v in out["VulnerabilityReport"] if v["metadata"]["labels"]["trivy-operator.resource.name"] == rs_new)
    assert vuln["metadata"]["name"] == f"replicaset-{rs_new}-app"
    assert out["PolicyReport"][0]["results"][0]["subjects"][0]["name"] == f"{rs_new}-x1"


def test_digest_rehash_consistent_across_imageid_artifact_sbom_and_pinned_refs(run):
    anon, out_dir, out = run()
    pod_ = next(p for p in out["Pod"] if p["metadata"]["namespace"] != "kube-system")
    image_id = pod_["status"]["containerStatuses"][0]["imageID"]
    assert image_id.startswith("docker-pullable://") and "@sha256:" in image_id
    new_digest = image_id.split("@")[1]
    assert new_digest != SHA_A and re.fullmatch(r"sha256:[0-9a-f]{64}", new_digest)
    vuln = next(v for v in out["VulnerabilityReport"] if v["metadata"]["labels"]["trivy-operator.resource.name"].endswith("-7d9f5b6c8d"))
    assert vuln["report"]["artifact"]["digest"] == new_digest
    assert out["SbomReport"][0]["report"]["artifact"]["digest"] == new_digest
    layer = out["SbomReport"][0]["report"]["components"]["components"][0]["properties"][0]["value"]
    assert layer == anon.sweep_digests(SHA_B)
    text = "".join(gzip.open(p, "rt").read() for p in out_dir.rglob("*.gz"))
    assert SHA_A not in text and SHA_B not in text and SHA_C not in text and SHA_OLD not in text


def test_images_registries_hosts_nodes_and_labels(run):
    anon, _, out = run()
    dep = next(d for d in out["Deployment"] if d["metadata"]["namespace"] == anon.ns("payments"))
    image = dep["spec"]["template"]["spec"]["containers"][0]["image"]
    assert image.endswith(":1.2.3") and "amazonaws" not in image and "payments" not in image
    assert image.split("/")[0].endswith(".example")
    agent = next(p for p in out["Pod"] if p["metadata"]["namespace"] == "kube-system")
    assert agent["spec"]["containers"][0]["image"] == "docker.io/library/busybox:1.36", "public registry + repo kept"
    ing = out["Ingress"][0]
    assert ing["spec"]["rules"][0]["host"].endswith(".example") and ing["spec"]["tls"][0]["hosts"][0] == ing["spec"]["rules"][0]["host"]
    svc_name = out["Service"][0]["metadata"]["name"]
    assert ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] == svc_name
    # label values hashed, selector still matches the pod template
    assert out["Service"][0]["spec"]["selector"]["app"] == dep["spec"]["template"]["metadata"]["labels"]["app"]
    assert dep["metadata"]["labels"]["version"] == "v1.2.3" and dep["metadata"]["labels"]["team"].startswith("lv-")
    node = out["Node"][0]
    assert node["metadata"]["name"].startswith("node-")
    assert node["metadata"]["labels"]["topology.kubernetes.io/region"] == "eu-west-1"
    assert node["spec"]["providerID"].startswith("aws:///eu-west-1a/i-")
    assert node["status"] == {"nodeInfo": {"kubeletVersion": "v1.30.2", "osImage": "Bottlerocket"}}
    assert dep["spec"]["template"]["spec"]["nodeName"] == node["metadata"]["name"]


def test_secrets_redacted_and_annotations_allowlisted(run):
    _, out_dir, out = run()
    dep = next(d for d in out["Deployment"] if d["metadata"]["name"].startswith("wl-"))
    c = dep["spec"]["template"]["spec"]["containers"][0]
    assert c["env"][0]["value"] == "REDACTED"
    assert c["env"][1]["valueFrom"]["secretKeyRef"]["name"] != "db-secret"
    assert c["command"] == ["REDACTED"]
    assert dep["spec"]["template"]["spec"]["volumes"][0]["secret"]["secretName"] != "tls-cert"
    assert dep["spec"]["template"]["spec"]["serviceAccountName"].startswith("sa-")
    assert dep["metadata"]["annotations"] == {"posture.io/contains-sensitive-data": "true"}
    assert "creationTimestamp" not in dep["metadata"] and "managedFields" not in dep["metadata"]
    assert out["ExposedSecretReport"][0]["report"]["secrets"][0]["match"] == "REDACTED"
    assert out["ExposedSecretReport"][0]["report"]["secrets"][0]["target"] == "/app/.env"
    assert out["PolicyReport"][0]["results"][0]["message"] == "disallow-host-namespaces/r"
    assert "clusterIP" not in out["Service"][0]["spec"]
    text = "".join(gzip.open(p, "rt").read() for p in out_dir.rglob("*.gz"))
    for secret in ("hunter2", "AKIA1234567890SECRET", "db-secret", "tls-cert", "last-applied", "10.0.1.23", "ip-10-0-1-23"):
        assert secret not in text, secret


def test_uuid_names_mapped_consistently(run):
    anon, _, out = run()
    polr = out["PolicyReport"][0]
    assert polr["metadata"]["name"] == polr["scope"]["uid"] == anon.uid("9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f")
    assert re.fullmatch(r"[0-9a-f-]{36}", polr["metadata"]["name"])


def test_keep_namespaces_subset_drops_reports_of_dropped_namespaces(run):
    anon, _, out = run(keep_namespaces={"payments"})
    assert anon.ns("other-team") not in {n["metadata"]["name"] for n in out["Namespace"]}
    assert all(d["metadata"]["namespace"] != anon.ns("other-team") for d in out["Deployment"])
    assert len(out["VulnerabilityReport"]) == 2, "the other-team report is dropped with its namespace"
    assert len(out["Node"]) == 1, "cluster-scoped objects kept"
    assert any(n["metadata"]["name"] == "kube-system" for n in out["Namespace"])


def test_slim_drops_vulnerability_descriptions(run):
    _, _, out = run(slim=True)
    assert "description" not in out["VulnerabilityReport"][0]["report"]["vulnerabilities"][0]


def test_verify_filter_stats_identical_and_no_leaks(anon_mod, run):
    anon, out_dir, _ = run()
    assert anon_mod.verify(anon, out_dir) == []
    before = anon_mod._filter_report(anon.by_kind())
    after = anon_mod._filter_report(_load_out(out_dir))
    assert before == after
    assert after["kinds"]["trivy.VulnerabilityReport"]["dropped_image_not_deployed"] == 2, "RS-history + other-team"
    assert after["deployed_digests"] == 2


def test_verify_detects_a_leak(anon_mod, run):
    anon, out_dir, _ = run()
    p = next(out_dir.glob("kubeapi/deployments.json.gz"))
    doc = json.loads(gzip.open(p, "rt").read())
    doc["items"][0]["metadata"]["annotations"]["note"] = "cluster payments api"
    with gzip.open(p, "wt") as fh:
        fh.write(json.dumps(doc))
    problems = anon_mod.verify(anon, out_dir)
    assert any("leaked" in msg and "payments" in msg for msg in problems)


def test_write_golden_produces_stats_bundles_and_unfiltered_counts(anon_mod, run):
    _, out_dir, _ = run()
    anon_mod.write_golden(out_dir)
    stats = json.loads((out_dir / "golden/filter_stats.json").read_text())
    bundles = json.loads((out_dir / "golden/bundles.json").read_text())
    unfiltered = json.loads((out_dir / "golden/unfiltered_counts.json").read_text())
    assert stats["kinds"]["trivy.VulnerabilityReport"]["count"] == 1
    assert unfiltered["kinds"]["trivy.VulnerabilityReport"]["count"] == 3
    assert bundles["inventory"]["count"] == 1
    assert bundles["trivy.VulnerabilityReport"]["count"] == 1
    assert re.fullmatch(r"[0-9a-f]{64}", bundles["trivy.SbomReport"]["sha256"])
    assert not (out_dir / "golden/.tmp").exists()


def test_cli_end_to_end_with_salt_generation(anon_mod, tmp_path, capsys):
    src = _capture(tmp_path / "src")
    salt = tmp_path / "salt.bin"
    rc = anon_mod.main([str(src), str(tmp_path / "out"), "--salt-file", str(salt), "--verify", "--write-golden",
                        "--keep-namespaces", "payments"])
    assert rc == 0
    assert salt.exists() and len(salt.read_bytes()) == 32
    out = capsys.readouterr().out
    assert "verify: filter statistics identical" in out and "golden files written" in out
    assert (tmp_path / "out/capture-meta.json").exists()
    assert "kubectl_version" not in (tmp_path / "out/capture-meta.json").read_text()
