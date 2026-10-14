#!/usr/bin/env python3
"""Anonymise a captured cluster fixture so it can be committed.

    python scripts/anonymize-fixture.py <capture-dir> <out-dir> --salt-file SALT \
        [--keep-namespaces a,b] [--slim] [--verify] [--write-golden]

Deterministic HMAC renaming (the salt is generated once and NOT
committed): namespaces, object names (K8s suffix structure preserved so
ReplicaSet → Deployment and Pod → ReplicaSet relations survive), image
registries / repositories, hostnames, nodes, service accounts, label
VALUES (keys kept), UIDs. A final text-level sweep re-hashes every
`sha256:<64hex>` consistently, so Pod imageIDs, Trivy artifact digests,
pinned image refs and SBOM layer digests keep agreeing. Everything that
can carry a secret (env values, command/args, Secret/ConfigMap names,
annotations other than the ones the server reads, ExposedSecret matches,
Kyverno messages) is redacted or dropped.

`--verify` proves the anonymisation is faithful: the importer's
relevance-filter statistics and deployed-digest count are identical
before and after, and none of the original sensitive strings appear in
the output. `--write-golden` records the filter stats, bundle hashes and
unfiltered counts the real-data tests check against.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import re
import shutil
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kubeposture_importer.bundle import BundleWriter  # noqa: E402
from kubeposture_importer.coverage import compute_coverage  # noqa: E402
from kubeposture_importer.kinds import (  # noqa: E402
    FROM_FOLDER_KUBEAPI,
    FROM_FOLDER_KYVERNO,
    FROM_FOLDER_TRIVY,
    INVENTORY_ITEM_KINDS,
    SCAN_KINDS,
)
from kubeposture_importer.relevance import apply_relevance_filter  # noqa: E402
from kubeposture_importer.snapshot_index import build_index, controller_owner  # noqa: E402
from kubeposture_importer.trim import derive_cluster_meta, trim_manifest  # noqa: E402

SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease", "default", "trivy-system", "kyverno",
})
PUBLIC_REGISTRIES = frozenset({
    "docker.io", "registry.k8s.io", "k8s.gcr.io", "gcr.io", "quay.io", "ghcr.io",
    "public.ecr.aws", "mcr.microsoft.com", "cgr.dev",
})
# Annotations the server reads (core/parsers/inventory.py exposure logic).
ANNOTATION_ALLOWLIST = frozenset({
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/aws-load-balancer-scheme",
    "networking.gke.io/load-balancer-type",
    "service.beta.kubernetes.io/azure-load-balancer-internal",
    "alb.ingress.kubernetes.io/scheme",
    "kubernetes.io/ingress.class",
    "posture.io/contains-sensitive-data",
})
# Node label keys whose VALUES are safe and useful to keep.
NODE_LABEL_KEEP_VALUES = frozenset({
    "topology.kubernetes.io/region", "topology.kubernetes.io/zone",
    "failure-domain.beta.kubernetes.io/region", "failure-domain.beta.kubernetes.io/zone",
    "node.kubernetes.io/instance-type", "beta.kubernetes.io/instance-type",
    "kubernetes.io/os", "kubernetes.io/arch", "beta.kubernetes.io/os", "beta.kubernetes.io/arch",
})
LAYOUT = (("kubeapi", FROM_FOLDER_KUBEAPI), ("trivy", FROM_FOLDER_TRIVY), ("kyverno", FROM_FOLDER_KYVERNO))
GRAPH_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "ReplicaSet", "Pod")
CONTROLLER_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod")

_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)*([-+._][\w.]+)?$")
_HEX_RE = re.compile(r"^[a-f0-9]{5,12}$")
_IMAGE_RE = re.compile(
    r"^(?:(?P<registry>(?:[^/]+\.[^/]+|localhost)(?::\d+)?)/)?(?P<repo>[^@:]+?)(?::(?P<tag>[^@/]+))?(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)


def _read_json(path: Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(path.read_text())


def _items_of(doc) -> list[dict]:
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        return doc["items"]
    if isinstance(doc, list):
        return doc
    return [doc] if isinstance(doc, dict) else []


def _find(directory: Path, fname: str) -> Path | None:
    for candidate in (directory / fname, directory / (fname + ".gz")):
        if candidate.is_file():
            return candidate
    return None


class Anonymizer:
    def __init__(self, salt: bytes, *, keep_public_registries: bool = True, slim: bool = False,
                 keep_namespaces: set[str] | None = None):
        self.salt = salt
        self.keep_public_registries = keep_public_registries
        self.slim = slim
        self.keep_namespaces = None if keep_namespaces is None else (set(keep_namespaces) | SYSTEM_NAMESPACES)
        self.controllers: dict[str, set[str]] = {}   # ns → controller names
        self.leak: set[str] = set()                   # original strings that must not survive
        self.files: dict[str, list[dict]] = {}        # "kubeapi/pods.json" → items (subsetted)
        self.kind_of_file: dict[str, str] = {}

    # ── hashing primitives ─────────────────────────────────────────

    def h(self, category: str, value: str) -> str:
        return hmac.new(self.salt, f"{category}\0{value}".encode(), hashlib.sha256).hexdigest()

    def tag(self, prefix: str, category: str, value: str, n: int = 8) -> str:
        return f"{prefix}-{self.h(category, value)[:n]}"

    # ── per-field maps ─────────────────────────────────────────────

    def ns(self, name: str) -> str:
        if not name or name in SYSTEM_NAMESPACES:
            return name
        return self.tag("ns", "ns", name)

    def obj_name(self, ns: str, name: str) -> str:
        """Keep K8s suffix structure: `<controller>-<hash>[-<5>]` → the
        controller's new name + the original suffix."""
        if not name:
            return name
        if ns in SYSTEM_NAMESPACES and self.keep_namespaces is None:
            pass
        best = ""
        for ctrl in self.controllers.get(ns, ()):
            if (name == ctrl or name.startswith(ctrl + "-")) and len(ctrl) > len(best):
                best = ctrl
        if best:
            base = self.tag("wl", f"obj/{ns}", best)
            return base + name[len(best):]
        return self.tag("obj", f"obj/{ns}", name)

    def label_value(self, key: str, value) -> object:
        if not isinstance(value, str) or value == "":
            return value
        if value in ("true", "false") or value.isdigit() or _VERSION_RE.match(value) or _HEX_RE.match(value):
            return value
        return self.tag("lv", "label", value, 6)

    def host(self, name: str) -> str:
        if not name or name == "*":
            return name
        self.leak.add(name)
        return self.tag("host", "host", name) + ".example"

    def uid(self, value: str) -> str:
        if not value:
            return value
        return str(uuid.UUID(self.h("uid", value)[:32]))

    def sa(self, name: str) -> str:
        if not name or name == "default":
            return name
        return self.tag("sa", "sa", name)

    def node(self, name: str) -> str:
        if not name:
            return name
        self.leak.add(name)
        return self.tag("node", "node", name)

    def registry(self, reg: str) -> str:
        if not reg:
            return reg
        if self.keep_public_registries and reg.split(":")[0] in PUBLIC_REGISTRIES:
            return reg
        self.leak.add(reg)
        return self.tag("reg", "registry", reg) + ".example"

    def repo(self, repo: str, *, public: bool = False) -> str:
        if not repo:
            return repo
        # Repos on a kept public registry (library/busybox, kyverno/kyverno)
        # are public coordinates; everything else is flattened to one
        # hashed segment.
        if public:
            return repo
        self.leak.add(repo)
        return self.tag("img", "repo", repo)

    def _registry_is_public(self, reg: str) -> bool:
        return bool(reg) and self.keep_public_registries and reg.split(":")[0] in PUBLIC_REGISTRIES

    def image_tag(self, tag: str) -> str:
        if not tag or tag == "latest" or _VERSION_RE.match(tag) or re.match(r"^[a-f0-9]{7,40}$", tag):
            return tag
        return self.tag("tag", "tag", tag, 6)

    def image(self, ref: str) -> str:
        if not ref:
            return ref
        m = _IMAGE_RE.match(ref)
        if not m:
            return self.tag("img", "repo", ref)
        reg, repo, tag, digest = m.group("registry"), m.group("repo"), m.group("tag"), m.group("digest")
        out = ""
        if reg:
            out = self.registry(reg) + "/"
        out += self.repo(repo, public=self._registry_is_public(reg))
        if tag:
            out += ":" + self.image_tag(tag)
        if digest:
            out += "@" + digest  # re-hashed by the final sweep
        return out

    def image_id(self, image_id: str) -> str:
        if not image_id:
            return image_id
        prefix = ""
        body = image_id
        if "://" in body:
            prefix, body = body.split("://", 1)
            prefix += "://"
        if "@" in body:
            ref, _, digest = body.partition("@")
            return prefix + self.image(ref) + "@" + digest
        return prefix + self.image(body)

    # ── load / catalogue / subset ──────────────────────────────────

    def load(self, root: Path) -> None:
        for sub, mapping in LAYOUT:
            for fname, kind in mapping.items():
                p = _find(root / sub, fname)
                if p is None:
                    continue
                items = [it for it in _items_of(_read_json(p)) if isinstance(it, dict)]
                for it in items:
                    it.setdefault("kind", kind)
                self.files[f"{sub}/{fname}"] = items
                self.kind_of_file[f"{sub}/{fname}"] = kind
        ver = _find(root / "kubeapi", "version.json")
        self.version_doc = _read_json(ver) if ver else None
        self._subset()
        self._catalogue()

    def _subset(self) -> None:
        if self.keep_namespaces is None:
            return
        keep = self.keep_namespaces
        for key, items in self.files.items():
            kind = self.kind_of_file[key]
            kept = []
            for it in items:
                md = it.get("metadata") or {}
                if kind == "Namespace":
                    if md.get("name") in keep:
                        kept.append(it)
                elif md.get("namespace"):
                    if md["namespace"] in keep:
                        kept.append(it)
                else:
                    kept.append(it)  # cluster-scoped
            self.files[key] = kept

    def _catalogue(self) -> None:
        for key, items in self.files.items():
            kind = self.kind_of_file[key]
            for it in items:
                md = it.get("metadata") or {}
                ns = md.get("namespace") or ""
                name = md.get("name") or ""
                if kind == "Namespace" and name and name not in SYSTEM_NAMESPACES:
                    self.leak.add(name)
                if kind in CONTROLLER_KINDS:
                    if kind in ("Job", "Pod") and controller_owner(it) is not None:
                        continue
                    self.controllers.setdefault(ns, set()).add(name)
                    if ns not in SYSTEM_NAMESPACES:
                        self.leak.add(name)
                if ns and ns not in SYSTEM_NAMESPACES:
                    self.leak.add(ns)
        # Workload names shorter than 6 chars would produce false leak hits
        # against hashes/suffixes; the leak scan handles that via word
        # boundaries, but drop pathological tiny names anyway.
        self.leak = {s for s in self.leak if len(s) >= 4}

    def by_kind(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for key, items in self.files.items():
            out.setdefault(self.kind_of_file[key], []).extend(items)
        if self.version_doc is not None and isinstance(self.version_doc, dict):
            gv = self.version_doc.get("gitVersion") or (self.version_doc.get("serverVersion") or {}).get("gitVersion") or ""
            out["__version__"] = {"git_version": gv}
        return out

    # ── rewrite ────────────────────────────────────────────────────

    def rewrite_all(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for key, items in self.files.items():
            kind = self.kind_of_file[key]
            out[key] = [self.rewrite_item(kind, it) for it in items]
        return out

    def rewrite_item(self, kind: str, item: dict) -> dict:
        it = json.loads(json.dumps(item))  # deep copy
        md = it.get("metadata") or {}
        ns = md.get("namespace") or ""
        if kind in FROM_FOLDER_TRIVY.values():
            self._rewrite_trivy(kind, it, ns)
        elif kind in FROM_FOLDER_KYVERNO.values():
            self._rewrite_kyverno(it, ns)
        else:
            self._rewrite_k8s(kind, it, ns)
        return it

    def _rewrite_metadata(self, md: dict, ns: str, *, name_fn) -> None:
        for key in ("managedFields", "creationTimestamp", "resourceVersion", "generation", "selfLink"):
            md.pop(key, None)
        if "uid" in md:
            md["uid"] = self.uid(md["uid"])
        if md.get("namespace"):
            md["namespace"] = self.ns(md["namespace"])
        if "name" in md:
            md["name"] = name_fn(md["name"])
        if "generateName" in md:
            md.pop("generateName")
        if isinstance(md.get("labels"), dict):
            md["labels"] = {k: self.label_value(k, v) for k, v in md["labels"].items()}
        if isinstance(md.get("annotations"), dict):
            md["annotations"] = {k: v for k, v in md["annotations"].items() if k in ANNOTATION_ALLOWLIST}
        for ref in md.get("ownerReferences") or []:
            if isinstance(ref, dict):
                if "name" in ref:
                    ref["name"] = self.obj_name(ns, ref["name"])
                if "uid" in ref:
                    ref["uid"] = self.uid(ref["uid"])

    def _rewrite_selector(self, sel) -> None:
        if isinstance(sel, dict):
            if isinstance(sel.get("matchLabels"), dict):
                sel["matchLabels"] = {k: self.label_value(k, v) for k, v in sel["matchLabels"].items()}
            for expr in sel.get("matchExpressions") or []:
                if isinstance(expr, dict) and isinstance(expr.get("values"), list):
                    expr["values"] = [self.label_value(expr.get("key", ""), v) for v in expr["values"]]

    def _rewrite_pod_spec(self, spec: dict, ns: str) -> None:
        if not isinstance(spec, dict):
            return
        for key in ("containers", "initContainers", "ephemeralContainers"):
            for c in spec.get(key) or []:
                if not isinstance(c, dict):
                    continue
                if "image" in c:
                    c["image"] = self.image(c["image"])
                for env in c.get("env") or []:
                    if isinstance(env, dict):
                        if "value" in env:
                            env["value"] = "REDACTED"
                        vf = env.get("valueFrom") or {}
                        for src in ("secretKeyRef", "configMapKeyRef"):
                            if isinstance(vf.get(src), dict) and "name" in vf[src]:
                                vf[src]["name"] = self.obj_name(ns, vf[src]["name"])
                for ef in c.get("envFrom") or []:
                    for src in ("secretRef", "configMapRef"):
                        if isinstance(ef.get(src), dict) and "name" in ef[src]:
                            ef[src]["name"] = self.obj_name(ns, ef[src]["name"])
                for key2 in ("command", "args"):
                    if key2 in c:
                        c[key2] = ["REDACTED"]
                c.pop("lifecycle", None)
        for vol in spec.get("volumes") or []:
            if not isinstance(vol, dict):
                continue
            if isinstance(vol.get("secret"), dict) and "secretName" in vol["secret"]:
                vol["secret"]["secretName"] = self.obj_name(ns, vol["secret"]["secretName"])
            if isinstance(vol.get("configMap"), dict) and "name" in vol["configMap"]:
                vol["configMap"]["name"] = self.obj_name(ns, vol["configMap"]["name"])
            if isinstance(vol.get("persistentVolumeClaim"), dict) and "claimName" in vol["persistentVolumeClaim"]:
                vol["persistentVolumeClaim"]["claimName"] = self.obj_name(ns, vol["persistentVolumeClaim"]["claimName"])
            if isinstance(vol.get("hostPath"), dict) and "path" in vol["hostPath"]:
                vol["hostPath"]["path"] = "/REDACTED"
        for ips in spec.get("imagePullSecrets") or []:
            if isinstance(ips, dict) and "name" in ips:
                ips["name"] = self.obj_name(ns, ips["name"])
        if "serviceAccountName" in spec:
            spec["serviceAccountName"] = self.sa(spec["serviceAccountName"])
        if "serviceAccount" in spec:
            spec["serviceAccount"] = self.sa(spec["serviceAccount"])
        if "nodeName" in spec:
            spec["nodeName"] = self.node(spec["nodeName"])
        for key in ("hostAliases", "dnsConfig", "nodeSelector", "affinity", "topologySpreadConstraints", "hostname", "subdomain"):
            spec.pop(key, None)

    def _rewrite_k8s(self, kind: str, it: dict, ns: str) -> None:
        md = it.setdefault("metadata", {})
        if kind == "Namespace":
            self._rewrite_metadata(md, ns, name_fn=self.ns)
            it.pop("status", None)
            return
        if kind == "Node":
            # Node labels carry region / zone / instance type the server's
            # cluster-meta derivation reads — keep those values verbatim,
            # hash the rest (hostnames, nodegroup names, …).
            original_labels = dict(md.get("labels") or {})
            self._rewrite_metadata(md, ns, name_fn=self.node)
            md["labels"] = {
                k: (original_labels[k] if k in NODE_LABEL_KEEP_VALUES else v)
                for k, v in (md.get("labels") or {}).items()
            }
            spec = it.get("spec") or {}
            if "providerID" in spec:
                pid = spec["providerID"]
                scheme, _, path = pid.partition("://")
                parts = path.split("/")
                if parts:
                    parts[-1] = self.tag("i", "provider", parts[-1])
                spec["providerID"] = f"{scheme}://{'/'.join(parts)}"
            spec.pop("podCIDR", None)
            spec.pop("podCIDRs", None)
            info = (it.get("status") or {}).get("nodeInfo") or {}
            for k in ("machineID", "systemUUID", "bootID"):
                info.pop(k, None)
            it["status"] = {"nodeInfo": info}
            return

        self._rewrite_metadata(md, ns, name_fn=lambda n: self.obj_name(ns, n))
        spec = it.get("spec") or {}
        it.pop("status", None) if kind != "Pod" else None

        if kind == "Pod":
            self._rewrite_pod_spec(spec, ns)
            status = it.get("status") or {}
            keep: dict = {}
            for key in ("containerStatuses", "initContainerStatuses"):
                statuses = status.get(key)
                if isinstance(statuses, list):
                    for cs in statuses:
                        if isinstance(cs, dict):
                            if "image" in cs:
                                cs["image"] = self.image(cs["image"])
                            if "imageID" in cs:
                                cs["imageID"] = self.image_id(cs["imageID"])
                            cs.pop("containerID", None)
                    keep[key] = statuses
            if "phase" in status:
                keep["phase"] = status["phase"]
            it["status"] = keep
            return
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            self._rewrite_selector(spec.get("selector"))
            tpl = spec.get("template") or {}
            if isinstance(tpl.get("metadata"), dict):
                self._rewrite_metadata(tpl["metadata"], ns, name_fn=lambda n: self.obj_name(ns, n))
            self._rewrite_pod_spec(tpl.get("spec") or {}, ns)
            if kind == "StatefulSet" and "serviceName" in spec:
                spec["serviceName"] = self.obj_name(ns, spec["serviceName"])
            return
        if kind == "CronJob":
            jt = (spec.get("jobTemplate") or {}).get("spec") or {}
            self._rewrite_selector(jt.get("selector"))
            tpl = jt.get("template") or {}
            if isinstance(tpl.get("metadata"), dict):
                self._rewrite_metadata(tpl["metadata"], ns, name_fn=lambda n: self.obj_name(ns, n))
            self._rewrite_pod_spec(tpl.get("spec") or {}, ns)
            return
        if kind == "Service":
            if isinstance(spec.get("selector"), dict):
                spec["selector"] = {k: self.label_value(k, v) for k, v in spec["selector"].items()}
            for key in ("clusterIP", "clusterIPs", "externalIPs", "loadBalancerIP", "externalName", "loadBalancerSourceRanges"):
                spec.pop(key, None)
            return
        if kind == "Ingress":
            for rule in spec.get("rules") or []:
                if isinstance(rule, dict):
                    if "host" in rule:
                        rule["host"] = self.host(rule["host"])
                    for path in ((rule.get("http") or {}).get("paths") or []):
                        svc = ((path.get("backend") or {}).get("service") or {})
                        if "name" in svc:
                            svc["name"] = self.obj_name(ns, svc["name"])
            for tls in spec.get("tls") or []:
                if isinstance(tls, dict):
                    if isinstance(tls.get("hosts"), list):
                        tls["hosts"] = [self.host(h) for h in tls["hosts"]]
                    if "secretName" in tls:
                        tls["secretName"] = self.obj_name(ns, tls["secretName"])
            svc = ((spec.get("defaultBackend") or {}).get("service") or {})
            if "name" in svc:
                svc["name"] = self.obj_name(ns, svc["name"])
            return
        if kind == "NetworkPolicy":
            self._rewrite_selector(spec.get("podSelector"))
            for direction in ("ingress", "egress"):
                for rule in spec.get(direction) or []:
                    for peer in (rule.get("from") or []) + (rule.get("to") or []):
                        if isinstance(peer, dict):
                            self._rewrite_selector(peer.get("podSelector"))
                            self._rewrite_selector(peer.get("namespaceSelector"))
                            if isinstance(peer.get("ipBlock"), dict):
                                peer["ipBlock"] = {"cidr": "10.0.0.0/8"}
            return

    def _rewrite_trivy(self, kind: str, it: dict, ns: str) -> None:
        md = it.setdefault("metadata", {})
        labels = md.get("labels") or {}
        res_ns = labels.get("trivy-operator.resource.namespace") or ns
        res_kind = labels.get("trivy-operator.resource.kind") or ""
        res_name = labels.get("trivy-operator.resource.name") or ""
        container = labels.get("trivy-operator.container.name") or ""
        new_res_name = self.obj_name(res_ns, res_name) if res_name else ""

        def _name(_old: str) -> str:
            if res_name:
                parts = [res_kind.lower(), new_res_name] + ([container] if container else [])
                return "-".join(p for p in parts if p)
            return self.tag("rep", "report", _old)

        self._rewrite_metadata(md, ns, name_fn=_name)
        new_labels = {}
        for k, v in labels.items():
            if k == "trivy-operator.resource.namespace":
                new_labels[k] = self.ns(v)
            elif k == "trivy-operator.resource.name":
                new_labels[k] = new_res_name
            elif k in ("trivy-operator.resource.kind", "trivy-operator.container.name", "trivy-operator.resource.name"):
                new_labels[k] = v
            else:
                new_labels[k] = self.label_value(k, v)
        md["labels"] = new_labels

        report = it.get("report") or {}
        artifact = report.get("artifact")
        if isinstance(artifact, dict):
            if "repository" in artifact:
                m = _IMAGE_RE.match(artifact["repository"])
                if m and m.group("registry"):
                    reg = m.group("registry")
                    artifact["repository"] = (
                        self.registry(reg) + "/" + self.repo(m.group("repo"), public=self._registry_is_public(reg))
                    )
                else:
                    artifact["repository"] = self.repo(artifact["repository"])
            if "tag" in artifact:
                artifact["tag"] = self.image_tag(artifact["tag"])
        if isinstance(report.get("registry"), dict) and "server" in report["registry"]:
            report["registry"]["server"] = self.registry(report["registry"]["server"])
        for check in report.get("checks") or []:
            if isinstance(check, dict) and "messages" in check:
                check["messages"] = []
        for secret in report.get("secrets") or []:
            if isinstance(secret, dict) and "match" in secret:
                secret["match"] = "REDACTED"
        if self.slim:
            for vuln in report.get("vulnerabilities") or []:
                if isinstance(vuln, dict):
                    vuln.pop("description", None)
        bom = report.get("components")
        if isinstance(bom, dict):
            comp = (bom.get("metadata") or {}).get("component")
            if isinstance(comp, dict) and "name" in comp:
                comp["name"] = self.image(comp["name"])
            if isinstance((bom.get("metadata") or {}).get("tools"), (list, dict)):
                pass
            bom.pop("serialNumber", None)

    def _rewrite_kyverno(self, it: dict, ns: str) -> None:
        md = it.setdefault("metadata", {})

        def _name(old: str) -> str:
            if _UUID_RE.match(old):
                return self.uid(old)
            return self.tag("polr", "report", old)

        self._rewrite_metadata(md, ns, name_fn=_name)
        scope = it.get("scope")
        if isinstance(scope, dict):
            if "name" in scope:
                scope["name"] = self.obj_name(scope.get("namespace") or ns, scope["name"])
            if scope.get("namespace"):
                scope["namespace"] = self.ns(scope["namespace"])
            if "uid" in scope:
                scope["uid"] = self.uid(scope["uid"])
        for result in it.get("results") or []:
            if not isinstance(result, dict):
                continue
            result["message"] = f"{result.get('policy', '')}/{result.get('rule', '')}"
            for key in ("subjects", "resources"):
                for subj in result.get(key) or []:
                    if isinstance(subj, dict):
                        if "name" in subj:
                            subj["name"] = self.obj_name(subj.get("namespace") or ns, subj["name"])
                        if subj.get("namespace"):
                            subj["namespace"] = self.ns(subj["namespace"])
                        if "uid" in subj:
                            subj["uid"] = self.uid(subj["uid"])
            result.pop("properties", None)

    # ── output ─────────────────────────────────────────────────────

    def sweep_digests(self, text: str) -> str:
        return _SHA_RE.sub(lambda m: "sha256:" + self.h("digest", m.group(0))[:64], text)

    def write(self, out: Path, rewritten: dict[str, list[dict]]) -> None:
        for key, items in rewritten.items():
            kind = self.kind_of_file[key]
            path = out / (key + ".gz")
            path.parent.mkdir(parents=True, exist_ok=True)
            text = json.dumps({"apiVersion": "v1", "kind": f"{kind}List", "items": items}, separators=(",", ":"))
            with gzip.open(path, "wt", encoding="utf-8", compresslevel=9) as fh:
                fh.write(self.sweep_digests(text))
        if self.version_doc is not None:
            (out / "kubeapi").mkdir(parents=True, exist_ok=True)
            gv = ""
            if isinstance(self.version_doc, dict):
                gv = self.version_doc.get("gitVersion") or (self.version_doc.get("serverVersion") or {}).get("gitVersion") or ""
            with gzip.open(out / "kubeapi/version.json.gz", "wt", encoding="utf-8") as fh:
                json.dump({"gitVersion": gv}, fh)


# ── verification / golden ──────────────────────────────────────────


def _filter_report(by_kind: dict, *, relevance: bool = True) -> dict:
    idx = build_index(by_kind)
    scan_items = {env_kind: list(by_kind[crd]) for crd, env_kind in SCAN_KINDS if crd in by_kind}
    filtered, stats = apply_relevance_filter(scan_items, idx, enabled=relevance)
    report = {"deployed_digests": len(idx.deployed_digests), "controllers": len(idx.controllers), "kinds": {}}
    for kind in filtered:
        cov = compute_coverage(kind, stats[kind], idx, threshold=0.9)
        report["kinds"][kind] = {**stats[kind].as_dict(), "count": len(filtered[kind]),
                                 "expected": cov.expected, "matched": cov.matched}
    return report


def verify(anon: Anonymizer, out: Path) -> list[str]:
    """Returns a list of problems (empty = faithful + leak-free)."""
    problems: list[str] = []
    from kubeposture_importer.sources.folder import collect_from_folder
    before = _filter_report(anon.by_kind())
    after = _filter_report(collect_from_folder(out))
    if before != after:
        problems.append(f"filter statistics differ:\n  before={json.dumps(before, sort_keys=True)}\n  after ={json.dumps(after, sort_keys=True)}")
    text = "\n".join(
        gzip.open(p, "rt", encoding="utf-8").read() for p in sorted(out.rglob("*.gz"))
    )
    # Hosts / registries / repos are added to the leak set during the
    # rewrite, after the catalogue's length filter — apply it here too so
    # a 1-3 character token can't produce false positives.
    for needle in sorted(s for s in anon.leak if len(s) >= 4):
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(needle) + r"(?![A-Za-z0-9])", text):
            problems.append(f"original string leaked: {needle!r}")
    original_text = json.dumps(anon.by_kind(), separators=(",", ":"))
    for digest in set(_SHA_RE.findall(original_text)):
        if digest in text:
            problems.append(f"original digest leaked: {digest}")
            break
    return problems


def write_golden(out: Path) -> None:
    from kubeposture_importer.sources.folder import collect_from_folder
    by_kind = collect_from_folder(out)
    golden = out / "golden"
    golden.mkdir(exist_ok=True)
    (golden / "filter_stats.json").write_text(json.dumps(_filter_report(by_kind), indent=2, sort_keys=True) + "\n")
    (golden / "unfiltered_counts.json").write_text(
        json.dumps(_filter_report(by_kind, relevance=False), indent=2, sort_keys=True) + "\n"
    )
    bundles: dict = {}
    idx = build_index(by_kind)
    scan_items = {env_kind: list(by_kind[crd]) for crd, env_kind in SCAN_KINDS if crd in by_kind}
    filtered, _ = apply_relevance_filter(scan_items, idx, enabled=True)
    tmp = golden / ".tmp"
    tmp.mkdir(exist_ok=True)
    try:
        cluster_meta = derive_cluster_meta("fixture", by_kind)
        with BundleWriter(cluster="fixture", import_id="GOLDEN", kind="inventory", tmp_dir=tmp, complete_snapshot=True) as w:
            w.write_inventory_envelope(cluster_meta, (trim_manifest(it) for k in sorted(INVENTORY_ITEM_KINDS) for it in by_kind.get(k) or []))
            meta = w.finish()
        bundles["inventory"] = {"count": meta.count, "sha256": meta.sha256,
                                "uncompressed_bytes": meta.uncompressed_bytes, "compressed_bytes": meta.compressed_bytes}
        meta.unlink()
        for kind, items in filtered.items():
            with BundleWriter(cluster="fixture", import_id="GOLDEN", kind=kind, tmp_dir=tmp) as w:
                for item in items:
                    w.write_item(item)
                meta = w.finish()
            bundles[kind] = {"count": meta.count, "sha256": meta.sha256,
                             "uncompressed_bytes": meta.uncompressed_bytes, "compressed_bytes": meta.compressed_bytes}
            meta.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    (golden / "bundles.json").write_text(json.dumps(bundles, indent=2, sort_keys=True) + "\n")


def anonymize(src: Path, out: Path, *, salt: bytes, keep_namespaces: set[str] | None = None,
              slim: bool = False, keep_public_registries: bool = True) -> Anonymizer:
    anon = Anonymizer(salt, keep_public_registries=keep_public_registries, slim=slim, keep_namespaces=keep_namespaces)
    anon.load(src)
    rewritten = anon.rewrite_all()
    out.mkdir(parents=True, exist_ok=True)
    anon.write(out, rewritten)
    meta_src = src / "capture-meta.json"
    if meta_src.is_file():
        meta = json.loads(meta_src.read_text())
        meta.pop("kubectl_version", None)
        (out / "capture-meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return anon


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("src", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--salt-file", type=Path, required=True,
                        help="File with the HMAC salt (created with random bytes if missing). Never commit it.")
    parser.add_argument("--keep-namespaces", default=None,
                        help="Comma-separated namespaces to keep (plus system namespaces); others and their reports are dropped.")
    parser.add_argument("--slim", action="store_true", help="Drop vulnerability descriptions to cut size.")
    parser.add_argument("--no-keep-public-registries", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--write-golden", action="store_true")
    args = parser.parse_args(argv)

    if not args.salt_file.exists():
        import secrets
        args.salt_file.write_bytes(secrets.token_bytes(32))
        print(f"generated new salt at {args.salt_file} — keep it private, do not commit it")
    salt = args.salt_file.read_bytes()
    keep = None
    if args.keep_namespaces:
        keep = {n.strip() for n in args.keep_namespaces.split(",") if n.strip()}

    anon = anonymize(args.src, args.out, salt=salt, keep_namespaces=keep, slim=args.slim,
                     keep_public_registries=not args.no_keep_public_registries)
    total = sum(p.stat().st_size for p in args.out.rglob("*.gz"))
    print(f"wrote {args.out} ({total / 1024 / 1024:.2f} MB compressed)")

    rc = 0
    if args.verify:
        problems = verify(anon, args.out)
        if problems:
            rc = 1
            print("VERIFY FAILED:", file=sys.stderr)
            for p in problems:
                print("  - " + p, file=sys.stderr)
        else:
            print("verify: filter statistics identical before/after; no original identifiers or digests leaked")
    if args.write_golden:
        write_golden(args.out)
        print(f"golden files written under {args.out / 'golden'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
