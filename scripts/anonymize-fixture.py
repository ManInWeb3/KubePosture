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
# Registries whose repository paths are well-known public projects and
# safe to keep readable. Deliberately NOT ghcr.io / quay.io / gcr.io /
# docker.io orgs: private images live there too (ghcr.io/<company>/app),
# so their repo paths are hashed. docker.io keeps only `library/…` and
# bare official names; see Anonymizer.repo_is_public.
PUBLIC_REGISTRIES = frozenset({
    "registry.k8s.io", "k8s.gcr.io", "mcr.microsoft.com", "cgr.dev", "public.ecr.aws",
})
DOCKER_HUB = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})

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
# Label-key domains that are public APIs (keep readable). Any other
# domain-qualified key (`superapp.company.com/preview`) names the
# organisation and is hashed.
PUBLIC_LABEL_DOMAINS = (
    "kubernetes.io", "k8s.io", "amazonaws.com", "k8s.aws", "helm.sh", "github.io",
    "cilium.io", "istio.io", "linkerd.io", "argoproj.io", "fluxcd.io", "cert-manager.io",
    "external-secrets.io", "karpenter.sh", "kyverno.io", "wgpolicyk8s.io", "openebs.io",
    "prometheus.io", "posture.io", "projectcalico.org", "metallb.io", "traefik.io",
)
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
                 keep_namespaces: set[str] | None = None, private_words: list[str] | None = None):
        self.salt = salt
        self.private_words = sorted({w.strip().lower() for w in (private_words or []) if w.strip()}, key=len, reverse=True)
        self._words_re = (
            re.compile("|".join(re.escape(w) for w in self.private_words), re.I) if self.private_words else None
        )
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

    # K8s-generated name suffixes: random pod / ReplicaSet-hash strings use
    # the alphabet "bcdfghjklmnpqrstvwxz2456789" (vowel-free, so no words),
    # plus StatefulSet ordinals and Job timestamps. Anything else after a
    # controller-name prefix is human text (`-data-api-redis-0`) and must
    # not survive.
    _GEN = r"(?:-[bcdfghjklmnpqrstvwxz2456789]{5}|-[bcdfghjklmnpqrstvwxz2456789]{8,10}|-\d{1,10})"
    _GEN_SUFFIX_RE = re.compile(r"(?:%s){1,3}" % _GEN)

    def obj_name(self, ns: str, name: str) -> str:
        """Keep K8s suffix structure — `<controller>-<hash>[-<5>]` → the
        controller's new name + the GENERATED suffix — so ReplicaSet →
        Deployment and Pod → ReplicaSet relations stay recognisable.
        Everything else is hashed whole."""
        if not name:
            return name
        best = ""
        for ctrl in self.controllers.get(ns, ()):
            if name.startswith(ctrl + "-") and len(ctrl) > len(best):
                if self._GEN_SUFFIX_RE.fullmatch(name[len(ctrl):]):
                    best = ctrl
        if name in self.controllers.get(ns, ()):
            return self.tag("wl", f"obj/{ns}", name)
        if best:
            return self.tag("wl", f"obj/{ns}", best) + name[len(best):]
        return self.tag("obj", f"obj/{ns}", name)

    def label_key(self, key: str) -> str:
        """Keep Kubernetes / well-known vendor keys; hash the domain of
        anything else so an organisation's own domain never survives."""
        if "/" not in key:
            return key
        domain, _, name = key.partition("/")
        if domain.endswith(PUBLIC_LABEL_DOMAINS):
            return key
        return f"{self.tag('lk', 'labelkey', domain, 6)}.example/{name}"

    def labels(self, d: dict) -> dict:
        return {self.label_key(k): self.label_value(k, v) for k, v in d.items()}

    def scrub(self, obj):
        """Replace every operator-supplied private word, anywhere
        (values AND keys, SBOM package names included), with a stable
        hashed token."""
        if self._words_re is None:
            return obj
        if isinstance(obj, str):
            return self._words_re.sub(lambda m: "w" + self.h("word", m.group(0).lower())[:7], obj)
        if isinstance(obj, list):
            return [self.scrub(v) for v in obj]
        if isinstance(obj, dict):
            return {self.scrub(k): self.scrub(v) for k, v in obj.items()}
        return obj

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
        if self.keep_public_registries and reg.split(":")[0] in PUBLIC_REGISTRIES | DOCKER_HUB:
            return reg
        self.leak.add(reg)
        return self.tag("reg", "registry", reg) + ".example"

    def repo_is_public(self, reg: str | None, repo: str) -> bool:
        """Is `reg`/`repo` a well-known public coordinate? A registry-less
        reference is Docker Hub: bare official names (`nginx`) are public,
        `org/name` may be a company's private repo."""
        if not self.keep_public_registries:
            return False
        host = (reg or "").split(":")[0]
        if not host:
            return "/" not in repo
        if host in DOCKER_HUB:
            return repo.startswith("library/") or "/" not in repo
        return host in PUBLIC_REGISTRIES

    def repo(self, repo: str, *, public: bool = False) -> str:
        if not repo:
            return repo
        if public:
            return repo
        if "/" in repo or len(repo) >= 12:
            self.leak.add(repo)
        return self.tag("img", "repo", repo)

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
        out += self.repo(repo, public=self.repo_is_public(reg, repo))
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
        if body.startswith("sha256:"):
            return prefix + body  # bare digest — nothing to rename
        if "@" in body:
            ref, _, digest = body.partition("@")
            return prefix + self.image(ref) + "@" + digest
        return prefix + self.image(body)

    def ctr(self, name: str) -> str:
        """Container names usually equal the workload name; hash them
        consistently (spec ↔ status ↔ Trivy label) so the server's
        name-based imageID lookup still matches."""
        return self.tag("ctr", "container", name, 6) if name else name

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
    #
    # Everything below builds each object from an ALLOWLIST of the fields
    # the server (core/parsers) actually reads, rather than redacting
    # field by field: env, mounts, probes, volumes, PVC templates,
    # finalizers, OCI image labels … simply never make it into the
    # fixture. Whatever is kept is renamed consistently.

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
        """Replace `md` in place with an allowlisted, renamed copy."""
        new: dict = {}
        if "name" in md:
            new["name"] = name_fn(md["name"])
        if md.get("namespace"):
            new["namespace"] = self.ns(md["namespace"])
        if "uid" in md:
            new["uid"] = self.uid(md["uid"])
        if isinstance(md.get("labels"), dict):
            new["labels"] = self.labels(md["labels"])
        annotations = {k: v for k, v in (md.get("annotations") or {}).items() if k in ANNOTATION_ALLOWLIST}
        if annotations:
            new["annotations"] = annotations
        refs = []
        for ref in md.get("ownerReferences") or []:
            if isinstance(ref, dict):
                kept = {k: ref[k] for k in ("apiVersion", "kind", "controller", "blockOwnerDeletion") if k in ref}
                if "name" in ref:
                    kept["name"] = self.obj_name(ns, ref["name"])
                if "uid" in ref:
                    kept["uid"] = self.uid(ref["uid"])
                refs.append(kept)
        if refs:
            new["ownerReferences"] = refs
        if "deletionTimestamp" in md:
            new["deletionTimestamp"] = md["deletionTimestamp"]
        md.clear()
        md.update(new)

    def _rewrite_selector(self, sel) -> None:
        if isinstance(sel, dict):
            if isinstance(sel.get("matchLabels"), dict):
                sel["matchLabels"] = self.labels(sel["matchLabels"])
            for expr in sel.get("matchExpressions") or []:
                if isinstance(expr, dict) and isinstance(expr.get("values"), list):
                    expr["values"] = [self.label_value(expr.get("key", ""), v) for v in expr["values"]]

    _SEC_CTX_KEYS = ("privileged", "allowPrivilegeEscalation", "runAsNonRoot", "readOnlyRootFilesystem")

    def _rewrite_pod_spec(self, spec: dict, ns: str) -> None:
        """Keep only what core/parsers/inventory.py reads from a pod
        spec: host namespaces, container name / image / the four
        security-context flags, hostPath volumes, the service account."""
        if not isinstance(spec, dict):
            return
        new: dict = {}
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if key in spec:
                new[key] = spec[key]
        for key in ("containers", "initContainers"):
            kept = []
            for c in spec.get(key) or []:
                if not isinstance(c, dict):
                    continue
                entry = {"name": self.ctr(c.get("name", "")), "image": self.image(c.get("image", ""))}
                ctx = {k: c["securityContext"][k] for k in self._SEC_CTX_KEYS
                       if isinstance(c.get("securityContext"), dict) and k in c["securityContext"]}
                if ctx:
                    entry["securityContext"] = ctx
                kept.append(entry)
            if kept:
                new[key] = kept
        host_volumes = [
            {"name": self.tag("vol", "volume", v.get("name", ""), 6), "hostPath": {"path": "/REDACTED"}}
            for v in spec.get("volumes") or [] if isinstance(v, dict) and v.get("hostPath")
        ]
        if host_volumes:
            new["volumes"] = host_volumes
        for key in ("serviceAccountName", "serviceAccount"):
            if key in spec:
                new[key] = self.sa(spec[key])
        spec.clear()
        spec.update(new)

    def _rewrite_template(self, tpl: dict, ns: str) -> None:
        if isinstance(tpl.get("metadata"), dict):
            self._rewrite_metadata(tpl["metadata"], ns, name_fn=lambda n: self.obj_name(ns, n))
        self._rewrite_pod_spec(tpl.get("spec") or {}, ns)

    @staticmethod
    def _restrict(spec: dict, allowed: tuple[str, ...]) -> None:
        for key in [k for k in spec if k not in allowed]:
            del spec[key]

    def _rewrite_k8s(self, kind: str, it: dict, ns: str) -> None:
        md = it.setdefault("metadata", {})
        spec = it.get("spec") or {}
        if kind == "Namespace":
            self._rewrite_metadata(md, ns, name_fn=self.ns)
            it.pop("spec", None)
            it.pop("status", None)
            return
        if kind == "Node":
            # region / zone / instance type are what cluster-meta
            # derivation reads — keep those label values verbatim.
            original_labels = dict(md.get("labels") or {})
            self._rewrite_metadata(md, ns, name_fn=self.node)
            md["labels"] = {
                k: (original_labels[k] if k in NODE_LABEL_KEEP_VALUES else v)
                for k, v in (md.get("labels") or {}).items()
            }
            node_spec: dict = {}
            if "providerID" in spec:
                scheme, _, path = spec["providerID"].partition("://")
                parts = path.split("/")
                if parts:
                    parts[-1] = self.tag("i", "provider", parts[-1])
                node_spec["providerID"] = f"{scheme}://{'/'.join(parts)}"
            it["spec"] = node_spec
            info = {k: v for k, v in ((it.get("status") or {}).get("nodeInfo") or {}).items()
                    if k in ("kubeletVersion", "kubeProxyVersion", "containerRuntimeVersion",
                             "osImage", "kernelVersion", "architecture", "operatingSystem")}
            it["status"] = {"nodeInfo": info}
            return

        self._rewrite_metadata(md, ns, name_fn=lambda n: self.obj_name(ns, n))

        if kind == "Pod":
            self._rewrite_pod_spec(spec, ns)
            status = it.get("status") or {}
            keep: dict = {}
            for key in ("containerStatuses", "initContainerStatuses"):
                statuses = status.get(key)
                if isinstance(statuses, list):
                    kept_statuses = []
                    for cs in statuses:
                        if not isinstance(cs, dict):
                            continue
                        # Allowlist: `state` / `lastState` carry raw container
                        # log output (termination messages — IPs, hostnames,
                        # secrets). The server reads only name + imageID.
                        slim = {k: cs[k] for k in ("name", "image", "imageID", "ready", "started", "restartCount") if k in cs}
                        if "name" in slim:
                            slim["name"] = self.ctr(slim["name"])
                        if "image" in slim:
                            slim["image"] = self.image(slim["image"])
                        if "imageID" in slim:
                            slim["imageID"] = self.image_id(slim["imageID"])
                        kept_statuses.append(slim)
                    keep[key] = kept_statuses
            if "phase" in status:
                keep["phase"] = status["phase"]
            it["status"] = keep
            return

        it.pop("status", None)
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            self._rewrite_selector(spec.get("selector"))
            self._rewrite_template(spec.get("template") or {}, ns)
            if "serviceName" in spec:
                spec["serviceName"] = self.obj_name(ns, spec["serviceName"])
            self._restrict(spec, ("replicas", "selector", "template", "serviceName", "suspend"))
            return
        if kind == "CronJob":
            jt = spec.get("jobTemplate") or {}
            if isinstance(jt.get("metadata"), dict):
                self._rewrite_metadata(jt["metadata"], ns, name_fn=lambda n: self.obj_name(ns, n))
            jspec = jt.get("spec") or {}
            self._rewrite_selector(jspec.get("selector"))
            self._rewrite_template(jspec.get("template") or {}, ns)
            self._restrict(jspec, ("selector", "template"))
            self._restrict(jt, ("metadata", "spec"))
            self._restrict(spec, ("schedule", "suspend", "jobTemplate"))
            return
        if kind == "Service":
            kept = {"type": spec.get("type") or "ClusterIP"}
            if isinstance(spec.get("selector"), dict):
                kept["selector"] = self.labels(spec["selector"])
            kept["ports"] = [{k: pt[k] for k in ("port", "protocol") if k in pt}
                             for pt in spec.get("ports") or [] if isinstance(pt, dict)]
            it["spec"] = kept
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
                        if isinstance(path.get("backend"), dict):
                            path["backend"] = {"service": {"name": svc.get("name", ""), "port": {"number": (svc.get("port") or {}).get("number", 80)}}}
            for tls in spec.get("tls") or []:
                if isinstance(tls, dict):
                    if isinstance(tls.get("hosts"), list):
                        tls["hosts"] = [self.host(h) for h in tls["hosts"]]
                    if "secretName" in tls:
                        tls["secretName"] = self.obj_name(ns, tls["secretName"])
            svc = ((spec.get("defaultBackend") or {}).get("service") or {})
            if "name" in svc:
                svc["name"] = self.obj_name(ns, svc["name"])
            self._restrict(spec, ("ingressClassName", "rules", "tls", "defaultBackend"))
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

    # Trivy BOM component properties the server reads (PkgType, LayerDigest)
    # plus classification; FilePath / SrcName / PkgID / image labels carry
    # application paths and repository URLs and are dropped.
    _BOM_PROPERTY_KEEP = frozenset({
        "aquasecurity:trivy:PkgType", "aquasecurity:trivy:LayerDigest",
        "aquasecurity:trivy:Class", "aquasecurity:trivy:Type",
    })

    def _rewrite_bom(self, bom: dict, anon_ref: str, digest: str) -> None:
        """Rebuild a CycloneDX BOM: the root image component carries the
        registry host, repo path, OCI image labels (GitHub URLs,
        descriptions) — replace it with an anonymised stub. The server
        reads only `components[]`; `dependencies` and `serialNumber` go."""
        root = (bom.get("metadata") or {}).get("component")
        if isinstance(root, dict):
            leaf = anon_ref.split("/")[-1].split(":")[0]
            purl = f"pkg:oci/{leaf}@{digest}" if digest else f"pkg:oci/{leaf}"
            bom["metadata"] = {
                "component": {"type": root.get("type", "container"), "name": anon_ref, "bom-ref": purl, "purl": purl},
                "tools": (bom.get("metadata") or {}).get("tools"),
            }
        bom.pop("serialNumber", None)
        bom.pop("dependencies", None)
        for comp in bom.get("components") or []:
            if isinstance(comp, dict) and isinstance(comp.get("properties"), list):
                comp["properties"] = [pr for pr in comp["properties"]
                                      if isinstance(pr, dict) and pr.get("name") in self._BOM_PROPERTY_KEEP]

    def _rewrite_trivy(self, kind: str, it: dict, ns: str) -> None:
        md = it.setdefault("metadata", {})
        labels = md.get("labels") or {}
        res_ns = labels.get("trivy-operator.resource.namespace") or ns
        res_kind = labels.get("trivy-operator.resource.kind") or ""
        res_name = labels.get("trivy-operator.resource.name") or ""
        container = labels.get("trivy-operator.container.name") or ""
        if not res_name:
            # name > 63 chars: Trivy sets only `resource.name-hash`; the real
            # name is the owner reference (the server falls back to it too).
            for ref in md.get("ownerReferences") or []:
                if isinstance(ref, dict) and ref.get("name"):
                    res_name = ref["name"]
                    break
        new_res_name = self.obj_name(res_ns, res_name) if res_name else ""
        new_container = self.ctr(container)

        def _name(_old: str) -> str:
            if res_name:
                parts = [res_kind.lower(), new_res_name] + ([new_container] if container else [])
                return "-".join(p for p in parts if p)
            return self.tag("rep", "report", _old)

        self._rewrite_metadata(md, ns, name_fn=_name)
        new_labels = {}
        for k, v in labels.items():
            if k == "trivy-operator.resource.namespace":
                new_labels[k] = self.ns(v)
            elif k == "trivy-operator.resource.name":
                new_labels[k] = new_res_name
            elif k == "trivy-operator.container.name":
                new_labels[k] = new_container
            elif k == "trivy-operator.resource.kind":
                new_labels[k] = v
            else:
                new_labels[self.label_key(k)] = self.label_value(k, v)
        md["labels"] = new_labels

        report = it.get("report") or {}
        registry = report.get("registry") if isinstance(report.get("registry"), dict) else {}
        server = registry.get("server") or ""
        artifact = report.get("artifact")
        anon_ref, digest = "", ""
        if isinstance(artifact, dict):
            digest = artifact.get("digest") or ""
            if "repository" in artifact:
                m = _IMAGE_RE.match(artifact["repository"])
                if m and m.group("registry"):
                    reg = m.group("registry")
                    artifact["repository"] = (
                        self.registry(reg) + "/" + self.repo(m.group("repo"), public=self.repo_is_public(reg, m.group("repo")))
                    )
                else:
                    artifact["repository"] = self.repo(
                        artifact["repository"], public=self.repo_is_public(server, artifact["repository"]),
                    )
            if "tag" in artifact:
                artifact["tag"] = self.image_tag(artifact["tag"])
            anon_ref = artifact.get("repository", "") + (":" + artifact["tag"] if artifact.get("tag") else "")
        if "server" in registry:
            registry["server"] = self.registry(server)
            anon_ref = f"{registry['server']}/{anon_ref}" if anon_ref else anon_ref
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
        if isinstance(report.get("components"), dict):
            self._rewrite_bom(report["components"], anon_ref, digest)
        it.pop("spec", None)

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
            text = json.dumps({"apiVersion": "v1", "kind": f"{kind}List", "items": self.scrub(items)}, separators=(",", ":"))
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


def _iter_strings(obj):
    """Every string value, plus plain dict keys. Vendor-qualified keys
    (`vector.dev/exclude`, `eks.amazonaws.com/component`) are public
    API names that merely share a word with a namespace — skipped."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if "." not in k and "/" not in k:
                yield k
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)
    elif isinstance(obj, str):
        yield obj


def _iter_all_strings(obj):
    """Every string value and every key — no exemptions (used for the
    operator's private words, which must appear NOWHERE)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _iter_all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_all_strings(v)
    elif isinstance(obj, str):
        yield obj


# Words common to infrastructure / public projects: never worth suggesting.
_GENERIC_WORDS = frozenset("""
    service services container containers internal controller controllers exporter network networks
    registry secrets secret policy policies operator operators cluster config configs public docker
    generic worker workers kubernetes amazon apache elastic alpine system manager server client
    backend frontend indexer indexers gateway ingress metrics monitoring logging storage default
    external namespace driver plugin library package platform provider resource runtime
""".split())


def suggest_private_words(anon: Anonymizer, out: Path) -> list[str]:
    """Words from the private identifiers that still occur in the
    output (typically SBOM package names of your own images) — the
    candidates for --private-words."""
    words: set[str] = set()
    for needle in anon.leak:
        for w in re.split(r"[^A-Za-z0-9]+", needle.lower()):
            if len(w) >= 6 and not w.isdigit() and w not in _GENERIC_WORDS:
                words.add(w)
    text = "\n".join(
        x for p in sorted(out.rglob("*.gz")) for x in _iter_all_strings(json.load(gzip.open(p, "rt", encoding="utf-8")))
    ).lower()
    counts = {w: text.count(w) for w in words if w in text and w not in anon.private_words}
    return [w for w, _ in sorted(counts.items(), key=lambda kv: -kv[1])][:8]


def _identity_parts(doc):
    """Drop the parts of a Trivy report that are public software data —
    package / module names (`github.com/cilium/cilium`), vulnerability
    entries, check descriptions — which legitimately coincide with the
    (hashed) image repo names. Identity lives in metadata, artifact,
    registry and the BOM root."""
    items = doc.get("items") if isinstance(doc, dict) and "items" in doc else [doc]
    out = []
    for it in items:
        if isinstance(it, dict) and isinstance(it.get("report"), dict):
            report = dict(it["report"])
            for key in ("vulnerabilities", "checks", "secrets"):
                report.pop(key, None)
            bom = report.get("components")
            if isinstance(bom, dict):
                report["components"] = {k: v for k, v in bom.items() if k != "components"}
            it = {**it, "report": report}
        out.append(it)
    return out


def _is_identifying(needle: str) -> bool:
    """A single short lowercase word (`vector`, `redis`, `python`) is a
    product / package name as often as a private identifier and collides
    with public SBOM content — not treated as a leak. Anything with a
    separator, digits, or 12+ characters is."""
    if len(needle) < 4:
        return False
    return not (re.fullmatch(r"[a-z]+", needle) and len(needle) < 12)


def verify(anon: Anonymizer, out: Path) -> list[str]:
    """Returns a list of problems (empty = faithful + leak-free)."""
    problems: list[str] = []
    from kubeposture_importer.sources.folder import collect_from_folder
    before = _filter_report(anon.by_kind())
    after = _filter_report(collect_from_folder(out))
    if before != after:
        problems.append(f"filter statistics differ:\n  before={json.dumps(before, sort_keys=True)}\n  after ={json.dumps(after, sort_keys=True)}")
    text = "\n".join(
        s for p in sorted(out.rglob("*.gz"))
        for s in _iter_strings(_identity_parts(json.load(gzip.open(p, "rt", encoding="utf-8"))))
    )
    for needle in sorted(n for n in anon.leak if _is_identifying(n)):
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(needle) + r"(?![A-Za-z0-9])", text):
            problems.append(f"original string leaked: {needle!r}")
    if anon._words_re is not None:
        full = "\n".join(
            x for p in sorted(out.rglob("*.gz")) for x in _iter_all_strings(json.load(gzip.open(p, "rt", encoding="utf-8")))
        )
        for word in anon.private_words:
            if re.search(re.escape(word), full, re.I):
                problems.append(f"private word still present: {word!r}")
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
        with BundleWriter(cluster="fixture", import_id="GOLDEN", kind="inventory", tmp_dir=tmp) as w:
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
              slim: bool = False, keep_public_registries: bool = True,
              private_words: list[str] | None = None) -> Anonymizer:
    anon = Anonymizer(salt, keep_public_registries=keep_public_registries, slim=slim,
                      keep_namespaces=keep_namespaces, private_words=private_words)
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
    parser.add_argument(
        "--private-words", default="",
        help="Comma-separated words (company / product names, e.g. 'acme,payroll') scrubbed from EVERYTHING, "
             "SBOM package names included; verify asserts they appear nowhere. Needed because your own "
             "internal packages inside image SBOMs (@acme/foo, github.com/acme/…) cannot be detected generically.",
    )
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

    words = [w for w in args.private_words.split(",") if w.strip()]
    anon = anonymize(args.src, args.out, salt=salt, keep_namespaces=keep, slim=args.slim,
                     keep_public_registries=not args.no_keep_public_registries, private_words=words)
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
            hint = suggest_private_words(anon, args.out)
            if hint:
                print("hint: these words from your private identifiers still occur in the output (e.g. SBOM "
                      f"package names of your own images): {', '.join(hint)}\n      add the ones that are "
                      "company / product names to --private-words and re-run.")
    if args.write_golden:
        write_golden(args.out)
        print(f"golden files written under {args.out / 'golden'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
