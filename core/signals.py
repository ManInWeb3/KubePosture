"""Signal registry — exploitability-likelihood facts about Workloads.

Every entry is independent (no `equivalent_to` chain): if Kyverno's
`disallow-privileged-containers` AND Trivy's `KSV-0017` both report
the same fact, two `WorkloadSignal` rows land in the DB. They both
flip `currently_active=false` together when the underlying issue is
fixed, which is the lifecycle that matters.

Adding a new signal is a one-line dict entry. Detector functions for
derived (kp:*) signals live in `core.parsers.inventory`.

ID convention:
    kyverno:<policy-name>   — Kyverno PolicyReport / ClusterPolicyReport
    ksv:<AVD-id>            — Trivy ConfigAuditReport / RbacAssessmentReport
    kp:<custom>             — KubePostureNG-derived (kube-api manifest detector)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SignalSource(str, Enum):
    KYVERNO = "kyverno"
    TRIVY = "trivy"
    KUBE_API = "kube-api"
    DERIVED = "derived"


class SignalCategory(str, Enum):
    HOST_ESCAPE = "host_escape"
    PRIV_ESCALATION = "priv_escalation"
    RBAC_ELEVATION = "rbac_elevation"
    SUPPLY_CHAIN = "supply_chain"
    SECRET_LEAK = "secret_leak"
    NETWORK_EXPOSURE = "network_exposure"
    HARDENING_GAP = "hardening_gap"


@dataclass(frozen=True)
class SignalDef:
    id: str
    source: SignalSource
    category: SignalCategory
    title: str
    description: str
    matcher: str
    """Source-specific identifier matched at ingest:
       Kyverno policy name, Trivy AVD ID, or detector function name."""


def _kyverno(policy: str, category: SignalCategory, title: str, description: str) -> SignalDef:
    return SignalDef(
        id=f"kyverno:{policy}",
        source=SignalSource.KYVERNO,
        category=category,
        title=title,
        description=description,
        matcher=policy,
    )


def _ksv(avd_id: str, category: SignalCategory, title: str, description: str) -> SignalDef:
    return SignalDef(
        id=f"ksv:{avd_id}",
        source=SignalSource.TRIVY,
        category=category,
        title=title,
        description=description,
        matcher=avd_id,
    )


def _kp(name: str, source: SignalSource, category: SignalCategory, title: str, description: str) -> SignalDef:
    return SignalDef(
        id=f"kp:{name}",
        source=source,
        category=category,
        title=title,
        description=description,
        matcher=name,
    )


# --- v1 starter set -----------------------------------------------

SIGNALS: dict[str, SignalDef] = {
    # ── Host escape ──
    s.id: s for s in [
        _kyverno(
            "disallow-privileged-containers",
            SignalCategory.HOST_ESCAPE,
            "Privileged container",
            "Container runs with full host root privilege; trivial host escape on exploit.",
        ),
        _ksv(
            "KSV-0017",
            SignalCategory.HOST_ESCAPE,
            "Privileged container (Trivy)",
            "Container runs as privileged. Trivy KSV-0017.",
        ),
        _kyverno(
            "disallow-host-path",
            SignalCategory.HOST_ESCAPE,
            "Host path mount",
            "Pod mounts a hostPath volume — direct access to node filesystem.",
        ),
        _ksv(
            "KSV-0023",
            SignalCategory.HOST_ESCAPE,
            "Host path mount (Trivy)",
            "hostPath volume detected. Trivy KSV-0023.",
        ),
        _kyverno(
            "disallow-host-namespaces",
            SignalCategory.HOST_ESCAPE,
            "Host namespace",
            "hostNetwork / hostPID / hostIPC enabled.",
        ),
        _ksv(
            "KSV-0008",
            SignalCategory.HOST_ESCAPE,
            "hostIPC enabled (Trivy)",
            "hostIPC=true on PodSpec.",
        ),
        _ksv(
            "KSV-0009",
            SignalCategory.HOST_ESCAPE,
            "hostNetwork enabled (Trivy)",
            "hostNetwork=true on PodSpec.",
        ),
        _ksv(
            "KSV-0010",
            SignalCategory.HOST_ESCAPE,
            "hostPID enabled (Trivy)",
            "hostPID=true on PodSpec.",
        ),
        # ── RBAC & identity ──
        _ksv(
            "KSV-0051",
            SignalCategory.RBAC_ELEVATION,
            "ServiceAccount cluster-admin bind",
            "ServiceAccount is bound to cluster-admin (or equivalent broad ClusterRole).",
        ),
        _ksv(
            "KSV-0053",
            SignalCategory.RBAC_ELEVATION,
            "Role grants pods/exec",
            "Role grants pods/exec | attach | ephemeralcontainers.",
        ),
        _ksv(
            "KSV-0044",
            SignalCategory.RBAC_ELEVATION,
            "Role grants wildcard verb/resource",
            "Role uses '*' for verbs or resources.",
        ),
        _ksv(
            "KSV-0041",
            SignalCategory.RBAC_ELEVATION,
            "Role grants secrets:list/get",
            "Role grants cluster-wide secrets access.",
        ),
        # ── Privilege escalation ──
        _kyverno(
            "disallow-privilege-escalation",
            SignalCategory.PRIV_ESCALATION,
            "allowPrivilegeEscalation",
            "allowPrivilegeEscalation true or unset.",
        ),
        _ksv(
            "KSV-0001",
            SignalCategory.PRIV_ESCALATION,
            "allowPrivilegeEscalation (Trivy)",
            "allowPrivilegeEscalation true. Trivy KSV-0001.",
        ),
        _kyverno(
            "disallow-capabilities",
            SignalCategory.PRIV_ESCALATION,
            "Risky capability added",
            "Container adds a risky Linux capability (SYS_ADMIN, NET_RAW, etc.).",
        ),
        _ksv(
            "KSV-0005",
            SignalCategory.PRIV_ESCALATION,
            "Risky capability added (Trivy)",
            "Container adds a risky Linux capability. Trivy KSV-0005.",
        ),
        # ── Supply chain ──
        _kyverno(
            "disallow-latest-tag",
            SignalCategory.SUPPLY_CHAIN,
            "Mutable image tag",
            "Image referenced by mutable tag (no digest pin).",
        ),
        _ksv(
            "KSV-0013",
            SignalCategory.SUPPLY_CHAIN,
            "Mutable image tag (Trivy)",
            "Image uses mutable tag. Trivy KSV-0013.",
        ),
        # ── Secret leak ──
        _kp(
            "exposed-secret-in-image",
            SignalSource.TRIVY,
            SignalCategory.SECRET_LEAK,
            "Exposed secret in image",
            "Trivy ExposedSecretReport flagged a baked-in credential.",
        ),
        # ── Hardening gaps ──
        _kyverno(
            "require-run-as-nonroot",
            SignalCategory.HARDENING_GAP,
            "Run as non-root not required",
            "runAsNonRoot=false or unset; container can run as UID 0.",
        ),
        _ksv(
            "KSV-0012",
            SignalCategory.HARDENING_GAP,
            "Run as non-root (Trivy)",
            "Container runs as root. Trivy KSV-0012.",
        ),
        _kyverno(
            "require-ro-rootfs",
            SignalCategory.HARDENING_GAP,
            "Read-only root filesystem not required",
            "readOnlyRootFilesystem=false or unset.",
        ),
        _ksv(
            "KSV-0014",
            SignalCategory.HARDENING_GAP,
            "Read-only root FS (Trivy)",
            "readOnlyRootFilesystem not enforced. Trivy KSV-0014.",
        ),
        # ── Network exposure (derived) ──
        _kp(
            "has-external-ingress",
            SignalSource.DERIVED,
            SignalCategory.NETWORK_EXPOSURE,
            "External Ingress",
            "An external Ingress (non-internal class/annotation) backs this workload.",
        ),
        _kp(
            "has-external-lb",
            SignalSource.DERIVED,
            SignalCategory.NETWORK_EXPOSURE,
            "External LoadBalancer",
            "A LoadBalancer Service without an internal-LB annotation selects this workload.",
        ),
        _kp(
            "has-nodeport-service",
            SignalSource.DERIVED,
            SignalCategory.NETWORK_EXPOSURE,
            "NodePort service",
            "Workload is selected by a Service of type=NodePort.",
        ),
        _kp(
            "missing-networkpolicy",
            SignalSource.KYVERNO,
            SignalCategory.NETWORK_EXPOSURE,
            "Namespace has no NetworkPolicy",
            "No NetworkPolicy resources in the workload's namespace.",
        ),
    ]
}


# --- Lookup helpers -----------------------------------------------

# Reverse maps for O(1) ingest-side resolution.
_KYVERNO_POLICY_TO_SIGNAL_ID: dict[str, str] = {
    s.matcher: s.id for s in SIGNALS.values() if s.source is SignalSource.KYVERNO
}
_TRIVY_AVD_TO_SIGNAL_ID: dict[str, str] = {
    s.matcher: s.id for s in SIGNALS.values() if s.source is SignalSource.TRIVY
}


def signal_for_kyverno_policy(policy_name: str) -> str | None:
    """Return the registry signal_id for a Kyverno policy name, or None."""
    return _KYVERNO_POLICY_TO_SIGNAL_ID.get(policy_name)


def signal_for_trivy_avd(avd_id: str) -> str | None:
    """Return the registry signal_id for a Trivy AVD check ID, or None.

    Accepts any of `KSV051`, `KSV-0051`, `AVD-KSV-0051` and looks up
    by the canonical registry matcher (`KSV-0051`).
    """
    if not avd_id:
        return None
    if avd_id in _TRIVY_AVD_TO_SIGNAL_ID:
        return _TRIVY_AVD_TO_SIGNAL_ID[avd_id]
    # Try AVD-KSV-XXXX → KSV-XXXX
    canonical = avd_id
    if canonical.startswith("AVD-"):
        canonical = canonical[4:]
    if canonical in _TRIVY_AVD_TO_SIGNAL_ID:
        return _TRIVY_AVD_TO_SIGNAL_ID[canonical]
    # Try KSV051 → KSV-0051
    if canonical.startswith("KSV") and "-" not in canonical:
        rest = canonical[3:]
        if rest.isdigit():
            normalised = f"KSV-{int(rest):04d}"
            if normalised in _TRIVY_AVD_TO_SIGNAL_ID:
                return _TRIVY_AVD_TO_SIGNAL_ID[normalised]
    return None


def signals_in_category(category: SignalCategory) -> set[str]:
    """All signal_ids whose def is in `category`."""
    return {s.id for s in SIGNALS.values() if s.category is category}


# Pre-computed category sets used by the urgency scorer.
HOST_ESCAPE_SIGNALS = signals_in_category(SignalCategory.HOST_ESCAPE)
PRIV_ESCALATION_SIGNALS = signals_in_category(SignalCategory.PRIV_ESCALATION)
RBAC_ELEVATION_SIGNALS = signals_in_category(SignalCategory.RBAC_ELEVATION)
NETWORK_EXPOSURE_SIGNALS = signals_in_category(SignalCategory.NETWORK_EXPOSURE)
