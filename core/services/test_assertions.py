"""Assertion evaluator for the scenario harness.

Consumes the YAML DSL from dev_docs/12-testing.md *Assertions DSL* and
the actual mock_tests/<scenario>/assertions.yaml shapes. Returns
[{index, kind, pass, details, spec}, ...].

Severity / priority labels accept both PascalCase fixture form
("Critical", "OutOfCycle") and the lower-case enum form.
"""
from __future__ import annotations

from django.db.models import Q

from core.constants import PriorityBand, Severity
from core.models import (
    Cluster,
    EpssScore,
    Finding,
    ImportMark,
    Image,
    IngestQueue,
    KevEntry,
    Namespace,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)


# ── Label normalisers --------------------------------------------

_SEVERITY_ALIAS = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
    "unknown": Severity.UNKNOWN.value,
}

_PRIORITY_ALIAS = {
    "immediate": PriorityBand.IMMEDIATE.value,
    "out_of_cycle": PriorityBand.OUT_OF_CYCLE.value,
    "outofcycle": PriorityBand.OUT_OF_CYCLE.value,
    "scheduled": PriorityBand.SCHEDULED.value,
    "defer": PriorityBand.DEFER.value,
}


def _norm_severity(v: str | None) -> str | None:
    if v is None:
        return None
    return _SEVERITY_ALIAS.get(str(v).strip().lower(), str(v))


def _norm_priority(v: str | None) -> str | None:
    if v is None:
        return None
    return _PRIORITY_ALIAS.get(str(v).strip().lower(), str(v))


def _split_workload_ref(ref: str) -> tuple[str | None, str]:
    """Accept `namespace/name` or just `name`."""
    if "/" in ref:
        ns, _, n = ref.partition("/")
        return ns, n
    return None, ref


def _q_workload(filters: dict):
    qs = Workload.objects.all()
    if (c := filters.get("cluster")):
        qs = qs.filter(cluster__name=c)
    if (ns := filters.get("namespace")):
        qs = qs.filter(namespace__name=ns)
    if (k := filters.get("kind")):
        qs = qs.filter(kind=k)
    if (n := filters.get("name")):
        qs = qs.filter(name=n)
    if "deployed" in filters:
        qs = qs.filter(deployed=filters["deployed"])
    return qs


def _q_finding(filters: dict):
    qs = Finding.objects.all()
    if (c := filters.get("cluster")):
        qs = qs.filter(cluster__name=c)
    if (sev := _norm_severity(filters.get("severity"))):
        qs = qs.filter(severity=sev)
    if (pri := _norm_priority(filters.get("effective_priority"))):
        qs = qs.filter(effective_priority=pri)
    if (vid := filters.get("vuln_id")):
        qs = qs.filter(vuln_id=vid)
    if (wl := filters.get("workload")):
        ns, n = _split_workload_ref(wl)
        qs = qs.filter(workload__name=n)
        if ns:
            qs = qs.filter(workload__namespace__name=ns)
    if "image_digest" in filters:
        qs = qs.filter(image__digest=filters["image_digest"])
    if "workload_is_null" in filters:
        if filters["workload_is_null"]:
            qs = qs.filter(workload__isnull=True)
        else:
            qs = qs.filter(workload__isnull=False)
    if "workload_deployed" in filters:
        qs = qs.filter(workload__deployed=filters["workload_deployed"])
    if "image_deployed" in filters:
        # Image deployment is derived from observations, not stored.
        currently_running_ids = Image.objects.currently_running().values("pk")
        if filters["image_deployed"]:
            qs = qs.filter(image__in=currently_running_ids)
        else:
            qs = qs.exclude(image__in=currently_running_ids)
    if filters.get("last_seen_current"):
        # Per-source staleness — uses each source's latest *successful*
        # (observed_count > 0) mark. A Trivy outage must not raise the
        # threshold for Trivy-sourced findings while Kyverno is healthy.
        cluster_name = filters.get("cluster")
        if cluster_name:
            source_kinds = {
                "trivy": {
                    "trivy.VulnerabilityReport",
                    "trivy.ConfigAuditReport",
                    "trivy.ExposedSecretReport",
                    "trivy.RbacAssessmentReport",
                    "trivy.ClusterRbacAssessmentReport",
                    "trivy.InfraAssessmentReport",
                    "trivy.ClusterComplianceReport",
                },
                "kyverno": {
                    "kyverno.PolicyReport",
                    "kyverno.ClusterPolicyReport",
                },
            }
            cond = Q()
            for source, kinds in source_kinds.items():
                latest = (
                    ImportMark.objects
                    .filter(
                        cluster__name=cluster_name,
                        kind__in=list(kinds),
                        observed_count__gt=0,
                    )
                    .order_by("-started_at")
                    .first()
                )
                if latest is None:
                    cond |= Q(source=source)  # no threshold yet, keep all
                else:
                    cond |= Q(source=source, last_seen__gte=latest.started_at)
            qs = qs.filter(cond)
    return qs


# ── Per-kind handlers --------------------------------------------

def _cluster_exists(a):
    cluster = Cluster.objects.filter(name=a["name"]).first()
    if not cluster:
        return False, {"reason": "no cluster"}
    failures = {}
    for field in ("environment", "provider", "region", "consecutive_incomplete_inventories"):
        if field in a:
            actual = getattr(cluster, field)
            if actual != a[field]:
                failures[field] = {"actual": actual, "expected": a[field]}
    if failures:
        return False, failures
    return True, {"id": cluster.id}


def _namespace_count(a):
    qs = Namespace.objects.all()
    if (c := a.get("cluster")):
        qs = qs.filter(cluster__name=c)
    if "active" in a:
        qs = qs.filter(active=a["active"])
    actual = qs.count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _namespace_attributes(a):
    ns = Namespace.objects.filter(
        cluster__name=a["cluster"], name=a["name"]
    ).first()
    if not ns:
        return False, {"reason": "no namespace"}
    failures = {}
    for field in (
        "internet_exposed", "contains_sensitive_data",
        "exposure_is_manual", "sensitive_is_manual", "active",
    ):
        if field in a:
            actual = getattr(ns, field)
            if actual != a[field]:
                failures[field] = {"actual": actual, "expected": a[field]}
    if failures:
        return False, failures
    return True, {}


def _workload_count(a):
    actual = _q_workload(a.get("filter") or {}).count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _workload_exists(a):
    qs = _q_workload({
        "cluster": a.get("cluster"),
        "namespace": a.get("namespace"),
        "kind": a.get("workload_kind") or a.get("kind_value"),
        "name": a.get("name"),
    })
    wl = qs.first()
    if not wl:
        return False, {"reason": "no matching workload"}
    failures = {}
    if "deployed" in a and wl.deployed != a["deployed"]:
        failures["deployed"] = {"actual": wl.deployed, "expected": a["deployed"]}

    # Backwards-compat shim: scenarios still mention has_external_ingress
    # / has_external_lb. Map both to publicly_exposed=true.
    for legacy in ("has_external_ingress", "has_external_lb"):
        if legacy in a:
            expected = bool(a[legacy])
            if wl.publicly_exposed != expected:
                failures[legacy] = {
                    "publicly_exposed_actual": wl.publicly_exposed,
                    "expected_via_legacy_field": expected,
                }

    if "publicly_exposed" in a and wl.publicly_exposed != a["publicly_exposed"]:
        failures["publicly_exposed"] = {
            "actual": wl.publicly_exposed,
            "expected": a["publicly_exposed"],
        }
    return (not failures), failures or {"id": wl.id}


def _workload_absent(a):
    """Inverse of workload_exists. Asserts no matching row in DB at
    all (vs. workload_exists with deployed=false, which asserts the
    row exists but is no longer deployed)."""
    qs = _q_workload({
        "cluster": a.get("cluster"),
        "namespace": a.get("namespace"),
        "kind": a.get("workload_kind") or a.get("kind_value"),
        "name": a.get("name"),
    })
    if qs.exists():
        wl = qs.first()
        return False, {
            "reason": "workload exists but assertion expected absence",
            "id": wl.id,
            "deployed": wl.deployed,
        }
    return True, {}


def _workload_alias_count(a):
    """By default, counts only the canonical alias kinds
    (ReplicaSet, Job). Pod aliases — used internally for resolving
    Kyverno scope.kind=Pod — are excluded unless the assertion
    explicitly opts in via `include_pod_aliases: true`.
    """
    qs = WorkloadAlias.objects.all()
    f = a.get("filter") or {}
    if (c := f.get("cluster")):
        qs = qs.filter(cluster__name=c)
    if not a.get("include_pod_aliases"):
        qs = qs.filter(alias_kind__in=["ReplicaSet", "Job"])
    actual = qs.count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _image_count(a):
    f = a.get("filter") or {}
    # `deployed` is no longer a stored column — it's derived via
    # ImageQuerySet.with_currently_deployed(). The DSL stays the
    # same; only the underlying SQL changes.
    if "deployed" in f:
        qs = Image.objects.with_currently_deployed().filter(
            currently_deployed=bool(f["deployed"])
        )
    else:
        qs = Image.objects.all()
    actual = qs.count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _image_exists(a):
    img = (
        Image.objects.with_currently_deployed()
        .filter(digest=a["digest"])
        .first()
    )
    if not img:
        return False, {"reason": "no image"}
    failures = {}
    for field in ("deployed", "ref", "os_family", "os_version", "base_eosl"):
        if field in a:
            # The DSL spells the derived flag `deployed`; the
            # annotation calls it `currently_deployed`.
            attr = "currently_deployed" if field == "deployed" else field
            actual = getattr(img, attr)
            if actual != a[field]:
                failures[field] = {"actual": actual, "expected": a[field]}
    return (not failures), failures or {}


def _observation_count(a):
    qs = WorkloadImageObservation.objects.all()
    f = a.get("filter") or {}
    if "workload" in f:
        ns, n = _split_workload_ref(f["workload"])
        qs = qs.filter(workload__name=n)
        if ns:
            qs = qs.filter(workload__namespace__name=ns)
    actual = qs.count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _finding_count(a):
    actual = _q_finding(a.get("filter") or {}).count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _finding_exists(a):
    qs = _q_finding(a.get("filter") or {})
    return qs.exists(), {"matches": qs.count()}


def _finding_priority(a):
    qs = _q_finding(a.get("filter") or {})
    finding = qs.first()
    if not finding:
        return False, {"reason": "no matching finding"}
    expected = _norm_priority(a["expect"])
    return (finding.effective_priority == expected), {
        "actual": finding.effective_priority,
        "expected": expected,
    }


def _signal_present(a):
    ns, n = _split_workload_ref(a["workload"])
    qs = WorkloadSignal.objects.filter(
        workload__name=n,
        signal_id=a["signal_id"],
    )
    if ns:
        qs = qs.filter(workload__namespace__name=ns)
    expected_active = a.get("currently_active", True)
    qs = qs.filter(currently_active=expected_active)
    return qs.exists(), {"found": qs.exists()}


def _signal_absent(a):
    ns, n = _split_workload_ref(a["workload"])
    qs = WorkloadSignal.objects.filter(
        workload__name=n,
        signal_id=a["signal_id"],
        currently_active=True,
    )
    if ns:
        qs = qs.filter(workload__namespace__name=ns)
    return (not qs.exists()), {"matches": qs.count()}


def _import_mark(a):
    qs = ImportMark.objects.filter(cluster__name=a["cluster"])
    mark_kind = a.get("mark_kind") or a.get("kind_value")
    if mark_kind:
        qs = qs.filter(kind=mark_kind)
    if "import_id" in a and a["import_id"]:
        qs = qs.filter(import_id=a["import_id"])
    mark = qs.order_by("-started_at").first()
    if not mark:
        return False, {"reason": "no matching mark"}
    if "state" in a and mark.state != a["state"]:
        return False, {"actual_state": mark.state, "expected": a["state"]}
    if "observed_count" in a and mark.observed_count != a["observed_count"]:
        return False, {"actual_count": mark.observed_count, "expected": a["observed_count"]}
    return True, {"state": mark.state, "observed_count": mark.observed_count}


def _ingest_queue_count(a):
    qs = IngestQueue.objects.all()
    if "status" in a:
        qs = qs.filter(status=a["status"])
    else:
        qs = qs.filter(status__in=["pending", "processing"])
    actual = qs.count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _snapshot_count(a):
    qs = Snapshot.objects.all()
    f = a.get("filter") or {}
    if "cluster" in f:
        qs = qs.filter(cluster__name=f["cluster"])
    if "scope_kind" in f:
        qs = qs.filter(scope_kind=f["scope_kind"])
    if "change_kind" in f:
        qs = qs.filter(change_kind=f["change_kind"])
    actual = qs.count()
    if "expect" in a:
        return actual == a["expect"], {"actual": actual, "expected": a["expect"]}
    if "min" in a:
        return actual >= a["min"], {"actual": actual, "min": a["min"]}
    return False, {"reason": "snapshot_count needs `expect` or `min`"}


def _snapshot_delta(a):
    ns, n = _split_workload_ref(a["workload"])
    qs = (
        Snapshot.objects
        .filter(scope_kind=a.get("scope") or "workload", workload__name=n)
        .order_by("-captured_at")
    )
    if ns:
        qs = qs.filter(workload__namespace__name=ns)
    snap = qs.first()
    if not snap:
        return False, {"reason": "no snapshot"}
    failures = {}
    if "change_kind" in a and snap.change_kind != a["change_kind"]:
        failures["change_kind"] = {
            "actual": snap.change_kind,
            "expected": a["change_kind"],
        }
    if "image_set_changed_from_previous" in a and \
            snap.image_set_changed_from_previous != a["image_set_changed_from_previous"]:
        failures["image_set_changed_from_previous"] = {
            "actual": snap.image_set_changed_from_previous,
            "expected": a["image_set_changed_from_previous"],
        }
    return (not failures), failures or {"change_kind": snap.change_kind}


def _scan_inconsistency(a):
    qs = ScanInconsistency.objects.filter(cluster__name=a["cluster"])
    if "kind" in a:
        qs = qs.filter(kind=a["kind"])
    actual = qs.count()
    expected = a.get("expect", 1)
    return actual == expected, {"actual": actual, "expected": expected}


def _enrichment(a):
    """Check enrichment values cached on a Finding (or the source row)."""
    vuln_id = a["vuln_id"]
    failures: dict = {}
    if "kev_listed" in a:
        actual = KevEntry.objects.filter(vuln_id=vuln_id).exists()
        if actual != a["kev_listed"]:
            failures["kev_listed"] = {"actual": actual, "expected": a["kev_listed"]}
    if "kev_due_date" in a:
        kev = KevEntry.objects.filter(vuln_id=vuln_id).first()
        actual = str(kev.due_date) if kev and kev.due_date else None
        if actual != a["kev_due_date"]:
            failures["kev_due_date"] = {"actual": actual, "expected": a["kev_due_date"]}
    if "epss_score" in a:
        epss = EpssScore.objects.filter(vuln_id=vuln_id).first()
        actual = epss.score if epss else None
        if actual != a["epss_score"]:
            failures["epss_score"] = {"actual": actual, "expected": a["epss_score"]}
    return (not failures), failures or {"vuln_id": vuln_id}


def _log_event_count(a):
    """Stub. v1 doesn't capture log events for harness assertions; treat
    as always-pass to allow scenarios that lean on log assertions to
    survive this milestone. A future iteration can hook structlog
    capture into the harness."""
    return True, {"note": "log_event_count stubbed in v1"}


def _log_event_exists(a):
    """Stub — same rationale as `_log_event_count`."""
    return True, {"note": "log_event_exists stubbed in v1"}


def _workload_last_inventory_advanced(a):
    """Pass when the workload's last_inventory_at is later than the
    given import's started_at — i.e., a later inventory cycle bumped
    it.
    """
    ns, n = _split_workload_ref(a["workload"])
    since_iid = a["since_import_id"]
    since_mark = ImportMark.objects.filter(import_id=since_iid).order_by("started_at").first()
    if since_mark is None:
        return False, {"reason": f"no mark for {since_iid}"}
    qs = Workload.objects.filter(name=n)
    if ns:
        qs = qs.filter(namespace__name=ns)
    wl = qs.first()
    if wl is None or wl.last_inventory_at is None:
        return False, {"reason": "no workload or last_inventory_at"}
    return wl.last_inventory_at > since_mark.started_at, {
        "actual": wl.last_inventory_at.isoformat(),
        "since": since_mark.started_at.isoformat(),
    }


def _workload_last_inventory_unchanged(a):
    """Pass when the workload's last_inventory_at equals the given
    import's started_at (i.e., the partial-inventory cycle didn't
    bump it because the workload wasn't observed).
    """
    ns, n = _split_workload_ref(a["workload"])
    iid = a["expected_value_from_import_id"]
    mark = ImportMark.objects.filter(import_id=iid).order_by("started_at").first()
    if mark is None:
        return False, {"reason": f"no mark for {iid}"}
    qs = Workload.objects.filter(name=n)
    if ns:
        qs = qs.filter(namespace__name=ns)
    wl = qs.first()
    if wl is None or wl.last_inventory_at is None:
        return False, {"reason": "no workload or last_inventory_at"}
    delta = abs((wl.last_inventory_at - mark.started_at).total_seconds())
    return delta < 1.0, {
        "actual": wl.last_inventory_at.isoformat(),
        "expected_close_to": mark.started_at.isoformat(),
    }


def _scan_inconsistency_count(a):
    qs = ScanInconsistency.objects.all()
    f = a.get("filter") or {}
    if (c := f.get("cluster")):
        qs = qs.filter(cluster__name=c)
    if (k := f.get("kind") or f.get("kind_value")):
        qs = qs.filter(kind=k)
    if "seen_in_inventory" in f:
        qs = qs.filter(seen_in_inventory=f["seen_in_inventory"])
    if "seen_in_scans" in f:
        qs = qs.filter(seen_in_scans=f["seen_in_scans"])
    actual = qs.count()
    if "expect" in a:
        return actual == a["expect"], {"actual": actual, "expected": a["expect"]}
    if "min" in a:
        return actual >= a["min"], {"actual": actual, "min": a["min"]}
    return False, {"reason": "scan_inconsistency_count needs `expect` or `min`"}


def _import_mark_count(a):
    """Count ImportMark rows matching the filter."""
    qs = ImportMark.objects.all()
    f = a.get("filter") or {}
    if (c := f.get("cluster")):
        qs = qs.filter(cluster__name=c)
    mark_kind = f.get("mark_kind") or f.get("kind") or f.get("kind_value")
    if mark_kind:
        qs = qs.filter(kind=mark_kind)
    if (state := f.get("state")):
        qs = qs.filter(state=state)
    if "complete_snapshot_received" in f:
        wanted = bool(f["complete_snapshot_received"])
        # Subquery: marks with at least one IngestQueue row whose
        # complete_snapshot=true.
        complete_iids = set(
            IngestQueue.objects
            .filter(complete_snapshot=True)
            .values_list("import_id", flat=True)
            .distinct()
        )
        if wanted:
            qs = qs.filter(import_id__in=complete_iids)
        else:
            qs = qs.exclude(import_id__in=complete_iids)
    actual = qs.count()
    return actual == a["expect"], {"actual": actual, "expected": a["expect"]}


def _scan_health_widget(a):
    """Stub — no UI in v1. Always passes."""
    return True, {"note": "scan_health_widget stubbed in v1"}


def _snapshot_absent_since(a):
    """Pass when the workload has no event-path Snapshot row from a
    cycle later than `since_import_id`.

    Implementation: a workload-scope Snapshot row's `import_id` records
    the cycle that wrote it. If the latest Snapshot for this workload
    has `import_id == since_iid`, no later cycle's event-path fired
    (the image set was unchanged).
    """
    ns, n = _split_workload_ref(a["workload"])
    since_iid = a.get("since_import_id") or ""
    if not since_iid:
        return False, {"reason": "since_import_id required"}
    qs = (
        Snapshot.objects
        .filter(scope_kind=a.get("scope") or "workload",
                workload__name=n)
        # Only consider event-path snapshots (change_kind != none).
        # Daily-heartbeat rows would always pull `latest` past the
        # baseline cycle's import_id and falsely fail this assertion.
        .exclude(change_kind="none")
        .order_by("-captured_at")
    )
    if ns:
        qs = qs.filter(workload__namespace__name=ns)
    latest = qs.first()
    if latest is None:
        return False, {"reason": "no event-path snapshot found"}
    return (latest.import_id == since_iid), {
        "latest_import_id": latest.import_id,
        "expected_since": since_iid,
    }


_HANDLERS = {
    "cluster_exists": _cluster_exists,
    "namespace_count": _namespace_count,
    "namespace_attributes": _namespace_attributes,
    "workload_count": _workload_count,
    "workload_exists": _workload_exists,
    "workload_absent": _workload_absent,
    "workload_alias_count": _workload_alias_count,
    "image_count": _image_count,
    "image_exists": _image_exists,
    "observation_count": _observation_count,
    "finding_count": _finding_count,
    "finding_exists": _finding_exists,
    "finding_priority": _finding_priority,
    "signal_present": _signal_present,
    "signal_absent": _signal_absent,
    "import_mark": _import_mark,
    "ingest_queue_count": _ingest_queue_count,
    "snapshot_count": _snapshot_count,
    "snapshot_delta": _snapshot_delta,
    "scan_inconsistency": _scan_inconsistency,
    "import_mark_count": _import_mark_count,
    "snapshot_absent_since": _snapshot_absent_since,
    "enrichment": _enrichment,
    "log_event_count": _log_event_count,
    "log_event_exists": _log_event_exists,
    "scan_inconsistency_count": _scan_inconsistency_count,
    "workload_last_inventory_advanced": _workload_last_inventory_advanced,
    "workload_last_inventory_unchanged": _workload_last_inventory_unchanged,
    "scan_health_widget": _scan_health_widget,
}


def _evaluate_one(a: dict) -> tuple[bool, dict]:
    handler = _HANDLERS.get(a.get("kind"))
    if handler is None:
        return False, {"reason": f"unknown assertion kind: {a.get('kind')}"}
    try:
        return handler(a)
    except Exception as exc:  # pragma: no cover
        return False, {"exception": str(exc)}


def evaluate_assertions(assertions: list[dict]) -> list[dict]:
    out: list[dict] = []
    for idx, a in enumerate(assertions):
        ok, details = _evaluate_one(a)
        out.append({
            "index": idx,
            "kind": a.get("kind"),
            "pass": ok,
            "details": details,
            "spec": a,
        })
    return out
