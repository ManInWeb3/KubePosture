"""
Parser functions for extracting structured metadata from K8s names.
Convention D2 — see dev_docs/conventions.md

parse_cluster_meta extracts environment only — the only parsed field that
affects priority scoring. All other cluster metadata (provider, region,
project) defaults to empty and is set in Django admin when needed.
"""

# ── Environment keyword → canonical value ──────────────────────────
# Scanned left-to-right across dash-separated name segments.
# Add synonyms here as new naming conventions are encountered.

_ENV_KEYWORDS = {
    "prod":        "prod",
    "prd":         "prod",
    "production":  "prod",
    "stg":         "staging",
    "staging":     "staging",
    "stage":       "staging",
    "uat":         "staging",     # user-acceptance testing = pre-prod
    "preprod":     "staging",
    "dev":         "dev",
    "development": "dev",
}

# ── Namespace overrides ─────────────────────────────────────────────
NAMESPACE_OVERRIDES = {
    "kube-system": {
        "environment": "system",
        "project": "kubernetes",
        "service": "system",
    },
    "argocd": {
        "environment": "system",
        "project": "platform",
        "service": "argocd",
    },
    "cert-manager": {
        "environment": "system",
        "project": "platform",
        "service": "cert-manager",
    },
}


# ── Parser functions ───────────────────────────────────────────────


def parse_cluster_meta(name: str) -> dict:
    """Extract environment from cluster name.

    Scans each dash-separated segment for a known environment keyword.
    Returns {"environment": <value>} where value is one of:
      prod | staging | dev | unknown

    Examples:
      someapp-prd-usw2-eks   → prod
      azure-prod-eastus-01   → prod
      myapp-staging-cluster  → staging
      uat-payments-cluster   → staging
      dev-sandbox-do         → dev
      random-cluster-name    → unknown
    """
    for part in name.split("-"):
        env = _ENV_KEYWORDS.get(part.lower())
        if env:
            return {"environment": env}
    return {"environment": "unknown"}


def parse_namespace_meta(name: str) -> dict:
    """Extract environment, project, service from namespace name.

    Convention: {env}-{project}-{service} (e.g., prod-app-backend)
    """
    if name in NAMESPACE_OVERRIDES:
        return NAMESPACE_OVERRIDES[name]

    meta = {"environment": "unknown", "project": "", "service": ""}
    parts = name.split("-", 2)

    if len(parts) >= 1 and parts[0] in ("dev", "stg", "staging", "prod", "prd"):
        meta["environment"] = _normalize_env(parts[0])
    if len(parts) >= 2:
        meta["project"] = parts[1]
    if len(parts) >= 3:
        meta["service"] = parts[2]

    return meta


def parse_image_meta(ref: str) -> dict:
    """Extract registry, project, component, tag from image reference."""
    meta = {"registry": "", "project": "", "component": "", "tag": "latest"}

    if ":" in ref:
        ref, meta["tag"] = ref.rsplit(":", 1)

    parts = ref.split("/")
    if len(parts) >= 3:
        meta["registry"] = parts[0]
        meta["project"] = parts[1]
        meta["component"] = "/".join(parts[2:])
    elif len(parts) == 2:
        meta["registry"] = parts[0] if "." in parts[0] else ""
        meta["project"] = parts[0] if "." not in parts[0] else ""
        meta["component"] = parts[1]
    else:
        meta["component"] = parts[0]

    return meta


# ── Helpers ────────────────────────────────────────────────────────


def _normalize_env(env: str) -> str:
    return {"prd": "prod", "stg": "staging", "dev": "dev", "prod": "prod", "staging": "staging"}.get(
        env, env
    )
