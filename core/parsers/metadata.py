"""
Parser functions for extracting structured metadata from K8s names.
Each function: parse from naming convention first, then apply overrides.
Overrides handle exceptions that don't follow conventions.

Convention D2 — see docs/conventions.md

──────────────────────────────────────────────────────────────────────
CLUSTER_NAME_PARSING_OVERRIDES_JSON — runtime configuration
──────────────────────────────────────────────────────────────────────
Set the CLUSTER_NAME_PARSING_OVERRIDES_JSON environment variable to
inject cluster metadata overrides at deploy time. Value must be a JSON
object mapping exact cluster names to metadata dicts.

Fields per entry:
  provider     – ovh | eks | aks | do | gke | unknown
  environment  – prod | staging | dev | unknown
  region       – cloud region string (e.g. "eu-west-par", "us-east-1")
  project      – logical grouping / team name

Example (set in your Helm values or directly as an env var):

  CLUSTER_NAME_PARSING_OVERRIDES_JSON='{
    "central-cluster": {
      "provider": "ovh",
      "environment": "prod",
      "region": "eu-west-par",
      "project": "central"
    },
    "legacy-payments-cluster": {
      "provider": "eks",
      "environment": "prod",
      "region": "us-east-1",
      "project": "payments"
    }
  }'

Standard naming conventions (e.g. myapp-prd-usw2-eks) are auto-parsed
with no configuration needed — only add overrides for exceptions.

To apply updated overrides to already-registered clusters without waiting
for the next ingest, run:

  manage.py sync_cluster_meta [--cluster NAME] [--dry-run]

Env entries take precedence over any hardcoded CLUSTER_NAME_PARSING_OVERRIDES below.
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

# ── Hardcoded fallbacks ─────────────────────────────────────────────
# These run even without CLUSTER_NAME_PARSING_OVERRIDES_JSON set.
# Prefer using the env var (via Helm clusterNameParsingOverrides) for new entries.

CLUSTER_NAME_PARSING_OVERRIDES: dict = {}

# ── Merge env-var overrides (env wins over hardcoded entries above) ─
_raw = os.environ.get("CLUSTER_NAME_PARSING_OVERRIDES_JSON", "").strip()
if _raw:
    try:
        _env_overrides = json.loads(_raw)
        if not isinstance(_env_overrides, dict):
            raise ValueError("expected a JSON object, got %s" % type(_env_overrides).__name__)
        CLUSTER_NAME_PARSING_OVERRIDES.update(_env_overrides)
        logger.debug(
            "Loaded %d cluster name parsing override(s) from CLUSTER_NAME_PARSING_OVERRIDES_JSON",
            len(_env_overrides),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("CLUSTER_NAME_PARSING_OVERRIDES_JSON is invalid — ignored: %s", exc)


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
    """Extract provider, environment, region, project from cluster name.

    Convention patterns:
      {project}-{env}-{region}-eks     -> AWS EKS (someapp-prd-usw2-eks)
      azure-{env}-{region}-{id}        -> Azure AKS
      {env}-rpc-{region}               -> OVH baremetal someproject
      {name}-{region}-do               -> DigitalOcean

    Checks CLUSTER_NAME_PARSING_OVERRIDES first (populated from
    CLUSTER_NAME_PARSING_OVERRIDES_JSON env var), then falls back to
    convention parsing, then to 'unknown' for unparseable names.
    """
    if name in CLUSTER_NAME_PARSING_OVERRIDES:
        return CLUSTER_NAME_PARSING_OVERRIDES[name]

    meta = {"provider": "unknown", "environment": "unknown", "region": "", "project": ""}

    # AWS EKS: *-eks suffix
    if name.endswith("-eks"):
        meta["provider"] = "eks"
        parts = name.removesuffix("-eks").split("-")
        for p in parts:
            if p in ("dev", "stg", "staging", "prd", "prod"):
                meta["environment"] = _normalize_env(p)
        if len(parts) >= 3:
            meta["region"] = _expand_aws_region(parts[-1])
            meta["project"] = parts[0]

    # Azure AKS: azure-* prefix
    elif name.startswith("azure-"):
        meta["provider"] = "aks"
        parts = name.removeprefix("azure-").split("-")
        for p in parts:
            if p in ("dev", "stg", "staging", "prod"):
                meta["environment"] = _normalize_env(p)
            if p in ("japaneast", "swedencentral", "westeurope", "eastus"):
                meta["region"] = p
        meta["project"] = "someproject"  # all Azure clusters are someproject currently

    # DigitalOcean: *-do suffix
    elif name.endswith("-do"):
        meta["provider"] = "do"
        parts = name.removesuffix("-do").split("-")
        if len(parts) >= 2:
            meta["region"] = parts[-1]

    return meta


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

    # Split tag
    if ":" in ref:
        ref, meta["tag"] = ref.rsplit(":", 1)

    # Split registry / path
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
    return {
        "prd": "prod",
        "stg": "staging",
        "dev": "dev",
        "prod": "prod",
        "staging": "staging",
    }.get(env, env)


def _expand_aws_region(code: str) -> str:
    """Expand short AWS region codes used in cluster names."""
    regions = {
        "usw2": "us-west-2",
        "euc1": "eu-central-1",
        "apne1": "ap-northeast-1",
    }
    return regions.get(code, code)
