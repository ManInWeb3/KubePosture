"""Template tags for finding display — severity/status/EPSS/priority badges with tooltips."""
from django import template
from django.utils.html import format_html

register = template.Library()

# --- Colors (light variants for readability in both themes) ---

SEVERITY_COLORS = {
    "Critical": "bg-danger-lt text-danger",
    "High": "bg-orange-lt text-orange",
    "Medium": "bg-yellow-lt text-yellow",
    "Low": "bg-blue-lt text-blue",
}

STATUS_COLORS = {
    "active": "bg-danger-lt text-danger",
    "acknowledged": "bg-blue-lt text-blue",
    "risk_accepted": "bg-warning-lt text-warning",
    "false_positive": "bg-secondary-lt text-secondary",
    "resolved": "bg-success-lt text-success",
}

PRIORITY_COLORS = {
    "immediate": "bg-danger-lt text-danger",
    "out_of_cycle": "bg-orange-lt text-orange",
    "scheduled": "bg-azure-lt text-azure",
    "defer": "bg-secondary-lt text-secondary",
}

# --- Labels ---

STATUS_LABELS = {
    "active": "Active",
    "acknowledged": "Acknowledged",
    "risk_accepted": "Risk Accepted",
    "false_positive": "False Positive",
    "resolved": "Resolved",
}

PRIORITY_LABELS = {
    "immediate": "Immediate",
    "out_of_cycle": "Out-of-Cycle",
    "scheduled": "Scheduled",
    "defer": "Defer",
}

# --- Tooltip descriptions (shown on hover via title attribute) ---

SEVERITY_DESCRIPTIONS = {
    "Critical": "Highest severity \u2014 CVSS 9.0-10.0. Typically allows remote code execution or full system compromise.",
    "High": "CVSS 7.0-8.9. Significant impact \u2014 data exposure, privilege escalation, or service disruption.",
    "Medium": "CVSS 4.0-6.9. Moderate impact \u2014 requires specific conditions or limited scope.",
    "Low": "CVSS 0.1-3.9. Minor impact \u2014 informational or requires unlikely conditions.",
}

STATUS_DESCRIPTIONS = {
    "active": "Open finding, needs attention. Detected by scanner, not yet acted on.",
    "acknowledged": "Team is aware. Investigation or fix is in progress.",
    "risk_accepted": "Risk formally accepted with reason and expiry. Will reactivate when acceptance expires.",
    "false_positive": "Confirmed not a real issue in this context. Requires admin approval with justification.",
    "resolved": "Fixed \u2014 scanner no longer reports this finding. Auto-set when absent from scan.",
}

PRIORITY_DESCRIPTIONS = {
    "immediate": "Fix now \u2014 actively exploited (KEV) or high-risk on exposed production. SLA: 24-48h.",
    "out_of_cycle": "Fix before next sprint \u2014 significant risk, don't wait for normal cycle. SLA: 1 week.",
    "scheduled": "Fix in next regular cycle \u2014 real risk but contained by environment. SLA: 30 days.",
    "defer": "Low risk in this context \u2014 fix when convenient. Next maintenance window.",
}


# --- Badge tags ---

@register.simple_tag
def severity_badge(severity):
    css = SEVERITY_COLORS.get(severity, "bg-secondary")
    desc = SEVERITY_DESCRIPTIONS.get(severity, "")
    return format_html('<span class="badge {}" title="{}">{}</span>', css, desc, severity)


@register.simple_tag
def status_badge(status):
    css = STATUS_COLORS.get(status, "bg-secondary")
    label = STATUS_LABELS.get(status, status)
    desc = STATUS_DESCRIPTIONS.get(status, "")
    return format_html('<span class="badge {}" title="{}">{}</span>', css, desc, label)


@register.simple_tag
def priority_badge(priority):
    css = PRIORITY_COLORS.get(priority, "bg-secondary")
    label = PRIORITY_LABELS.get(priority, priority)
    desc = PRIORITY_DESCRIPTIONS.get(priority, "")
    return format_html('<span class="badge {}" title="{}">{}</span>', css, desc, label)


@register.filter
def dict_get(d, key):
    if not isinstance(d, dict):
        return ""
    return d.get(key, "")


_PSS_COLORS = {
    "restricted": "bg-success-lt text-success",
    "baseline": "bg-warning-lt text-warning",
    "privileged": "bg-danger-lt text-danger",
}
_PSS_DESCRIPTIONS = {
    "restricted": "Most restrictive policy — no privileged containers, enforced non-root.",
    "baseline": "Prevents known privilege escalations while permitting baseline workloads.",
    "privileged": "No restrictions — any workload, including privileged pods, can run.",
    "": "No pod-security.kubernetes.io/enforce label — K8s treats as privileged.",
}


@register.simple_tag
def pss_badge(level):
    """Render a Pod Security Standards level as a badge."""
    key = (level or "").lower()
    css = _PSS_COLORS.get(key, "bg-secondary-lt text-secondary")
    desc = _PSS_DESCRIPTIONS.get(key, _PSS_DESCRIPTIONS[""])
    label = key or "unlabeled"
    return format_html('<span class="badge {}" title="{}">{}</span>', css, desc, label)


@register.simple_tag
def network_policy_badge(count):
    """Render NetworkPolicy count; zero is a risk signal."""
    try:
        n = int(count)
    except (TypeError, ValueError):
        n = 0
    if n == 0:
        css = "bg-danger-lt text-danger"
        desc = "No NetworkPolicies — pod-to-pod traffic is unrestricted."
    else:
        css = "bg-success-lt text-success"
        desc = f"{n} NetworkPolicy resource(s) in this namespace."
    return format_html('<span class="badge {}" title="{}">{}</span>', css, desc, n)


@register.simple_tag
def epss_badge(score):
    if score is None:
        return ""
    score_f = float(score)
    if score_f >= 0.5:
        css = "bg-danger-lt text-danger"
    elif score_f >= 0.1:
        css = "bg-orange-lt text-orange"
    elif score_f >= 0.01:
        css = "bg-yellow-lt text-yellow"
    else:
        css = "bg-azure-lt text-azure"
    pct = f"{score_f:.1%}"
    desc = f"EPSS: {pct} probability this CVE will be exploited in the next 30 days"
    return format_html('<span class="badge {}" title="{}">{}</span>', css, desc, pct)
