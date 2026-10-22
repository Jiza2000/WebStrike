"""OWASP Top 10:2025 mapping for WebStrike findings.

Category IDs and names follow https://top10.owasp.org/2025/.
WebStrike does NOT detect all ten categories automatically; only
findings that have an entry here are tagged.
"""

OWASP_TOP_10_2025 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# Exact finding title -> OWASP category ID
TITLE_TO_OWASP = {
    "HTTP Port Exposed": "A02",
    "Content Security Policy Missing": "A02",
    "X-Content-Type-Options Header Missing": "A02",
    "Strict-Transport-Security Header Missing": "A02",
    "X-Frame-Options Header Missing": "A02",
    "Referrer-Policy Header Missing": "A02",
    "SSL Certificate Expired": "A04",
    "SSL Certificate Expiring Soon": "A04",
}

# Title prefix -> OWASP category ID (for findings with dynamic titles)
PREFIX_TO_OWASP = {
    "Known Vulnerability:": "A03",
}


def get_owasp_category(title):
    """Return {"id", "name", "label"} for a finding title, or None."""
    category_id = TITLE_TO_OWASP.get(title)

    if category_id is None:
        for prefix, mapped_id in PREFIX_TO_OWASP.items():
            if title.startswith(prefix):
                category_id = mapped_id
                break

    if category_id is None:
        return None

    name = OWASP_TOP_10_2025[category_id]
    return {
        "id": f"{category_id}:2025",
        "name": name,
        "label": f"{category_id}:2025 {name}",
    }


_SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


def summarize_by_category(findings):
    """Group findings by OWASP category.

    Returns a list sorted by category ID:
    [{"label", "count", "highest_severity"}, ...]
    Unmapped findings are skipped.
    """
    groups = {}

    for finding in findings:
        owasp = finding.get("owasp")
        if not owasp:
            continue

        severity = str(finding.get("severity", "Informational")).strip().capitalize()
        if severity not in _SEVERITY_ORDER:
            severity = "Informational"

        group = groups.setdefault(
            owasp["id"],
            {"label": owasp["label"], "count": 0, "highest_severity": severity},
        )
        group["count"] += 1

        if _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(group["highest_severity"]):
            group["highest_severity"] = severity

    return [groups[key] for key in sorted(groups)]


def tag_findings(findings):
    """Add an 'owasp' field to each finding (None if unmapped)."""
    for finding in findings:
        finding["owasp"] = get_owasp_category(finding.get("title", ""))
    return findings
