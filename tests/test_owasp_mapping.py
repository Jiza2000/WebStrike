from modules.owasp_mapping import get_owasp_category, OWASP_TOP_10_2025
from modules.risk_analyzer import analyze_risks


def test_top_10_has_ten_categories():
    assert len(OWASP_TOP_10_2025) == 10


def test_header_finding_maps_to_misconfiguration():
    category = get_owasp_category("Content Security Policy Missing")
    assert category["label"] == "A02:2025 Security Misconfiguration"


def test_http_port_maps_to_cryptographic_failures():
    assert get_owasp_category("HTTP Port Exposed")["id"] == "A04:2025"


def test_cve_title_maps_to_supply_chain():
    category = get_owasp_category("Known Vulnerability: CVE-2021-41773")
    assert category["id"] == "A03:2025"


def test_unmapped_title_returns_none():
    assert get_owasp_category("Something Unknown") is None


def test_analyze_risks_tags_findings():
    results = {
        "ports": {80: "Open"},
        "headers": {},
        "ssl": {},
        "services": {},
    }

    findings = analyze_risks(results)

    assert findings
    assert all(f["owasp"] is not None for f in findings)


def test_summarize_by_category_groups_and_ranks_severity():
    from modules.owasp_mapping import summarize_by_category

    findings = [
        {"severity": "Low", "owasp": get_owasp_category("Referrer-Policy Header Missing")},
        {"severity": "Medium", "owasp": get_owasp_category("Content Security Policy Missing")},
        {"severity": "High", "owasp": get_owasp_category("SSL Certificate Expired")},
        {"severity": "Low", "owasp": None},
    ]

    summary = summarize_by_category(findings)

    assert [s["label"] for s in summary] == [
        "A02:2025 Security Misconfiguration",
        "A04:2025 Cryptographic Failures",
    ]
    assert summary[0]["count"] == 2
    assert summary[0]["highest_severity"] == "Medium"
    assert summary[1]["highest_severity"] == "High"
