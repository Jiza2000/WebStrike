from reporting.report_generator import generate_html_report


def test_critical_risk_has_priority_over_high():
    results = {
        "target": "example.com",
        "ip": "93.184.216.34",
        "findings": [
            {"severity": "High"},
            {"severity": "Critical"},
        ],
        "ssl": {},
        "ports": {},
        "headers": {},
        "services": {},
        "dns": {},
    }

    generate_html_report(results)

    with open("reports/report.html", "r") as file:
        html = file.read()

    assert "Critical" in html


def test_report_shows_owasp_category_and_summary():
    from modules.owasp_mapping import tag_findings

    findings = tag_findings([
        {
            "title": "Content Security Policy Missing",
            "severity": "Medium",
            "evidence": "e",
            "impact": "i",
            "recommendation": "r",
        }
    ])

    results = {
        "target": "example.com",
        "ip": "93.184.216.34",
        "findings": findings,
        "ssl": {},
        "ports": {},
        "headers": {},
        "services": {},
        "dns": {},
    }

    generate_html_report(results)

    with open("reports/report.html", "r") as file:
        html = file.read()

    assert "A02:2025 Security Misconfiguration" in html
    assert "OWASP Top 10:2025 Coverage of Findings" in html
