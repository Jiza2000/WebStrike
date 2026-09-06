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
