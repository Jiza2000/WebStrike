from modules.risk_analyzer import analyze_risks


def test_http_port_finding():
    results = {
        "ports": {
            80: "Open",
            443: "Open",
        },
        "headers": {},
        "ssl": {},
        "services": {},
    }

    findings = analyze_risks(results)

    titles = [finding["title"] for finding in findings]

    assert "HTTP Port Exposed" in titles
