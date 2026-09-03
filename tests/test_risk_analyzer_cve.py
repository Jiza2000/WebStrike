from modules.risk_analyzer import analyze_risks


def test_cve_finding_conversion():
    results = {
        "ports": {},
        "headers": {
            "content_security_policy": "present",
            "x_content_type_options": "nosniff",
            "strict_transport_security": "max-age=31536000",
            "x_frame_options": "DENY",
            "referrer_policy": "strict-origin",
        },
        "ssl": {},
        "services": {
            80: {
                "service": "HTTP",
                "server": "Apache",
                "version": "2.4.49",
                "cves": [
                    {
                        "id": "CVE-2021-41773",
                        "cvss_score": 9.8,
                        "severity": "CRITICAL",
                        "description": "Path traversal vulnerability.",
                        "published": "2021-10-05",
                        "last_modified": "2022-01-05",
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                        ],
                    }
                ],
            }
        },
    }

    findings = analyze_risks(results)

    cve_findings = [
        finding
        for finding in findings
        if finding.get("cve_id") == "CVE-2021-41773"
    ]

    assert len(cve_findings) == 1

    finding = cve_findings[0]

    assert finding["title"] == "Known Vulnerability: CVE-2021-41773"
    assert finding["severity"] == "Critical"
    assert finding["cvss_score"] == 9.8
    assert finding["product"] == "Apache"
    assert finding["version"] == "2.4.49"
