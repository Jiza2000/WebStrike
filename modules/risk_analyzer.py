from datetime import datetime, timezone
from modules.owasp_mapping import tag_findings

def create_finding(title, severity, evidence, impact, recommendation):
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation
    }

def analyze_risks(results):
    findings = []

    # Check if HTTP port 80 is open
    if results["ports"].get(80) == "Open":
        findings.append(create_finding(
            "HTTP Port Exposed",
            "Medium",
            "Port 80 is open.",
            "Unencrypted HTTP can expose web traffic to interception or manipulation if sensitive information is transmitted without adequate protection.",
            "Redirect HTTP traffic to HTTPS and disable unencrypted HTTP where possible."
        ))

    # Check for missing Content-Security-Policy
    if not results["headers"].get("content_security_policy"):
        findings.append(create_finding(
            "Content Security Policy Missing",
            "Medium",
            "Content-Security-Policy header was not detected.",
            "Without CSP, the application has fewer browser-level protections against certain cross-site scripting and content-injection attacks.",
            "Implement a Content-Security-Policy header appropriate for the application."
        ))

         # Check for missing X-Content-Type-Options
    if not results["headers"].get("x_content_type_options"):
        findings.append(create_finding(
            "X-Content-Type-Options Header Missing",
            "Low",
            "X-Content-Type-Options header was not detected.",
            "Without this header, browsers may perform MIME-type sniffing, which can increase the risk of unintended content interpretation.",
            "Set X-Content-Type-Options: nosniff."
        ))

        # Check for missing Strict-Transport-Security
    if not results["headers"].get("strict_transport_security"):
        findings.append(create_finding(
            "Strict-Transport-Security Header Missing",
            "Low",
            "Strict-Transport-Security header was not detected.",
            "Without HSTS, users may remain vulnerable to downgrade or first-connection attacks that attempt to prevent secure HTTPS communication.",
            "Implement an appropriate Strict-Transport-Security policy."
        ))

        # Check for missing X-Frame-Options
    if not results["headers"].get("x_frame_options"):
        findings.append(create_finding(
            "X-Frame-Options Header Missing",
            "Low",
            "X-Frame-Options header was not detected.",
            "The application may have reduced protection against clickjacking when framing restrictions are not otherwise enforced.",
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use an appropriate CSP frame-ancestors policy."
        ))

       # Check for missing Referrer-Policy
    if not results["headers"].get("referrer_policy"):
        findings.append(create_finding(
             "Referrer-Policy Header Missing",
             "Low",
             "Referrer-Policy header was not detected.",
             "Without an explicit Referrer-Policy, browsers may disclose more referrer information than intended when navigating between resources or sites.",
             "Set an appropriate Referrer-Policy to control referrer information."
        ))

        # Check if SSL certificate is expired
    valid_until = results["ssl"].get("valid_until")

    if valid_until:
        expiry_date = datetime.strptime(
            valid_until,
            "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        current_time = datetime.now(timezone.utc)
        days_remaining = (expiry_date - current_time).days

        if expiry_date < current_time:
            findings.append(create_finding(
               "SSL Certificate Expired",
               "High",
               f"Certificate expired on {valid_until}.",
               "An expired certificate can cause browser warnings, disrupt trust in the service, and potentially interrupt secure communications.",
               "Renew the SSL/TLS certificate and ensure the replacement certificate is valid."
            ))

        if 0 <= days_remaining <= 30:
            findings.append(create_finding(
               "SSL Certificate Expiring Soon",
               "Low",
               f"Certificate expires in approximately {days_remaining} days.",
               "An approaching certificate expiration can cause service disruption and browser security warnings if renewal is not completed in time.",
               "Renew the SSL/TLS certificate before it expires."
            ))


        # Check for known CVE vulnerabilities
    for port, service in results.get("services", {}).items():

       for cve in service.get("cves", []):

            cve_id = cve.get("id", "Unknown")
            cvss_score = cve.get("cvss_score", "Unknown")
            severity = cve.get("severity", "Unknown").strip().capitalize()

            if severity not in ["Critical", "High", "Medium", "Low"]:
                severity = "Informational"

            server = service.get(
                "server",
                service.get("service", "Unknown")
            )

            version = service.get(
                "version",
                "Unknown"
            )

            description = cve.get(
                "description",
                "No description available"
            )

            references = cve.get(
                "references",
                []
            )

            finding = create_finding(
               f"Known Vulnerability: {cve_id}",
               severity,
               (
                   f"{server} {version} is associated with "
                   f"{cve_id} (CVSS {cvss_score}). "
                   f"{description}"
               ),
               (
                   f"The identified version may be affected by the known "
                   f"vulnerability represented by {cve_id}, potentially "
                   f"exposing the service to security risks described by the CVE."
               ),
               (
                   f"Upgrade {server} to a supported version that addresses "
                   f"{cve_id}, and apply the vendor's security updates."
               )
            )

            finding["cve_id"] = cve_id
            finding["cvss_score"] = cvss_score
            finding["product"] = server
            finding["version"] = version
            finding["published"] = cve.get("published", "Unknown")
            finding["last_modified"] = cve.get("last_modified", "Unknown")
            finding["references"] = references

            findings.append(finding)

    return tag_findings(findings)
