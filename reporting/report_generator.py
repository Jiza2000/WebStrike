import json
from jinja2 import Environment, FileSystemLoader
from datetime import datetime, timezone
from modules.owasp_mapping import summarize_by_category

def generate_json_report(results):
    with open("reports/report.json", "w") as file:
        json.dump(results, file, indent=4)

def generate_html_report(results):
    env = Environment(loader=FileSystemLoader("templates"))

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    severity_weights = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1,
        "Informational": 0
    }

    risk_score = 0

    for finding in results["findings"]:
        severity = finding.get("severity", "Informational").strip().capitalize()

        if severity in severity_counts:
           severity_counts[severity] += 1
           risk_score += severity_weights[severity]

    if severity_counts["Critical"] > 0:
       overall_risk = "Critical"
    elif severity_counts["High"] > 0:
       overall_risk = "High"
    elif severity_counts["Medium"] > 0:
       overall_risk = "Medium"
    elif severity_counts["Low"] > 0:
       overall_risk = "Low"
    else:
       overall_risk = "Informational"
    template = env.get_template("report.html")

    ssl_info = results["ssl"]

    valid_until = ssl_info.get("valid_until")

    if valid_until:
       expiry_date = datetime.strptime(
            valid_until,
            "%b %d %H:%M:%S %Y %Z"
       ).replace(tzinfo=timezone.utc)

       current_time = datetime.now(timezone.utc)

       if expiry_date < current_time:
           ssl_status = "Expired"
       elif (expiry_date - current_time).days <= 30:
            ssl_status = "Expiring Soon"
       else:
            ssl_status = "Valid"
    else:
       ssl_status = "Unknown"

    html = template.render(
        target=results["target"],
        ip=results["ip"],
        ports=results["ports"],
        services=results["services"],
        headers=results["headers"],
        ssl=results["ssl"],
        dns=results["dns"],
        findings=results["findings"],
        screenshot="screenshot.png" if results.get("screenshot") else None,
        severity_counts=severity_counts,
        owasp_summary=summarize_by_category(results["findings"]),
        overall_risk=overall_risk,
        risk_score=risk_score,
        ssl_status=ssl_status
    )

    with open("reports/report.html", "w") as file:
        file.write(html)
