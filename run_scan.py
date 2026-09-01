import argparse

from core.engine import run_scan
from reporting.report_generator import generate_json_report, generate_html_report
from modules.risk_analyzer import analyze_risks


def main():
    parser = argparse.ArgumentParser(
        description="WebStrike - Web Application Security Assessment Framework"
    )

    parser.add_argument(
        "target",
        help="Target URL to scan (example: https://example.com)"
    )

    args = parser.parse_args()

    target = args.target

    print(f"[*] Starting WebStrike scan against: {target}")

    results = run_scan(target)

    findings = analyze_risks(results)
    results["findings"] = findings

    generate_json_report(results)
    generate_html_report(results)

    print("[+] Scan completed successfully!")
    print("[+] Reports saved to reports/report.json and reports/report.html")


if __name__ == "__main__":
    main()
