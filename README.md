# WebStrike

A modular Python-based web application security assessment framework for authorized security testing.

WebStrike automates multiple reconnaissance and security assessment tasks and combines the results into structured JSON and HTML reports. The project is designed as a learning-focused security assessment platform while following a modular architecture that makes individual security checks easy to maintain and extend.

---

## Features

### Target Analysis
- Target URL validation
- URL normalization
- Domain/IP resolution
- Hostname identification

### Network & Service Assessment
- TCP port scanning
- HTTP/HTTPS service detection
- Server/banner identification
- HTTP status detection
- Version detection when disclosed by the target
- Handles undisclosed service versions without guessing

### HTTP Security Analysis
Checks for commonly recommended security headers, including:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

Also collects:
- Server information
- Content-Type
- Content-Length
- Response time
- X-Powered-By information when disclosed

### SSL/TLS Assessment
- SSL/TLS certificate inspection
- Certificate subject
- Certificate issuer
- Certificate validity period

### DNS Enumeration
WebStrike collects:

- A records
- MX records
- NS records
- TXT records

The DNS module also handles cases such as missing records and DNS resolution errors gracefully.

### CVE Intelligence
When a service version is actually detected, WebStrike can query the National Vulnerability Database (NVD) for relevant CVEs.

CVE information can include:

- CVE ID
- CVSS score
- Severity
- Description
- Published date
- Last modified date
- References

WebStrike does not invent or assume software versions when a target does not disclose them.

### Risk Analysis
The risk analyzer converts assessment results into structured security findings.

Findings include:

- Title
- Severity
- Evidence
- Impact
- Recommendation
- CVE information when applicable

The reporting layer also calculates an overall risk level and risk score based on identified findings.

### Screenshot Capture
WebStrike captures a screenshot of the assessed web target and includes it in the generated report.

### Automated Reporting

#### JSON Report
Machine-readable assessment results containing:

- Target information
- IP address
- Port results
- HTTP information
- SSL information
- DNS information
- Service detection
- CVE intelligence
- Security findings

#### HTML Report
A human-readable security assessment report containing:

- Executive summary
- Target information
- Port scan results
- Service detection
- SSL/TLS information
- DNS records
- Security findings
- CVE details
- Recommendations
- Target screenshot
- Risk summary

### Flask Web Interface
WebStrike includes a Flask-based interface for running assessments and viewing generated results.

---

## Architecture

WebStrike follows a modular architecture where each security assessment task is separated into its own module.

```text
WebStrike/
│
├── app.py
├── config.py
├── run_scan.py
│
├── core/
│   └── engine.py
│
├── modules/
│   ├── target.py
│   ├── port_scanner.py
│   ├── service_detector.py
│   ├── http_headers.py
│   ├── ssl_checker.py
│   ├── dns_enum.py
│   ├── cve_lookup.py
│   ├── risk_analyzer.py
│   └── screenshot.py
│
├── reporting/
│   └── report_generator.py
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── results.html
│   └── report.html
│
├── static/
│   └── css/
│       └── style.css
│
├── tests/
│   ├── test_target.py
│   ├── test_dns_enum.py
│   ├── test_service_detector.py
│   ├── test_risk_analyzer.py
│   ├── test_risk_analyzer_cve.py
│   └── test_report_generator.py
│
└── requirements.txt

## Scan Workflow
Target URL
    │
    ▼
Target Validation
    │
    ▼
IP Resolution
    │
    ├──► Port Scanning
    │       │
    │       ▼
    │   Service Detection
    │       │
    │       ▼
    │   Version Detection
    │       │
    │       ▼
    │   CVE Lookup
    │
    ├──► HTTP Security Analysis
    │
    ├──► SSL/TLS Analysis
    │
    ├──► DNS Enumeration
    │
    └──► Screenshot Capture
            │
            ▼
       Risk Analysis
            │
            ▼
     JSON / HTML Reports
## Technologies
Python
Flask
Requests
Socket
SSL/TLS
DNSPython
BeautifulSoup
NVD API
Jinja2
ReportLab
Pillow
pytest

## Installation

### Clone the repository and enter the project directory:

git clone <repository-url>
cd WebStrike

### Create a virtual environment:

python3 -m venv venv

### Activate it:

source venv/bin/activate

### Install dependencies:

pip install -r requirements.txt

## Usage
### Command-Line Scan

Run a complete assessment against an authorized target:

python3 run_scan.py https://example.com

After a successful scan:

[+] Scan completed successfully!
[+] Reports saved to reports/report.json and reports/report.html

Generated reports are stored in:

reports/report.json
reports/report.html
reports/screenshot.png
Flask Interface

### Start the Flask application:

python3 app.py

Then open the local WebStrike interface in your browser.

## Testing

WebStrike includes automated tests covering core functionality such as:

Target validation
DNS error handling
HTTP service parsing
Undisclosed service versions
Risk analysis
CVE-based findings
Report generation

### Run the test suite:

PYTHONPATH=. pytest -q tests/

Current test status:

9 passed

## Example Security Findings

A scan can identify issues such as:

Finding	Severity
HTTP Port Exposed	Medium
Content Security Policy Missing	Medium
X-Content-Type-Options Header Missing	Low
Strict-Transport-Security Header Missing	Low
X-Frame-Options Header Missing	Low
Referrer-Policy Header Missing	Low

Severity is determined by WebStrike's risk-analysis logic and should not be confused with CVSS scoring.

## Design Principles

WebStrike was built around several principles:

Modularity — each assessment task has a dedicated module.
Evidence-based detection — the framework avoids guessing information that is not disclosed.
Graceful error handling — failure of one assessment component should not unnecessarily stop unrelated checks.
Structured results — scan data is collected in dictionaries and passed through the assessment pipeline.
Automated testing — core modules are covered by repeatable tests.
Extensibility — the architecture allows additional security checks and intelligence sources to be added later.

## Future Improvements

Planned improvements include:

Nmap integration
OWASP ZAP integration
Nikto integration
Additional vulnerability intelligence
Expanded service/version detection
Improved screenshot and evidence handling
Additional report formats
AI-assisted report summarization
Expanded automated test coverage

## Security & Authorization

WebStrike is intended for authorized security assessments, controlled laboratories, and systems where you have explicit permission to perform testing.

Do not use WebStrike to scan or assess systems without authorization.

## Project Status

WebStrike is an actively developed cybersecurity portfolio project focused on building practical experience with:

Web security assessment
Network reconnaissance
HTTP/HTTPS analysis
DNS enumeration
Vulnerability intelligence
Security risk analysis
Python automation
Flask application development
Security reporting
Automated testing

### One important thing

I deliberately used:

> **"version detection when disclosed by the target"**

instead of claiming **service/version detection** without qualification. That's important because we specifically tested WebStrike against a target that disclosed `cloudflare` but **didn't disclose its version**, and WebStrike correctly reported `Unknown` rather than inventing a version.

I also left `<repository-url>` as a placeholder rather than inventing your GitHub URL.

**Next step:** we should put this into `README.md`, then review the rendered Markdown and make it look like a real GitHub cybersecurity project—not just a block of documentation.
