from modules.risk_analyzer import analyze_risks
from modules.screenshot import capture_screenshot
from modules.cve_lookup import lookup_cves
from modules.service_detector import detect_service, parse_http_banner
from modules.target import validate_target, resolve_ip, get_hostname
from modules.port_scanner import scan_ports
from modules.http_headers import get_http_headers
from modules.ssl_checker import get_ssl_info
from modules.dns_enum import get_dns_records


def run_scan(target):
    """
    Main scan engine.
    Calls all scanning modules and returns a single result dictionary.
    """

    target = validate_target(target)

    ip = resolve_ip(target)

    hostname = get_hostname(target)

    port_results = scan_ports(ip)

    services = {}

    for port, status in port_results.items():

        if status == "Open":

            raw_response = detect_service(
                ip,
                port,
                hostname
            )

            if port == 80:
                service_info = parse_http_banner(
                    raw_response,
                    "HTTP"
                )

            elif port == 443:
                service_info = parse_http_banner(
                    raw_response,
                    "HTTPS"
                )

            else:
                service_info = {
                    "service": "Unknown",
                    "banner": raw_response,
                    "version": "Unknown"
                }

            service_info["cves"] = []

            server = service_info.get("server")
            version = service_info.get("version")

            if (
               server
               and version
               and server != "Unknown"
               and version != "Unknown"
            ):
               service_info["cves"] = lookup_cves(
                  server,
                  version
               )

            services[port] = service_info

    headers = get_http_headers(target)

    ssl_info = get_ssl_info(target)

    dns_info = get_dns_records(hostname)

    screenshot = capture_screenshot(target)

    results = {
        "target": target,
        "ip": ip,
        "ports": port_results,
        "headers": headers,
        "ssl": ssl_info,
        "dns": dns_info,
        "services": services,
        "screenshot": screenshot
    }

    results["findings"] = analyze_risks(results)

    return results
