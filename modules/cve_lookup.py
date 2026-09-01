import requests


def get_cvss_data(cve):
    """
    Extract CVSS score and severity from NVD CVE data.

    Supports CVSS v4.0, v3.1, v3.0 and v2.0.
    """

    metrics = cve.get("metrics", {})

    # CVSS v4.0
    if metrics.get("cvssMetricV40"):
        cvss = metrics["cvssMetricV40"][0].get("cvssData", {})

        return {
            "cvss_score": cvss.get("baseScore", "Unknown"),
            "severity": cvss.get("baseSeverity", "Unknown")
        }

    # CVSS v3.1
    if metrics.get("cvssMetricV31"):
        cvss = metrics["cvssMetricV31"][0].get("cvssData", {})

        return {
            "cvss_score": cvss.get("baseScore", "Unknown"),
            "severity": cvss.get("baseSeverity", "Unknown")
        }

    # CVSS v3.0
    if metrics.get("cvssMetricV30"):
        cvss = metrics["cvssMetricV30"][0].get("cvssData", {})

        return {
            "cvss_score": cvss.get("baseScore", "Unknown"),
            "severity": cvss.get("baseSeverity", "Unknown")
        }

    # CVSS v2.0
    if metrics.get("cvssMetricV2"):
        cvss = metrics["cvssMetricV2"][0].get("cvssData", {})

        return {
            "cvss_score": cvss.get("baseScore", "Unknown"),
            "severity": "Unknown"
        }

    return {
        "cvss_score": "Unknown",
        "severity": "Unknown"
    }


def lookup_cves(product, version, limit=5):
    """
    Search NVD for known vulnerabilities affecting
    a specific product and version.
    """

    if not product or not version:
        return []

    if product == "Unknown" or version == "Unknown":
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": limit
    }

    try:
        response = requests.get(
            url,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get(
                "id",
                "Unknown"
            )

            references = []

            for reference in cve.get("references", []):
               ref_url = reference.get("url")

               if ref_url:
                  references.append({
                     "url": ref_url,
                     "source": reference.get("source", "Unknown")
                   })

            descriptions = cve.get(
                "descriptions",
                []
            )

            description = "No description available"

            for desc in descriptions:

                if desc.get("lang") == "en":

                    description = desc.get(
                        "value",
                        description
                    )

                    break

            cvss_data = get_cvss_data(cve)

            vulnerabilities.append({

                "id": cve_id,

                "description": description,

                "cvss_score": cvss_data["cvss_score"],

                "severity": cvss_data["severity"],

                "published": cve.get(
                    "published",
                    "Unknown"
                ),

                "last_modified": cve.get(
                    "lastModified",
                    "Unknown"
                ),

                "references": references
       })

        return vulnerabilities

    except requests.RequestException:
        return []
