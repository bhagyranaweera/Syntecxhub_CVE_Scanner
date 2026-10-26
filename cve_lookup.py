
import requests
import re

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PRODUCTS = {
    "Apache HTTP Server": ("apache", "http_server"),
    "MariaDB": ("mariadb", "mariadb"),
}


def version_parts(version):
    """Convert common numeric versions into comparable tuples."""
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts)


def compare_versions(version1, version2):
    """Compare simple numeric software versions."""
    a = version_parts(version1)
    b = version_parts(version2)

    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))

    return (a > b) - (a < b)


def version_matches(version, match):
    """Check the affected version and version boundaries."""

    criteria = match.get("criteria", "")
    fields = criteria.split(":")

    if len(fields) < 6:
        return None

    cpe_version = fields[5]

    # Unsupported or complex version formats need manual review.
    if not re.fullmatch(r"\d+(?:\.\d+)*", version):
        return None

    if cpe_version not in ("*", "-"):
        if not re.fullmatch(r"\d+(?:\.\d+)*", cpe_version):
            return None

        if compare_versions(version, cpe_version) != 0:
            return False

    boundaries = [
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    ]

    for field, condition in boundaries:
        boundary = match.get(field)

        if boundary is not None:
            if not re.fullmatch(r"\d+(?:\.\d+)*", boundary):
                return None

            comparison = compare_versions(version, boundary)

            if not condition(comparison):
                return False

    return True


def get_cvss(cve):
    """Extract the CVSS score and severity from NVD."""

    metrics = cve.get("metrics", {})

    for metric_type in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        entries = metrics.get(metric_type, [])

        if entries:
            metric = next(
                (m for m in entries if m.get("type") == "Primary"),
                entries[0],
            )

            cvss_data = metric.get("cvssData", {})

            score = cvss_data.get("baseScore", "N/A")

            severity = cvss_data.get(
                "baseSeverity",
                metric.get("baseSeverity", "UNKNOWN"),
            )

            return score, severity

    return "N/A", "UNKNOWN"


def check_configuration(cve, product, version):
    """
    Evaluate CPE matches for the selected product.

    Returns:
        MATCHED
        NOT_AFFECTED
        UNVERIFIED

    This is a conservative check, not a full NVD
    configuration-expression evaluator.
    """

    vendor, product_name = PRODUCTS[product]

    configurations = cve.get("configurations", [])

    if not configurations:
        return "UNVERIFIED"

    found_match = False
    uncertain = False
    found_product = False

    def inspect_node(node):
        nonlocal found_match, uncertain, found_product

        operator = node.get("operator", "OR")
        negate = node.get("negate", False)

        # Complex logical conditions cannot be safely reduced
        # to an individual product/version comparison.
        if negate or operator == "AND":
            uncertain = True

        for match in node.get("cpeMatch", []):
            criteria = match.get("criteria", "")
            fields = criteria.split(":")

            if len(fields) < 6:
                continue

            if fields[3] != vendor or fields[4] != product_name:
                continue

            found_product = True

            if not match.get("vulnerable", False):
                continue

            result = version_matches(version, match)

            if result is True:
                found_match = True
            elif result is None:
                uncertain = True

        for child in node.get("children", []):
            inspect_node(child)

    for configuration in configurations:
        for node in configuration.get("nodes", []):
            inspect_node(node)

    if uncertain:
        return "UNVERIFIED"

    if found_match:
        return "MATCHED"

    if found_product:
        return "NOT_AFFECTED"

    return "UNVERIFIED"


def search_cves(product, version):
    """Search NVD and return relevant CVEs with verification status."""

    print(f"\nSearching CVEs for {product} {version}...")

    if product not in PRODUCTS:
        print("[ERROR] Unsupported product.")
        return []

    vendor, product_name = PRODUCTS[product]

    # CPE-based search narrows the results to the
    # selected software and version.
    cpe = (
        f"cpe:2.3:a:{vendor}:{product_name}:"
        f"{version}:*:*:*:*:*:*:*"
    )

    results = []
    start_index = 0
    page_size = 2000

    try:
        while True:
            response = requests.get(
                NVD_API,
                params={
                    "virtualMatchString": cpe,
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                },
                timeout=30,
            )

            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")

                descriptions = cve.get("descriptions", [])

                description = next(
                    (
                        d.get("value", "")
                        for d in descriptions
                        if d.get("lang") == "en"
                    ),
                    "No description available",
                )

                status = check_configuration(cve, product, version)

                if status == "NOT_AFFECTED":
                    continue

                score, severity = get_cvss(cve)

                result = {
                    "id": cve_id,
                    "description": description,
                    "cvss_score": score,
                    "severity": severity,
                    "status": status,
                }

                results.append(result)

                print(f"\n[CVE] {cve_id}")
                print(f"CVSS Score: {score}")
                print(f"Severity: {severity}")
                print(f"Version Status: {status}")
                print(f"Description: {description[:200]}")

            start_index += len(vulnerabilities)

            if not vulnerabilities or start_index >= total_results:
                break

        print(f"\nTotal CVEs requiring review: {len(results)}")
        return results

    except requests.RequestException as error:
        print(f"[ERROR] CVE lookup failed: {error}")
        return []


if __name__ == "__main__":
    search_cves("Apache HTTP Server", "2.4.58")
