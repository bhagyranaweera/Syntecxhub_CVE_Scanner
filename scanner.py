import socket
from cve_lookup import search_cves
import os
from datetime import datetime

print("=== SYNTECXHUB CVE SCANNER ===")

target = "127.0.0.1"
ports = [21, 22, 80, 443, 3306, 8080]

print(f"Scanning target: {target}")

for port in ports:
    try:
        with socket.create_connection(
            (target, port), timeout=2
        ) as sock:

            print(f"[OPEN] Port {port}")

            try:
                sock.settimeout(2)

                if port in (80, 8080):
                    sock.sendall(
                        b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
                    )

                    banner = sock.recv(2048).decode(
                        "utf-8", errors="ignore"
                    )

                    for line in banner.splitlines():
                        if line.lower().startswith("server:"):
                            print(f"[SERVICE] {line.strip()}")
                            break

                else:
                    banner = sock.recv(1024).decode(
                        "utf-8", errors="ignore"
                    )

                    if banner.strip():
                        print(f"[BANNER] {banner.strip()[:200]}")

            except (socket.timeout, OSError):
                print("[INFO] No banner received")

    except (socket.timeout, OSError):
        print(f"[CLOSED/FILTERED] Port {port}")

print("\nBasic port scan completed!")
print("\n=== STARTING CVE VULNERABILITY LOOKUP ===")

services = [
    ("Apache HTTP Server", "2.4.58"),
    ("MariaDB", "10.4.32")
]

all_results = []

for product, version in services:
    print(f"\nChecking {product} {version}")

    cves = search_cves(product, version)

    all_results.append({
        "product": product,
        "version": version,
        "cves": cves
    })

    print(f"Potential CVE matches found: {len(cves)}")

print("\nCVE lookup completed!")

os.makedirs("reports", exist_ok=True)

report_file = "reports/cve_scan_report.txt"

with open(report_file, "w", encoding="utf-8") as report:
    report.write("SYNTECXHUB CVE VULNERABILITY SCAN REPORT\n")
    report.write("=" * 45 + "\n\n")
    report.write(f"Date: {datetime.now()}\n")
    report.write(f"Target: {target}\n")
    report.write("Scan type: Local service and CVE lookup\n")
    report.write("Finding status: Potential matches only\n\n")

    for item in all_results:
        report.write(
            f"\nService: {item['product']} {item['version']}\n"
        )
        report.write("-" * 45 + "\n")

        if not item["cves"]:
            report.write(
                "No CVEs returned by the keyword search.\n"
            )

        for cve in item["cves"]:
    
            report.write(f"CVE ID: {cve['id']}\n")

            report.write(
        f"CVSS Score: {cve.get('cvss_score', 'N/A')}\n"
    )

            report.write(
        f"Severity: {cve.get('severity', 'UNKNOWN')}\n"
    )

            report.write(
        f"Version Status: {cve.get('status', 'UNVERIFIED')}\n"
    )

            report.write(
        f"Description: {cve['description']}\n"
    )

            report.write(
        "Status: Requires manual verification\n\n"
    )

    report.write("\nSECURITY RECOMMENDATIONS\n")
    report.write("=" * 45 + "\n")
    report.write("1. Keep software updated.\n")
    report.write("2. Review relevant security advisories.\n")
    report.write("3. Verify affected versions and configurations.\n")
    report.write("4. Disable unnecessary services.\n")
    report.write("5. Perform regular authorized security scans.\n")

    report.write("\nDISCLAIMER\n")
    report.write(
        "Keyword matches do not confirm vulnerabilities.\n"
    )
    report.write(
        "Testing was performed against the local environment.\n"
    )

print(f"\nReport generated: {report_file}")