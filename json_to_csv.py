import csv
import json

with open("trivy.json") as f:
    data = json.load(f)

rows = []

for result in data.get("Results", []):
    target = result.get("Target")
    rtype = result.get("Type")

    for vuln in result.get("Vulnerabilities", []):
        rows.append(
            [
                target,
                rtype,
                vuln.get("PkgName"),
                vuln.get("VulnerabilityID"),
                vuln.get("Severity"),
                vuln.get("Status"),
                vuln.get("InstalledVersion"),
                vuln.get("FixedVersion"),
                vuln.get("Title"),
            ]
        )

with open("scan.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(
        [
            "Target",
            "Type",
            "Library",
            "Vulnerability",
            "Severity",
            "Status",
            "InstalledVersion",
            "FixedVersion",
            "Title",
        ]
    )
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to scan.csv")
