import csv
from collections import Counter, defaultdict

severity_count = Counter()
package_count = Counter()
fix_status = Counter()
targets = set()
types = set()

with open("scan.csv") as f:
    reader = csv.DictReader(f)

    for row in reader:
        severity = row["Severity"]
        package = row["Library"]
        fixed = row["FixedVersion"]
        target = row["Target"]
        rtype = row["Type"]

        severity_count[severity] += 1
        package_count[package] += 1
        fix_status["Fix Available" if fixed else "No Fix"] += 1
        targets.add(target)
        types.add(rtype)

total = sum(severity_count.values())

print("\n=== Trivy Scan Summary ===\n")

print(f"Targets scanned      : {len(targets)}")
print(f"Scan types           : {', '.join(types)}")
print(f"Total vulnerabilities: {total}\n")

print("Severity Breakdown:")
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
    if sev in severity_count:
        print(f"  {sev:8}: {severity_count[sev]}")

print("\nFix Status:")
for k, v in fix_status.items():
    print(f"  {k:13}: {v}")

print("\nTop 10 Affected Packages:")
for pkg, count in package_count.most_common(10):
    print(f"  {pkg:25} {count}")
