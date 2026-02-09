# Trivy Image Scan Parser & Aggregator

A lightweight python extensible parser built around **Trivy container image scanning** that converts Trivy JSON reports into structured CSV outputs and generates **aggregate security summaries across multiple builds and images**.
where raw Trivy output is too noisy and hard to consume directly.

---

## Features

- Parses **Trivy JSON (SchemaVersion v2)**
- Converts scan results into clean **CSV reports**

---

## How to Use

- **Pre-requisite** - trivy cli is installed
- run this command trivy image ubuntu:latest --scanners vuln --format json --output trivy.json
- A json is generated, after that run the json_to_csv.py to parse into a csv report file
- Run csv_summary.py to get overall statistics.
