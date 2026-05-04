"""
Unified BI Preparation Script — AWS Security Assurance Toolkit.

Reads every audit JSON file in the current directory, flattens all findings
into a single tabular structure, adds a Risk_Weight score, and exports
enterprise_security_data.csv for use in Google Looker Studio or Power BI.

Files consumed
--------------
Any *.json file whose name starts with:
  - full_security_audit_*
  - s3_security_scanner_*
  - iam_security_scanner_*

Output
------
  enterprise_security_data.csv   (written to the current directory)

Usage
-----
    uv run python scripts/unified_bi_prep.py
"""

import csv
import json
from pathlib import Path

OUTPUT_FILE = "enterprise_security_data.csv"

_PREFIXES = (
    "full_security_audit",
    "s3_security_scanner",
    "iam_security_scanner",
)

# Risk_Weight scoring rubric — aligns with standard risk heat-map conventions.
_RISK_WEIGHTS: dict[str, int] = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   4,
    "LOW":      1,
}

_CSV_HEADERS = [
    "Source_File",
    "Scanner",
    "Scan_Timestamp",
    "Scan_Region",
    "Resource_ID",
    "Control_ID",
    "Severity",
    "Status",
    "Risk_Weight",
    "Reason",
    "Remediation",
    "ISO_Mappings",
]


def find_audit_files() -> list[Path]:
    """Return all matching audit JSON files in the current directory, oldest first."""
    files = [
        p for p in Path(".").glob("*.json")
        if p.name.startswith(_PREFIXES)
    ]
    return sorted(files, key=lambda p: p.stat().st_mtime)


def flatten_file(path: Path) -> list[dict]:
    """Extract and flatten all findings from a single audit JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    meta = data.get("scan_metadata", {})
    rows = []

    for finding in data.get("findings", []):
        severity = finding.get("severity", "").upper()
        fmeta = finding.get("metadata", {})

        rows.append({
            "Source_File":    path.name,
            "Scanner":        meta.get("scanner", ""),
            "Scan_Timestamp": meta.get("timestamp", ""),
            "Scan_Region":    meta.get("region", ""),
            "Resource_ID":    finding.get("resource_id", ""),
            "Control_ID":     finding.get("control_id", ""),
            "Severity":       severity.title(),
            "Status":         finding.get("status", ""),
            "Risk_Weight":    _RISK_WEIGHTS.get(severity, 0),
            "Reason":         fmeta.get("reason", ""),
            "Remediation":    fmeta.get("remediation", ""),
            "ISO_Mappings":   "; ".join(fmeta.get("mappings", [])),
        })

    return rows


def export_csv(rows: list[dict], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_HEADERS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    files = find_audit_files()
    if not files:
        print("[ERROR] No audit JSON files found in the current directory.")
        return

    print(f"Found {len(files)} audit file(s):\n")
    all_rows: list[dict] = []
    for path in files:
        rows = flatten_file(path)
        all_rows.extend(rows)
        fail_count = sum(1 for r in rows if r["Status"] == "FAIL")
        print(f"  {path.name}  →  {len(rows)} findings  ({fail_count} FAIL)")

    output = Path(OUTPUT_FILE)
    export_csv(all_rows, output)

    total_weight = sum(r["Risk_Weight"] for r in all_rows if r["Status"] == "FAIL")
    fail_total   = sum(1 for r in all_rows if r["Status"] == "FAIL")

    print(f"\nExported {len(all_rows)} rows → {output}")
    print(f"  FAIL findings : {fail_total}")
    print(f"  Total Risk_Weight (FAIL only) : {total_weight}")


if __name__ == "__main__":
    main()
