"""
Audit Evidence Generator — AWS Security Assurance Toolkit.

Reads the most recent scan results for each scanner, then:

  1. Assigns a stable Workpaper Reference ID (WP-S3-NNN / WP-IAM-NNN) to
     every FAIL finding, sorted deterministically so IDs are reproducible.
  2. Writes one evidence file per FAIL finding to evidence/.
  3. Generates control_effectiveness_report.md — a formal report suitable
     for inclusion in an audit workpaper package.

Output
------
  evidence/WP-S3-001.json          One file per FAIL finding
  evidence/WP-IAM-001.json         ...
  control_effectiveness_report.md  Control Effectiveness Report (Markdown)

Usage
-----
    uv run python scripts/generate_audit_evidence.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PREFIXES = ("s3_security_scanner", "iam_security_scanner", "full_security_audit")

_RISK_WEIGHTS: dict[str, int] = {
    "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1,
}

# Maps scanner name → short prefix used in WP IDs.
_WP_PREFIX: dict[str, str] = {
    "S3 Security Scanner":  "S3",
    "IAM Security Scanner": "IAM",
}

# Human-readable description of the API call used to detect each condition.
_DETECTION_METHODS: dict[str, str] = {
    "NIST-PR.DS-01": (
        "AWS S3 GetPublicAccessBlock API — evaluated BlockPublicAcls, "
        "IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets flags"
    ),
    "NIST-SC-28": (
        "AWS S3 GetBucketEncryption API — inspected "
        "ServerSideEncryptionConfiguration rules"
    ),
    "NIST-IA-2(1)": (
        "AWS IAM ListMFADevices API — enumerated registered virtual and "
        "hardware MFA devices per user principal"
    ),
    "NIST-AC-2(1)": (
        "AWS IAM ListAttachedUserPolicies API — enumerated managed policies "
        "directly attached to user principals"
    ),
    "NIST-IA-5(1)": (
        "AWS IAM ListAccessKeys API — retrieved AccessKeyMetadata and "
        "calculated key age from CreateDate against datetime.now(UTC)"
    ),
}

EVIDENCE_DIR = Path("evidence")
REPORT_FILE  = Path("control_effectiveness_report.md")


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def find_latest_per_scanner() -> list[Path]:
    """Return the most recently modified file for each recognised scanner prefix."""
    seen: dict[str, Path] = {}
    for p in sorted(Path(".").glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        prefix = next((px for px in _PREFIXES if p.name.startswith(px)), None)
        if prefix and prefix not in seen:
            seen[prefix] = p
    return list(seen.values())


# ---------------------------------------------------------------------------
# Workpaper reference assignment
# ---------------------------------------------------------------------------

def assign_wp_ids(all_findings: list[dict]) -> list[dict]:
    """
    Attach a stable WP reference ID to every FAIL finding.

    Sort order: scanner prefix → control_id → resource_id.
    This makes IDs reproducible across runs as long as the set of unique
    (scanner, control_id, resource_id) tuples does not change.
    """
    fail_findings = [f for f in all_findings if f["status"] == "FAIL"]
    fail_findings.sort(key=lambda f: (
        _WP_PREFIX.get(f["_scanner"], "XX"),
        f["control_id"],
        f["resource_id"],
    ))

    counters: dict[str, int] = {}
    for finding in fail_findings:
        prefix = _WP_PREFIX.get(finding["_scanner"], "XX")
        counters[prefix] = counters.get(prefix, 0) + 1
        finding["wp_ref"] = f"WP-{prefix}-{counters[prefix]:03d}"

    return fail_findings


# ---------------------------------------------------------------------------
# Evidence string construction
# ---------------------------------------------------------------------------

def build_evidence_string(finding: dict) -> str:
    """
    Construct a formal evidence narrative from the structured finding data.

    In production this would embed the raw API response (e.g. the full
    IAM policy JSON or S3 ACL). Against LocalStack, the finding metadata
    is the authoritative record of the observed configuration state.
    """
    control   = finding["control_id"]
    resource  = finding["resource_id"]
    reason    = finding["metadata"]["reason"]
    iso       = "; ".join(finding["metadata"]["mappings"])
    method    = _DETECTION_METHODS.get(control, "Automated AWS API scan")
    timestamp = finding["timestamp"]
    scanner   = finding["_scanner"]
    source    = finding["_source_file"]

    return (
        f"Resource '{resource}' was evaluated against control {control} ({iso}) "
        f"during an automated security assessment conducted by the {scanner}.\n\n"
        f"Observed condition:\n  {reason}\n\n"
        f"Detection method:\n  {method}\n\n"
        f"Assessment timestamp: {timestamp}\n"
        f"Source file: {source}"
    )


# ---------------------------------------------------------------------------
# Evidence file writer
# ---------------------------------------------------------------------------

def write_evidence_files(fail_findings: list[dict]) -> None:
    EVIDENCE_DIR.mkdir(exist_ok=True)
    for f in fail_findings:
        record = {
            "workpaper_reference": f["wp_ref"],
            "evidence_timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scanner":             f["_scanner"],
            "source_file":         f["_source_file"],
            "resource_id":         f["resource_id"],
            "control_id":          f["control_id"],
            "severity":            f["severity"],
            "status":              f["status"],
            "risk_weight":         _RISK_WEIGHTS.get(f["severity"].upper(), 0),
            "evidence_string":     build_evidence_string(f),
            "remediation":         f["metadata"]["remediation"],
            "iso_mappings":        f["metadata"]["mappings"],
            "raw_finding": {
                "resource_id": f["resource_id"],
                "control_id":  f["control_id"],
                "severity":    f["severity"],
                "timestamp":   f["timestamp"],
                "status":      f["status"],
                "metadata":    f["metadata"],
            },
        }
        out = EVIDENCE_DIR / f"{f['wp_ref']}.json"
        out.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"  [+] {out}")


# ---------------------------------------------------------------------------
# Control Effectiveness Report
# ---------------------------------------------------------------------------

def generate_report(
    all_findings: list[dict],
    fail_findings: list[dict],
    source_files: list[Path],
) -> None:
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    total     = len(all_findings)
    fail_n    = len(fail_findings)
    pass_n    = total - fail_n
    weight    = sum(_RISK_WEIGHTS.get(f["severity"].upper(), 0) for f in fail_findings)
    crit_n    = sum(1 for f in fail_findings if f["severity"].upper() == "CRITICAL")
    high_n    = sum(1 for f in fail_findings if f["severity"].upper() == "HIGH")

    lines: list[str] = []

    # ---- Header ----
    lines += [
        "# Control Effectiveness Report",
        "",
        f"**Toolkit:** AWS Security Assurance Toolkit  ",
        f"**Prepared:** {now}  ",
        f"**Prepared by:** Digital Audit Associate  ",
        f"**Scope:** S3 Data Protection · IAM Identity and Access Management  ",
        f"**Frameworks:** NIST CSF 2.0 · NIST SP 800-53 · ISO/IEC 27001:2022  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Source files | {len(source_files)} |",
        f"| Total checks | {total} |",
        f"| FAIL (non-compliant) | **{fail_n}** |",
        f"| PASS (compliant) | {pass_n} |",
        f"| Critical findings | {crit_n} |",
        f"| High findings | {high_n} |",
        f"| Total Risk Weight (FAIL only) | **{weight}** |",
        "",
        "Source files reviewed:",
        "",
    ]
    for p in source_files:
        lines.append(f"- `{p.name}`")

    lines += ["", "---", ""]

    # ---- Findings by scanner ----
    lines += ["## 2. Findings by Control Domain", ""]

    scanners_seen = dict.fromkeys(f["_scanner"] for f in all_findings)
    section_num = 1

    for scanner in scanners_seen:
        scanner_findings = [f for f in all_findings if f["_scanner"] == scanner]
        fail_set = {f["wp_ref"] for f in fail_findings}

        lines += [
            f"### 2.{section_num} {scanner}",
            "",
            "| WP Reference | Resource | Control | ISO Mapping | Severity | Status |",
            "|---|---|---|---|---|---|",
        ]

        for f in scanner_findings:
            wp    = f.get("wp_ref", "—")
            iso   = "; ".join(f["metadata"]["mappings"])
            sev   = f["severity"].title()
            badge = "**FAIL**" if f["status"] == "FAIL" else "PASS"
            lines.append(
                f"| {wp} | `{f['resource_id']}` | `{f['control_id']}` "
                f"| {iso} | {sev} | {badge} |"
            )

        lines += [""]
        section_num += 1

    lines += ["---", ""]

    # ---- Evidence index ----
    lines += [
        "## 3. Evidence Index",
        "",
        "Each row below corresponds to a FAIL finding. The Evidence File column "
        "links to the structured evidence record saved in `evidence/`.",
        "",
        "| WP Reference | Resource | Control | Severity | Risk Weight | Evidence File |",
        "|---|---|---|---|---|---|",
    ]

    for f in fail_findings:
        w  = _RISK_WEIGHTS.get(f["severity"].upper(), 0)
        ef = f"evidence/{f['wp_ref']}.json"
        lines.append(
            f"| {f['wp_ref']} | `{f['resource_id']}` | `{f['control_id']}` "
            f"| {f['severity'].title()} | {w} | `{ef}` |"
        )

    lines += ["", "---", ""]

    # ---- Methodology ----
    lines += [
        "## 4. Audit Methodology",
        "",
        "All findings were produced by automated inspection of AWS service "
        "configuration APIs via boto3. No manual sampling was performed — "
        "the scanner evaluates the complete population of in-scope resources.",
        "",
        "| Control | API Inspected | Population |",
        "|---|---|---|",
        "| NIST-PR.DS-01 | `GetPublicAccessBlock` | All S3 buckets |",
        "| NIST-SC-28 | `GetBucketEncryption` | All S3 buckets |",
        "| NIST-IA-2(1) | `ListMFADevices` | All IAM users |",
        "| NIST-AC-2(1) | `ListAttachedUserPolicies` | All IAM users |",
        "| NIST-IA-5(1) | `ListAccessKeys` | All IAM users (active keys only) |",
        "",
        "Paginated API calls ensure 100% coverage regardless of account size. "
        "All timestamps are UTC. Access key IDs are masked "
        "(`AKIA****MPLE`) in all output to prevent partial-secret leakage.",
        "",
        "---",
        "",
        "## 5. Audit Trail",
        "",
        "| Artefact | Location | Purpose |",
        "|---|---|---|",
        "| Scan JSON exports | `*_scanner_*.json` | Machine-readable finding records |",
        "| Evidence files | `evidence/WP-*.json` | Per-finding evidence packages |",
        "| This report | `control_effectiveness_report.md` | Control effectiveness summary |",
        "| BI dataset | `enterprise_security_data.csv` | Trend and dashboard data |",
        "| SIEM dispatch log | `dispatch_audit.py` stdout | Real-time delivery confirmation |",
        "",
    ]

    REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    source_files = find_latest_per_scanner()
    if not source_files:
        print("[ERROR] No audit JSON files found.")
        return

    # Load and tag every finding with its scanner name and source filename.
    all_findings: list[dict] = []
    for path in source_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        scanner = data["scan_metadata"]["scanner"]
        for f in data["findings"]:
            f["_scanner"]     = scanner
            f["_source_file"] = path.name
            all_findings.append(f)

    # Assign WP IDs to FAIL findings (modifies in place, returns only FAILs).
    fail_findings = assign_wp_ids(all_findings)

    # Mirror WP refs back onto all_findings for the report table.
    wp_map = {(f["_scanner"], f["resource_id"], f["control_id"]): f.get("wp_ref", "—")
              for f in fail_findings}
    for f in all_findings:
        f["wp_ref"] = wp_map.get((f["_scanner"], f["resource_id"], f["control_id"]), "—")

    print(f"\nProcessing {len(source_files)} source file(s):")
    for p in source_files:
        print(f"  {p.name}")

    print(f"\nWriting {len(fail_findings)} evidence file(s) to {EVIDENCE_DIR}/:\n")
    write_evidence_files(fail_findings)

    generate_report(all_findings, fail_findings, source_files)

    print(f"\nReport written → {REPORT_FILE}")
    print(f"\nSummary: {len(fail_findings)} FAIL findings | "
          f"{sum(_RISK_WEIGHTS.get(f['severity'].upper(), 0) for f in fail_findings)} total Risk Weight\n")


if __name__ == "__main__":
    main()
