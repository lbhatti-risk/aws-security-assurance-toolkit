"""
Shared JSON export for scanner findings.

Produces a timestamped JSON file conforming to the standard audit schema:

{
    "scan_metadata": {
        "scanner":   "S3 Security Scanner",
        "timestamp": "2026-05-04T20:24:00Z",
        "region":    "us-east-1",
        "summary": {
            "resources_scanned": 2,
            "total_checks": 4,
            "fail": 2,
            "pass": 2
        }
    },
    "findings": [
        {
            "resource_id": "pwc-leaky-bucket",
            "control_id":  "NIST-SC-28",
            "severity":    "HIGH",
            "timestamp":   "2026-05-04T20:24:00Z",
            "status":      "FAIL",
            "metadata": {
                "region":      "us-east-1",
                "reason":      "Server-side encryption is not configured",
                "remediation": "Enable default encryption via s3:PutBucketEncryption ...",
                "mappings":    ["ISO-27001-A.8.24"]
            }
        }
    ]
}

Works with any Finding dataclass that carries nist_control, iso_control,
severity, finding, and remediation fields. The caller supplies the attribute
name that holds the resource identifier ('bucket' for S3, 'entity' for IAM).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from assurance.aws_client import get_region

_FAIL_SEVERITIES = {"High", "Critical"}


def _status(severity: str) -> str:
    return "FAIL" if severity in _FAIL_SEVERITIES else "PASS"


def export_findings_to_json(
    findings: list,
    *,
    resource_id_attr: str,
    scanner_name: str,
) -> Path:
    """Write findings to a timestamped JSON file using the standard audit schema.

    Args:
        findings:         List of Finding dataclass instances (S3 or IAM).
        resource_id_attr: Attribute on each Finding that holds the resource
                          identifier — 'bucket' for S3, 'entity' for IAM.
        scanner_name:     Human-readable label written into scan_metadata
                          (e.g. 'S3 Security Scanner').

    Returns:
        Path of the JSON file written.
    """
    region = get_region()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _record(f) -> dict:
        return {
            "resource_id": getattr(f, resource_id_attr),
            "control_id":  f"NIST-{f.nist_control}",
            "severity":    f.severity.upper(),
            "timestamp":   now,
            "status":      _status(f.severity),
            "metadata": {
                "region":      region,
                "reason":      f.finding,
                "remediation": f.remediation,
                "mappings":    [f"ISO-27001-{f.iso_control}"],
            },
        }

    resources_scanned = len({getattr(f, resource_id_attr) for f in findings})
    fail_count = sum(1 for f in findings if f.severity in _FAIL_SEVERITIES)

    output = {
        "scan_metadata": {
            "scanner":   scanner_name,
            "timestamp": now,
            "region":    region,
            "summary": {
                "resources_scanned": resources_scanned,
                "total_checks":      len(findings),
                "fail":              fail_count,
                "pass":              len(findings) - fail_count,
            },
        },
        "findings": [_record(f) for f in findings],
    }

    safe_name = scanner_name.lower().replace(" ", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(f"{safe_name}_{ts}.json")

    with path.open("w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)

    return path
