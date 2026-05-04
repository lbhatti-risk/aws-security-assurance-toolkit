"""
S3 Security Scanner — Public Access Block and encryption audit.

Control objectives:
  1. Every S3 bucket must have all four Block Public Access settings enabled.
     A missing or partially-disabled configuration creates a pathway for data
     exfiltration and is treated as a High severity finding.
  2. Every S3 bucket must have server-side encryption explicitly configured.
     Absent encryption leaves data at rest unprotected.

NIST mappings:
  Public Access Block : NIST CSF 2.0 PR.DS-01 (Data-at-rest is protected)
  Encryption          : NIST SP 800-53 SC-28   (Protection of Information at Rest)
ISO/IEC 27001:2022:
  Public Access Block : A.8.3  (Information access restriction)
  Encryption          : A.8.24 (Use of cryptography)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from botocore.exceptions import ClientError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from assurance.aws_client import get_client
from assurance.analyst import generate_risk_statement

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

Severity = Literal["High", "Low", "Info"]


@dataclass
class Finding:
    bucket: str
    severity: Severity
    finding: str
    nist_control: str
    iso_control: str
    remediation: str
    # Raw block config for reference; populated only when a partial config exists.
    raw_config: dict = field(default_factory=dict)


@dataclass
class S3ScanResult:
    findings: list[Finding]
    ai_reports: dict[str, str]  # bucket name → AI report text


# ---------------------------------------------------------------------------
# Scanner logic
# ---------------------------------------------------------------------------

def _check_public_access_block(s3_client, bucket_name: str) -> Finding:
    """
    Evaluate the Block Public Access configuration for a single bucket.

    Three outcomes:
      1. Configuration is absent     → High (no protection whatsoever)
      2. Any of the four flags is False → High (partial protection, still exploitable)
      3. All four flags are True     → Low / compliant
    """
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            # The setting was never applied — the bucket is fully open to public ACLs/policies.
            return Finding(
                bucket=bucket_name,
                severity="High",
                finding="Block Public Access configuration is absent",
                nist_control="PR.DS-01",
                iso_control="A.8.3",
                remediation=(
                    "Apply s3:PutPublicAccessBlock with all four flags set to True. "
                    "Enable at the account level via S3 console > Block Public Access settings."
                ),
            )
        raise  # Unexpected error — let it surface.

    if all_blocked:
        return Finding(
            bucket=bucket_name,
            severity="Low",
            finding="Block Public Access is fully enabled — compliant",
            nist_control="PR.DS-01",
            iso_control="A.8.3",
            remediation="No action required.",
            raw_config=cfg,
        )

    # Partial configuration — identify which flags are off.
    disabled = [k for k, v in cfg.items() if not v]
    return Finding(
        bucket=bucket_name,
        severity="High",
        finding=f"Block Public Access partially disabled: {', '.join(disabled)}",
        nist_control="PR.DS-01",
        iso_control="A.8.3",
        remediation=(
            f"Re-run s3:PutPublicAccessBlock and set {', '.join(disabled)} to True."
        ),
        raw_config=cfg,
    )


def _check_encryption(s3_client, bucket_name: str) -> Finding:
    """
    Verify that server-side encryption is explicitly configured on a bucket.

    Two outcomes:
      1. No encryption configuration exists → High (data at rest unprotected)
      2. A valid encryption rule exists     → Low / compliant
    """
    try:
        resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = resp["ServerSideEncryptionConfiguration"]["Rules"]
        algorithm = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        return Finding(
            bucket=bucket_name,
            severity="Low",
            finding=f"Server-side encryption enabled ({algorithm}) — compliant",
            nist_control="SC-28",
            iso_control="A.8.24",
            remediation="No action required.",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return Finding(
                bucket=bucket_name,
                severity="High",
                finding="Server-side encryption is not configured",
                nist_control="SC-28",
                iso_control="A.8.24",
                remediation=(
                    "Enable default encryption via s3:PutBucketEncryption. "
                    "Use SSE-S3 (AES-256) as a baseline or SSE-KMS for "
                    "enhanced key management and audit trail via AWS KMS."
                ),
            )
        raise  # Unexpected error — let it surface.


def scan() -> list[Finding]:
    """List all buckets and evaluate each for public access and encryption misconfigurations."""
    s3 = get_client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    return [
        check(s3, b["Name"])
        for b in buckets
        for check in (_check_public_access_block, _check_encryption)
    ]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_SEVERITY_STYLE = {
    "High": "bold red",
    "Low":  "bold green",
    "Info": "dim",
}


def print_findings(findings: list[Finding]) -> dict[str, str]:
    console = Console()

    table = Table(
        title="[bold]S3 Security Audit — Findings[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Bucket",         style="cyan",        no_wrap=True)
    table.add_column("Severity",       justify="center",    no_wrap=True)
    table.add_column("Finding",        style="white",       ratio=3)
    table.add_column("NIST Control",   justify="center",    no_wrap=True)
    table.add_column("ISO 27001:2022", justify="center",    no_wrap=True)
    table.add_column("Remediation",    style="dim white",   ratio=4)

    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        table.add_row(
            f.bucket,
            f"[{style}]{f.severity}[/{style}]",
            f.finding,
            f.nist_control,
            f.iso_control,
            f.remediation,
        )

    console.print()
    console.print(table)

    bucket_count = len({f.bucket for f in findings})
    high_count = sum(1 for f in findings if f.severity == "High")
    console.print(
        f"\n[bold]Summary:[/bold] {bucket_count} bucket(s) scanned, {len(findings)} check(s) — "
        f"[bold red]{high_count} High[/bold red] severity finding(s)\n"
    )

    # For every High finding, call the AI analyst and print the formal report.
    high_findings = [f for f in findings if f.severity == "High"]
    if not high_findings:
        return {}

    ai_reports: dict[str, str] = {}
    console.print("[bold]AI-Generated Audit Findings[/bold]\n")
    for f in high_findings:
        finding_details = (
            f"Affected resource: S3 bucket '{f.bucket}'. "
            f"Condition: {f.finding}. "
            f"Severity: {f.severity}. "
            f"NIST CSF 2.0 control: {f.nist_control}. "
            f"ISO/IEC 27001:2022 control: {f.iso_control}. "
            f"Recommended remediation: {f.remediation}"
        )

        console.print(
            f"  Calling AI analyst for [cyan]{f.bucket}[/cyan]…",
            highlight=False,
        )
        try:
            report = generate_risk_statement(finding_details)
            ai_reports[f"{f.bucket}|{f.nist_control}"] = report
        except Exception as exc:
            console.print(f"  [bold red]AI analyst error:[/bold red] {exc}\n")
            continue

        console.print(
            Panel(
                report,
                title=f"[bold red]Audit Finding — {f.bucket}[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        console.print()

    return ai_reports


def run_s3_scan() -> S3ScanResult:
    """Scan all S3 buckets, print rich output, and return findings with AI reports."""
    findings = scan()
    ai_reports = print_findings(findings)
    return S3ScanResult(findings=findings, ai_reports=ai_reports)
