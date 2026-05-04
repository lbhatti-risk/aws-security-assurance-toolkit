"""
IAM Security Scanner — MFA coverage, least-privilege, and stale key audit.

Control objectives:
  1. Every IAM user must have MFA enabled (credential theft mitigation).
  2. No user should carry AdministratorAccess attached directly to their account
     (least-privilege / separation of duties).
  3. No active access key should exceed the rotation age limit.

NIST 800-53 mappings used here rather than CSF 2.0 because MFA, privilege, and
credential controls map more precisely to 800-53 identifiers in audit engagements.
  MFA check    : IA-2(1) — Multi-factor authentication for privileged accounts
  Admin check  : AC-2(1) — Automated system account management
  Stale key    : IA-5(1) — Authenticator management / password-based authentication
ISO/IEC 27001:2022:
  MFA check    : A.5.17 — Authentication information
  Admin check  : A.8.2  — Privileged access rights
  Stale key    : A.5.17 — Authentication information
"""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from botocore.exceptions import ClientError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from assurance.aws_client import get_client
from assurance.analyst import generate_risk_statement

Severity = Literal["Critical", "High", "Low"]

_SEVERITY_STYLE = {
    "Critical": "bold magenta",
    "High":     "bold red",
    "Low":      "bold green",
}


@dataclass
class Finding:
    entity: str          # IAM user name
    severity: Severity
    finding: str
    nist_control: str
    iso_control: str
    remediation: str


@dataclass
class IAMScanResult:
    findings: list[Finding]
    ai_reports: dict[str, str]  # "entity|finding" → AI report text


# ---------------------------------------------------------------------------
# Scanner logic
# ---------------------------------------------------------------------------

def _scan_mfa(iam_client) -> list[Finding]:
    """Flag every IAM user that has no MFA device registered."""
    findings = []
    user_paginator = iam_client.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                # MFADevices is an empty list when no device is enrolled.
                device_paginator = iam_client.get_paginator("list_mfa_devices")
                devices = [
                    device
                    for device_page in device_paginator.paginate(UserName=name)
                    for device in device_page["MFADevices"]
                ]
            except ClientError:
                devices = []

            if not devices:
                findings.append(Finding(
                    entity=name,
                    severity="High",
                    finding="No MFA device enrolled",
                    nist_control="IA-2(1)",
                    iso_control="A.5.17",
                    remediation=(
                        "Require the user to register a virtual or hardware MFA device "
                        "via IAM console > Security credentials. Enforce MFA at the "
                        "account level using an IAM policy condition: "
                        "aws:MultiFactorAuthPresent = true."
                    ),
                ))
    return findings


def _scan_admin_policies(iam_client) -> list[Finding]:
    """Flag every IAM user with AdministratorAccess attached directly."""
    findings = []
    user_paginator = iam_client.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                policy_paginator = iam_client.get_paginator("list_attached_user_policies")
                policies = [
                    policy
                    for policy_page in policy_paginator.paginate(UserName=name)
                    for policy in policy_page["AttachedPolicies"]
                ]
            except ClientError:
                policies = []

            for policy in policies:
                if policy["PolicyName"] == "AdministratorAccess":
                    findings.append(Finding(
                        entity=name,
                        severity="Critical",
                        finding="AdministratorAccess attached directly to user",
                        nist_control="AC-2(1)",
                        iso_control="A.8.2",
                        remediation=(
                            "Detach AdministratorAccess from the user. Grant elevated "
                            "permissions via IAM roles with time-limited assumption "
                            "(aws:TokenIssueTime condition) and require MFA. "
                            "Apply least-privilege inline or managed policies scoped "
                            "to the specific services the user requires."
                        ),
                    ))
    return findings


def _mask_key_id(key_id: str) -> str:
    """Redact the middle of an access key ID for safe display in reports.

    Full key IDs must not appear in audit outputs — they are partial secrets.
    Example: AKIAIOSFODNN7EXAMPLE → AKIA****MPLE
    """
    return f"{key_id[:4]}****{key_id[-4:]}"


def _scan_stale_keys(iam_client, age_limit_days: int = 90) -> list[Finding]:
    """Flag active access keys that exceed the rotation age limit.

    Severity tiers:
      90–179 days → High   (overdue for rotation)
      180+ days   → Critical (long-lived key, high exfiltration risk)
    """
    findings = []
    user_paginator = iam_client.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                key_paginator = iam_client.get_paginator("list_access_keys")
                keys = [
                    key
                    for key_page in key_paginator.paginate(UserName=name)
                    for key in key_page["AccessKeyMetadata"]
                ]
            except ClientError:
                keys = []

            for key in keys:
                if key["Status"] != "Active":
                    continue

                # CreateDate is timezone-aware; datetime.now(timezone.utc) matches it.
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days

                if age_days < age_limit_days:
                    continue

                severity: Severity = "Critical" if age_days >= 180 else "High"
                masked = _mask_key_id(key["AccessKeyId"])

                findings.append(Finding(
                    entity=name,
                    severity=severity,
                    finding=f"Access key {masked} is {age_days} days old (limit: {age_limit_days})",
                    nist_control="IA-5(1)",
                    iso_control="A.5.17",
                    remediation=(
                        f"Rotate key {masked} immediately: create a replacement key, "
                        "update all applications referencing the old key, verify the "
                        "replacement works, then deactivate and delete the old key. "
                        "Enforce rotation via AWS Config rule 'access-keys-rotated'."
                    ),
                ))
    return findings


def scan(stale_key_days: int = 90) -> list[Finding]:
    """Run all IAM checks and return a combined findings list."""
    iam = get_client("iam")
    return _scan_mfa(iam) + _scan_admin_policies(iam) + _scan_stale_keys(iam, stale_key_days)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_findings(findings: list[Finding]) -> dict[str, str]:
    console = Console()

    table = Table(
        title="[bold]IAM Security Audit — Findings[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("IAM User",        style="cyan",       no_wrap=True)
    table.add_column("Severity",        justify="center",   no_wrap=True)
    table.add_column("Finding",         style="white",      ratio=3)
    table.add_column("NIST 800-53",     justify="center",   no_wrap=True)
    table.add_column("ISO 27001:2022",  justify="center",   no_wrap=True)
    table.add_column("Remediation",     style="dim white",  ratio=4)

    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        table.add_row(
            f.entity,
            f"[{style}]{f.severity}[/{style}]",
            f.finding,
            f.nist_control,
            f.iso_control,
            f.remediation,
        )

    console.print()
    console.print(table)

    crit_count = sum(1 for f in findings if f.severity == "Critical")
    high_count = sum(1 for f in findings if f.severity == "High")
    console.print(
        f"\n[bold]Summary:[/bold] {len(findings)} finding(s) — "
        f"[bold magenta]{crit_count} Critical[/bold magenta], "
        f"[bold red]{high_count} High[/bold red]\n"
    )

    # AI analyst runs after the full table is printed so the user sees
    # structured findings immediately even if the API call takes a moment.
    elevated = [f for f in findings if f.severity in ("Critical", "High")]
    if not elevated:
        return {}

    ai_reports: dict[str, str] = {}
    console.print("[bold]AI-Generated Audit Findings[/bold]\n")
    for f in elevated:
        finding_details = (
            f"Affected IAM user: '{f.entity}'. "
            f"Condition: {f.finding}. "
            f"Severity: {f.severity}. "
            f"NIST 800-53 control: {f.nist_control}. "
            f"ISO/IEC 27001:2022 control: {f.iso_control}. "
            f"Recommended remediation: {f.remediation}"
        )
        style = _SEVERITY_STYLE.get(f.severity, "white")
        console.print(
            f"  Calling AI analyst for [{style}]{f.entity}[/{style}] "
            f"({f.severity})…",
            highlight=False,
        )
        try:
            report = generate_risk_statement(finding_details)
            ai_reports[f"{f.entity}|{f.finding}"] = report
        except Exception as exc:
            console.print(f"  [bold red]AI analyst error:[/bold red] {exc}\n")
            continue

        console.print(
            Panel(
                report,
                title=f"[{style}]Audit Finding — {f.entity} / {f.finding}[/{style}]",
                border_style=f.severity.lower() if f.severity == "high" else "magenta",
                padding=(1, 2),
            )
        )
        console.print()

    return ai_reports


def export_findings_to_csv(findings: list[Finding]) -> Path:
    """Write findings to a timestamped CSV in the current working directory.

    Column headers mirror the Finding dataclass fields using the same labels
    as the rich table so the CSV and console output stay in sync.

    Returns the Path of the file written so the caller can log or display it.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"iam_findings_{timestamp}.csv")

    _HEADERS = ["IAM User", "Severity", "Finding", "NIST 800-53", "ISO 27001:2022", "Remediation"]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_HEADERS)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "IAM User":       f.entity,
                "Severity":       f.severity,
                "Finding":        f.finding,
                "NIST 800-53":    f.nist_control,
                "ISO 27001:2022": f.iso_control,
                "Remediation":    f.remediation,
            })

    return path


def print_summary(findings: list[Finding]) -> None:
    """Render a severity breakdown table for a quick risk-profile view."""
    console = Console()
    counts = Counter(f.severity for f in findings)

    table = Table(
        title="[bold]Risk Profile Summary[/bold]",
        box=box.ROUNDED,
        show_lines=False,
        highlight=False,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)

    for severity in ("Critical", "High", "Low"):
        style = _SEVERITY_STYLE.get(severity, "white")
        count = counts.get(severity, 0)
        table.add_row(
            f"[{style}]{severity}[/{style}]",
            f"[{style}]{count}[/{style}]",
        )

    table.add_row("[bold]Total[/bold]", f"[bold]{len(findings)}[/bold]")

    console.print()
    console.print(table)
    console.print()


def run_iam_scan(stale_key_days: int = 90) -> IAMScanResult:
    """Scan all IAM users, print rich output with summary, and return findings with AI reports."""
    findings = scan(stale_key_days=stale_key_days)
    ai_reports = print_findings(findings)
    print_summary(findings)
    return IAMScanResult(findings=findings, ai_reports=ai_reports)
