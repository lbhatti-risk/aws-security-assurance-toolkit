"""
AWS Security Assurance Toolkit — CLI entry point.

Commands
--------
s3    Scan S3 buckets for Block Public Access and encryption misconfigurations.
iam   Scan IAM users for MFA gaps, admin over-privilege, and stale keys.
all   Run both scanners sequentially (full audit).

Usage
-----
    uv run aws-audit s3
    uv run aws-audit s3 --export-json

    uv run aws-audit iam --stale-key-days 60
    uv run aws-audit iam --export-csv
    uv run aws-audit iam --export-json

    uv run aws-audit all --stale-key-days 60 --export-csv --export-json
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.rule import Rule

from assurance.export import export_findings_to_json
from assurance.scanners.iam import export_findings_to_csv, run_iam_scan
from assurance.scanners.s3 import run_s3_scan

app = typer.Typer(
    name="assurance",
    help=(
        "AWS Security Assurance Toolkit.\n\n"
        "Scans a live AWS environment (or LocalStack) for security misconfigurations "
        "and maps every finding to NIST CSF 2.0, NIST 800-53, and ISO/IEC 27001:2022. "
        "High and Critical findings are automatically analysed by a Claude-powered "
        "audit engine that produces formal risk statements in Big 4 style."
    ),
    no_args_is_help=True,
)

console = Console()


@app.command()
def s3(
    export_json: bool = typer.Option(
        False,
        "--export-json",
        help="Save findings to a timestamped JSON file using the standard audit schema.",
        is_flag=True,
    ),
) -> None:
    """Scan all S3 buckets for Block Public Access and encryption misconfigurations.

    Runs two checks per bucket:

    \b
    1. Block Public Access — flags missing or partially disabled settings (NIST PR.DS-01 / ISO A.8.3).
    2. Encryption          — flags buckets with no server-side encryption configured (NIST SC-28 / ISO A.8.24).

    High severity findings are automatically passed to the AI analyst,
    which produces a formal audit finding in executive report style.
    """
    result = run_s3_scan()

    if export_json:
        path = export_findings_to_json(
            result.findings,
            resource_id_attr="bucket",
            scanner_name="S3 Security Scanner",
        )
        console.print(f"[dim]JSON saved → {path}[/dim]\n")


@app.command()
def iam(
    stale_key_days: int = typer.Option(
        90,
        "--stale-key-days",
        help="Flag active IAM access keys older than this many days.",
        show_default=True,
    ),
    export_csv: bool = typer.Option(
        False,
        "--export-csv",
        help="Save all IAM findings to a timestamped CSV file.",
        is_flag=True,
    ),
    export_json: bool = typer.Option(
        False,
        "--export-json",
        help="Save findings to a timestamped JSON file using the standard audit schema.",
        is_flag=True,
    ),
) -> None:
    """Scan all IAM users for MFA gaps, admin over-privilege, and stale keys.

    Runs three checks against every IAM user in the account:

    \b
    1. MFA — flags users with no MFA device enrolled (High, NIST IA-2(1)).
    2. Admin — flags users with AdministratorAccess attached directly (Critical, NIST AC-2(1)).
    3. Stale keys — flags active access keys past the rotation window:
         90–179 days → High | 180+ days → Critical (NIST IA-5(1)).

    Critical and High findings are automatically passed to the AI analyst.
    Both --export-csv and --export-json can be used together.
    """
    result = run_iam_scan(stale_key_days=stale_key_days)

    if export_csv:
        path = export_findings_to_csv(result.findings)
        console.print(f"[dim]CSV saved → {path}[/dim]\n")

    if export_json:
        path = export_findings_to_json(
            result.findings,
            resource_id_attr="entity",
            scanner_name="IAM Security Scanner",
        )
        console.print(f"[dim]JSON saved → {path}[/dim]\n")


@app.command(name="all")
def scan_all(
    stale_key_days: int = typer.Option(
        90,
        "--stale-key-days",
        help="Flag active IAM access keys older than this many days.",
        show_default=True,
    ),
    export_csv: bool = typer.Option(
        False,
        "--export-csv",
        help="Save IAM findings to a timestamped CSV file after the scan.",
        is_flag=True,
    ),
    export_json: bool = typer.Option(
        False,
        "--export-json",
        help=(
            "Save findings to timestamped JSON files using the standard audit schema. "
            "Produces one file per scanner (s3_security_scanner_*.json and iam_security_scanner_*.json)."
        ),
        is_flag=True,
    ),
) -> None:
    """Run a full security audit across S3 and IAM sequentially.

    Equivalent to running the 's3' and 'iam' commands back-to-back.
    All High and Critical findings from both scanners are passed to the
    AI analyst, which generates formal audit statements for each one.

    With --export-json, two JSON files are produced: one per scanner.
    With --export-csv, one CSV file is produced for the IAM findings.
    Both flags can be combined.
    """
    console.print(Rule("[bold cyan]S3 Security Audit[/bold cyan]"))
    s3_result = run_s3_scan()

    if export_json:
        path = export_findings_to_json(
            s3_result.findings,
            resource_id_attr="bucket",
            scanner_name="S3 Security Scanner",
        )
        console.print(f"[dim]JSON saved → {path}[/dim]\n")

    console.print(Rule("[bold cyan]IAM Security Audit[/bold cyan]"))
    iam_result = run_iam_scan(stale_key_days=stale_key_days)

    if export_csv:
        path = export_findings_to_csv(iam_result.findings)
        console.print(f"[dim]CSV saved → {path}[/dim]\n")

    if export_json:
        path = export_findings_to_json(
            iam_result.findings,
            resource_id_attr="entity",
            scanner_name="IAM Security Scanner",
        )
        console.print(f"[dim]JSON saved → {path}[/dim]\n")
