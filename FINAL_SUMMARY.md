# AWS Security Assurance Toolkit — Final Summary

**Author:** Digital Audit Associate, PwC  
**Environment:** LocalStack 3.8 (development) · AWS (production target)  
**Frameworks:** NIST CSF 2.0 · NIST SP 800-53 · ISO/IEC 27001:2022

---

## 1. Purpose

The AWS Security Assurance Toolkit is a Python CLI that audits a live AWS environment for security misconfigurations, maps every finding to industry-standard control frameworks, and generates formal audit risk statements using a Claude-powered AI analyst. Findings are exported as structured JSON and dispatched automatically to a SIEM or webhook endpoint for real-time reporting.

---

## 2. Project Architecture

```
aws-security-assurance-toolkit/
│
├── src/
│   ├── assurance/                        # Core library
│   │   ├── aws_client.py                 # Boto3 client factory (single source of config)
│   │   ├── analyst.py                    # AI analyst engine (Claude Opus 4.7)
│   │   ├── export.py                     # Shared JSON export (standard audit schema)
│   │   └── scanners/
│   │       ├── s3.py                     # S3 public access + encryption checks
│   │       └── iam.py                    # IAM MFA, privilege, and stale key checks
│   │
│   └── aws_security_assurance_toolkit/
│       └── main.py                       # Typer CLI entry point
│
├── scripts/
│   ├── setup_localstack.py               # Seeds LocalStack with test fixtures
│   └── dispatch_audit.py                 # Uploads latest JSON export to SIEM endpoint
│
├── pyproject.toml                        # Dependencies and CLI entry points
└── .env                                  # ANTHROPIC_API_KEY (never committed)
```

### Data Flow

```
LocalStack / AWS
      │
      ▼
aws_client.py  ──────────────────────────────────────────────┐
      │                                                       │
      ▼                                                       ▼
s3.py::scan()                                       iam.py::scan()
  _check_public_access_block()                        _scan_mfa()
  _check_encryption()                                 _scan_admin_policies()
      │                                               _scan_stale_keys()
      ▼                                                       │
  list[s3.Finding]                                  list[iam.Finding]
      │                                                       │
      └──────────────────┬────────────────────────────────────┘
                         ▼
               print_findings()  ──► analyst.py  ──► Claude Opus 4.7
               (rich table + AI panels)                (formal audit statements)
                         │
                         ▼
               export.py::export_findings_to_json()
                         │
                         ▼
               iam_security_scanner_YYYYMMDD_HHMMSS.json
               s3_security_scanner_YYYYMMDD_HHMMSS.json
                         │
                         ▼
               dispatch_audit.py
                         │
                         ▼
               SIEM / Webhook endpoint  (HTTP POST)
```

---

## 3. How the Audit Tool Identifies Risks

Each scanner evaluates a specific AWS service against a defined set of control objectives. All findings are represented as typed `Finding` dataclass instances containing the affected resource, severity, condition, NIST control, ISO control, and remediation guidance.

### S3 Scanner (`src/assurance/scanners/s3.py`)

Two checks are executed per bucket:

| Check | API Call | Condition Flagged | Severity |
|---|---|---|---|
| Block Public Access | `get_public_access_block` | Any of the four flags is `False`, or configuration is absent | High |
| Server-Side Encryption | `get_bucket_encryption` | No encryption configuration found | High |

Compliant findings are recorded as `Low` severity so the audit trail captures both pass and fail states for every control.

### IAM Scanner (`src/assurance/scanners/iam.py`)

Three checks are executed across all IAM users. All list operations use Boto3 paginators to handle accounts with more than 100 users without truncation.

| Check | API Calls | Condition Flagged | Severity |
|---|---|---|---|
| MFA Coverage | `list_users` · `list_mfa_devices` | No MFA device enrolled on a user account | High |
| Least Privilege | `list_users` · `list_attached_user_policies` | `AdministratorAccess` attached directly to a user | Critical |
| Stale Access Keys | `list_users` · `list_access_keys` | Active key age ≥ 90 days (High) or ≥ 180 days (Critical) | High / Critical |

Access key IDs are masked in all output (`AKIA****MPLE`) — partial secrets must not appear in audit reports.

---

## 4. Compliance Framework Mapping

Every finding carries two framework identifiers populated at detection time:

| Scanner | Check | NIST Control | ISO/IEC 27001:2022 |
|---|---|---|---|
| S3 | Block Public Access | CSF 2.0 PR.DS-01 | A.8.3 |
| S3 | Encryption | SP 800-53 SC-28 | A.8.24 |
| IAM | MFA | SP 800-53 IA-2(1) | A.5.17 |
| IAM | Admin privilege | SP 800-53 AC-2(1) | A.8.2 |
| IAM | Stale access keys | SP 800-53 IA-5(1) | A.5.17 |

These identifiers flow through the entire pipeline: they appear in the rich console table, inside every AI-generated audit statement, in the CSV export, and in the JSON schema sent to the SIEM.

---

## 5. AI Analyst Engine (`src/assurance/analyst.py`)

After the structured findings table is printed, every High and Critical finding is automatically passed to `generate_risk_statement()`, which calls **Claude Opus 4.7** with adaptive thinking enabled.

The model is instructed to write in the voice of a Big 4 Senior IT Audit Manager and returns a formal three-paragraph audit finding covering:

1. **Condition** — what was observed and which controls are violated
2. **Potential Risk / Impact** — threat scenarios referenced against real-world breaches (e.g. Capital One 2019, Uber 2022)
3. **Recommendation** — specific, actionable remediation steps with target timelines

The response is streamed to prevent HTTP timeouts on long outputs, and thinking blocks are filtered so only the final text is displayed in the Rich panel.

---

## 6. JSON Export Schema (`src/assurance/export.py`)

The shared `export_findings_to_json()` function produces a timestamped file conforming to the standard audit schema. It works with both S3 and IAM findings via a `resource_id_attr` parameter and reads the region dynamically from `aws_client.get_region()` — nothing is hardcoded in the export layer.

```json
{
  "scan_metadata": {
    "scanner":   "IAM Security Scanner",
    "timestamp": "2026-05-04T19:48:19Z",
    "region":    "us-east-1",
    "summary": {
      "resources_scanned": 4,
      "total_checks": 5,
      "fail": 5,
      "pass": 0
    }
  },
  "findings": [
    {
      "resource_id": "bob-admin",
      "control_id":  "NIST-AC-2(1)",
      "severity":    "CRITICAL",
      "timestamp":   "2026-05-04T19:48:19Z",
      "status":      "FAIL",
      "metadata": {
        "region":      "us-east-1",
        "reason":      "AdministratorAccess attached directly to user",
        "remediation": "Detach AdministratorAccess from the user ...",
        "mappings":    ["ISO-27001-A.8.2"]
      }
    }
  ]
}
```

**Status mapping:** `High` / `Critical` → `"FAIL"` · `Low` / `Medium` → `"PASS"`  
**Control ID format:** `NIST-{control}` (e.g. `NIST-SC-28`, `NIST-IA-2(1)`)  
**ISO mapping:** nested under `metadata.mappings` as `["ISO-27001-{control}"]`

---

## 7. SIEM Dispatcher (`scripts/dispatch_audit.py`)

`dispatch_audit.py` bridges the toolkit and the downstream SIEM or alerting platform. It requires no arguments — it discovers the correct file automatically.

**Execution steps:**

1. Scans the current directory for JSON files beginning with `full_security_audit`, `s3_security_scanner`, or `iam_security_scanner`
2. Selects the most recently modified file by `st_mtime` (immune to filename clock skew)
3. Parses the JSON and counts findings where `"status": "FAIL"`
4. POSTs the full payload to the configured webhook URL with:
   - `Content-Type: application/json`
   - `X-Audit-Severity-Count: {fail_count}` — allows the SIEM to triage without parsing the body
5. Logs the filename, FAIL count, and HTTP response code to stdout

SSL verification is performed using the `certifi` CA bundle (a transitive dependency of the Anthropic SDK) to ensure compatibility with macOS system Python installations.

---

## 8. Running the Full Pipeline

### Prerequisites

```bash
# 1. Start LocalStack
docker run --rm -d -p 4566:4566 --name localstack localstack/localstack:3.8

# 2. Seed test fixtures (run once)
uv run python scripts/setup_localstack.py

# 3. Add your Anthropic API key to .env
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env
```

### Single-Command Full Pipeline

```bash
uv run aws-audit all --export-json --stale-key-days 0 && uv run python scripts/dispatch_audit.py
```

This single command:

| Step | What happens |
|---|---|
| `aws-audit all` | Runs S3 + IAM scanners sequentially |
| `--export-json` | Writes `s3_security_scanner_*.json` and `iam_security_scanner_*.json` |
| `--stale-key-days 0` | Flags any active access key regardless of age (useful for demo/CI) |
| `&& dispatch_audit.py` | Picks the newest JSON file and POSTs it to the SIEM endpoint |

### Individual Commands

```bash
# S3 only
uv run aws-audit s3 --export-json

# IAM only — with CSV and JSON export
uv run aws-audit iam --stale-key-days 60 --export-csv --export-json

# Full audit, no export (console output only)
uv run aws-audit all --stale-key-days 0

# Dispatch the most recent export manually
uv run python scripts/dispatch_audit.py
```

---

## 9. Test Fixtures (LocalStack)

`scripts/setup_localstack.py` seeds the following synthetic resources:

| Resource | Type | Expected Finding |
|---|---|---|
| `pwc-secure-bucket` | S3 | Low — Block Public Access enabled, AES-256 encryption present |
| `pwc-leaky-bucket` | S3 | **High** — all four Block Public Access flags explicitly disabled |
| `alice-no-mfa` | IAM user | **High** — no MFA device enrolled |
| `bob-admin` | IAM user | **High** (no MFA) + **Critical** (AdministratorAccess direct attach) |
| `carol-compliant` | IAM user | Compliant — MFA enrolled, no admin policy |
| `dave-stale-key` | IAM user | **High** — active access key (detected at `--stale-key-days 0`) |

---

## 10. Substantive Testing and ICFR Support

### What Is Substantive Testing?

Substantive testing is the audit procedure used to obtain direct evidence about whether a financial statement assertion — or an IT general control supporting financial reporting — is free from material misstatement. Unlike controls testing (which evaluates whether a control *exists*), substantive testing validates that the control *operated effectively* over the period under review.

This toolkit supports substantive testing in three ways:

**1. Full-population coverage**  
Every scanner uses paginated API calls (`get_paginator`) to evaluate 100% of in-scope resources — every S3 bucket, every IAM user, every access key. There is no sampling. This eliminates the risk of a misconfigured resource being missed and produces a complete, defensible population audit trail.

**2. Timestamped, immutable evidence packages**  
Each FAIL finding generates a structured evidence file in `evidence/WP-*.json` containing the observed condition, detection method, raw finding, and ISO/NIST control reference. These files are written at scan time and not modified afterward, providing the point-in-time snapshot required for substantive procedures.

**3. Workpaper traceability**  
Every FAIL finding is assigned a stable Workpaper Reference ID (`WP-IAM-001`, `WP-S3-001`, etc.) that links:
- The machine-readable JSON finding in the scan export
- The evidence file in `evidence/`
- The row in `enterprise_security_data.csv` (BI dashboard)
- The row in the `control_effectiveness_report.md`

This chain of references satisfies the auditing standard requirement that evidence be traceable from observation to conclusion.

---

### Internal Controls over Financial Reporting (ICFR)

Under SOX Section 404 and PCAOB AS 2201, management and external auditors must assess the design and operating effectiveness of internal controls over financial reporting. Cloud infrastructure controls — particularly IAM access controls and data-at-rest protections — are classified as **IT General Controls (ITGCs)** and fall within ICFR scope when the underlying systems process, store, or transmit data that feeds financial statements.

The following table maps this toolkit's checks to their ICFR relevance:

| Check | NIST Control | ICFR Relevance |
|---|---|---|
| IAM MFA Coverage | IA-2(1) | Logical access control — prevents unauthorised access to systems processing financial data |
| AdministratorAccess direct attach | AC-2(1) | Privileged access management — segregation of duties, prevents one individual from controlling entire financial system |
| Stale Access Keys | IA-5(1) | Credential lifecycle — unrotated keys represent persistent, unmonitored access vectors |
| S3 Block Public Access | PR.DS-01 | Data confidentiality — prevents unintended disclosure of financial records stored in S3 |
| S3 Encryption at Rest | SC-28 | Data protection — ensures financial data is encrypted if storage media is accessed outside authorised channels |

#### How the Toolkit Supports ICFR Audit Procedures

| ICFR Activity | Toolkit Artefact |
|---|---|
| Control design evaluation | `control_effectiveness_report.md` — documents the control objective, test procedure, and population |
| Operating effectiveness testing | Scan JSON exports — timestamped evidence of control state at a point in time |
| Exception identification | FAIL findings with severity, reason, and remediation |
| Workpaper documentation | `evidence/WP-*.json` — per-exception evidence packages with detection method |
| Management reporting | `enterprise_security_data.csv` — aggregated dataset for trend analysis and dashboard |
| Real-time monitoring | `dispatch_audit.py` — continuous control monitoring via SIEM integration |

#### Generating the Full Evidence Package

```bash
# Step 1 — Run the audit and export JSON
uv run aws-audit all --export-json --stale-key-days 0

# Step 2 — Generate evidence files and the Control Effectiveness Report
uv run python scripts/generate_audit_evidence.py

# Step 3 — Rebuild the BI dataset
uv run python scripts/unified_bi_prep.py

# Step 4 — Dispatch to SIEM
uv run python scripts/dispatch_audit.py
```

The `evidence/` directory and `control_effectiveness_report.md` produced in Step 2 constitute the workpaper package for the ICFR assessment. Each `WP-*.json` file is a self-contained evidence record that can be attached to an audit management system (e.g. TeamMate, Workiva) against the corresponding control test step.
