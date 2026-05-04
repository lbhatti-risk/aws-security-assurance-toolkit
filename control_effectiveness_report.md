# Control Effectiveness Report

**Toolkit:** AWS Security Assurance Toolkit  
**Prepared:** 2026-05-04  
**Prepared by:** Digital Audit Associate  
**Scope:** S3 Data Protection · IAM Identity and Access Management  
**Frameworks:** NIST CSF 2.0 · NIST SP 800-53 · ISO/IEC 27001:2022  

---

## 1. Executive Summary

| Metric | Value |
|---|---|
| Source files | 2 |
| Total checks | 9 |
| FAIL (non-compliant) | **6** |
| PASS (compliant) | 3 |
| Critical findings | 1 |
| High findings | 5 |
| Total Risk Weight (FAIL only) | **45** |

Source files reviewed:

- `iam_security_scanner_20260504_194819.json`
- `s3_security_scanner_20260504_194648.json`

---

## 2. Findings by Control Domain

### 2.1 IAM Security Scanner

| WP Reference | Resource | Control | ISO Mapping | Severity | Status |
|---|---|---|---|---|---|
| WP-IAM-002 | `alice-no-mfa` | `NIST-IA-2(1)` | ISO-27001-A.5.17 | High | **FAIL** |
| WP-IAM-003 | `bob-admin` | `NIST-IA-2(1)` | ISO-27001-A.5.17 | High | **FAIL** |
| WP-IAM-004 | `dave-stale-key` | `NIST-IA-2(1)` | ISO-27001-A.5.17 | High | **FAIL** |
| WP-IAM-001 | `bob-admin` | `NIST-AC-2(1)` | ISO-27001-A.8.2 | Critical | **FAIL** |
| WP-IAM-005 | `dave-stale-key` | `NIST-IA-5(1)` | ISO-27001-A.5.17 | High | **FAIL** |

### 2.2 S3 Security Scanner

| WP Reference | Resource | Control | ISO Mapping | Severity | Status |
|---|---|---|---|---|---|
| — | `pwc-secure-bucket` | `NIST-PR.DS-01` | ISO-27001-A.8.3 | Low | PASS |
| — | `pwc-secure-bucket` | `NIST-SC-28` | ISO-27001-A.8.24 | Low | PASS |
| WP-S3-001 | `pwc-leaky-bucket` | `NIST-PR.DS-01` | ISO-27001-A.8.3 | High | **FAIL** |
| — | `pwc-leaky-bucket` | `NIST-SC-28` | ISO-27001-A.8.24 | Low | PASS |

---

## 3. Evidence Index

Each row below corresponds to a FAIL finding. The Evidence File column links to the structured evidence record saved in `evidence/`.

| WP Reference | Resource | Control | Severity | Risk Weight | Evidence File |
|---|---|---|---|---|---|
| WP-IAM-001 | `bob-admin` | `NIST-AC-2(1)` | Critical | 10 | `evidence/WP-IAM-001.json` |
| WP-IAM-002 | `alice-no-mfa` | `NIST-IA-2(1)` | High | 7 | `evidence/WP-IAM-002.json` |
| WP-IAM-003 | `bob-admin` | `NIST-IA-2(1)` | High | 7 | `evidence/WP-IAM-003.json` |
| WP-IAM-004 | `dave-stale-key` | `NIST-IA-2(1)` | High | 7 | `evidence/WP-IAM-004.json` |
| WP-IAM-005 | `dave-stale-key` | `NIST-IA-5(1)` | High | 7 | `evidence/WP-IAM-005.json` |
| WP-S3-001 | `pwc-leaky-bucket` | `NIST-PR.DS-01` | High | 7 | `evidence/WP-S3-001.json` |

---

## 4. Audit Methodology

All findings were produced by automated inspection of AWS service configuration APIs via boto3. No manual sampling was performed — the scanner evaluates the complete population of in-scope resources.

| Control | API Inspected | Population |
|---|---|---|
| NIST-PR.DS-01 | `GetPublicAccessBlock` | All S3 buckets |
| NIST-SC-28 | `GetBucketEncryption` | All S3 buckets |
| NIST-IA-2(1) | `ListMFADevices` | All IAM users |
| NIST-AC-2(1) | `ListAttachedUserPolicies` | All IAM users |
| NIST-IA-5(1) | `ListAccessKeys` | All IAM users (active keys only) |

Paginated API calls ensure 100% coverage regardless of account size. All timestamps are UTC. Access key IDs are masked (`AKIA****MPLE`) in all output to prevent partial-secret leakage.

---

## 5. Audit Trail

| Artefact | Location | Purpose |
|---|---|---|
| Scan JSON exports | `*_scanner_*.json` | Machine-readable finding records |
| Evidence files | `evidence/WP-*.json` | Per-finding evidence packages |
| This report | `control_effectiveness_report.md` | Control effectiveness summary |
| BI dataset | `enterprise_security_data.csv` | Trend and dashboard data |
| SIEM dispatch log | `dispatch_audit.py` stdout | Real-time delivery confirmation |
