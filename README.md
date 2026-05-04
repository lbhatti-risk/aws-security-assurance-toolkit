# AWS Security Assurance Toolkit (ASAT)
**Automated Control Testing & Evidence Gathering for Digital Audit**

## Overview
The **AWS Security Assurance Toolkit (ASAT)** is a Python-based framework designed to automate the 'Testing of Operating Effectiveness' (ToE) for AWS cloud environments. Developed specifically for Digital Audit professionals, this toolkit bridges the gap between raw technical telemetry and formal audit documentation.

Unlike standard security scanners, ASAT focuses on the **Accountability** and **Evidence** requirements of international standards such as **ISO 27001**, **NIST SP 800-53**, and **UK Cyber Essentials**.

---

## Key Features

*   **Automated Control Testing:** Programmatic evaluation of IAM policies and S3 bucket configurations against best-practice benchmarks.
*   **Audit Evidence Locker:** Automated extraction of raw JSON 'Evidence Strings' for every control failure, mapped to unique Workpaper (WP) IDs.
*   **BI-Ready Reporting:** Seamless data export for executive-level visualisations in **Google Looker Studio** or **Microsoft Power BI**.
*   **ICFR & Substantive Testing Support:** Documentation structured to support Internal Controls over Financial Reporting (ICFR) and substantive audit procedures.

---

## Repository Structure

| Directory/File | Purpose |
| :--- | :--- |
| `scripts/` | Core Python audit procedures and evidence generation logic. |
| `evidence/` | The **Audit File** containing timestamped JSON evidence strings (WP-XXX). |
| `control_effectiveness_report.md` | The **Lead Schedule** providing the final audit opinion. |
| `FINAL_SUMMARY.md` | Comprehensive audit narrative and compliance mapping. |
| `README_BI.md` | Technical documentation for connecting data to BI platforms. |

---

## Privacy & Security

**This tool is designed with a "Security-First" audit mindset.** 

*   **AI Data Policy:** This tool may utilise LLM APIs (e.g., Anthropic or Gemini) for automated analysis of evidence files. Before use in a professional engagement context, confirm your firm's AI data policy. Most large firms have an approved AI gateway or internal instance. Check whether you should substitute API keys for your firm's internal credentials.
*   **PII Redaction:** Always redact PII and client-sensitive data (employee names, IP addresses, account numbers) from evidence files before processing, unless your firm's policy explicitly permits transmission of that data to the selected API endpoint.
*   **Version Control:** Never commit real client data to version control. The `.gitignore` in this repository is configured to exclude all generated workpaper files, local JSON scan results, and the `.env` file containing API credentials.
*   **Data Integrity:** All sample data in this repository is **fully synthetic**. No real client names, systems, or engagement details are present anywhere in this codebase.

---

## A Note on Confidentiality

All materials in this repository have been fully anonymised, restructured, and utilise synthetic data. No content originates from a live client engagement or proprietary internal system. These documents represent my personal methodologies and professional viewpoint on industry best practices.

**Return to main profile:** [github.com/lbhatti-risk](https://github.com/lbhatti-risk)  
**Connect on LinkedIn:** [linkedin.com/in/layla-b-3470a31b8](https://linkedin.com/in/layla-b-3470a31b8)

---

## Getting Started

### 1. Prerequisites
*   **LocalStack:** To simulate the AWS environment (LocalStack must be running).
*   **Python 3.10+**: Core execution environment.
*   **AWS CLI**: Configured for local testing.

### 2. Execution Flow
```bash
# Run the security scans
python3 scripts/aws_audit_scanner.py

# Generate the audit evidence locker and workpapers
python3 scripts/generate_audit_evidence.py
