"""
Dispatch the most recent audit JSON export to a webhook endpoint.

Behaviour
---------
1. Finds the most recent JSON file in the current directory whose name starts
   with one of the recognised scanner prefixes.
2. Counts findings with "status": "FAIL".
3. POSTs the full JSON payload to the configured webhook URL.
4. Attaches a custom X-Audit-Severity-Count header with the FAIL count.
5. Prints the HTTP response code and a confirmation message.

Usage
-----
    uv run python scripts/dispatch_audit.py
"""

import json
import ssl
import sys
import urllib.request
from pathlib import Path

import certifi

WEBHOOK_URL = "https://webhook.site/48133798-179c-452a-af28-553d4ddc7379"

_PREFIXES = (
    "full_security_audit",
    "s3_security_scanner",
    "iam_security_scanner",
)


def find_latest_audit_file() -> Path:
    """Return the most recently modified audit JSON file in the current directory."""
    candidates = [
        p for p in Path(".").glob("*.json")
        if p.name.startswith(_PREFIXES)
    ]
    if not candidates:
        prefixes_fmt = ", ".join(f"'{p}_*.json'" for p in _PREFIXES)
        print(f"[ERROR] No audit JSON files found matching: {prefixes_fmt}")
        sys.exit(1)

    # Sort by modification time so the newest file wins regardless of clock skew.
    return max(candidates, key=lambda p: p.stat().st_mtime)


def count_fails(findings: list[dict]) -> int:
    return sum(1 for f in findings if f.get("status") == "FAIL")


def dispatch(path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    fail_count = count_fails(payload.get("findings", []))

    body = json.dumps(payload, indent=2).encode("utf-8")

    request = urllib.request.Request(
        url=WEBHOOK_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type":           "application/json",
            "X-Audit-Severity-Count": str(fail_count),
        },
    )

    print(f"  File      : {path}")
    print(f"  FAIL count: {fail_count}")
    print(f"  Endpoint  : {WEBHOOK_URL}")
    print()

    ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(request, timeout=15, context=ssl_ctx) as response:
        status = response.status

    print(f"[OK] Dispatched — HTTP {status}")


if __name__ == "__main__":
    latest = find_latest_audit_file()
    dispatch(latest)
