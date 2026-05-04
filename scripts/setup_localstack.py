"""
Populate LocalStack with synthetic test data for scanner development.

S3 fixtures:
  - pwc-secure-bucket: Block Public Access fully enabled (compliant)
  - pwc-leaky-bucket:  Block Public Access disabled (High finding)

IAM fixtures:
  - alice-no-mfa:   user with no MFA device (High finding)
  - bob-admin:      user with AdministratorAccess attached directly (Critical finding)
  - carol-compliant: user with MFA enrolled and no over-privileged policies (compliant)

Run once before executing any scanner:
    uv run python scripts/setup_localstack.py
"""

import sys
from botocore.exceptions import ClientError, EndpointResolutionError

# Use the project factory so all LocalStack config lives in one place.
sys.path.insert(0, "src")
from assurance.aws_client import get_client

s3  = get_client("s3")
iam = get_client("iam")


def create_bucket(name: str) -> None:
    """Create an S3 bucket, swallowing the error if it already exists."""
    try:
        # us-east-1 is the only region that must NOT include CreateBucketConfiguration.
        s3.create_bucket(Bucket=name)
        print(f"  [+] Created bucket: {name}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"  [~] Bucket already exists, skipping: {name}")
        else:
            raise


def enable_block_public_access(name: str) -> None:
    """Apply a fully-restrictive Block Public Access policy to a bucket."""
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print(f"  [+] Block Public Access enabled on: {name}")


def disable_block_public_access(name: str) -> None:
    """Explicitly disable all Block Public Access flags to simulate a misconfiguration.

    LocalStack 3.x enables all four flags by default, so we must actively turn
    them off rather than merely omitting the put_public_access_block call.
    """
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    print(f"  [+] Block Public Access disabled on: {name}")


# ---------------------------------------------------------------------------
# IAM helpers
# ---------------------------------------------------------------------------

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def create_iam_user(name: str) -> None:
    try:
        iam.create_user(UserName=name)
        print(f"  [+] Created IAM user: {name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"  [~] IAM user already exists, skipping: {name}")
        else:
            raise


def attach_admin_policy(username: str) -> None:
    iam.attach_user_policy(UserName=username, PolicyArn=ADMIN_POLICY_ARN)
    print(f"  [+] Attached AdministratorAccess to: {username}")


def enroll_virtual_mfa(username: str) -> None:
    """Create and 'activate' a virtual MFA device for a user.

    LocalStack does not validate real TOTP codes, so we can activate the
    device with dummy authentication codes.
    """
    try:
        serial = iam.create_virtual_mfa_device(
            VirtualMFADeviceName=f"{username}-mfa"
        )["VirtualMFADevice"]["SerialNumber"]
        iam.enable_mfa_device(
            UserName=username,
            SerialNumber=serial,
            AuthenticationCode1="123456",
            AuthenticationCode2="234567",
        )
        print(f"  [+] MFA enrolled for: {username} ({serial})")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"  [~] MFA device already exists, skipping: {username}")
        else:
            raise


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        print("\nSetting up LocalStack S3 test fixtures...\n")

        # --- Compliant bucket ---
        create_bucket("pwc-secure-bucket")
        enable_block_public_access("pwc-secure-bucket")

        # --- Non-compliant bucket ---
        # LocalStack 3.x defaults all four flags to True, so we must explicitly
        # disable them to produce a realistic High-severity finding.
        create_bucket("pwc-leaky-bucket")
        disable_block_public_access("pwc-leaky-bucket")

        print("\nSetting up LocalStack IAM test fixtures...\n")

        # --- High: user with no MFA ---
        create_iam_user("alice-no-mfa")

        # --- Critical: user with direct AdministratorAccess ---
        create_iam_user("bob-admin")
        attach_admin_policy("bob-admin")

        # --- Compliant: user with MFA enrolled, no admin policy ---
        create_iam_user("carol-compliant")
        enroll_virtual_mfa("carol-compliant")

        # --- Stale key: user with an active access key (age tested via threshold=0) ---
        # LocalStack cannot backdate CreateDate, so the key will be 0 days old.
        # Run the scanner with stale_key_days=0 to verify detection works.
        create_iam_user("dave-stale-key")
        iam.create_access_key(UserName="dave-stale-key")
        print(f"  [+] Created access key for: dave-stale-key")

        print("\nLocalStack setup complete.\n")

    except EndpointResolutionError:
        print("\n[ERROR] Cannot reach LocalStack at http://localhost:4566.")
        print("Start it with: docker run --rm -p 4566:4566 localstack/localstack\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
