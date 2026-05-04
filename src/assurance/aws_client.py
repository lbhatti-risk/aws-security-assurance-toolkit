"""
AWS client factory for the Security Assurance Toolkit.

All clients point to LocalStack so we never accidentally hit real AWS endpoints
during development and testing. Dummy credentials satisfy boto3's requirement
for credentials without granting access to any real resources.
"""

import boto3
from botocore.config import Config

LOCALSTACK_ENDPOINT = "http://localhost:4566"

# Dummy credentials are intentional — LocalStack ignores them, and using
# these named constants prevents accidental real-credential injection.
_AWS_ACCESS_KEY = "test"
_AWS_SECRET_KEY = "test"
_AWS_REGION = "us-east-1"

_BOTO3_CONFIG = Config(
    # Retry aggressively so transient LocalStack startup delays don't break scans.
    retries={"max_attempts": 3, "mode": "standard"},
)


def get_region() -> str:
    """Return the AWS region configured for all toolkit clients."""
    return _AWS_REGION


def get_client(service: str) -> boto3.client:
    """Return a boto3 client wired to LocalStack for the given AWS service.

    Args:
        service: AWS service name (e.g. "s3", "iam", "ec2").

    Returns:
        A configured boto3 client ready to use against LocalStack.
    """
    return boto3.client(
        service,
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id=_AWS_ACCESS_KEY,
        aws_secret_access_key=_AWS_SECRET_KEY,
        region_name=_AWS_REGION,
        config=_BOTO3_CONFIG,
    )


def get_resource(service: str) -> boto3.resource:
    """Return a boto3 resource wired to LocalStack for the given AWS service.

    Use this when the higher-level resource API is more convenient than the
    low-level client (e.g. iterating S3 bucket objects).

    Args:
        service: AWS service name (e.g. "s3", "iam").

    Returns:
        A configured boto3 resource ready to use against LocalStack.
    """
    return boto3.resource(
        service,
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id=_AWS_ACCESS_KEY,
        aws_secret_access_key=_AWS_SECRET_KEY,
        region_name=_AWS_REGION,
        config=_BOTO3_CONFIG,
    )
