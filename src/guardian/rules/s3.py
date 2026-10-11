"""S3 exposure: buckets and accounts opened to the public."""

from __future__ import annotations

from ..models import CRITICAL, HIGH, Clients, Detection, Rule
from ..util import (
    PUBLIC_CANNED_ACLS,
    PUBLIC_GRANTEES,
    allows_everyone,
    as_list,
    load_policy,
    params,
    statements,
    walk_strings,
)

S3 = "s3.amazonaws.com"
BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _bucket(event: dict) -> str:
    return params(event).get("bucketName", "unknown-bucket")


def _relaxed_settings(event: dict) -> list[str]:
    config = params(event).get("PublicAccessBlockConfiguration") or {}
    return [key for key in BLOCK_ALL if config.get(key) is not True]


def bucket_block_removed(event: dict):
    if event["eventName"].startswith("Delete"):
        return Detection(_bucket(event), "Bucket public access block was deleted")
    relaxed = _relaxed_settings(event)
    if relaxed:
        return Detection(
            _bucket(event),
            "Bucket public access block relaxed: " + ", ".join(relaxed),
            {"relaxed": relaxed},
        )
    return None


def restore_bucket_block(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("s3").put_public_access_block(
        Bucket=detection.resource, PublicAccessBlockConfiguration=BLOCK_ALL
    )
    return "re-applied all four public access block settings on the bucket"


def bucket_acl_public(event: dict):
    p = params(event)
    canned = {str(v) for v in as_list(p.get("x-amz-acl"))}
    strings = set(walk_strings(p))
    if canned & PUBLIC_CANNED_ACLS or strings & set(PUBLIC_GRANTEES):
        return Detection(_bucket(event), "Bucket ACL grants access to everyone")
    return None


def make_bucket_private(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("s3").put_bucket_acl(Bucket=detection.resource, ACL="private")
    return "reset the bucket ACL to private"


def bucket_policy_public(event: dict):
    policy = load_policy(params(event).get("bucketPolicy"))
    if any(allows_everyone(s) for s in statements(policy)):
        return Detection(_bucket(event), "Bucket policy allows any principal with no condition")
    return None


def account_block_removed(event: dict):
    account = event.get("recipientAccountId", "unknown-account")
    if event["eventName"].startswith("Delete"):
        return Detection(account, "Account-level S3 public access block was deleted")
    relaxed = _relaxed_settings(event)
    if relaxed:
        return Detection(
            account,
            "Account-level S3 public access block relaxed: " + ", ".join(relaxed),
            {"relaxed": relaxed},
        )
    return None


def restore_account_block(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("s3control").put_public_access_block(
        AccountId=detection.resource, PublicAccessBlockConfiguration=BLOCK_ALL
    )
    return "re-applied the account-level public access block"


RULES = [
    Rule(
        id="S3-001",
        title="S3 bucket public access block removed",
        severity=HIGH,
        source=S3,
        events=("PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock"),
        mitre=("T1530",),
        evaluate=bucket_block_removed,
        remediate=restore_bucket_block,
        remediation="Re-apply the bucket public access block",
    ),
    Rule(
        id="S3-002",
        title="S3 bucket ACL made public",
        severity=CRITICAL,
        source=S3,
        events=("PutBucketAcl",),
        mitre=("T1530",),
        evaluate=bucket_acl_public,
        remediate=make_bucket_private,
        remediation="Reset the bucket ACL to private",
    ),
    Rule(
        id="S3-003",
        title="S3 bucket policy allows everyone",
        severity=CRITICAL,
        source=S3,
        events=("PutBucketPolicy",),
        mitre=("T1530",),
        evaluate=bucket_policy_public,
        remediate=restore_bucket_block,
        remediation="Re-apply the bucket public access block, which overrides the public policy",
    ),
    Rule(
        id="S3-004",
        title="Account-level S3 public access block removed",
        severity=CRITICAL,
        source=S3,
        events=("PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock"),
        mitre=("T1530",),
        evaluate=account_block_removed,
        remediate=restore_account_block,
        remediation="Re-apply the account-level public access block",
    ),
]
