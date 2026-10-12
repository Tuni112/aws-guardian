"""Scheduled posture scan: find risky configuration that already exists.

The event pipeline only sees changes made after it was deployed. This scan
reads the account's current state on a schedule and reports what is already
wrong. It is read-only: it never changes anything.

    python -m guardian.scan            # run against the current credentials and print the report
"""

from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

from .models import CRITICAL, HIGH, MEDIUM, Clients, Detection
from .rules.network import ADMIN_PORTS, DATA_PORTS
from .rules.s3 import BLOCK_ALL
from .util import WORLD_V4, WORLD_V6

log = logging.getLogger("guardian.scan")
log.setLevel(logging.INFO)

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
MAX_KEY_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14
SEVERITY_ORDER = (CRITICAL, HIGH, MEDIUM)
LISTED_PER_CHECK = 15  # resources shown per check in the email; the log has all of them


@dataclass(frozen=True)
class Scope:
    account: str
    region: Optional[str] = None  # None for account-wide checks


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    mitre: tuple[str, ...]
    run: Callable[[Clients, Scope], list[Detection]]
    regional: bool = False
    fix: str = ""  # what a person should do about it


@dataclass
class ScanFinding:
    check_id: str
    title: str
    severity: str
    mitre: list[str]
    resource: str
    reason: str
    region: str
    account: str
    detected_at: str
    fix: str


def _code(exc: Exception) -> str:
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")


def _missing(exc: Exception) -> bool:
    code = _code(exc)
    return "NoSuchEntity" in code or code == "NoSuchPublicAccessBlockConfiguration"


def _pages(client: Any, method: str, key: str, **kwargs) -> Iterator[Any]:
    """Every item under `key`, following pagination where the API has it."""
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            yield from page.get(key, [])
    else:
        yield from getattr(client, method)(**kwargs).get(key, [])


# ── account-wide checks ──────────────────────────────────────────────────────


def root_without_mfa(clients: Clients, scope: Scope) -> list[Detection]:
    summary = clients.get("iam").get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled"):
        return []
    return [Detection("root", "The root user has no MFA device")]


def root_access_keys(clients: Clients, scope: Scope) -> list[Detection]:
    summary = clients.get("iam").get_account_summary()["SummaryMap"]
    if not summary.get("AccountAccessKeysPresent"):
        return []
    return [Detection("root", "The root user has access keys")]


def console_users_without_mfa(clients: Clients, scope: Scope) -> list[Detection]:
    iam, found = clients.get("iam"), []
    for user in _pages(iam, "list_users", "Users"):
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)
        except Exception as exc:
            if _missing(exc):
                continue  # no console password
            raise
        if not list(_pages(iam, "list_mfa_devices", "MFADevices", UserName=name)):
            found.append(Detection(f"user/{name}", "Console password set but no MFA device"))
    return found


def old_access_keys(clients: Clients, scope: Scope) -> list[Detection]:
    iam, found, now = clients.get("iam"), [], datetime.now(timezone.utc)
    for user in _pages(iam, "list_users", "Users"):
        name = user["UserName"]
        for key in _pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
            age = (now - key["CreateDate"]).days
            if key.get("Status") == "Active" and age > MAX_KEY_AGE_DAYS:
                found.append(
                    Detection(f"user/{name}", f"Active access key ending {key['AccessKeyId'][-4:]} is {age} days old")
                )
    return found


def users_with_admin(clients: Clients, scope: Scope) -> list[Detection]:
    iam = clients.get("iam")
    users = _pages(iam, "list_entities_for_policy", "PolicyUsers", PolicyArn=ADMIN_POLICY, EntityFilter="User")
    return [
        Detection(f"user/{u['UserName']}", "AdministratorAccess is attached directly to this user") for u in users
    ]


def weak_password_policy(clients: Clients, scope: Scope) -> list[Detection]:
    try:
        policy = clients.get("iam").get_account_password_policy()["PasswordPolicy"]
    except Exception as exc:
        if _missing(exc):
            return [Detection("account", "No account password policy is set")]
        raise
    length = policy.get("MinimumPasswordLength", 0)
    if length < MIN_PASSWORD_LENGTH:
        return [Detection("account", f"Password policy allows passwords of {length} characters")]
    return []


def _account_block_complete(clients: Clients, scope: Scope) -> bool:
    try:
        config = clients.get("s3control").get_public_access_block(AccountId=scope.account)
    except Exception as exc:
        if _missing(exc):
            return False
        raise
    return all(config["PublicAccessBlockConfiguration"].get(key) is True for key in BLOCK_ALL)


def account_block_missing(clients: Clients, scope: Scope) -> list[Detection]:
    if _account_block_complete(clients, scope):
        return []
    return [Detection("account", "The account-level S3 public access block is missing or incomplete")]


def public_buckets(clients: Clients, scope: Scope) -> list[Detection]:
    s3, found = clients.get("s3"), []
    for bucket in _pages(s3, "list_buckets", "Buckets"):
        name = bucket["Name"]
        try:
            status = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
        except Exception as exc:
            if _code(exc) == "NoSuchBucketPolicy":
                continue
            raise
        if status.get("IsPublic"):
            found.append(Detection(name, "Bucket policy makes the bucket public"))
    return found


def no_logging_trail(clients: Clients, scope: Scope) -> list[Detection]:
    cloudtrail = clients.get("cloudtrail")
    for trail in cloudtrail.describe_trails().get("trailList", []):
        if trail.get("IsMultiRegionTrail") and cloudtrail.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            return []
    return [Detection("account", "No multi-region CloudTrail trail is logging")]


# ── per-region checks ────────────────────────────────────────────────────────


def _open_ports(permission: dict) -> Optional[str]:
    """How an ingress permission exposes the group to the internet, or None."""
    world = any(r.get("CidrIp") == WORLD_V4 for r in permission.get("IpRanges", []))
    world = world or any(r.get("CidrIpv6") == WORLD_V6 for r in permission.get("Ipv6Ranges", []))
    protocol = str(permission.get("IpProtocol", "-1"))
    if not world or protocol not in ("-1", "tcp", "6"):
        return None
    lo, hi = permission.get("FromPort"), permission.get("ToPort")
    if protocol == "-1" or lo is None or hi is None or (lo, hi) == (0, 65535):
        return "all ports"
    hit = [p for p in ADMIN_PORTS + DATA_PORTS if lo <= p <= hi]
    return "port(s) " + ", ".join(str(p) for p in hit) if hit else None


def open_security_groups(clients: Clients, scope: Scope) -> list[Detection]:
    found = []
    for group in _pages(clients.get("ec2", scope.region), "describe_security_groups", "SecurityGroups"):
        exposed = sorted({e for e in map(_open_ports, group.get("IpPermissions", [])) if e})
        if exposed:
            found.append(Detection(group["GroupId"], "Open to the internet on " + "; ".join(exposed)))
    return found


def vpcs_without_flow_logs(clients: Clients, scope: Scope) -> list[Detection]:
    ec2 = clients.get("ec2", scope.region)
    logged = {f.get("ResourceId") for f in _pages(ec2, "describe_flow_logs", "FlowLogs")}
    return [
        Detection(vpc["VpcId"], "VPC has no flow logs")
        for vpc in _pages(ec2, "describe_vpcs", "Vpcs")
        if vpc["VpcId"] not in logged
    ]


def ebs_encryption_off(clients: Clients, scope: Scope) -> list[Detection]:
    if clients.get("ec2", scope.region).get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
        return []
    return [Detection(f"region/{scope.region}", "EBS encryption by default is off")]


def guardduty_off(clients: Clients, scope: Scope) -> list[Detection]:
    if clients.get("guardduty", scope.region).list_detectors().get("DetectorIds"):
        return []
    return [Detection(f"region/{scope.region}", "GuardDuty is not enabled")]


def public_snapshots(clients: Clients, scope: Scope) -> list[Detection]:
    snapshots = _pages(
        clients.get("ec2", scope.region),
        "describe_snapshots",
        "Snapshots",
        OwnerIds=["self"],
        RestorableByUserIds=["all"],
    )
    return [Detection(s["SnapshotId"], "EBS snapshot is shared with everyone") for s in snapshots]


def public_images(clients: Clients, scope: Scope) -> list[Detection]:
    images = _pages(
        clients.get("ec2", scope.region),
        "describe_images",
        "Images",
        Owners=["self"],
        Filters=[{"Name": "is-public", "Values": ["true"]}],
    )
    return [Detection(i["ImageId"], "AMI is public") for i in images]


def public_databases(clients: Clients, scope: Scope) -> list[Detection]:
    instances = _pages(clients.get("rds", scope.region), "describe_db_instances", "DBInstances")
    return [
        Detection(db["DBInstanceIdentifier"], "RDS instance is publicly accessible")
        for db in instances
        if db.get("PubliclyAccessible")
    ]


CHECKS = [
    Check("POS-001", "Root user has no MFA", CRITICAL, ("T1078.004",), root_without_mfa,
          fix="Assign an MFA device to the root user"),
    Check("POS-002", "Root user has access keys", CRITICAL, ("T1078.004",), root_access_keys,
          fix="Delete the root access keys"),
    Check("POS-003", "Console user without MFA", HIGH, ("T1078.004",), console_users_without_mfa,
          fix="Require MFA for the user or remove its console password"),
    Check("POS-004", "Access key older than 90 days", MEDIUM, ("T1078.004",), old_access_keys,
          fix="Rotate or delete the key"),
    Check("POS-005", "Administrator access attached directly to a user", HIGH, ("T1098.003",), users_with_admin,
          fix="Grant admin through a role the user assumes with MFA"),
    Check("POS-006", "Account password policy missing or weak", MEDIUM, ("T1556",), weak_password_policy,
          fix=f"Set a password policy with a minimum length of {MIN_PASSWORD_LENGTH}"),
    Check("POS-007", "Account-level S3 public access block missing", HIGH, ("T1530",), account_block_missing,
          fix="Turn on all four account-level public access block settings"),
    Check("POS-008", "S3 bucket is public", CRITICAL, ("T1530",), public_buckets,
          fix="Remove the public statement from the bucket policy"),
    Check("POS-009", "No CloudTrail trail is logging", CRITICAL, ("T1562.008",), no_logging_trail,
          fix="Create a multi-region trail and start logging"),
    Check("POS-010", "Security group open to the internet", CRITICAL, ("T1190",), open_security_groups,
          regional=True, fix="Restrict the ingress rule to known addresses"),
    Check("POS-011", "VPC without flow logs", MEDIUM, ("T1562.008",), vpcs_without_flow_logs,
          regional=True, fix="Enable flow logs for the VPC"),
    Check("POS-012", "EBS encryption by default is off", MEDIUM, ("T1562.001",), ebs_encryption_off,
          regional=True, fix="Enable EBS encryption by default in the region"),
    Check("POS-013", "GuardDuty is not enabled", MEDIUM, ("T1562.001",), guardduty_off,
          regional=True, fix="Enable GuardDuty in the region"),
    Check("POS-014", "EBS snapshot is public", CRITICAL, ("T1537",), public_snapshots,
          regional=True, fix="Remove public sharing from the snapshot"),
    Check("POS-015", "AMI is public", HIGH, ("T1537",), public_images,
          regional=True, fix="Make the image private"),
    Check("POS-016", "RDS instance is publicly accessible", HIGH, ("T1190",), public_databases,
          regional=True, fix="Turn off public accessibility for the instance"),
]  # fmt: skip


# ── running the scan ─────────────────────────────────────────────────────────


@dataclass
class Report:
    account: str
    regions: list[str]
    findings: list[ScanFinding]
    errors: list[str]


def _regions(clients: Clients, wanted: list[str]) -> list[str]:
    if wanted:
        return wanted
    return sorted(r["RegionName"] for r in clients.get("ec2").describe_regions()["Regions"])


def _run(check: Check, clients: Clients, scope: Scope) -> tuple[list[ScanFinding], Optional[str]]:
    """One check in one scope. A check that fails is reported, never fatal."""
    try:
        detections = check.run(clients, scope)
    except Exception as exc:
        where = f" in {scope.region}" if scope.region else ""
        return [], f"{check.id}{where}: {type(exc).__name__}: {_code(exc) or exc}"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return [
        ScanFinding(
            check_id=check.id,
            title=check.title,
            severity=check.severity,
            mitre=list(check.mitre),
            resource=d.resource,
            reason=d.reason,
            region=scope.region or "global",
            account=scope.account,
            detected_at=now,
            fix=check.fix,
        )
        for d in detections
    ], None


def scan(clients: Clients, regions: Optional[list[str]] = None, checks: Optional[list[Check]] = None) -> Report:
    checks = CHECKS if checks is None else checks
    account = clients.get("sts").get_caller_identity()["Account"]
    regions = _regions(clients, regions or [])
    jobs = [(c, Scope(account)) for c in checks if not c.regional]
    jobs += [(c, Scope(account, r)) for r in regions for c in checks if c.regional]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda job: _run(job[0], clients, job[1]), jobs))
    findings = [f for found, _ in results for f in found]
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.check_id, f.region, f.resource))
    return Report(account, regions, findings, [error for _, error in results if error])


def format_report(report: Report) -> tuple[str, str]:
    counts = {s: sum(f.severity == s for f in report.findings) for s in SEVERITY_ORDER}
    tally = ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n) or "no findings"
    subject = f"[aws-guardian] posture scan: {tally}"[:100]
    lines = [
        f"Posture scan of account {report.account} across {len(report.regions)} region(s).",
        f"{len(report.findings)} finding(s): {tally}.",
    ]
    by_check: dict[str, list[ScanFinding]] = {}
    for finding in report.findings:
        by_check.setdefault(finding.check_id, []).append(finding)
    for found in by_check.values():
        first = found[0]
        lines += ["", f"[{first.severity}] {first.check_id}  {first.title}  ({len(found)})"]
        if all(f.resource.startswith("region/") for f in found):
            # a region-wide setting: one line naming the regions reads better than one line each
            lines.append(f"  - {first.reason} in: {', '.join(f.region for f in found)}")
        else:
            for f in found[:LISTED_PER_CHECK]:
                where = "" if f.region == "global" else f" [{f.region}]"
                lines.append(f"  - {f.resource}{where}: {f.reason}")
            if len(found) > LISTED_PER_CHECK:
                lines.append(f"  ... and {len(found) - LISTED_PER_CHECK} more, see the scan log")
        lines.append(f"  Fix: {first.fix}")
    if report.errors:
        lines += ["", f"{len(report.errors)} check(s) could not run:"] + [f"  - {e}" for e in report.errors]
    return subject, "\n".join(lines)


def lambda_handler(event: Optional[dict] = None, context=None) -> dict:
    clients = Clients()
    wanted = [r.strip() for r in os.environ.get("SCAN_REGIONS", "").split(",") if r.strip()]
    report = scan(clients, wanted)
    for finding in report.findings:
        log.info(json.dumps({"guardian_scan_finding": asdict(finding)}))
    for error in report.errors:
        log.warning(json.dumps({"guardian_scan_error": error}))
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if topic and (report.findings or report.errors):
        subject, body = format_report(report)
        clients.get("sns").publish(TopicArn=topic, Subject=subject, Message=body)
    return {"findings": len(report.findings), "errors": len(report.errors)}


if __name__ == "__main__":
    print(format_report(scan(Clients()))[1])
