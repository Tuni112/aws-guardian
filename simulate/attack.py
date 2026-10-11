#!/usr/bin/env python3
"""Perform real misconfigurations in a sandbox account and report how Guardian responded.

Every scenario creates its own throwaway resource, misconfigures it, waits to
see whether Guardian put it back, and then deletes the resource. Nothing that
already exists in the account is modified, except in the `trail` scenario,
which briefly stops Guardian's own trail and always restarts it.

    python simulate/attack.py --list
    python simulate/attack.py                 # run every scenario
    python simulate/attack.py sg-ssh iam-key  # run some

Run this only in an account you own and use for testing.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_DOC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
WORLD = [{"CidrIp": "0.0.0.0/0"}]


def ignore_missing(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if "NoSuchEntity" in code or "NotFound" in code or code in ("NoSuchBucket", "NoSuchPublicAccessBlockConfiguration"):
            return None
        raise


class Sandbox:
    def __init__(self, region: str, name: str):
        self.region, self.name = region, name
        self.session = boto3.Session(region_name=region)
        self.ec2 = self.session.client("ec2")
        self.s3 = self.session.client("s3")
        self.iam = self.session.client("iam")
        self.cloudtrail = self.session.client("cloudtrail")
        self.logs = self.session.client("logs")
        self.account = self.session.client("sts").get_caller_identity()["Account"]
        self.suffix = uuid.uuid4().hex[:8]

    # ── security groups ──────────────────────────────────────────────────
    def _security_group(self) -> str:
        vpcs = self.ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
        if not vpcs:
            raise RuntimeError("no default VPC in this region; create one or pick another region")
        return self.ec2.create_security_group(
            GroupName=f"{self.name}-sim-{self.suffix}-{uuid.uuid4().hex[:4]}",
            Description="aws-guardian attack simulation, safe to delete",
            VpcId=vpcs[0]["VpcId"],
        )["GroupId"]

    def _sg_scenario(self, permission: dict):
        group = self._security_group()
        permission = {**permission, "IpRanges": WORLD}

        def attack():
            self.ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[permission])

        def reverted():
            rules = self.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]["IpPermissions"]
            return not rules

        def cleanup():
            ignore_missing(self.ec2.delete_security_group, GroupId=group)

        return f"security group {group}", attack, reverted, cleanup

    def sg_ssh(self):
        return self._sg_scenario({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22})

    def sg_db(self):
        return self._sg_scenario({"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432})

    def sg_all(self):
        return self._sg_scenario({"IpProtocol": "-1"})

    # ── s3 ───────────────────────────────────────────────────────────────
    def s3_block(self):
        bucket = f"{self.name}-sim-{self.account}-{self.suffix}"
        kwargs = {} if self.region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": self.region}}
        self.s3.create_bucket(Bucket=bucket, **kwargs)

        def attack():
            self.s3.delete_public_access_block(Bucket=bucket)

        def reverted():
            config = ignore_missing(self.s3.get_public_access_block, Bucket=bucket)
            return bool(config) and all(config["PublicAccessBlockConfiguration"].values())

        def cleanup():
            ignore_missing(self.s3.delete_bucket, Bucket=bucket)

        return f"bucket {bucket}", attack, reverted, cleanup

    # ── iam ──────────────────────────────────────────────────────────────
    def _victim(self) -> str:
        user = f"{self.name}-sim-victim-{self.suffix}-{uuid.uuid4().hex[:4]}"
        self.iam.create_user(UserName=user)
        return user

    def _delete_victim(self, user: str):
        ignore_missing(self.iam.detach_user_policy, UserName=user, PolicyArn=ADMIN)
        ignore_missing(self.iam.delete_user_policy, UserName=user, PolicyName="sim-admin")
        ignore_missing(self.iam.delete_login_profile, UserName=user)
        for key in self.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            self.iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
        ignore_missing(self.iam.delete_user, UserName=user)

    def iam_admin(self):
        user = self._victim()

        def attack():
            self.iam.attach_user_policy(UserName=user, PolicyArn=ADMIN)

        def reverted():
            return not self.iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]

        return f"user {user}", attack, reverted, lambda: self._delete_victim(user)

    def iam_inline(self):
        user = self._victim()

        def attack():
            self.iam.put_user_policy(UserName=user, PolicyName="sim-admin", PolicyDocument=ADMIN_DOC)

        def reverted():
            return not self.iam.list_user_policies(UserName=user)["PolicyNames"]

        return f"user {user}", attack, reverted, lambda: self._delete_victim(user)

    def iam_key(self):
        user = self._victim()

        def attack():
            # The secret is discarded immediately and the key is deleted in cleanup.
            self.iam.create_access_key(UserName=user)

        def reverted():
            keys = self.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
            return bool(keys) and all(k["Status"] == "Inactive" for k in keys)

        return f"user {user}", attack, reverted, lambda: self._delete_victim(user)

    def iam_password(self):
        user = self._victim()

        def attack():
            self.iam.create_login_profile(UserName=user, Password=f"Sim-{uuid.uuid4().hex}-Aa1!", PasswordResetRequired=True)

        return f"user {user}", attack, None, lambda: self._delete_victim(user)

    # ── cloudtrail ───────────────────────────────────────────────────────
    def trail(self):
        trail = f"{self.name}-trail"
        self.cloudtrail.get_trail_status(Name=trail)  # fail early if it is not ours

        def attack():
            self.cloudtrail.stop_logging(Name=trail)

        def reverted():
            return self.cloudtrail.get_trail_status(Name=trail)["IsLogging"]

        def cleanup():
            self.cloudtrail.start_logging(Name=trail)  # always leave logging on

        return f"trail {trail}", attack, reverted, cleanup

    # ── evidence ─────────────────────────────────────────────────────────
    def findings_since(self, start_ms: int) -> list[dict]:
        found, token = [], None
        while True:
            kwargs = {"nextToken": token} if token else {}
            page = self.logs.filter_log_events(
                logGroupName=f"/aws/lambda/{self.name}",
                startTime=start_ms,
                filterPattern='"guardian_finding"',
                **kwargs,
            )
            for event in page["events"]:
                payload = event["message"][event["message"].find("{") :]
                try:
                    found.append(json.loads(payload)["guardian_finding"])
                except (ValueError, KeyError):
                    continue
            token = page.get("nextToken")
            if not token:
                return found


SCENARIOS = {
    "sg-ssh": ("NET-001", "Open SSH to the internet", Sandbox.sg_ssh),
    "sg-db": ("NET-002", "Open PostgreSQL to the internet", Sandbox.sg_db),
    "sg-all": ("NET-003", "Open every port to the internet", Sandbox.sg_all),
    "s3-block": ("S3-001", "Delete a bucket's public access block", Sandbox.s3_block),
    "iam-admin": ("IAM-001", "Attach AdministratorAccess to a user", Sandbox.iam_admin),
    "iam-inline": ("IAM-002", "Add an inline allow-everything policy", Sandbox.iam_inline),
    "iam-key": ("IAM-003", "Create an access key for another user", Sandbox.iam_key),
    "iam-password": ("IAM-005", "Set a console password for another user", Sandbox.iam_password),
    "trail": ("LOG-001", "Stop CloudTrail logging", Sandbox.trail),
}


def run(sandbox: Sandbox, key: str, wait: int) -> dict:
    rule_id, title, build = SCENARIOS[key]
    print(f"\n== {key}: {title} (expects {rule_id})")
    resource, attack, reverted, cleanup = build(sandbox)
    result = {"scenario": key, "rule": rule_id, "resource": resource, "reverted": None, "seconds": None}
    try:
        started = time.monotonic()
        attack()
        print(f"   attacked {resource}")
        if reverted is None:
            print("   alert-only rule: nothing to revert, check the findings below")
        else:
            deadline = started + wait
            while time.monotonic() < deadline:
                if reverted():
                    result["reverted"] = True
                    result["seconds"] = round(time.monotonic() - started, 1)
                    print(f"   REVERTED after {result['seconds']}s")
                    break
                time.sleep(3)
            else:
                result["reverted"] = False
                print(f"   not reverted within {wait}s (expected unless remediation_mode is enforce)")
    finally:
        cleanup()
        print("   cleaned up")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenarios", nargs="*", help="scenario names; default is all")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--name", default="aws-guardian", help="the Terraform `name` variable")
    parser.add_argument("--wait", type=int, default=180, help="seconds to wait for each remediation")
    parser.add_argument("--json", help="write results to this file")
    args = parser.parse_args()

    if args.list:
        for key, (rule_id, title, _) in SCENARIOS.items():
            print(f"{key:14} {rule_id:8} {title}")
        return 0
    unknown = [s for s in args.scenarios if s not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")

    sandbox = Sandbox(args.region, args.name)
    print(f"Account {sandbox.account}, region {args.region}. Simulated attacks start now.")
    start_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    results = [run(sandbox, key, args.wait) for key in (args.scenarios or SCENARIOS)]

    print("\nWaiting 60s for the last findings to reach CloudWatch Logs...")
    time.sleep(60)
    findings = sandbox.findings_since(start_ms)
    print(f"\n{'rule':9}{'remediated':12}{'latency':9}resource")
    for f in findings:
        print(f"{f['rule_id']:9}{str(f['remediated']):12}{str(f['seconds_to_respond']) + 's':9}{f['resource']}")
    missing = sorted({r["rule"] for r in results} - {f["rule_id"] for f in findings})
    if missing:
        print(f"\nNo finding logged for: {', '.join(missing)}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"results": results, "findings": findings}, fh, indent=2)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
