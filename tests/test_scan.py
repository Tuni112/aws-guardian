"""The posture scan is exercised against a fake account whose state each test sets up."""

from datetime import datetime, timedelta, timezone

import pytest
from conftest import ACCOUNT

from guardian import scan as scan_module
from guardian.models import Clients
from guardian.scan import CHECKS, format_report, scan

PAB_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
NOW = datetime.now(timezone.utc)


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeService:
    def __init__(self, service, region, state, calls):
        self._service, self._region, self._state, self._calls = service, region, state, calls

    def can_paginate(self, method):
        return False

    def __getattr__(self, method):
        def call(**kwargs):
            self._calls.append((self._service, method, kwargs))
            answer = self._state.get((self._service, method), {})
            if callable(answer):
                answer = answer(self._region, **kwargs)
            if isinstance(answer, Exception):
                raise answer
            return answer

        return call


# A well-configured account: every check passes against this.
HEALTHY = {
    ("sts", "get_caller_identity"): {"Account": ACCOUNT},
    ("iam", "get_account_summary"): {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    ("iam", "get_account_password_policy"): {"PasswordPolicy": {"MinimumPasswordLength": 14}},
    ("s3control", "get_public_access_block"): {"PublicAccessBlockConfiguration": PAB_ON},
    ("cloudtrail", "describe_trails"): {"trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": True}]},
    ("cloudtrail", "get_trail_status"): {"IsLogging": True},
    ("ec2", "get_ebs_encryption_by_default"): {"EbsEncryptionByDefault": True},
    ("guardduty", "list_detectors"): {"DetectorIds": ["d-1"]},
}


def run(overrides=None, regions=("us-east-1",)):
    calls = []
    state = {**HEALTHY, **(overrides or {})}
    clients = Clients(lambda service, region: FakeService(service, region, state, calls))
    return scan(clients, list(regions)), calls


def ids(report):
    return [f.check_id for f in report.findings]


def test_healthy_account_has_no_findings():
    report, _ = run()
    assert report.findings == [] and report.errors == []


def user(name):
    return {"UserName": name}


def sg(group_id, protocol="tcp", lo=22, hi=22, cidr="0.0.0.0/0"):
    perm = {"IpProtocol": protocol, "IpRanges": [{"CidrIp": cidr}]}
    if protocol != "-1":
        perm.update(FromPort=lo, ToPort=hi)
    return {"GroupId": group_id, "IpPermissions": [perm]}


FIRING = {
    "POS-001": {("iam", "get_account_summary"): {"SummaryMap": {"AccountMFAEnabled": 0}}},
    "POS-002": {
        ("iam", "get_account_summary"): {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}}
    },
    "POS-003": {("iam", "list_users"): {"Users": [user("emily")]}},
    "POS-004": {
        ("iam", "list_users"): {"Users": [user("alice")]},
        ("iam", "get_login_profile"): AwsError("NoSuchEntity"),
        ("iam", "list_access_keys"): {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAEXAMPLEOLD1", "Status": "Active", "CreateDate": NOW - timedelta(days=400)}
            ]
        },
    },
    "POS-005": {("iam", "list_entities_for_policy"): {"PolicyUsers": [user("emily")]}},
    "POS-006": {("iam", "get_account_password_policy"): AwsError("NoSuchEntity")},
    "POS-007": {("s3control", "get_public_access_block"): AwsError("NoSuchPublicAccessBlockConfiguration")},
    "POS-008": {
        ("s3", "list_buckets"): {"Buckets": [{"Name": "open-bucket"}]},
        ("s3", "get_bucket_policy_status"): {"PolicyStatus": {"IsPublic": True}},
    },
    "POS-009": {("cloudtrail", "get_trail_status"): {"IsLogging": False}},
    "POS-010": {("ec2", "describe_security_groups"): {"SecurityGroups": [sg("sg-open")]}},
    "POS-011": {("ec2", "describe_vpcs"): {"Vpcs": [{"VpcId": "vpc-1"}]}},
    "POS-012": {("ec2", "get_ebs_encryption_by_default"): {"EbsEncryptionByDefault": False}},
    "POS-013": {("guardduty", "list_detectors"): {"DetectorIds": []}},
    "POS-014": {("ec2", "describe_snapshots"): {"Snapshots": [{"SnapshotId": "snap-1"}]}},
    "POS-015": {("ec2", "describe_images"): {"Images": [{"ImageId": "ami-1"}]}},
    "POS-016": {
        ("rds", "describe_db_instances"): {
            "DBInstances": [
                {"DBInstanceIdentifier": "public-db", "PubliclyAccessible": True},
                {"DBInstanceIdentifier": "private-db", "PubliclyAccessible": False},
            ]
        }
    },
}


def test_every_check_has_a_firing_case():
    assert sorted(FIRING) == sorted(c.id for c in CHECKS)


@pytest.mark.parametrize("check_id", sorted(FIRING))
def test_check_fires_alone(check_id):
    report, _ = run(FIRING[check_id])
    assert ids(report) == [check_id]
    assert report.errors == []


def test_benign_lookalikes_do_not_fire():
    report, _ = run(
        {
            # a console user who does have MFA, and a fresh access key
            ("iam", "list_users"): {"Users": [user("alice")]},
            ("iam", "list_mfa_devices"): {"MFADevices": [{"SerialNumber": "arn:mfa"}]},
            ("iam", "list_access_keys"): {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "AKIAEXAMPLENEW1", "Status": "Active", "CreateDate": NOW - timedelta(days=5)},
                    {"AccessKeyId": "AKIAEXAMPLEOFF1", "Status": "Inactive", "CreateDate": NOW - timedelta(days=900)},
                ]
            },
            # a bucket with no policy, and one whose policy is not public
            ("s3", "list_buckets"): {"Buckets": [{"Name": "a"}]},
            ("s3", "get_bucket_policy_status"): AwsError("NoSuchBucketPolicy"),
            # ingress that is office-only, or open on a port nobody cares about
            ("ec2", "describe_security_groups"): {
                "SecurityGroups": [sg("sg-office", cidr="198.51.100.0/24"), sg("sg-web", lo=443, hi=443)]
            },
            # a VPC that already has flow logs
            ("ec2", "describe_vpcs"): {"Vpcs": [{"VpcId": "vpc-1"}]},
            ("ec2", "describe_flow_logs"): {"FlowLogs": [{"ResourceId": "vpc-1"}]},
        }
    )
    assert report.findings == []


@pytest.mark.parametrize(
    "group, expected",
    [
        (sg("sg-1", protocol="-1"), "all ports"),
        (sg("sg-1", lo=0, hi=65535), "all ports"),
        (sg("sg-1", lo=5000, hi=6000), "port(s) 5432, 5984"),
        (sg("sg-1", lo=3389, hi=3389), "port(s) 3389"),
    ],
)
def test_security_group_exposure_is_described(group, expected):
    report, _ = run({("ec2", "describe_security_groups"): {"SecurityGroups": [group]}})
    (finding,) = report.findings
    assert finding.reason == f"Open to the internet on {expected}"


def test_ipv6_world_is_detected():
    group = {
        "GroupId": "sg-6",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
    }
    report, _ = run({("ec2", "describe_security_groups"): {"SecurityGroups": [group]}})
    assert ids(report) == ["POS-010"]


def test_regional_checks_run_in_every_region_and_global_checks_once():
    def groups(region, **kwargs):
        return {"SecurityGroups": [sg(f"sg-{region}")]}

    report, calls = run({("ec2", "describe_security_groups"): groups}, regions=("us-east-1", "eu-west-1"))
    assert sorted((f.region, f.resource) for f in report.findings) == [
        ("eu-west-1", "sg-eu-west-1"),
        ("us-east-1", "sg-us-east-1"),
    ]
    assert sum(call[:2] == ("iam", "get_account_password_policy") for call in calls) == 1


def test_regions_default_to_every_enabled_region():
    report, _ = run({("ec2", "describe_regions"): {"Regions": [{"RegionName": "b"}, {"RegionName": "a"}]}}, regions=())
    assert report.regions == ["a", "b"]


def test_a_failing_check_is_reported_and_does_not_stop_the_scan():
    report, _ = run(
        {
            ("guardduty", "list_detectors"): AwsError("AccessDeniedException"),
            ("iam", "get_account_summary"): {"SummaryMap": {"AccountMFAEnabled": 0}},
        }
    )
    assert ids(report) == ["POS-001"]
    assert report.errors == ["POS-013 in us-east-1: AwsError: AccessDeniedException"]


def test_findings_are_ordered_most_severe_first():
    report, _ = run({**FIRING["POS-013"], **FIRING["POS-005"], **FIRING["POS-001"]})
    assert ids(report) == ["POS-001", "POS-005", "POS-013"]


def test_scan_makes_only_read_calls():
    """The scan must never change the account, whatever state it finds."""
    everything = {}
    for overrides in FIRING.values():
        everything.update(overrides)
    _, calls = run(everything)
    for _, method, _ in calls:
        assert method.split("_")[0] in ("get", "list", "describe"), method


def test_report_groups_findings_and_truncates_long_lists():
    many = {"SecurityGroups": [sg(f"sg-{i:02}") for i in range(20)]}
    report, _ = run({("ec2", "describe_security_groups"): many, **FIRING["POS-001"]})
    subject, body = format_report(report)
    assert subject == "[aws-guardian] posture scan: 21 critical"
    assert "POS-010  Security group open to the internet  (20)" in body
    assert "... and 5 more" in body
    assert "Fix: Assign an MFA device to the root user" in body


def test_clean_report_reads_sensibly():
    report, _ = run()
    subject, body = format_report(report)
    assert subject == "[aws-guardian] posture scan: no findings"
    assert "0 finding(s)" in body


def handler_clients(monkeypatch, overrides=None):
    calls = []
    state = {**HEALTHY, **(overrides or {})}
    monkeypatch.setattr(scan_module, "Clients", lambda: Clients(lambda s, r: FakeService(s, r, state, calls)))
    monkeypatch.setenv("SCAN_REGIONS", "us-east-1")
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    return calls


def test_handler_publishes_one_digest(monkeypatch):
    calls = handler_clients(monkeypatch, {**FIRING["POS-001"], **FIRING["POS-013"]})
    assert scan_module.lambda_handler({}) == {"findings": 2, "errors": 0}
    published = [kwargs for service, method, kwargs in calls if (service, method) == ("sns", "publish")]
    assert len(published) == 1
    assert published[0]["Subject"] == "[aws-guardian] posture scan: 1 critical, 1 medium"


def test_handler_stays_quiet_when_the_account_is_clean(monkeypatch):
    calls = handler_clients(monkeypatch)
    assert scan_module.lambda_handler({}) == {"findings": 0, "errors": 0}
    assert not [c for c in calls if c[:2] == ("sns", "publish")]


def test_region_wide_settings_are_listed_on_one_line():
    report, _ = run(FIRING["POS-013"], regions=("us-east-1", "eu-west-1"))
    _, body = format_report(report)
    assert "  - GuardDuty is not enabled in: eu-west-1, us-east-1" in body
