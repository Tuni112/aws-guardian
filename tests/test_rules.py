"""Every rule is exercised with an event that must fire and, where the rule has
logic beyond the event name, one that must not."""

import json

import pytest
from conftest import ACCOUNT, ROOT, envelope, make_event

from guardian.handler import ENFORCE, Settings, evaluate
from guardian.models import CONSOLE_SIGNIN
from guardian.rules import ALL_RULES

WORLD = {"items": [{"cidrIp": "0.0.0.0/0"}]}
OFFICE = {"items": [{"cidrIp": "198.51.100.0/24"}]}
ADMIN_DOC = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
SCOPED_DOC = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
PAB_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
PAB_OFF = {**PAB_ON, "BlockPublicPolicy": False}


def ingress(protocol="tcp", lo=22, hi=22, ranges=WORLD, v6=None):
    perm = {"ipProtocol": protocol, "fromPort": lo, "toPort": hi, "ipRanges": ranges}
    if v6:
        perm["ipv6Ranges"] = {"items": [{"cidrIpv6": v6}]}
    return {"groupId": "sg-0abc", "ipPermissions": {"items": [perm]}}


def trust(principal):
    return json.dumps({"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]})


def signin(identity, result="Success", mfa="No"):
    event = make_event(
        "signin.amazonaws.com",
        "ConsoleLogin",
        identity=identity,
        additionalEventData={"MFAUsed": mfa},
    )
    event["responseElements"] = {"ConsoleLogin": result}
    return envelope(event, CONSOLE_SIGNIN)


IAM_USER = {"type": "IAMUser", "userName": "alice", "arn": f"arn:aws:iam::{ACCOUNT}:user/alice"}
SSO_ROLE = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_Admin/alice"}

# (rule id, envelope, expected call the remediation makes, or None for alert-only)
FIRES = [
    ("LOG-001", envelope(make_event("cloudtrail.amazonaws.com", "StopLogging", {"name": "main"})), "start_logging"),
    ("LOG-002", envelope(make_event("cloudtrail.amazonaws.com", "DeleteTrail", {"name": "main"})), None),
    (
        "LOG-003",
        envelope(make_event("cloudtrail.amazonaws.com", "UpdateTrail", {"name": "main", "isMultiRegionTrail": False})),
        None,
    ),
    (
        "LOG-004",
        envelope(
            make_event(
                "cloudtrail.amazonaws.com",
                "PutEventSelectors",
                {"trailName": "main", "eventSelectors": [{"includeManagementEvents": False}]},
            )
        ),
        None,
    ),
    (
        "LOG-005",
        envelope(make_event("guardduty.amazonaws.com", "UpdateDetector", {"detectorId": "d1", "enable": False})),
        "update_detector",
    ),
    (
        "LOG-006",
        envelope(
            make_event("config.amazonaws.com", "StopConfigurationRecorder", {"configurationRecorderName": "default"})
        ),
        "start_configuration_recorder",
    ),
    (
        "LOG-007",
        envelope(
            make_event("ec2.amazonaws.com", "DeleteFlowLogs", {"DeleteFlowLogsRequest": {"FlowLogId": ["fl-1"]}})
        ),
        None,
    ),
    (
        "S3-001",
        envelope(
            make_event(
                "s3.amazonaws.com",
                "PutBucketPublicAccessBlock",
                {"bucketName": "b", "PublicAccessBlockConfiguration": PAB_OFF},
            )
        ),
        "put_public_access_block",
    ),
    (
        "S3-001",
        envelope(make_event("s3.amazonaws.com", "DeleteBucketPublicAccessBlock", {"bucketName": "b"})),
        "put_public_access_block",
    ),
    (
        "S3-002",
        envelope(make_event("s3.amazonaws.com", "PutBucketAcl", {"bucketName": "b", "x-amz-acl": ["public-read"]})),
        "put_bucket_acl",
    ),
    (
        "S3-002",
        envelope(
            make_event(
                "s3.amazonaws.com",
                "PutBucketAcl",
                {
                    "bucketName": "b",
                    "AccessControlPolicy": {
                        "AccessControlList": {
                            "Grant": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
                        }
                    },
                },
            )
        ),
        "put_bucket_acl",
    ),
    (
        "S3-003",
        envelope(
            make_event(
                "s3.amazonaws.com",
                "PutBucketPolicy",
                {
                    "bucketName": "b",
                    "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]},
                },
            )
        ),
        "put_public_access_block",
    ),
    (
        "S3-004",
        envelope(make_event("s3.amazonaws.com", "DeleteAccountPublicAccessBlock")),
        "put_public_access_block",
    ),
    ("NET-001", envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress())), "revoke_security_group_ingress"),
    (
        "NET-001",
        envelope(
            make_event(
                "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(lo=3389, hi=3389, ranges={}, v6="::/0")
            )
        ),
        "revoke_security_group_ingress",
    ),
    (
        "NET-001",
        envelope(
            make_event(
                "ec2.amazonaws.com",
                "AuthorizeSecurityGroupIngress",
                {"groupId": "sg-0abc", "cidrIp": "0.0.0.0/0", "ipProtocol": "tcp", "fromPort": 20, "toPort": 25},
            )
        ),
        "revoke_security_group_ingress",
    ),
    (
        "NET-002",
        envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(lo=5432, hi=5432))),
        "revoke_security_group_ingress",
    ),
    (
        "NET-003",
        envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(protocol="-1", lo=None, hi=None))),
        "revoke_security_group_ingress",
    ),
    (
        "EXP-001",
        envelope(
            make_event(
                "ec2.amazonaws.com",
                "ModifySnapshotAttribute",
                {"snapshotId": "snap-1", "createVolumePermission": {"add": {"items": [{"group": "all"}]}}},
            )
        ),
        "modify_snapshot_attribute",
    ),
    (
        "EXP-002",
        envelope(
            make_event(
                "ec2.amazonaws.com",
                "ModifyImageAttribute",
                {"imageId": "ami-1", "launchPermission": {"add": {"items": [{"group": "all"}]}}},
            )
        ),
        "modify_image_attribute",
    ),
    ("EXP-003", envelope(make_event("ec2.amazonaws.com", "DisableEbsEncryptionByDefault")), "enable_ebs_encryption_by_default"),
    (
        "EXP-004",
        envelope(
            make_event(
                "rds.amazonaws.com",
                "ModifyDBSnapshotAttribute",
                {"dBSnapshotIdentifier": "s1", "attributeName": "restore", "valuesToAdd": ["all"]},
            )
        ),
        "modify_db_snapshot_attribute",
    ),
    (
        "EXP-004",
        envelope(
            make_event(
                "rds.amazonaws.com",
                "ModifyDBClusterSnapshotAttribute",
                {"dBClusterSnapshotIdentifier": "c1", "attributeName": "restore", "valuesToAdd": ["all"]},
            )
        ),
        "modify_db_cluster_snapshot_attribute",
    ),
    (
        "EXP-005",
        envelope(
            make_event("rds.amazonaws.com", "ModifyDBInstance", {"dBInstanceIdentifier": "db", "publiclyAccessible": True})
        ),
        None,
    ),
    ("EXP-006", envelope(make_event("kms.amazonaws.com", "ScheduleKeyDeletion", {"keyId": "k1"})), "cancel_key_deletion"),
    ("EXP-006", envelope(make_event("kms.amazonaws.com", "DisableKey", {"keyId": "k1"})), "enable_key"),
    (
        "EXP-007",
        envelope(
            make_event(
                "lambda.amazonaws.com",
                "AddPermission20150331v2",
                {"functionName": "fn", "principal": "*", "statementId": "public"},
            )
        ),
        "remove_permission",
    ),
    (
        "IAM-001",
        envelope(
            make_event(
                "iam.amazonaws.com",
                "AttachUserPolicy",
                {"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            )
        ),
        "detach_user_policy",
    ),
    (
        "IAM-001",
        envelope(
            make_event(
                "iam.amazonaws.com",
                "AttachRolePolicy",
                {"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"},
            )
        ),
        "detach_role_policy",
    ),
    (
        "IAM-002",
        envelope(
            make_event(
                "iam.amazonaws.com", "PutUserPolicy", {"userName": "bob", "policyName": "x", "policyDocument": ADMIN_DOC}
            )
        ),
        "delete_user_policy",
    ),
    (
        "IAM-003",
        envelope(
            make_event(
                "iam.amazonaws.com",
                "CreateAccessKey",
                {"userName": "bob"},
                responseElements={"accessKey": {"accessKeyId": "AKIAEXAMPLE", "userName": "bob"}},
            )
        ),
        "update_access_key",
    ),
    ("IAM-004", envelope(make_event("iam.amazonaws.com", "CreateAccessKey", identity=ROOT)), None),
    ("IAM-005", envelope(make_event("iam.amazonaws.com", "UpdateLoginProfile", {"userName": "bob"})), None),
    (
        "IAM-006",
        envelope(make_event("iam.amazonaws.com", "DeactivateMFADevice", {"userName": "bob", "serialNumber": "mfa/bob"})),
        None,
    ),
    (
        "IAM-007",
        envelope(
            make_event(
                "iam.amazonaws.com",
                "UpdateAssumeRolePolicy",
                {"roleName": "app", "policyDocument": trust({"AWS": "arn:aws:iam::999988887777:root"})},
            )
        ),
        None,
    ),
    (
        "IAM-007",
        envelope(
            make_event(
                "iam.amazonaws.com", "CreateRole", {"roleName": "app", "assumeRolePolicyDocument": trust({"AWS": "*"})}
            )
        ),
        None,
    ),
    ("IAM-008", envelope(make_event("iam.amazonaws.com", "DeleteAccountPasswordPolicy")), None),
    (
        "IAM-008",
        envelope(make_event("iam.amazonaws.com", "UpdateAccountPasswordPolicy", {"minimumPasswordLength": 8})),
        None,
    ),
    ("IAM-009", envelope(make_event("organizations.amazonaws.com", "LeaveOrganization")), None),
    (
        "IAM-009",
        envelope(make_event("organizations.amazonaws.com", "LeaveOrganization", errorCode="AccessDenied")),
        None,
    ),
    ("ID-001", signin(ROOT, mfa="Yes"), None),
    ("ID-002", signin(IAM_USER), None),
    ("ID-003", signin(ROOT, result="Failure"), None),
    (
        "ID-004",
        envelope(make_event("ec2.amazonaws.com", "RunInstances", identity=ROOT), guardian_route="root"),
        None,
    ),
]

QUIET = [
    ("trail hardened", envelope(make_event("cloudtrail.amazonaws.com", "UpdateTrail", {"name": "main", "enableLogFileValidation": True}))),
    (
        "selectors keep management events",
        envelope(
            make_event(
                "cloudtrail.amazonaws.com",
                "PutEventSelectors",
                {"trailName": "main", "eventSelectors": [{"includeManagementEvents": True}]},
            )
        ),
    ),
    ("guardduty tuned, still on", envelope(make_event("guardduty.amazonaws.com", "UpdateDetector", {"detectorId": "d1", "findingPublishingFrequency": "ONE_HOUR"}))),
    (
        "public access block fully on",
        envelope(make_event("s3.amazonaws.com", "PutBucketPublicAccessBlock", {"bucketName": "b", "PublicAccessBlockConfiguration": PAB_ON})),
    ),
    ("private acl", envelope(make_event("s3.amazonaws.com", "PutBucketAcl", {"bucketName": "b", "x-amz-acl": ["private"]}))),
    (
        "bucket policy scoped by condition",
        envelope(
            make_event(
                "s3.amazonaws.com",
                "PutBucketPolicy",
                {
                    "bucketName": "b",
                    "bucketPolicy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "s3:GetObject",
                                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                            }
                        ]
                    },
                },
            )
        ),
    ),
    ("ssh from the office only", envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(ranges=OFFICE)))),
    ("https to the world", envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(lo=443, hi=443)))),
    ("udp 22 is not ssh", envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(protocol="udp")))),
    (
        "snapshot shared with one account",
        envelope(
            make_event(
                "ec2.amazonaws.com",
                "ModifySnapshotAttribute",
                {"snapshotId": "snap-1", "createVolumePermission": {"add": {"items": [{"userId": "999988887777"}]}}},
            )
        ),
    ),
    (
        "rds snapshot shared with one account",
        envelope(
            make_event(
                "rds.amazonaws.com",
                "ModifyDBSnapshotAttribute",
                {"dBSnapshotIdentifier": "s1", "attributeName": "restore", "valuesToAdd": ["999988887777"]},
            )
        ),
    ),
    ("private rds instance", envelope(make_event("rds.amazonaws.com", "CreateDBInstance", {"dBInstanceIdentifier": "db", "publiclyAccessible": False}))),
    (
        "lambda permission scoped to a source",
        envelope(
            make_event(
                "lambda.amazonaws.com",
                "AddPermission20150331v2",
                {"functionName": "fn", "principal": "*", "statementId": "s", "sourceArn": "arn:aws:s3:::b"},
            )
        ),
    ),
    (
        "read-only policy attached",
        envelope(
            make_event(
                "iam.amazonaws.com", "AttachUserPolicy", {"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
            )
        ),
    ),
    (
        "scoped inline policy",
        envelope(make_event("iam.amazonaws.com", "PutRolePolicy", {"roleName": "app", "policyName": "x", "policyDocument": SCOPED_DOC})),
    ),
    ("user rotates their own key", envelope(make_event("iam.amazonaws.com", "CreateAccessKey", {"userName": "alice"}))),
    ("user rotates own key, no username param", envelope(make_event("iam.amazonaws.com", "CreateAccessKey"))),
    ("user changes own password", envelope(make_event("iam.amazonaws.com", "UpdateLoginProfile", {"userName": "alice"}))),
    (
        "role trusted by a service",
        envelope(
            make_event(
                "iam.amazonaws.com",
                "CreateRole",
                {"roleName": "app", "assumeRolePolicyDocument": trust({"Service": "lambda.amazonaws.com"})},
            )
        ),
    ),
    (
        "role trusted by own account",
        envelope(
            make_event(
                "iam.amazonaws.com",
                "UpdateAssumeRolePolicy",
                {"roleName": "app", "policyDocument": trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})},
            )
        ),
    ),
    ("password policy strengthened", envelope(make_event("iam.amazonaws.com", "UpdateAccountPasswordPolicy", {"minimumPasswordLength": 16}))),
    ("iam user signs in with mfa", signin(IAM_USER, mfa="Yes")),
    ("sso session reports no mfa", signin(SSO_ROLE)),
    ("failed sign-in by a normal user", signin(IAM_USER, result="Failure")),
    ("denied attempt changed nothing", envelope(make_event("cloudtrail.amazonaws.com", "StopLogging", {"name": "main"}, errorCode="AccessDenied"))),
    (
        "service acting on behalf of root",
        envelope(
            make_event("kms.amazonaws.com", "Decrypt", identity={**ROOT, "invokedBy": "cloudtrail.amazonaws.com"}),
            guardian_route="root",
        ),
    ),
    ("normal user on the root route", envelope(make_event("ec2.amazonaws.com", "RunInstances"), guardian_route="root")),
]

ENFORCING = Settings(mode=ENFORCE)


@pytest.mark.parametrize("rule_id,env,expected_call", FIRES, ids=[f"{r}-{i}" for i, (r, _, _) in enumerate(FIRES)])
def test_rule_fires_and_remediates(rule_id, env, expected_call, clients, calls):
    findings = evaluate(env, ENFORCING, clients)
    fired = {f.rule_id: f for f in findings}
    assert rule_id in fired, f"{rule_id} did not fire; got {sorted(fired)}"
    finding = fired[rule_id]
    methods = [method for _, method, _ in calls]
    if expected_call is None:
        assert not finding.remediated
        assert finding.remediation.startswith("alert only")
    else:
        assert expected_call in methods
        assert finding.remediated


@pytest.mark.parametrize("label,env", QUIET, ids=[label for label, _ in QUIET])
def test_benign_event_is_quiet(label, env, clients, calls):
    assert evaluate(env, ENFORCING, clients) == []
    assert calls == []


def test_every_rule_has_a_firing_case():
    assert {r.id for r in ALL_RULES} == {rule_id for rule_id, _, _ in FIRES}


def test_rule_ids_are_unique_and_documented():
    ids = [r.id for r in ALL_RULES]
    assert len(ids) == len(set(ids))
    for rule in ALL_RULES:
        assert rule.title and rule.mitre
        assert bool(rule.remediate) == bool(rule.remediation), rule.id


def test_all_ports_rule_does_not_double_report(clients):
    env = envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", ingress(protocol="-1", lo=None, hi=None)))
    assert [f.rule_id for f in evaluate(env, ENFORCING, clients)] == ["NET-003"]


def test_revoke_only_touches_the_world_cidr(clients, calls):
    request = ingress(ranges={"items": [{"cidrIp": "0.0.0.0/0"}, {"cidrIp": "198.51.100.0/24"}]})
    evaluate(envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", request)), ENFORCING, clients)
    (_, method, kwargs), = calls
    assert method == "revoke_security_group_ingress"
    assert kwargs == {
        "GroupId": "sg-0abc",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }
