"""Data exposure and destruction: public snapshots, images, databases, functions and keys."""

from __future__ import annotations

from ..models import CRITICAL, HIGH, Clients, Detection, Rule
from ..util import as_list, items, params

EC2 = "ec2.amazonaws.com"
RDS = "rds.amazonaws.com"
KMS = "kms.amazonaws.com"
LAMBDA = "lambda.amazonaws.com"


def _adds_group_all(node) -> bool:
    return any(i.get("group") == "all" for i in items((node or {}).get("add")))


def snapshot_public(event: dict):
    p = params(event)
    if _adds_group_all(p.get("createVolumePermission")):
        return Detection(p.get("snapshotId", "unknown-snapshot"), "EBS snapshot shared with all AWS accounts")
    return None


def unshare_snapshot(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("ec2", event.get("awsRegion")).modify_snapshot_attribute(
        SnapshotId=detection.resource,
        Attribute="createVolumePermission",
        OperationType="remove",
        GroupNames=["all"],
    )
    return "removed public sharing from the snapshot"


def image_public(event: dict):
    p = params(event)
    if _adds_group_all(p.get("launchPermission")):
        return Detection(p.get("imageId", "unknown-image"), "AMI shared with all AWS accounts")
    return None


def unshare_image(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("ec2", event.get("awsRegion")).modify_image_attribute(
        ImageId=detection.resource, LaunchPermission={"Remove": [{"Group": "all"}]}
    )
    return "removed public launch permission from the AMI"


def ebs_default_encryption_disabled(event: dict):
    return Detection(event.get("awsRegion", "unknown-region"), "EBS encryption by default was disabled")


def enable_ebs_encryption(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("ec2", event.get("awsRegion")).enable_ebs_encryption_by_default()
    return "re-enabled EBS encryption by default"


def rds_snapshot_public(event: dict):
    p = params(event)
    if p.get("attributeName") != "restore" or "all" not in as_list(p.get("valuesToAdd")):
        return None
    cluster = p.get("dBClusterSnapshotIdentifier")
    name = cluster or p.get("dBSnapshotIdentifier", "unknown-snapshot")
    return Detection(name, "RDS snapshot shared with all AWS accounts", {"cluster": bool(cluster)})


def unshare_rds_snapshot(event: dict, detection: Detection, clients: Clients) -> str:
    rds = clients.get("rds", event.get("awsRegion"))
    if detection.context.get("cluster"):
        rds.modify_db_cluster_snapshot_attribute(
            DBClusterSnapshotIdentifier=detection.resource,
            AttributeName="restore",
            ValuesToRemove=["all"],
        )
    else:
        rds.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=detection.resource, AttributeName="restore", ValuesToRemove=["all"]
        )
    return "removed public restore permission from the RDS snapshot"


def rds_instance_public(event: dict):
    p = params(event)
    if p.get("publiclyAccessible") is True:
        return Detection(p.get("dBInstanceIdentifier", "unknown-instance"), "RDS instance set to publicly accessible")
    return None


def kms_key_disabled(event: dict):
    key = params(event).get("keyId", "unknown-key")
    if event["eventName"] == "ScheduleKeyDeletion":
        days = params(event).get("pendingWindowInDays")
        return Detection(key, f"KMS key scheduled for deletion in {days or 'the default 30'} days")
    return Detection(key, "KMS key was disabled")


def restore_kms_key(event: dict, detection: Detection, clients: Clients) -> str:
    kms = clients.get("kms", event.get("awsRegion"))
    if event["eventName"] == "ScheduleKeyDeletion":
        kms.cancel_key_deletion(KeyId=detection.resource)
    kms.enable_key(KeyId=detection.resource)  # a cancelled deletion leaves the key disabled
    return "cancelled deletion and re-enabled the key"


def lambda_public(event: dict):
    p = params(event)
    scoped = p.get("sourceArn") or p.get("sourceAccount") or p.get("principalOrgID")
    if p.get("principal") == "*" and not scoped:
        return Detection(
            p.get("functionName", "unknown-function"),
            "Lambda function can be invoked by anyone",
            {"statement_id": p.get("statementId")},
        )
    return None


def remove_lambda_permission(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("lambda", event.get("awsRegion")).remove_permission(
        FunctionName=detection.resource, StatementId=detection.context["statement_id"]
    )
    return "removed the public invoke permission"


RULES = [
    Rule(
        id="EXP-001",
        title="EBS snapshot made public",
        severity=CRITICAL,
        source=EC2,
        events=("ModifySnapshotAttribute",),
        mitre=("T1537",),
        evaluate=snapshot_public,
        remediate=unshare_snapshot,
        remediation="Remove public sharing",
    ),
    Rule(
        id="EXP-002",
        title="AMI made public",
        severity=HIGH,
        source=EC2,
        events=("ModifyImageAttribute",),
        mitre=("T1537",),
        evaluate=image_public,
        remediate=unshare_image,
        remediation="Remove the public launch permission",
    ),
    Rule(
        id="EXP-003",
        title="EBS encryption by default disabled",
        severity=HIGH,
        source=EC2,
        events=("DisableEbsEncryptionByDefault",),
        mitre=("T1562.001",),
        evaluate=ebs_default_encryption_disabled,
        remediate=enable_ebs_encryption,
        remediation="Re-enable EBS encryption by default",
    ),
    Rule(
        id="EXP-004",
        title="RDS snapshot made public",
        severity=CRITICAL,
        source=RDS,
        events=("ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"),
        mitre=("T1537",),
        evaluate=rds_snapshot_public,
        remediate=unshare_rds_snapshot,
        remediation="Remove the public restore permission",
    ),
    Rule(
        id="EXP-005",
        title="RDS instance made publicly accessible",
        severity=HIGH,
        source=RDS,
        events=("CreateDBInstance", "ModifyDBInstance"),
        mitre=("T1190",),
        evaluate=rds_instance_public,
    ),
    Rule(
        id="EXP-006",
        title="KMS key disabled or scheduled for deletion",
        severity=CRITICAL,
        source=KMS,
        events=("ScheduleKeyDeletion", "DisableKey"),
        mitre=("T1485",),
        evaluate=kms_key_disabled,
        remediate=restore_kms_key,
        remediation="Cancel the deletion and re-enable the key",
    ),
    Rule(
        id="EXP-007",
        title="Lambda function made publicly invokable",
        severity=HIGH,
        source=LAMBDA,
        events=("AddPermission20150331", "AddPermission20150331v2"),
        mitre=("T1190",),
        evaluate=lambda_public,
        remediate=remove_lambda_permission,
        remediation="Remove the public invoke permission",
    ),
]
