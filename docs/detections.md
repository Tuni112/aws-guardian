# Detections

Generated from the rule registry with `python -m guardian.manifest markdown`. Do not edit by hand.

34 rules.

| ID | Detection | Severity | ATT&CK | Trigger | Automatic response |
|---|---|---|---|---|---|
| LOG-001 | CloudTrail logging stopped | CRITICAL | T1562.008 | cloudtrail: StopLogging | Restart logging on the trail |
| LOG-002 | CloudTrail trail deleted | CRITICAL | T1562.008 | cloudtrail: DeleteTrail | Alert only |
| LOG-003 | CloudTrail trail weakened | HIGH | T1562.008 | cloudtrail: UpdateTrail | Alert only |
| LOG-004 | CloudTrail management events excluded | HIGH | T1562.008 | cloudtrail: PutEventSelectors | Alert only |
| LOG-005 | GuardDuty disabled or deleted | CRITICAL | T1562.001 | guardduty: DeleteDetector, UpdateDetector | Re-enable the detector |
| LOG-006 | AWS Config recorder stopped or deleted | HIGH | T1562.001 | config: StopConfigurationRecorder, DeleteConfigurationRecorder | Restart the recorder |
| LOG-007 | VPC flow logs deleted | HIGH | T1562.008 | ec2: DeleteFlowLogs | Alert only |
| S3-001 | S3 bucket public access block removed | HIGH | T1530 | s3: PutBucketPublicAccessBlock, DeleteBucketPublicAccessBlock | Re-apply the bucket public access block |
| S3-002 | S3 bucket ACL made public | CRITICAL | T1530 | s3: PutBucketAcl | Reset the bucket ACL to private |
| S3-003 | S3 bucket policy allows everyone | CRITICAL | T1530 | s3: PutBucketPolicy | Re-apply the bucket public access block, which overrides the public policy |
| S3-004 | Account-level S3 public access block removed | CRITICAL | T1530 | s3: PutAccountPublicAccessBlock, DeleteAccountPublicAccessBlock | Re-apply the account-level public access block |
| NET-001 | Security group opens SSH or RDP to the internet | CRITICAL | T1562.007 | ec2: AuthorizeSecurityGroupIngress | Revoke the offending ingress rules, leaving the rest of the group intact |
| NET-002 | Security group opens a database port to the internet | HIGH | T1562.007 | ec2: AuthorizeSecurityGroupIngress | Revoke the offending ingress rules, leaving the rest of the group intact |
| NET-003 | Security group opens all ports to the internet | CRITICAL | T1562.007 | ec2: AuthorizeSecurityGroupIngress | Revoke the offending ingress rules, leaving the rest of the group intact |
| EXP-001 | EBS snapshot made public | CRITICAL | T1537 | ec2: ModifySnapshotAttribute | Remove public sharing |
| EXP-002 | AMI made public | HIGH | T1537 | ec2: ModifyImageAttribute | Remove the public launch permission |
| EXP-003 | EBS encryption by default disabled | HIGH | T1562.001 | ec2: DisableEbsEncryptionByDefault | Re-enable EBS encryption by default |
| EXP-004 | RDS snapshot made public | CRITICAL | T1537 | rds: ModifyDBSnapshotAttribute, ModifyDBClusterSnapshotAttribute | Remove the public restore permission |
| EXP-005 | RDS instance made publicly accessible | HIGH | T1190 | rds: CreateDBInstance, ModifyDBInstance | Alert only |
| EXP-006 | KMS key disabled or scheduled for deletion | CRITICAL | T1485 | kms: ScheduleKeyDeletion, DisableKey | Cancel the deletion and re-enable the key |
| EXP-007 | Lambda function made publicly invokable | HIGH | T1190 | lambda: AddPermission20150331, AddPermission20150331v2 | Remove the public invoke permission |
| IAM-001 | Administrator policy attached to a user, role or group | CRITICAL | T1098.003 | iam: AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy | Detach the policy |
| IAM-002 | Inline policy grants full administrator access | CRITICAL | T1098.003 | iam: PutUserPolicy, PutRolePolicy, PutGroupPolicy | Delete the inline policy |
| IAM-003 | Access key created for another user | HIGH | T1098.001 | iam: CreateAccessKey | Deactivate the new key |
| IAM-004 | Root user access key created | CRITICAL | T1098.001 | iam: CreateAccessKey | Alert only |
| IAM-005 | Console password set for another user | HIGH | T1098 | iam: CreateLoginProfile, UpdateLoginProfile | Alert only |
| IAM-006 | MFA device deactivated | HIGH | T1556.006 | iam: DeactivateMFADevice | Alert only |
| IAM-007 | Role trust policy allows an external account | HIGH | T1098.003 | iam: UpdateAssumeRolePolicy, CreateRole | Alert only |
| IAM-008 | Account password policy weakened or deleted | MEDIUM | T1556 | iam: DeleteAccountPasswordPolicy, UpdateAccountPasswordPolicy | Alert only |
| IAM-009 | Attempt to leave the AWS Organization | CRITICAL | T1666 | organizations: LeaveOrganization | Alert only |
| ID-001 | Root user console sign-in | CRITICAL | T1078.004 | signin: ConsoleLogin | Alert only |
| ID-002 | Console sign-in without MFA | MEDIUM | T1078.004 | signin: ConsoleLogin | Alert only |
| ID-003 | Failed root console sign-in | HIGH | T1110 | signin: ConsoleLogin | Alert only |
| ID-004 | Root user API activity | HIGH | T1078.004 | any API call by the root user | Alert only |
