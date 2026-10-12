# Detections

Generated from the rule registry with `python -m guardian.manifest markdown`. Do not edit by hand.

35 rules.

| ID | Detection | Severity | ATT&CK | Trigger | Automatic response |
|---|---|---|---|---|---|
| LOG-001 | CloudTrail logging stopped | CRITICAL | T1562.008 | cloudtrail: StopLogging | Restart logging on the trail |
| LOG-002 | CloudTrail trail deleted | CRITICAL | T1562.008 | cloudtrail: DeleteTrail | Alert only |
| LOG-003 | CloudTrail trail weakened | HIGH | T1562.008 | cloudtrail: UpdateTrail | Alert only |
| LOG-004 | CloudTrail management events excluded | HIGH | T1562.008 | cloudtrail: PutEventSelectors | Alert only |
| LOG-005 | GuardDuty disabled or deleted | CRITICAL | T1562.001 | guardduty: DeleteDetector, UpdateDetector | Re-enable the detector |
| LOG-006 | AWS Config recorder stopped or deleted | HIGH | T1562.001 | config: StopConfigurationRecorder, DeleteConfigurationRecorder | Restart the recorder |
| LOG-007 | VPC flow logs deleted | HIGH | T1562.008 | ec2: DeleteFlowLogs | Alert only |
| LOG-008 | VPC created without flow logs | MEDIUM | T1562.008 | ec2: CreateVpc, CreateDefaultVpc | Enable flow logs for all traffic to the Guardian log bucket |
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

## Posture checks

Run on a schedule against the account's current state, to find what was already
misconfigured before the event rules above were deployed. Read-only: they report, never fix.

16 checks.

| ID | Check | Severity | ATT&CK | Scope | Recommended fix |
|---|---|---|---|---|---|
| POS-001 | Root user has no MFA | CRITICAL | T1078.004 | account | Assign an MFA device to the root user |
| POS-002 | Root user has access keys | CRITICAL | T1078.004 | account | Delete the root access keys |
| POS-003 | Console user without MFA | HIGH | T1078.004 | account | Require MFA for the user or remove its console password |
| POS-004 | Access key older than 90 days | MEDIUM | T1078.004 | account | Rotate or delete the key |
| POS-005 | Administrator access attached directly to a user | HIGH | T1098.003 | account | Grant admin through a role the user assumes with MFA |
| POS-006 | Account password policy missing or weak | MEDIUM | T1556 | account | Set a password policy with a minimum length of 14 |
| POS-007 | Account-level S3 public access block missing | HIGH | T1530 | account | Turn on all four account-level public access block settings |
| POS-008 | S3 bucket is public | CRITICAL | T1530 | account | Remove the public statement from the bucket policy |
| POS-009 | No CloudTrail trail is logging | CRITICAL | T1562.008 | account | Create a multi-region trail and start logging |
| POS-010 | Security group open to the internet | CRITICAL | T1190 | every region | Restrict the ingress rule to known addresses |
| POS-011 | VPC without flow logs | MEDIUM | T1562.008 | every region | Enable flow logs for the VPC |
| POS-012 | EBS encryption by default is off | MEDIUM | T1562.001 | every region | Enable EBS encryption by default in the region |
| POS-013 | GuardDuty is not enabled | MEDIUM | T1562.001 | every region | Enable GuardDuty in the region |
| POS-014 | EBS snapshot is public | CRITICAL | T1537 | every region | Remove public sharing from the snapshot |
| POS-015 | AMI is public | HIGH | T1537 | every region | Make the image private |
| POS-016 | RDS instance is publicly accessible | HIGH | T1190 | every region | Turn off public accessibility for the instance |
