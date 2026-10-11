data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "guardian" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Always granted: write its own logs and publish alerts. Nothing else.
data "aws_iam_policy_document" "base" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.guardian.arn}:*"]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "base" {
  name   = "base"
  role   = aws_iam_role.guardian.id
  policy = data.aws_iam_policy_document.base.json
}

# Granted only in enforce mode. Each action is a call one rule's remediation
# makes. There are no wildcard actions, and the only read is the flow log
# lookup that stops Guardian enabling flow logs twice on the same VPC.
data "aws_iam_policy_document" "remediate" {
  statement {
    sid = "RestoreLoggingAndDetection"
    actions = [
      "cloudtrail:StartLogging",
      "guardduty:UpdateDetector",
      "config:StartConfigurationRecorder",
    ]
    resources = ["*"]
  }

  statement {
    sid = "EnableVpcFlowLogs"
    actions = [
      "ec2:DescribeFlowLogs",
      "ec2:CreateFlowLogs",
      "logs:CreateLogDelivery",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CloseS3Exposure"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketAcl",
      "s3:PutAccountPublicAccessBlock",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CloseComputeAndDataExposure"
    actions = [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:ModifySnapshotAttribute",
      "ec2:ModifyImageAttribute",
      "ec2:EnableEbsEncryptionByDefault",
      "rds:ModifyDBSnapshotAttribute",
      "rds:ModifyDBClusterSnapshotAttribute",
      "lambda:RemovePermission",
      "kms:CancelKeyDeletion",
      "kms:EnableKey",
    ]
    resources = ["*"]
  }

  statement {
    sid = "RevokeIamEscalation"
    actions = [
      "iam:DetachUserPolicy",
      "iam:DetachRolePolicy",
      "iam:DetachGroupPolicy",
      "iam:DeleteUserPolicy",
      "iam:DeleteRolePolicy",
      "iam:DeleteGroupPolicy",
      "iam:UpdateAccessKey",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediate" {
  count  = local.enforce ? 1 : 0
  name   = "remediate"
  role   = aws_iam_role.guardian.id
  policy = data.aws_iam_policy_document.remediate.json
}
