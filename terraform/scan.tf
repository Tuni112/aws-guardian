# ── Scheduled posture scan ───────────────────────────────────────────────────
# Finds risky configuration that already exists, which the event rules never
# see. It runs as its own function with its own read-only role, so the
# responder's role stays free of read access.

locals {
  scan = var.scan_schedule != ""
}

resource "aws_cloudwatch_log_group" "scan" {
  count             = local.scan ? 1 : 0
  name              = "/aws/lambda/${var.name}-scan"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "scan" {
  count              = local.scan ? 1 : 0
  name               = "${var.name}-scan"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Read-only. Every action is a call one check makes; none can change the
# account or read data stored in it.
data "aws_iam_policy_document" "scan" {
  count = local.scan ? 1 : 0

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scan[0].arn}:*"]
  }

  statement {
    sid       = "PublishReport"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid = "ReadIdentityPosture"
    actions = [
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "iam:ListUsers",
      "iam:GetLoginProfile",
      "iam:ListMFADevices",
      "iam:ListAccessKeys",
      "iam:ListEntitiesForPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ReadStoragePosture"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketPolicyStatus",
      "s3:GetAccountPublicAccessBlock",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ReadNetworkAndComputePosture"
    actions = [
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
      "ec2:DescribeFlowLogs",
      "ec2:DescribeSnapshots",
      "ec2:DescribeImages",
      "ec2:GetEbsEncryptionByDefault",
      "rds:DescribeDBInstances",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ReadLoggingAndDetectionPosture"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "guardduty:ListDetectors",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "scan" {
  count  = local.scan ? 1 : 0
  name   = "scan"
  role   = aws_iam_role.scan[0].id
  policy = data.aws_iam_policy_document.scan[0].json
}

resource "aws_lambda_function" "scan" {
  count            = local.scan ? 1 : 0
  function_name    = "${var.name}-scan"
  role             = aws_iam_role.scan[0].arn
  runtime          = "python3.12"
  handler          = "guardian.scan.lambda_handler"
  filename         = data.archive_file.guardian.output_path
  source_code_hash = data.archive_file.guardian.output_base64sha256
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      SCAN_REGIONS    = join(",", var.scan_regions)
    }
  }

  depends_on = [aws_cloudwatch_log_group.scan, aws_iam_role_policy.scan]
}

resource "aws_cloudwatch_event_rule" "scan" {
  count               = local.scan ? 1 : 0
  name                = "${var.name}-scan-schedule"
  description         = "Runs the ${var.name} posture scan"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "scan" {
  count = local.scan ? 1 : 0
  rule  = aws_cloudwatch_event_rule.scan[0].name
  arn   = aws_lambda_function.scan[0].arn
}

resource "aws_lambda_permission" "scan" {
  count         = local.scan ? 1 : 0
  statement_id  = "AllowScanSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan[0].arn
}
