data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Generated from the rule registry: python -m guardian.manifest events
  manifest = jsondecode(file("${path.module}/events.json"))

  api_call = "AWS API Call via CloudTrail"
  signin   = "AWS Console Sign In via CloudTrail"
  enforce  = var.remediation_mode == "enforce"
}

# ── Alerts ───────────────────────────────────────────────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${var.name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── Lambda ───────────────────────────────────────────────────────────────────

data "archive_file" "guardian" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/guardian.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_cloudwatch_log_group" "guardian" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "guardian" {
  function_name    = var.name
  role             = aws_iam_role.guardian.arn
  runtime          = "python3.12"
  handler          = "guardian.handler.lambda_handler"
  filename         = data.archive_file.guardian.output_path
  source_code_hash = data.archive_file.guardian.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      REMEDIATION_MODE    = var.remediation_mode
      REMEDIATE_RULES     = join(",", var.remediate_rules)
      TRUSTED_PRINCIPALS  = join(",", var.trusted_principals)
      ALERT_TOPIC_ARN     = aws_sns_topic.alerts.arn
      GUARDIAN_ROLE_ARN   = aws_iam_role.guardian.arn
      FLOW_LOG_BUCKET_ARN = aws_s3_bucket.flow_logs.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.guardian]
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowGuardianEventRules"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardian.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:${local.partition}:events:${var.region}:${local.account_id}:rule/${var.name}-*"
}

# ── Event routing: one rule per service, built from the manifest ─────────────

resource "aws_cloudwatch_event_rule" "api" {
  for_each    = local.manifest.api
  name        = "${var.name}-${split(".", each.key)[0]}"
  description = "Risky ${split(".", each.key)[0]} API calls inspected by ${var.name}"

  event_pattern = jsonencode({
    "detail-type" = [local.api_call]
    detail = {
      eventSource = [each.key]
      eventName   = each.value
    }
  })
}

resource "aws_cloudwatch_event_target" "api" {
  for_each = aws_cloudwatch_event_rule.api
  rule     = each.value.name
  arn      = aws_lambda_function.guardian.arn
}

resource "aws_cloudwatch_event_rule" "signin" {
  name        = "${var.name}-signin"
  description = "Console sign-ins inspected by ${var.name}"

  event_pattern = jsonencode({
    "detail-type" = [local.signin]
    detail        = { eventName = local.manifest.signin }
  })
}

resource "aws_cloudwatch_event_target" "signin" {
  rule = aws_cloudwatch_event_rule.signin.name
  arn  = aws_lambda_function.guardian.arn
}

# Every API call made by the root user. The input transformer marks the event
# so the Lambda runs only the root rule for it, which avoids duplicate alerts
# when a root call also matches one of the per-service rules above.
resource "aws_cloudwatch_event_rule" "root" {
  name        = "${var.name}-root-activity"
  description = "Any API call by the root user"

  event_pattern = jsonencode({
    "detail-type" = [local.api_call]
    detail        = { userIdentity = { type = ["Root"] } }
  })
}

resource "aws_cloudwatch_event_target" "root" {
  rule = aws_cloudwatch_event_rule.root.name
  arn  = aws_lambda_function.guardian.arn

  input_transformer {
    input_paths    = { detail = "$.detail" }
    input_template = "{\"guardian_route\": \"root\", \"detail-type\": \"${local.api_call}\", \"detail\": <detail>}"
  }
}

# ── Cost guard ───────────────────────────────────────────────────────────────

resource "aws_budgets_budget" "monthly" {
  count        = var.monthly_budget_usd > 0 && var.alert_email != "" ? 1 : 0
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
