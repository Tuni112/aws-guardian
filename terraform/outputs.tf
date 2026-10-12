output "lambda_function" {
  value = aws_lambda_function.guardian.function_name
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "log_group" {
  value = aws_cloudwatch_log_group.guardian.name
}

output "event_rules" {
  value = concat(
    [for r in aws_cloudwatch_event_rule.api : r.name],
    [aws_cloudwatch_event_rule.signin.name, aws_cloudwatch_event_rule.root.name],
  )
}

output "remediation_mode" {
  value = var.remediation_mode
}

output "scan_function" {
  value = local.scan ? aws_lambda_function.scan[0].function_name : null
}
