variable "name" {
  description = "Prefix for every resource this module creates."
  type        = string
  default     = "aws-guardian"
}

variable "region" {
  description = "Region to deploy into. IAM, root and most sign-in events are only delivered in us-east-1."
  type        = string
  default     = "us-east-1"
}

variable "remediation_mode" {
  description = "off: alert only. dry_run: alert and say what would be fixed. enforce: alert and fix."
  type        = string
  default     = "dry_run"

  validation {
    condition     = contains(["off", "dry_run", "enforce"], var.remediation_mode)
    error_message = "remediation_mode must be off, dry_run or enforce."
  }
}

variable "remediate_rules" {
  description = "Rule ids allowed to auto-remediate in enforce mode, or [\"all\"]."
  type        = list(string)
  default     = ["all"]
}

variable "trusted_principals" {
  description = "IAM ARNs (users, or the role behind an assumed-role session) whose changes are never flagged, such as a deployment pipeline."
  type        = list(string)
  default     = []
}

variable "alert_email" {
  description = "Address subscribed to alerts and the budget alarm. Leave empty to skip both subscriptions."
  type        = string
  default     = ""
}

variable "create_trail" {
  description = "Create a multi-region CloudTrail trail. EventBridge only receives API events while a trail is logging, so set this to false only if the account already has one."
  type        = bool
  default     = true
}

variable "monthly_budget_usd" {
  description = "Monthly account budget; an email is sent at 80% of it. Set to 0 to skip the budget."
  type        = number
  default     = 5
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "scan_schedule" {
  description = "How often the posture scan runs, as an EventBridge schedule expression. Set to \"\" to leave the scan out."
  type        = string
  default     = "rate(24 hours)"
}

variable "scan_regions" {
  description = "Regions the posture scan covers. Empty means every region enabled in the account."
  type        = list(string)
  default     = []
}
