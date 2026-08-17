# ============================================================
# waf.tf — the web ACL, its rules, its association, its logs
#
# ANALOGY: a web ACL is a bouncer with a rulebook. Requests walk
# up in priority order; the first rule that decides wins. A rule
# can say BLOCK, ALLOW, or COUNT ("write it down, let them in").
# default_action is what happens if no rule fires.
#
# We use default_action = allow: block only what the rules
# recognise as bad. The opposite (default deny) is stronger but
# requires you to enumerate every legitimate request first — a
# different project.
# ============================================================

resource "aws_wafv2_web_acl" "intake" {
  name        = "chewbacca-11a-intake-acl"
  description = "Baseline managed rules + rate limiting for the intake API"
  scope       = "REGIONAL" # REGIONAL for API Gateway/ALB; CLOUDFRONT only for CloudFront

  default_action {
    allow {}
  }

  # ---------------------------------------------------------------
  # Rule 1 — rate limiting. Deliberately FIRST.
  #
  # Priority is evaluated low-to-high. Rate limiting goes first
  # because a flood should be cut off before you spend compute
  # inspecting each request against SQLi signatures.
  # ---------------------------------------------------------------
  rule {
    name     = "RateLimitPerIP"
    priority = 0

    action {
      block {}
    }

    statement {
      rate_based_statement {
        # Requests per rolling 5-minute window, per source IP.
        # A tunable, not an identifier — so a variable is correct
        # here, and it carries a validation rule (AWS minimum 100).
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------
  # Rule 2 — AWS managed common rule set (OWASP-ish baseline:
  # XSS, path traversal, oversized bodies, bad user agents).
  # ---------------------------------------------------------------
  rule {
    name     = "AWSCommonRuleSet"
    priority = 1

    # override_action = none means "use whatever the managed group
    # says to do". Use `count {}` instead when you first deploy to
    # production, so you can measure false positives before you
    # start rejecting real users.
    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # A JSON intake endpoint legitimately posts larger bodies
        # than this rule's default limit. Left enabled here so you
        # can SEE it fire; flip to a rule_action_override if it
        # blocks real submissions.
        #
        # rule_action_override {
        #   name = "SizeRestrictions_BODY"
        #   action_to_use { count {} }
        # }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------
  # Rule 3 — known bad inputs (exploit payloads, log4j patterns,
  # host-header injection).
  # ---------------------------------------------------------------
  rule {
    name     = "AWSKnownBadInputs"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSKnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------
  # Rule 4 — SQL injection. This endpoint writes to MySQL, so this
  # is the rule with the most direct relevance to the backend.
  # ---------------------------------------------------------------
  rule {
    name     = "AWSSQLiRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Metrics for the ACL as a whole (AllowedRequests / BlockedRequests)
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "chewbacca11aIntakeAcl"
    sampled_requests_enabled   = true
  }

  tags = {
    Lab     = "SEIR-I-11A"
    Purpose = "api-edge-protection"
  }
}

# ============================================================
# Association — bolt the bouncer to the door
#
# resource_arn must be a REST API *stage* ARN. This is the line
# that would fail with an HTTP API: there is no supported ARN to
# put here.
# ============================================================
resource "aws_wafv2_web_acl_association" "intake" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.intake.arn
}

# ============================================================
# Logging — per-request ALLOW/BLOCK evidence
#
# HARD REQUIREMENT: the log group name must start with
# "aws-waf-logs-". AWS rejects any other name for WAF logging.
# ============================================================
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-chewbacca-11a-intake"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "SEIR-I-11A"
  }
}

# CloudWatch Logs needs a resource policy permitting the log
# delivery service to write. The console creates this silently;
# via API/Terraform you must declare it or logging fails with an
# unhelpful permissions error.
data "aws_iam_policy_document" "waf_logs" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.waf.arn}:*"]

    # Confused-deputy guard: only OUR account's log delivery can
    # use this permission, not any AWS customer's.
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf_logs" {
  policy_name     = "chewbacca-11a-waf-logs"
  policy_document = data.aws_iam_policy_document.waf_logs.json
}

resource "aws_wafv2_web_acl_logging_configuration" "intake" {
  resource_arn            = aws_wafv2_web_acl.intake.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  # WAF logs the full request. On a healthcare intake endpoint that
  # means PHI could land in logs. Redaction is not optional here —
  # it is the difference between an audit log and a data leak.
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  depends_on = [aws_cloudwatch_log_resource_policy.waf_logs]
}

# ---- Alarm: someone is being blocked ------------------------------
# Reuses the 11B SNS topic. A spike in blocks is either an attack or
# a false positive rejecting real patients — both need a human.
resource "aws_cloudwatch_metric_alarm" "waf_blocked" {
  alarm_name        = "seir-11a-waf-blocked-requests"
  alarm_description = "WAF is blocking requests to the intake API"

  namespace   = "AWS/WAFV2"
  metric_name = "BlockedRequests"
  dimensions = {
    WebACL = aws_wafv2_web_acl.intake.name
    Region = data.aws_region.current.name
    Rule   = "ALL"
  }

  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.incidents.arn]
  ok_actions    = [aws_sns_topic.incidents.arn]

  tags = {
    Lab = "SEIR-I-11A"
  }
}
