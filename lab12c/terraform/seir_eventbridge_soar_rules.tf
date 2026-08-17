# ============================================================
# seir_eventbridge_soar_rules.tf — the routing table that decides
# who gets woken up for which severity
#
# THREE RULES (the original design doc only specified two --
# Medium/High and Critical -- Low was added by deliberate choice
# so RECORD_ONLY actually runs automatically instead of only ever
# being reachable through a manual invoke):
#   LOW              -> soar-response-agent only (RECORD_ONLY playbook)
#   MEDIUM, HIGH      -> soar-response-agent only
#   CRITICAL          -> soar-response-agent AND directly to the
#                        soar-critical-alerts SNS topic (the fan-out
#                        redundancy explained in
#                        seir_sns_soar_notifications.tf)
# ============================================================

resource "aws_cloudwatch_event_rule" "soar_low" {
  name           = "soar-low-severity-findings"
  description    = "Routes LOW severity findings to SOAR (RECORD_ONLY playbook)"
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["LOW"]
    }
  })

  tags = {
    Lab = "SEIR-12A"
  }
}

resource "aws_cloudwatch_event_rule" "soar_medium_high" {
  name           = "soar-medium-high-severity-findings"
  description    = "Routes MEDIUM/HIGH severity findings to SOAR"
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["MEDIUM", "HIGH"]
    }
  })

  tags = {
    Lab = "SEIR-12A"
  }
}

resource "aws_cloudwatch_event_rule" "soar_critical" {
  name           = "soar-critical-severity-findings"
  description    = "Routes CRITICAL severity findings to SOAR and directly to the critical-alert SNS topic"
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["CRITICAL"]
    }
  })

  tags = {
    Lab = "SEIR-12A"
  }
}

# ---- Lambda permissions: one per rule, each scoped to that rule's
# own ARN specifically, not "any rule on the bus" -----------------
resource "aws_lambda_permission" "soar_from_low_rule" {
  statement_id  = "AllowEventBridgeInvokeLow"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_response_agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.soar_low.arn
}

resource "aws_lambda_permission" "soar_from_medium_high_rule" {
  statement_id  = "AllowEventBridgeInvokeMediumHigh"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_response_agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.soar_medium_high.arn
}

resource "aws_lambda_permission" "soar_from_critical_rule" {
  statement_id  = "AllowEventBridgeInvokeCritical"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_response_agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.soar_critical.arn
}

# ---- Targets ---------------------------------------------------
resource "aws_cloudwatch_event_target" "soar_low" {
  rule           = aws_cloudwatch_event_rule.soar_low.name
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name
  target_id      = "soar-response-agent"
  arn            = aws_lambda_function.soar_response_agent.arn
}

resource "aws_cloudwatch_event_target" "soar_medium_high" {
  rule           = aws_cloudwatch_event_rule.soar_medium_high.name
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name
  target_id      = "soar-response-agent"
  arn            = aws_lambda_function.soar_response_agent.arn
}

# Critical rule fans out to TWO targets: the Lambda (same as the
# other two rules) AND directly to the critical-alerts SNS topic
# (see seir_sns_soar_notifications.tf for why that's deliberate
# redundancy, not duplication of SOAR's own SNS publish).
resource "aws_cloudwatch_event_target" "soar_critical_lambda" {
  rule           = aws_cloudwatch_event_rule.soar_critical.name
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name
  target_id      = "soar-response-agent"
  arn            = aws_lambda_function.soar_response_agent.arn
}

resource "aws_cloudwatch_event_target" "soar_critical_sns" {
  rule           = aws_cloudwatch_event_rule.soar_critical.name
  event_bus_name = aws_cloudwatch_event_bus.seir_security.name
  target_id      = "soar-critical-alerts-topic"
  arn            = aws_sns_topic.soar_critical_alerts.arn
}
