# ============================================================
# seir_eventbridge_correlation_schedule.tf — the alarm clock that
# wakes the Correlation Agent up on its own, no manual invoke
# ============================================================

resource "aws_cloudwatch_event_rule" "correlation_agent_schedule" {
  name                = "waf-correlation-agent-schedule"
  description         = "Triggers the Threat Correlation Agent on a fixed cadence"
  schedule_expression = "rate(15 minutes)"

  tags = {
    Lab = "SEIR-12A"
  }
}

# Without this, the rule above would be accepted by Terraform but
# every actual scheduled firing would fail silently with an
# access-denied error visible only in EventBridge's own internal
# delivery-failure metrics -- same lesson as the analyzer's
# CloudWatch Logs permission earlier this session.
resource "aws_lambda_permission" "correlation_agent_from_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_correlation_agent.function_name
  principal     = "events.amazonaws.com"

  # Scoped to THIS specific rule only, not "any EventBridge rule
  # in the account."
  source_arn = aws_cloudwatch_event_rule.correlation_agent_schedule.arn
}

resource "aws_cloudwatch_event_target" "correlation_agent" {
  rule      = aws_cloudwatch_event_rule.correlation_agent_schedule.name
  target_id = "waf-correlation-agent"
  arn       = aws_lambda_function.waf_correlation_agent.arn
}
