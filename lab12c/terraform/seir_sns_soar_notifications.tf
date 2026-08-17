# ============================================================
# seir_sns_soar_notifications.tf — the two loudspeakers SOAR uses
#
# TWO SEPARATE TOPICS, matching the original design doc exactly:
#   - soar-incident-notifications: SOAR's Lambda publishes here
#     itself, for every Medium/High/Critical playbook that has
#     notify=True.
#   - soar-critical-alerts: EventBridge publishes here DIRECTLY,
#     bypassing the Lambda entirely, the instant a CRITICAL-severity
#     event lands on the bus -- see seir_eventbridge_soar_rules.tf.
#     This is deliberate redundancy: a critical alert reaches
#     someone even if the Lambda itself is broken, throttled, or
#     mid-cold-start.
#
# NEW topics, not reused from Lab 11B's aws_sns_topic.incidents --
# same state-separation-by-naming discipline as everything else
# prefixed seir_ in this directory.
# ============================================================

resource "aws_sns_topic" "soar_incidents" {
  name = "soar-incident-notifications"

  tags = {
    Lab = "SEIR-12A"
  }
}

resource "aws_sns_topic" "soar_critical_alerts" {
  name = "soar-critical-alerts"

  tags = {
    Lab = "SEIR-12A"
  }
}

# Reusing the same alarm_email variable Lab 11B's monitoring.tf
# already uses -- one email address, one place it's declared.
resource "aws_sns_topic_subscription" "soar_incidents_email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.soar_incidents.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_sns_topic_subscription" "soar_critical_alerts_email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.soar_critical_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---- Resource policy: let EventBridge publish directly ----------
# Without this, EventBridge's attempt to deliver a matching event
# straight to this SNS topic (as a rule TARGET, not via the Lambda)
# fails silently -- same lesson as every other cross-service
# permission this session. Scoped via Condition to the ONE specific
# rule ARN that will target this topic, not "any EventBridge rule
# in the account."
data "aws_iam_policy_document" "soar_critical_alerts_policy" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.soar_critical_alerts.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.soar_critical.arn]
    }
  }
}

resource "aws_sns_topic_policy" "soar_critical_alerts" {
  arn    = aws_sns_topic.soar_critical_alerts.arn
  policy = data.aws_iam_policy_document.soar_critical_alerts_policy.json
}
