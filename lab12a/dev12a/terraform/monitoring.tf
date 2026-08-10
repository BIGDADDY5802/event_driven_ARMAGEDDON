# ============================================================
# monitoring.tf — Smoke detectors
#
# Human notes question #6 asks: "What would you monitor next
# time to catch this faster?" This file IS that answer,
# written as code.
#
# ANALOGY: You don't discover a kitchen fire by waiting for a
# guest to complain about the smell. You install smoke
# detectors. Two detectors here:
#   1. Lambda Errors  — the cook is dropping pans
#   2. API 5xx        — guests are being told "kitchen closed"
# ============================================================

# ---- Optional alert channel (SNS = the loudspeaker) --------
resource "aws_sns_topic" "incidents" {
  name = "seir-11b-incident-alerts"

  tags = {
    Lab = "SEIR-I-11B"
  }
}

# Only subscribe an email if one was provided.
# count = 0 means "build zero of these" — Terraform's if-statement.
resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.incidents.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---- Detector 1: Lambda is throwing errors ------------------
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name        = "seir-11b-${var.lambda_name}-errors"
  alarm_description = "Lab 11B: Lambda reported errors (e.g., cannot reach RDS)"

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  dimensions = {
    FunctionName = var.lambda_name
  }

  statistic           = "Sum"
  period              = 60 # look at 1-minute buckets
  evaluation_periods  = 1  # one bad minute is enough
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"

  # "notBreaching" = no data means healthy (a quiet Lambda is
  # a happy Lambda, not a missing one).
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.incidents.arn]
  ok_actions    = [aws_sns_topic.incidents.arn]

  tags = {
    Lab = "SEIR-I-11B"
  }
}

# ---- Detector 2: API is returning 5xx to clients ------------
#
# HISTORY NOTE: this alarm originally watched the HTTP API (v2)
# from Lab 11A, using the {ApiId, Stage} dimension pair that
# metric shape requires. The HTTP API has been retired in favor
# of the REST API + WAF front door (see rest_api.tf), and REST
# APIs report CloudWatch metrics under a DIFFERENT dimension
# pair: {ApiName, Stage} — not ApiId. Repointed accordingly.
resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name        = "seir-11b-api-${aws_api_gateway_rest_api.waf_front.id}-5xx"
  alarm_description = "Lab 11B: API Gateway returning server errors to clients"

  namespace   = "AWS/ApiGateway"
  metric_name = "5xx"
  dimensions = {
    ApiName = aws_api_gateway_rest_api.waf_front.name
    Stage   = var.stage_name
  }

  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.incidents.arn]
  ok_actions    = [aws_sns_topic.incidents.arn]

  tags = {
    Lab = "SEIR-I-11B"
  }
}
