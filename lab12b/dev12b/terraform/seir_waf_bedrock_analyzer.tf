# ============================================================
# seir_waf_bedrock_analyzer.tf — the pull-based, per-event
# Bedrock analyzer required by the lab 12 spec
#
# REPLACES seir_waf_analyzer_push.tf entirely. That file's
# resources (a CloudWatch Logs subscription filter, its Lambda
# permission, and the push-triggered Lambda) should be DELETED
# from your terraform/ directory -- this is a genuine architecture
# swap, not an addition alongside the old one. Remove that file and
# its matching lambda/seir_waf_analyzer_push/ directory.
# ============================================================

data "archive_file" "waf_bedrock_analyzer_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/seir_waf_bedrock_analyzer/waf_bedrock_analyzer.py"
  output_path = "${path.module}/../build/seir_waf_bedrock_analyzer.zip"
}

# ---- IAM -----------------------------------------------------
data "aws_iam_policy_document" "waf_bedrock_analyzer_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "waf_bedrock_analyzer" {
  name               = "waf-bedrock-analyzer-role"
  assume_role_policy = data.aws_iam_policy_document.waf_bedrock_analyzer_trust.json

  tags = {
    Lab = "SEIR-12A"
  }
}

data "aws_iam_policy_document" "waf_bedrock_analyzer_permissions" {
  # Read raw WAF log lines -- scoped to exactly the one log group
  # this Lambda pulls from, not "logs:*" account-wide.
  statement {
    effect    = "Allow"
    actions   = ["logs:FilterLogEvents"]
    resources = ["${aws_cloudwatch_log_group.waf.arn}:*"]
  }

  # Write normalized events -- scoped to exactly this one table.
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.waf_events.arn]
  }

  # Bedrock, via cross-Region inference profile -- same two-grant
  # pattern learned the hard way on the Correlation Agent. Grant 1:
  # the profile itself, scoped to this account+region.
  statement {
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0"
    ]
  }

  # Grant 2: the underlying model in whichever US region the
  # profile routes to. Region wildcard here is structurally
  # required by how cross-Region inference works, not a shortcut --
  # the model ID itself stays fully pinned.
  statement {
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"]
  }

  # AWS Marketplace subscription actions -- confirmed required via
  # a live AccessDeniedException on the Correlation Agent. These
  # three actions do not support resource-level ARN scoping at all
  # per AWS's own IAM documentation; Resource "*" is the only valid
  # option for them specifically.
  statement {
    effect = "Allow"
    actions = [
      "aws-marketplace:Subscribe",
      "aws-marketplace:Unsubscribe",
      "aws-marketplace:ViewSubscriptions",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.waf_bedrock_analyzer.arn}:*"]
  }
}

resource "aws_iam_role_policy" "waf_bedrock_analyzer" {
  name   = "waf-bedrock-analyzer-permissions"
  role   = aws_iam_role.waf_bedrock_analyzer.id
  policy = data.aws_iam_policy_document.waf_bedrock_analyzer_permissions.json
}

# ---- Log group -----------------------------------------------
resource "aws_cloudwatch_log_group" "waf_bedrock_analyzer" {
  name              = "/aws/lambda/waf-bedrock-analyzer"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "SEIR-12A"
  }
}

# ---- The Lambda itself ------------------------------------------
resource "aws_lambda_function" "waf_bedrock_analyzer" {
  function_name = "waf-bedrock-analyzer"
  role          = aws_iam_role.waf_bedrock_analyzer.arn
  handler       = "waf_bedrock_analyzer.lambda_handler"
  runtime       = "python3.13"

  # Generous timeout: MAX_LOG_EVENTS=500 sequential per-event
  # Bedrock calls could, in the worst case, exceed even 5 minutes.
  # TRACKED GAP, not fixed here (matches the codebase's existing
  # GAP-N convention): under real production volume this would
  # need fan-out (SQS + concurrent Lambda invocations, or Step
  # Functions) instead of one Lambda looping sequentially. Fine for
  # lab-scale curl-loop traffic, a real scaling limit beyond that.
  timeout     = 300
  memory_size = 256

  filename         = data.archive_file.waf_bedrock_analyzer_zip.output_path
  source_code_hash = data.archive_file.waf_bedrock_analyzer_zip.output_base64sha256

  environment {
    variables = {
      WAF_LOG_GROUP    = aws_cloudwatch_log_group.waf.name
      DYNAMODB_TABLE   = aws_dynamodb_table.waf_events.name
      BEDROCK_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      LOOKBACK_MINUTES = "10"
      MAX_LOG_EVENTS   = "500"
    }
  }

  depends_on = [aws_cloudwatch_log_group.waf_bedrock_analyzer]

  tags = {
    Lab = "SEIR-12A"
  }
}

# ---- Schedule: pull-based means it needs its own alarm clock ----
resource "aws_cloudwatch_event_rule" "waf_bedrock_analyzer_schedule" {
  name                = "waf-bedrock-analyzer-schedule"
  description         = "Triggers the WAF Bedrock Analyzer on a fixed cadence"
  schedule_expression = "rate(5 minutes)"

  tags = {
    Lab = "SEIR-12A"
  }
}

resource "aws_lambda_permission" "waf_bedrock_analyzer_from_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_bedrock_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.waf_bedrock_analyzer_schedule.arn
}

resource "aws_cloudwatch_event_target" "waf_bedrock_analyzer" {
  rule      = aws_cloudwatch_event_rule.waf_bedrock_analyzer_schedule.name
  target_id = "waf-bedrock-analyzer"
  arn       = aws_lambda_function.waf_bedrock_analyzer.arn
}
