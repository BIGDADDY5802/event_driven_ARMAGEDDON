# ============================================================
# seir_soar_response_agent.tf — the analyst that acts on findings
# ============================================================

data "archive_file" "soar_response_agent_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/seir_soar_response_agent/soar_response_agent.py"
  output_path = "${path.module}/../build/seir_soar_response_agent.zip"
}

# ---- IAM -----------------------------------------------------
data "aws_iam_policy_document" "soar_response_agent_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "soar_response_agent" {
  name               = "soar-response-agent-role"
  assume_role_policy = data.aws_iam_policy_document.soar_response_agent_trust.json

  tags = {
    Lab = "SEIR-12A"
  }
}

data "aws_iam_policy_document" "soar_response_agent_permissions" {
  # claim_finding() and validate_finding() both read+update the
  # SAME finding row -- GetItem to read it, UpdateItem for the
  # atomic claim. Scoped to exactly this one table.
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.waf_correlation_findings.arn]
  }

  # create_incident() writes a new row here -- scoped to exactly
  # this one table, never the findings table.
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.security_incidents.arn]
  }

  # publish_notification() sends to exactly this one topic -- not
  # the critical-alerts topic, which EventBridge publishes to
  # directly without the Lambda's involvement at all.
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.soar_incidents.arn]
  }

  # Same two-grant CRIS pattern as both other Lambdas this session.
  statement {
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0"
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"]
  }

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
    resources = ["${aws_cloudwatch_log_group.soar_response_agent.arn}:*"]
  }
}

resource "aws_iam_role_policy" "soar_response_agent" {
  name   = "soar-response-agent-permissions"
  role   = aws_iam_role.soar_response_agent.id
  policy = data.aws_iam_policy_document.soar_response_agent_permissions.json
}

# ---- Log group -----------------------------------------------
resource "aws_cloudwatch_log_group" "soar_response_agent" {
  name              = "/aws/lambda/soar-response-agent"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "SEIR-12A"
  }
}

# ---- The Lambda itself ----------------------------------------
resource "aws_lambda_function" "soar_response_agent" {
  function_name = "soar-response-agent"
  role          = aws_iam_role.soar_response_agent.arn
  handler       = "soar_response_agent.lambda_handler"
  runtime       = "python3.13"
  timeout       = 60 # Bedrock call + a few DynamoDB round-trips
  memory_size   = 256

  filename         = data.archive_file.soar_response_agent_zip.output_path
  source_code_hash = data.archive_file.soar_response_agent_zip.output_base64sha256

  environment {
    variables = {
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.security_incidents.name
      SNS_TOPIC_ARN               = aws_sns_topic.soar_incidents.arn
      BEDROCK_MODEL_ID            = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      ENABLE_BEDROCK              = "true"
    }
  }

  depends_on = [aws_cloudwatch_log_group.soar_response_agent]

  tags = {
    Lab = "SEIR-12A"
  }
}
