# ============================================================
# seir_waf_correlation_agent.tf — the clerk that reads waf-events
# and writes waf-correlation-findings
#
# DELIBERATELY NO TRIGGER YET: this Lambda is deployed callable
# but nothing invokes it automatically. That's intentional --
# we already have 9 real rows sitting in waf-events from the
# analyzer smoke test, so the plan is to manually invoke this once
# against real data and confirm a real finding comes out the other
# end BEFORE wiring an EventBridge schedule that would run it every
# N minutes unattended. Smaller working example before scaling.
# ============================================================

data "archive_file" "waf_correlation_agent_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/seir_waf_correlation_agent/handler.py"
  output_path = "${path.module}/../build/seir_waf_correlation_agent.zip"
}

# ---- IAM ---------------------------------------------------------
data "aws_iam_policy_document" "waf_correlation_agent_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "waf_correlation_agent" {
  name               = "waf-correlation-agent-role"
  assume_role_policy = data.aws_iam_policy_document.waf_correlation_agent_trust.json

  tags = {
    Lab = "SEIR-12A"
  }
}

data "aws_iam_policy_document" "waf_correlation_agent_permissions" {
  # Read the raw events -- Scan, not Query, matching the Lambda's
  # own documented "first lab version" limitation. Scoped to
  # exactly the one table it reads.
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:Scan"]
    resources = [aws_dynamodb_table.waf_events.arn]
  }

  # Write findings AND the RUN# idempotency-lock items -- both go
  # through put_item against this same table. Also needs
  # UpdateItem? No -- claim_run() and save_finding() both only
  # ever call put_item on this table, never update_item, so
  # PutItem alone covers both code paths.
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.waf_correlation_findings.arn]
  }

  # Haiku 4.5 only supports invocation through a cross-Region
  # inference profile (confirmed via a live ValidationException),
  # not direct on-demand foundation-model invocation. That requires
  # TWO grants, matching AWS's own documented CRIS IAM pattern:

  # 1. Permission to invoke the specific inference profile itself,
  # scoped to this exact account and requesting region.
  statement {
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0"
    ]
  }

  # 2. Permission for the profile to actually reach the underlying
  # model in whichever US region it routes to. The region segment
  # is a wildcard HERE ONLY, and only because cross-Region
  # inference's entire purpose is routing across us-east-1/
  # us-east-2/us-west-2 to whichever has capacity -- the model ID
  # itself stays fully pinned to this one specific model, so this
  # is not a broad "any model, any region" grant, just the one
  # dimension CRIS structurally requires to be flexible.
  statement {
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"]
  }

  # 3. AWS Marketplace subscription permissions -- confirmed
  # required via a live AccessDeniedException: some Bedrock models
  # (including this one) are distributed through an AWS Marketplace
  # listing, and the FIRST invocation from any IAM role needs these
  # actions to auto-subscribe. This is genuinely different from the
  # rest of this file's least-privilege scoping: AWS's own IAM
  # documentation confirms aws-marketplace:Subscribe,
  # aws-marketplace:Unsubscribe, and aws-marketplace:ViewSubscriptions
  # do not support resource-level ARN scoping at all -- Resource
  # must be "*" for these three actions specifically, full stop.
  # The one narrowing lever available is restricting WHICH model can
  # be subscribed to via a Condition on aws-marketplace:ProductId
  # (Subscribe only) -- omitted here since finding the exact product
  # ID requires a console lookup under Bedrock's model access page.
  # Worth adding that condition later if you want the extra guardrail.
  statement {
    effect  = "Allow"
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
    resources = ["${aws_cloudwatch_log_group.waf_correlation_agent.arn}:*"]
  }

  # Publish the finding-created event that SOAR listens for.
  # Scoped to this ONE bus, not "events:*" on every bus in the
  # account.
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.seir_security.arn]
  }
}

resource "aws_iam_role_policy" "waf_correlation_agent" {
  name   = "waf-correlation-agent-permissions"
  role   = aws_iam_role.waf_correlation_agent.id
  policy = data.aws_iam_policy_document.waf_correlation_agent_permissions.json
}

# ---- Log group -----------------------------------------------------
resource "aws_cloudwatch_log_group" "waf_correlation_agent" {
  name              = "/aws/lambda/waf-correlation-agent"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "SEIR-12A"
  }
}

# ---- The Lambda itself ----------------------------------------------
resource "aws_lambda_function" "waf_correlation_agent" {
  function_name = "waf-correlation-agent"
  role          = aws_iam_role.waf_correlation_agent.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.13"

  # Higher than the analyzer's 30s: this Lambda does a Scan (up to
  # MAX_EVENTS=500 items, paginated) AND a Bedrock invocation in
  # the same execution, both slower than the analyzer's simple
  # parse-and-write.
  timeout     = 60
  memory_size = 256

  filename         = data.archive_file.waf_correlation_agent_zip.output_path
  source_code_hash = data.archive_file.waf_correlation_agent_zip.output_base64sha256

  environment {
    variables = {
      WAF_EVENTS_TABLE            = aws_dynamodb_table.waf_events.name
      CORRELATION_FINDINGS_TABLE  = aws_dynamodb_table.waf_correlation_findings.name
      CORRELATION_WINDOW_MINUTES  = "60"
      MINIMUM_EVENT_COUNT         = "3"
      ENABLE_BEDROCK              = "true"
      EVENT_BUS_NAME              = aws_cloudwatch_event_bus.seir_security.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.waf_correlation_agent]

  tags = {
    Lab = "SEIR-12A"
  }
}
