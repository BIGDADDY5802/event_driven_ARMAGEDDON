# ============================================================
# compliance_agent_lambda.tf — Agent 9, the Compliance Agent
#
# NAMING: install.md resolves the compliance_agent.py vs
# compliance.py mismatch itself - the repository file is
# lambda/compliance.py, so that's the source_file and handler
# referenced below.
#
# BEDROCK: install.md's own default is Claude 3 Haiku direct-invoke,
# with a matching IAM statement. Deliberately NOT followed here -
# same reasoning report_executive_lambda.tf already documents: CRIS
# Haiku 4.5, for IAM consistency across all five Bedrock-calling
# Lambdas in this stack now, rather than a sixth invocation pattern.
#
# BUCKET: install.md's Step 2 creates a new bucket
# (chewbacca-s3-<account_id>). Deliberately NOT followed - reusing
# aws_s3_bucket.executive_reports (already encrypted, already
# public-access-blocked) under a new compliance-reports/ prefix
# instead of standing up a second bucket's worth of the same
# boilerplate to maintain.
# ============================================================

# ---- Packaging ----------------------------------------------
# Same platform-targeting fix report_executive_lambda.tf already
# proved necessary: ReportLab pulls Pillow as a transitive
# dependency, and Pillow ships compiled platform-specific wheels.
# A plain `pip install` on Windows/Git Bash silently grabs Windows
# .pyd binaries that crash on import inside Lambda's Linux runtime.
resource "null_resource" "build_compliance_agent_pkg" {
  triggers = {
    handler_hash      = filesha256("${path.module}/../lab12c/compliance_agent/lambda/compliance.py")
    controls_hash     = filesha256("${path.module}/../lab12c/compliance_agent/json/controls.json")
    requirements_hash = filesha256("${path.module}/../lab12c/compliance_agent/lambda/requirements.txt")
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      rm -rf "${path.module}/build/compliance_agent_pkg"
      mkdir -p "${path.module}/build/compliance_agent_pkg"
      cp "${path.module}/../lab12c/compliance_agent/lambda/compliance.py" "${path.module}/build/compliance_agent_pkg/"
      cp "${path.module}/../lab12c/compliance_agent/json/controls.json" "${path.module}/build/compliance_agent_pkg/"
      pip install \
        -r "${path.module}/../lab12c/compliance_agent/lambda/requirements.txt" \
        -t "${path.module}/build/compliance_agent_pkg" \
        --platform manylinux_2_28_x86_64 \
        --platform manylinux2014_x86_64 \
        --implementation cp \
        --python-version 3.12 \
        --abi cp312 \
        --only-binary=:all: \
        --upgrade
    EOT
  }
}

data "archive_file" "compliance_agent_zip" {
  type        = "zip"
  source_dir  = "${path.module}/build/compliance_agent_pkg"
  output_path = "${path.module}/build/compliance_agent.zip"

  depends_on = [null_resource.build_compliance_agent_pkg]
}

# ---- IAM -------------------------------------------------------
data "aws_iam_policy_document" "compliance_agent_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "compliance_agent" {
  name               = "compliance-agent-role"
  assume_role_policy = data.aws_iam_policy_document.compliance_agent_trust.json

  tags = {
    Lab = "12C-compliance-agent"
  }
}

data "aws_iam_policy_document" "compliance_agent_permissions" {
  # Write evidence -- tightly scoped to exactly this Lambda's own
  # table, never table/* like install.md's Step 6 draft.
  statement {
    sid       = "WriteComplianceEvidence"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem", "dynamodb:BatchWriteItem"]
    resources = [aws_dynamodb_table.compliance_evidence.arn]
  }

  # Read whatever tables the *validators* check -- structurally
  # broad by necessity, not an oversight: table_exists,
  # table_not_empty, and minimum_records validators run against
  # whichever table controls.json names, which varies per control
  # and isn't knowable in advance without hardcoding every current
  # and future table this account might ever hold. This is the
  # generic-engine tradeoff the playbook itself describes ("the
  # engine doesn't care whether the control is WAF, Lambda, S3, or
  # SNS") -- read-only, scoped to this account's own DynamoDB
  # tables, never write.
  statement {
    sid       = "ReadValidatedTables"
    effect    = "Allow"
    actions   = ["dynamodb:DescribeTable", "dynamodb:Scan"]
    resources = ["arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*"]
  }

  # List the bucket -- structurally broad by necessity, same reasoning
  # as ReadValidatedTables above: a generic compliance engine has to be
  # able to check evidence from OTHER components (e.g. CTRL-004 checks
  # that report_executive published under executive-reports/), not
  # just its own compliance-reports/ prefix. Scoping this to one
  # prefix was the original mistake here -- caught via a live
  # AccessDenied on exactly that cross-component check. Read-only;
  # writes stay tightly scoped below.
  statement {
    sid       = "ListBucketForValidation"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.executive_reports.arn]
  }

  statement {
    sid       = "PutComplianceReports"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.executive_reports.arn}/compliance-reports/*"]
  }

  # Bedrock via CRIS -- same two-grant pattern as the other four
  # Bedrock-calling Lambdas in this stack.
  statement {
    sid     = "InvokeInferenceProfile"
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0"
    ]
  }

  statement {
    sid       = "InvokeUnderlyingModel"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"]
  }

  statement {
    sid    = "BedrockMarketplaceAccess"
    effect = "Allow"
    actions = [
      "aws-marketplace:Subscribe",
      "aws-marketplace:Unsubscribe",
      "aws-marketplace:ViewSubscriptions",
    ]
    resources = ["*"] # structurally required - see the other four Lambdas' identical statement
  }

  # Validator read-only checks against other services -- same
  # "structurally broad, read-only, account-scoped" reasoning as
  # the DynamoDB read statement above. install.md's own draft used
  # Resource "*" globally for these four actions; scoped here to
  # this account's own resources of each type instead.
  statement {
    sid    = "ValidatorReadOnly"
    effect = "Allow"
    actions = [
      "events:DescribeRule",
      "lambda:GetFunctionConfiguration",
    ]
    resources = [
      "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/*",
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*",
    ]
  }

  statement {
    sid       = "ValidatorSnsReadOnly"
    effect    = "Allow"
    actions   = ["sns:GetTopicAttributes"]
    resources = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
  }

  # NOTE: install.md's scheduler:GetSchedule validator targets AWS
  # EventBridge Scheduler, a different service from the classic
  # aws_cloudwatch_event_rule schedule_expression pattern this stack
  # actually uses everywhere (waf_bedrock_analyzer_schedule,
  # correlation_agent_schedule). Omitted here as dead permission for
  # a service this account doesn't use - add it back if that ever
  # changes.

  statement {
    sid    = "OwnLogGroupWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.compliance_agent.arn}:*"]
  }
}

resource "aws_iam_role_policy" "compliance_agent" {
  name   = "compliance-agent-permissions"
  role   = aws_iam_role.compliance_agent.id
  policy = data.aws_iam_policy_document.compliance_agent_permissions.json
}

# ---- Log group -----------------------------------------------
resource "aws_cloudwatch_log_group" "compliance_agent" {
  name              = "/aws/lambda/compliance-agent"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "12C-compliance-agent"
  }
}

# ---- The Lambda itself ----------------------------------------
resource "aws_lambda_function" "compliance_agent" {
  function_name = "compliance-agent"
  role          = aws_iam_role.compliance_agent.arn
  handler       = "compliance.lambda_handler"
  runtime       = "python3.12"

  # Matches install.md's own reasoning: Bedrock narration + DynamoDB
  # scans need more than the 3s default; ReportLab PDF generation is
  # memory-hungry.
  timeout     = 120
  memory_size = 512

  filename         = data.archive_file.compliance_agent_zip.output_path
  source_code_hash = data.archive_file.compliance_agent_zip.output_base64sha256

  environment {
    variables = {
      COMPLIANCE_EVIDENCE_TABLE = aws_dynamodb_table.compliance_evidence.name
      REPORT_BUCKET             = aws_s3_bucket.executive_reports.id
      REPORT_PREFIX             = "compliance-reports"

      BEDROCK_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      ENABLE_BEDROCK   = "true"

      COMPLIANCE_FRAMEWORKS = "NIST CSF 2.0"
      UNEVALUATED_STATUS    = "REVIEW"

      ORGANIZATION_NAME = "SEIR Cloud Security"
      REPORT_TITLE       = "Compliance Evidence Report"
    }
  }

  depends_on = [aws_cloudwatch_log_group.compliance_agent]

  tags = {
    Lab = "12C-compliance-agent"
  }
}
