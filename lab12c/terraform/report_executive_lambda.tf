# ============================================================
# report_executive_lambda.tf — reads the three SEIR ledgers,
# writes a synchronized PDF + JSON executive report to S3
#
# PACKAGING: CORRECTED after a live failure. reportlab==4.4.3
# itself ships as a pure-Python wheel, but it pulls in pillow
# (image handling) as a transitive dependency, and pillow ships
# platform-specific COMPILED wheels (.pyd on Windows, .so on
# Linux). A plain `pip install` on Windows/Git Bash -- the pattern
# that works fine for pure-Python pymysql in lab11a/lambda.tf --
# silently downloaded Windows .pyd binaries here, which crash on
# import inside Lambda's Linux runtime. Confirmed by manual test:
# the fix is forcing pip to fetch manylinux-tagged wheels via
# --platform instead of letting it match the local machine.
# Verified against PyPI that pillow==12.3.0 publishes only
# manylinux_2_27/manylinux_2_28 tags (not the older manylinux2014
# tag), so both are passed -- Amazon Linux 2023 (Lambda's
# python3.12 runtime) satisfies manylinux_2_28's glibc floor.
#
# BEDROCK: uses the pipeline's established CRIS two-grant pattern
# (us.anthropic.claude-haiku-4-5-20251001-v1:0) rather than the
# spec's literal claude-3-haiku-20240307 direct-invoke default —
# deliberate deviation, confirmed with Jerome, for IAM consistency
# across all four Bedrock-calling Lambdas in this stack rather than
# a fifth invocation pattern.
# ============================================================

resource "null_resource" "build_report_executive_pkg" {
  triggers = {
    handler_hash      = filesha256("${path.module}/../lambda/report_executive/lambda_function.py")
    requirements_hash = filesha256("${path.module}/../lambda/report_executive/requirements.txt")
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      rm -rf "${path.module}/build/report_executive_pkg"
      mkdir -p "${path.module}/build/report_executive_pkg"
      cp "${path.module}/../lambda/report_executive/lambda_function.py" "${path.module}/build/report_executive_pkg/"
      pip install \
        -r "${path.module}/../lambda/report_executive/requirements.txt" \
        -t "${path.module}/build/report_executive_pkg" \
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

data "archive_file" "report_executive_zip" {
  type        = "zip"
  source_dir  = "${path.module}/build/report_executive_pkg"
  output_path = "${path.module}/build/report_executive_generator.zip"

  depends_on = [null_resource.build_report_executive_pkg]
}

# ---- IAM -------------------------------------------------------
data "aws_iam_policy_document" "report_executive_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "report_executive" {
  name               = "report-executive-role"
  assume_role_policy = data.aws_iam_policy_document.report_executive_trust.json

  tags = {
    Lab = "12B-executive-report"
  }
}

data "aws_iam_policy_document" "report_executive_permissions" {
  # Read the three SEIR ledgers -- scoped to exactly those tables,
  # not dynamodb:* account-wide.
  statement {
    effect  = "Allow"
    actions = ["dynamodb:Scan"]
    resources = [
      aws_dynamodb_table.waf_events.arn,
      aws_dynamodb_table.waf_correlation_findings.arn,
      aws_dynamodb_table.security_incidents.arn,
    ]
  }

  # Bedrock via cross-Region inference profile -- same two-grant
  # pattern as the other three Bedrock-calling Lambdas. Grant 1:
  # the profile itself, scoped to this account+region.
  statement {
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0"
    ]
  }

  # Grant 2: the underlying model in whichever US region the
  # profile routes to. Region wildcard is structurally required by
  # how cross-Region inference works, not a shortcut -- the model
  # ID itself stays fully pinned.
  statement {
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"]
  }

  # AWS Marketplace subscription actions -- required for Bedrock
  # model access per the pattern confirmed via live
  # AccessDeniedException on the Correlation Agent. These three
  # actions do not support resource-level ARN scoping at all;
  # Resource "*" is the only valid option for them specifically.
  statement {
    effect = "Allow"
    actions = [
      "aws-marketplace:Subscribe",
      "aws-marketplace:Unsubscribe",
      "aws-marketplace:ViewSubscriptions",
    ]
    resources = ["*"]
  }

  # Write the finished report pair -- scoped to this bucket's
  # report prefix only, not the whole bucket.
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.executive_reports.arn}/executive-reports/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.report_executive.arn}:*"]
  }
}

resource "aws_iam_role_policy" "report_executive" {
  name   = "report-executive-permissions"
  role   = aws_iam_role.report_executive.id
  policy = data.aws_iam_policy_document.report_executive_permissions.json
}

# ---- Log group ---------------------------------------------------
resource "aws_cloudwatch_log_group" "report_executive" {
  name              = "/aws/lambda/executive-report-generator"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "12B-executive-report"
  }
}

# ---- The Lambda itself --------------------------------------------
resource "aws_lambda_function" "report_executive" {
  function_name = "executive-report-generator"
  role          = aws_iam_role.report_executive.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  memory_size = 1024
  timeout     = 120
  # ephemeral_storage left at the 512 MB default -- built in memory,
  # no /tmp usage yet. Raise this later if chart images or larger
  # artifacts get added.

  filename         = data.archive_file.report_executive_zip.output_path
  source_code_hash = data.archive_file.report_executive_zip.output_base64sha256

  environment {
    variables = {
      WAF_EVENTS_TABLE           = aws_dynamodb_table.waf_events.name
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.security_incidents.name

      REPORT_BUCKET = aws_s3_bucket.executive_reports.id
      REPORT_PREFIX = "executive-reports"

      BEDROCK_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      ENABLE_BEDROCK   = "true"

      REPORT_PERIOD_HOURS = "24"
      MAX_ITEMS_PER_TABLE = "5000"

      ORGANIZATION_NAME = "SEIR Cloud Security"
      REPORT_TITLE      = "Executive Security Report"
    }
  }

  depends_on = [aws_cloudwatch_log_group.report_executive]

  tags = {
    Lab = "12B-executive-report"
  }
}
