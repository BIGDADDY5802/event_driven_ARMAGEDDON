# Trust policy: who is allowed to ASSUME this role. Lambda service only.
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

# Permission grant 1: CloudWatch Logs (AWS managed policy)
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Permission grant 2: create/manage ENIs inside the VPC (AWS managed policy)
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Permission grant 3: read exactly ONE secret ARN. Not a wildcard.
data "aws_iam_policy_document" "lambda_read_secret" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [aws_secretsmanager_secret.db_secret.arn]
  }
}

resource "aws_iam_role_policy" "lambda_read_secret" {
  name   = "${var.project_name}-read-secret"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_read_secret.json
}
