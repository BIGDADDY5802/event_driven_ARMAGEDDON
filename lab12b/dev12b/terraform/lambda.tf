# Build a deployable package: copy the handler + pip-install dependencies
# into a build dir, then zip it. Re-runs whenever the handler or
# requirements change (triggers hash the file contents).
#
# Windows/Git Bash note (matches the rest of the class labs): pip needs
# --break-system-packages on this machine. Adjust the command below if
# you're applying from a different environment.
resource "null_resource" "build_lambda_pkg" {
  triggers = {
    handler_hash      = filesha256("${path.module}/../lambda/lambda_function.py")
    requirements_hash = filesha256("${path.module}/../lambda/requirements.txt")
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      rm -rf "${path.module}/build/lambda_pkg"
      mkdir -p "${path.module}/build/lambda_pkg"
      cp "${path.module}/../lambda/lambda_function.py" "${path.module}/build/lambda_pkg/"
      pip install -r "${path.module}/../lambda/requirements.txt" -t "${path.module}/build/lambda_pkg" --break-system-packages --quiet
    EOT
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/build/lambda_pkg"
  output_path = "${path.module}/build/chewbacca_lambda_11a.zip"

  depends_on = [null_resource.build_lambda_pkg]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "intake" {
  function_name = var.lambda_function_name
  role          = aws_iam_role.lambda_exec.arn

  runtime = var.lambda_runtime
  handler = "lambda_function.lambda_handler"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory_size

  vpc_config {
    subnet_ids         = local.selected_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      DB_SECRET_ARN      = aws_secretsmanager_secret.db_secret.arn
      DB_NAME            = var.db_name
      DB_CONNECT_TIMEOUT = tostring(var.db_connect_timeout)
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy_attachment.lambda_vpc_access,
    aws_iam_role_policy.lambda_read_secret,
    aws_cloudwatch_log_group.lambda,
    aws_vpc_endpoint.secretsmanager,
  ]

  tags = {
    Name = var.lambda_function_name
  }
}
