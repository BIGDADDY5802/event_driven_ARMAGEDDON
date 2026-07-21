output "invoke_url" {
  description = "Full invoke URL for the intake endpoint."
  value       = "https://${aws_apigatewayv2_api.this.id}.execute-api.${var.aws_region}.amazonaws.com/${var.stage_name}${var.route_path}"
}

output "api_id" {
  description = "API Gateway API ID (feed to gate_11a_apigw_route_invoke.sh as API_ID)."
  value       = aws_apigatewayv2_api.this.id
}

output "lambda_function_name" {
  description = "Lambda function name (feed to gate_11a_lambda_secret_vpc.sh as LAMBDA_NAME)."
  value       = aws_lambda_function.intake.function_name
}

output "db_secret_arn" {
  description = "Secrets Manager ARN holding DB credentials (feed to gates as SECRET_ARN)."
  value       = aws_secretsmanager_secret.db_secret.arn
  sensitive   = true
}

output "db_instance_id" {
  description = "RDS instance identifier (feed to gate_11a_rds_sg_private.sh as DB_ID)."
  value       = aws_db_instance.this.identifier
}

output "db_endpoint" {
  description = "RDS endpoint address."
  value       = aws_db_instance.this.address
}

output "rds_security_group_id" {
  description = "RDS security group ID (feed to gates as RDS_SG_ID)."
  value       = aws_security_group.rds_sg.id
}

output "lambda_security_group_id" {
  description = "Lambda security group ID (feed to gates as LAMBDA_SG_ID)."
  value       = aws_security_group.lambda_sg.id
}

output "subnet_ids" {
  description = "Subnets the DB/Lambda live in — use one when launching a temporary bastion to run sql/schema.sql."
  value       = local.selected_subnet_ids
}
