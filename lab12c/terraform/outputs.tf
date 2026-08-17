# output "invoke_url" {
#   description = "Full invoke URL for the intake endpoint."
#   value       = "https://${aws_apigatewayv2_api.this.id}.execute-api.${var.aws_region}.amazonaws.com/${var.stage_name}${var.route_path}"
# }

# output "api_id" {
#   description = "API Gateway API ID (feed to gate_11a_apigw_route_invoke.sh as API_ID)."
#   value       = aws_apigatewayv2_api.this.id
# }

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

output "rest_invoke_url" {
  description = "WAF-protected front door (REST API)"
  value       = "${aws_api_gateway_stage.prod.invoke_url}/intake"
}

# output "http_invoke_url" {
#   description = "Original unprotected front door (HTTP API) — for A/B comparison"
#   value       = "${aws_apigatewayv2_api.this.api_endpoint}/${aws_apigatewayv2_stage.this.name}/intake"
# }

output "waf_web_acl_arn" {
  description = "ARN of the web ACL"
  value       = aws_wafv2_web_acl.intake.arn
}

output "waf_web_acl_name" {
  description = "Name of the web ACL (needed for get-sampled-requests)"
  value       = aws_wafv2_web_acl.intake.name
}

output "waf_log_group" {
  description = "CloudWatch log group holding per-request WAF decisions"
  value       = aws_cloudwatch_log_group.waf.name
}

output "rest_access_log_group" {
  description = "API Gateway access logs for the REST stage"
  value       = aws_cloudwatch_log_group.rest_access.name
}

output "rest_stage_arn" {
  description = "Stage ARN the web ACL is associated with"
  value       = aws_api_gateway_stage.prod.arn
}

# Lab 12A needs this: the analyzer's CloudWatch Logs subscription
# filter has to grant logs.amazonaws.com permission to invoke it,
# scoped to this exact log group ARN (not just the name).
output "waf_log_group_arn" {
  description = "ARN of the WAF log group (feed to the waf-analyzer-push subscription filter's source permission)"
  value       = aws_cloudwatch_log_group.waf.arn
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.intake_users.id
}

output "cognito_app_client_id" {
  value = aws_cognito_user_pool_client.intake_client.id
}