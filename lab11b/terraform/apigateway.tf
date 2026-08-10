# resource "aws_apigatewayv2_api" "this" {
#   name          = var.api_name
#   protocol_type = "HTTP"
# }

# resource "aws_apigatewayv2_integration" "lambda" {
#   api_id           = aws_apigatewayv2_api.this.id
#   integration_type = "AWS_PROXY"

#   integration_uri        = aws_lambda_function.intake.invoke_arn
#   payload_format_version = "2.0"
# }

# resource "aws_apigatewayv2_route" "intake" {
#   api_id    = aws_apigatewayv2_api.this.id
#   route_key = "POST ${var.route_path}"
#   target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
# }

# # GAP-7 (tracked): no throttling settings on the stage and no WAF web ACL
# # in front of this API. /intake is a public, unauthenticated POST endpoint
# # right now. See README "Known gaps" before this goes anywhere near real
# # traffic.

# # GAP-6 (tracked): auto_deploy=true means every route change goes live
# # immediately, with no manual/canary gate. Fine for a lab, not for a real
# # prod stage. See README "Known gaps".
# resource "aws_apigatewayv2_stage" "this" {
#   api_id      = aws_apigatewayv2_api.this.id
#   name        = var.stage_name
#   auto_deploy = true
# }

# # Resource-based policy on the Lambda: without this, API Gateway is not
# # allowed to invoke the function even though the route/integration exist.
# resource "aws_lambda_permission" "apigw_invoke" {
#   statement_id  = "apigw-invoke-11a"
#   action        = "lambda:InvokeFunction"
#   function_name = aws_lambda_function.intake.function_name
#   principal     = "apigateway.amazonaws.com"

#   source_arn = "${aws_apigatewayv2_api.this.execution_arn}/*/*${var.route_path}"
# }
