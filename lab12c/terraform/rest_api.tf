# ============================================================
# restapi.tf — a REST API mirror of the existing HTTP API
#
# WHY THIS FILE EXISTS AT ALL:
# AWS WAF cannot be attached to an HTTP API (apigatewayv2).
# Web ACLs associate to API Gateway *REST* stages, CloudFront,
# ALB, AppSync, Cognito, App Runner, Amplify, Verified Access.
# So to put a WAF in front of this Lambda we need a REST API.
#
# ANALOGY: WAF is a metal detector that only bolts onto one model
# of doorframe. Your building has the other model. You can't
# bolt it on — you install the supported doorframe next to it.
#
# STAGED APPROACH: the HTTP API from 11A stays exactly as it is
# (your 11B evidence still resolves), and this adds a second,
# WAF-protected front door to the SAME Lambda. That gives you a
# before/after comparison: identical backend, one door guarded.
#
# NOTE ON EVENT SHAPE: REST proxy integrations send payload
# format 1.0; HTTP APIs send 2.0. Both put the request body in
# event["body"], so a handler that only reads the body works on
# both. If your handler reads event["requestContext"]["http"]
# ["method"] (2.0 only) it must also accept event["httpMethod"]
# (1.0). Verify before trusting a 200.
# ============================================================

# STAGED APPROACH (HISTORICAL): this was originally built to add a
# second, WAF-protected front door alongside the 11A HTTP API, so
# both could be compared side by side. The original HTTP API no
# longer exists as of the dev12b consolidation - this REST API is
# now the only front door to the intake Lambda. gate_11a_cognito_auth.sh
# is the current evidence gate for this endpoint; the original
# apigw_route_invoke gate that targeted the retired HTTP API has been
# retired (see run_all_gates.sh).

data "aws_region" "current" {}

resource "aws_api_gateway_rest_api" "waf_front" {
  name        = "chewbacca-11a-intake-rest"
  description = "REST mirror of the 11A HTTP API, created so a WAF web ACL can be associated"

  endpoint_configuration {
    types = ["REGIONAL"] # REGIONAL is required for a REGIONAL-scope web ACL
  }

  tags = {
    Lab     = "SEIR-I-11A"
    Purpose = "waf-attachable-frontend"
  }
}


# /intake — same path as the HTTP API route, so the same client works
resource "aws_api_gateway_resource" "intake" {
  rest_api_id = aws_api_gateway_rest_api.waf_front.id
  parent_id   = aws_api_gateway_rest_api.waf_front.root_resource_id
  path_part   = "intake"
}

# resource "aws_api_gateway_method" "intake_post" {
#   rest_api_id   = aws_api_gateway_rest_api.waf_front.id
#   resource_id   = aws_api_gateway_resource.intake.id
#   http_method   = "POST"
#   authorization = "NONE" # the WAF is the control being demonstrated here
# }

resource "aws_api_gateway_method" "intake_post" {
  rest_api_id   = aws_api_gateway_rest_api.waf_front.id
  resource_id   = aws_api_gateway_resource.intake.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

# AWS_PROXY = Lambda proxy integration. Note integration_http_method
# is ALWAYS POST for Lambda invocations, regardless of the client's
# method — that is the Lambda Invoke API's requirement, not yours.
resource "aws_api_gateway_integration" "intake_lambda" {
  rest_api_id = aws_api_gateway_rest_api.waf_front.id
  resource_id = aws_api_gateway_resource.intake.id
  http_method = aws_api_gateway_method.intake_post.http_method

  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.intake.invoke_arn
}

# Let this REST API invoke the Lambda. Separate from the HTTP API's
# permission — each front door needs its own key.
resource "aws_lambda_permission" "rest_invoke" {
  statement_id  = "apigw-rest-invoke-11a"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"

  # Scope to this API only. /*/* = any stage, any method — still far
  # narrower than allowing all of API Gateway to invoke the function.
  source_arn = "${aws_api_gateway_rest_api.waf_front.execution_arn}/*/*"
}

# ---- Deployment + stage ------------------------------------------
# REST APIs need an explicit deployment: the config you declare is a
# draft until you "publish" it to a stage.
#
# The triggers block is the classic REST-API gotcha. Without it,
# Terraform sees no change to the deployment resource when you edit a
# method or integration, so your edits never reach the live stage.
# Hashing the dependencies forces a redeploy when they change.
resource "aws_api_gateway_deployment" "waf_front" {
  rest_api_id = aws_api_gateway_rest_api.waf_front.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.intake.id,
      aws_api_gateway_method.intake_post.id,
      aws_api_gateway_method.intake_post.authorization,
      aws_api_gateway_integration.intake_lambda.id,
      aws_api_gateway_authorizer.cognito.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Access logs for the stage. This is request-level evidence from the
# API's own perspective — separate from, and cross-checkable against,
# the WAF logs.
resource "aws_cloudwatch_log_group" "rest_access" {
  name              = "/aws/apigateway/chewbacca-11a-intake-rest/access"
  retention_in_days = var.log_retention_days

  tags = {
    Lab = "SEIR-I-11A"
  }
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.waf_front.id
  deployment_id = aws_api_gateway_deployment.waf_front.id
  stage_name    = "prod"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.rest_access.arn
    format = jsonencode({
      requestId  = "$context.requestId"
      ip         = "$context.identity.sourceIp"
      method     = "$context.httpMethod"
      path       = "$context.path"
      status     = "$context.status"
      latency    = "$context.responseLatency"
      wafStatus  = "$context.wafResponseCode"
      wafRuleArn = "$context.webaclArn"
    })


  }

  tags = {
    Lab = "SEIR-I-11A"
  }
}
