# ============================================================
# cognito.tf — Cognito User Pool + REST API authorizer for the
# WAF-fronted /intake endpoint.
#
# ANALOGY: the User Pool is the DMV that issues ID cards (JWTs).
# The aws_api_gateway_authorizer below is the bouncer at the door
# who already trusts the DMV's seal — API Gateway itself verifies
# the token's signature and expiry natively. No Lambda, no code
# of yours ever sees the token's internals.
#
# GOTCHA TO REMEMBER WHEN TESTING: the identity_source header is
# read RAW. Cognito's COGNITO_USER_POOLS authorizer expects just
# the token in the Authorization header — no "Bearer " prefix.
# `curl -H "Authorization: eyJraWQ..."`, not "Authorization: Bearer eyJ...".
# ============================================================

resource "aws_cognito_user_pool" "intake_users" {
  name = "chewbacca-11a-intake-users"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = true # least privilege: no public self-signup for a lab-scoped pool
  }

  tags = {
    Lab = "SEIR-I-11A"
  }
}

resource "aws_cognito_user_pool_client" "intake_client" {
  name         = "chewbacca-11a-intake-client"
  user_pool_id = aws_cognito_user_pool.intake_users.id

  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}

resource "aws_api_gateway_authorizer" "cognito" {
  name          = "chewbacca-11a-cognito-authorizer"
  rest_api_id   = aws_api_gateway_rest_api.waf_front.id
  type          = "COGNITO_USER_POOLS"
  provider_arns = [aws_cognito_user_pool.intake_users.arn]

  identity_source = "method.request.header.Authorization"
}

# output "cognito_user_pool_id" {
#   value = aws_cognito_user_pool.intake_users.id
# }

# output "cognito_app_client_id" {
#   value = aws_cognito_user_pool_client.intake_client.id
# }