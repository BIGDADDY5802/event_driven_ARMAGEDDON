# terraform/

Single flat root module (not split into Terraform modules — see the plan
note this reorg was done under: kept flat because restructuring module
source paths can't be verified without running `terraform plan`, which
wasn't available in this environment). Files grouped below by concern to
make the flat list scannable.

## Core API / DB / auth (the original Lab 11A stack)
| File | Purpose |
|---|---|
| `vpc.tf` | Reuses the account's default VPC — no dedicated VPC created. |
| `vpc_endpoints.tf` | Private VPC endpoints (e.g. Secrets Manager) so the Lambda can reach them without internet egress. |
| `security_groups.tf` | Security groups for the Lambda and RDS. |
| `connectivity.tf` | The single SG rule allowing the Lambda SG to reach RDS on 3306 — the resource `gate_11b_incident.sh` deliberately breaks and restores. |
| `rds.tf` | The MySQL RDS instance. |
| `secrets.tf` | Secrets Manager secret holding DB credentials. |
| `cognito.tf` | Cognito user pool used to authorize `/intake`. |
| `apigateway.tf` | Original HTTP API (apigatewayv2) — WAF can't attach to this API type; see `rest_api.tf`. |
| `rest_api.tf` | REST API mirror of the HTTP API, added specifically so a WAF Web ACL can be associated with it. |
| `waf.tf` | The WAF Web ACL, its rules, association, and logging. |
| `lambda.tf` | Builds and deploys the `chewbacca_intake` Lambda (see `../lambda/README.md`). |

## SEIR pipeline (WAF telemetry → correlation → response)
| File | Purpose |
|---|---|
| `seir_waf_bedrock_analyzer.tf` | Deploys `seir_waf_bedrock_analyzer` (WAF log analysis + Bedrock summaries). |
| `seir_dynamodb_waf_events.tf` | DynamoDB table the analyzer writes normalized WAF events to. |
| `seir_waf_correlation_agent.tf` | Deploys `seir_waf_correlation_agent`. |
| `seir_eventbridge_correlation_scheduler.tf` | Schedule that triggers the correlation agent. |
| `seir_dynamo_db_waf_correlation_findings.tf` | DynamoDB table the correlation agent writes findings to. |
| `seir_evenbridge_bus.tf` | The custom EventBridge bus findings are published on. |
| `seir_soar_response_agent.tf` | Deploys `seir_soar_response_agent`. |
| `seir_eventbridge_soar_rules.tf` | EventBridge rules routing findings to the SOAR agent. |
| `seir_dynamodb_security_incidents.tf` | DynamoDB table the SOAR agent writes incident records to. |
| `seir_sns_soar_notifications.tf` | SNS topic the SOAR agent notifies on. |

## Reporting
| File | Purpose |
|---|---|
| `report_executive_lambda.tf` | Deploys `report_executive` (PDF/JSON executive report generator). |
| `report_executive_bucket.tf` | S3 bucket the reports are uploaded to. |

## Cross-cutting
| File | Purpose |
|---|---|
| `variables.tf` | All input variables. |
| `outputs.tf` | Stack outputs — several `gate_*.sh` scripts and `gate_env.sh` consume these via `terraform output`. |
| `versions.tf` | Terraform + provider version constraints. |
| `data.tf` | Read-only lookups (existing resources Terraform references but doesn't manage). |
| `iam.tf` | IAM roles/policies (Lambda trust policy, execution permissions). |
| `monitoring.tf` | CloudWatch alarms — the "smoke detectors" for this stack. |
| `terraform.tfvars.example` | Template for `terraform.tfvars` (gitignored). Copy and fill in real values before `apply`. |

## Not tracked here
`build/` (generated Lambda zip packages) is gitignored and created by
`null_resource` provisioners in `lambda.tf` / `report_executive_lambda.tf` —
don't hand-edit anything under it.
