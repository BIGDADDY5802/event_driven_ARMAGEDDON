# lambda/

One subfolder per deployed function. Each folder's `.py` file is the exact
`source_file`/`source_dir` Terraform packages — renaming or moving anything
here requires updating the matching path in `terraform/`.

| Folder | Entry file | What it does | Wired up by |
|---|---|---|---|
| `chewbacca_intake/` | `lambda_function.py` | API-Gateway-triggered handler for `POST /intake`. Validates and inserts an audit event into RDS MySQL via a parameterized query, using DB creds pulled fresh from Secrets Manager on every invocation. | `terraform/lambda.tf` |
| `report_executive/` | `lambda_function.py` | Turns WAF telemetry, correlation findings, and SOAR incident records into a human-readable PDF and a machine-readable JSON executive report, both uploaded to S3. Informational only — no containment actions. | `terraform/report_executive_lambda.tf`, `terraform/report_executive_bucket.tf` |
| `seir_waf_bedrock_analyzer/` | `waf_bedrock_analyzer.py` | Scheduled pull from CloudWatch Logs (not push-driven, by design — see the file's own header for the idempotency tradeoff). Normalizes WAF events, stores them in DynamoDB, and asks Bedrock for a short incident summary per event. | `terraform/seir_waf_bedrock_analyzer.tf` |
| `seir_waf_correlation_agent/` | `handler.py` | Scheduled pass over stored WAF events that groups related activity into correlation findings, written to DynamoDB, and emits an EventBridge event per finding. | `terraform/seir_waf_correlation_agent.tf`, `terraform/seir_eventbridge_correlation_scheduler.tf` |
| `seir_soar_response_agent/` | `soar_response_agent.py` | EventBridge-triggered. Loads the full finding from DynamoDB, atomically claims it (conditional write, so duplicate EventBridge deliveries can't double-process), picks a response playbook by severity, asks Bedrock for a human-readable summary, records an incident, and sends an SNS notification. | `terraform/seir_soar_response_agent.tf`, `terraform/seir_eventbridge_soar_rules.tf`, `terraform/seir_sns_soar_notifications.tf` |

Entry-point filenames aren't consistent across functions (`lambda_function.py`
vs `handler.py` vs a name matching the folder) — left as-is since renaming any
of them means updating the Terraform `source_file` path *and* the Lambda
`handler` setting together; not done as part of this reorganization.
