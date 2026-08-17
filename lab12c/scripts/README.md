# scripts/

Bash helpers for setup, evidence collection, and gate/verification checks.
Run from this directory unless noted; several read `terraform output`, so
`terraform apply` must have already run in `../terraform/`.

| Script | Purpose | Run when |
|---|---|---|
| `gate_env.sh` | Populates env vars (`LAMBDA_NAME`, `SECRET_ARN`, `API_ID`, security group IDs, etc.) from live `terraform output`. Must be **sourced**, not executed. | Before running `gate_11a_lambda_secret_vpc.sh` or other gates that need those vars. |
| `bootstrap_schema.sh` | One-shot: launches a temporary bastion EC2 (reusing the Lambda security group), applies `../sql/schema.sql` to RDS over SSM Run Command, then terminates the bastion. | Once, after the first `terraform apply`. |
| `teardown_bastion_role.sh` | Removes the IAM role/instance profile `bootstrap_schema.sh` creates. Idempotent — checks existence before deleting. | Any time after `bootstrap_schema.sh` has finished. |
| `gate_11a_cognito_auth.sh` | Proves `/intake` actually enforces the Cognito authorizer (creates a unique throwaway test user per run, cleans it up via `trap ... EXIT`). | Manual verification / grading gate. |
| `gate_11a_lambda_secret_vpc.sh` | Verifies the Lambda's Secrets Manager + VPC wiring. | Manual verification / grading gate. |
| `gate_11b_incident.sh` | Simulates a DB-connectivity incident (breaks the RDS security group), confirms the failure is detected, then recovers and re-verifies. | Manual incident-response exercise. |
| `run_all_gates.sh` | Runs every current gate script in sequence, logs each to `gate_logs/`, prints one aggregated pass/fail summary. | Whenever you want the full current status in one command. |
| `test_waf.sh` | Sends a legit request (expect 200), an XSS-shaped request, and a SQLi-shaped request (expect 403 each) through the WAF-protected endpoint. | Manual WAF verification. |
| `collect_evidencev2.sh` | Captures baseline/failure/recovery evidence (invoke results, Lambda logs, SG state, alarm state, `terraform plan` drift) for `gate_11b_incident.sh`. Auto-discovers resource IDs via `terraform output`, falling back to AWS API lookups. | `./collect_evidencev2.sh baseline\|failure\|recovery` during the incident exercise. |
| `make_manifestv2.sh` | Validates the evidence pack `collect_evidencev2.sh` produced (completeness, chronology, HTTP-code story, SG-state story), then hashes everything into `evidence_manifest.json`. Refuses to write a manifest if any gate fails. | After collecting all three evidence phases. |

`gate_11a_apigw_route_invoke.sh` and the v1 `collect_evidence.sh`/`make_manifest.sh`
have been retired/superseded — see `../archive/README.md`.
