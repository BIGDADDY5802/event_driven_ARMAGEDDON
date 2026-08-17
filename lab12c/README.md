# dev12c — SEIR (Security Event Incident Response) stack

Consolidated Terraform/Lambda stack that carries forward lab11's Chewbacca
API/DB deployment and adds the SEIR pipeline: WAF telemetry → correlation →
Bedrock analysis → automated SOAR response → executive reporting.

## Directory map

| Path | What it is |
|---|---|
| `terraform/` | All infrastructure (API Gateway, Cognito, RDS, VPC, the 5 Lambdas, DynamoDB, EventBridge, SNS, S3). See `terraform/README.md` for the file-by-file breakdown. |
| `lambda/` | Source for the 5 Lambda functions, one subfolder each. See `lambda/README.md`. |
| `scripts/` | Bash helpers for setup, evidence collection, and gate/verification checks used during the lab. See `scripts/README.md`. |
| `sql/` | The `audit_events` table schema, applied manually post-`apply`. See `sql/README.md`. |
| `archive/` | Retired files kept for reference — superseded script versions and dead duplicates. See `archive/README.md`. |

## How the pieces connect

```
Client
  │  POST /intake
  ▼
API Gateway (Cognito-authorized) ──► chewbacca_intake Lambda ──► RDS MySQL (audit_events)

WAF ──► CloudWatch Logs
          │  (polled on a schedule)
          ▼
   seir_waf_bedrock_analyzer ──► DynamoDB (waf_events) + Bedrock summary
          │  (scheduled correlation pass)
          ▼
   seir_waf_correlation_agent ──► DynamoDB (correlation_findings) ──► EventBridge
          │
          ▼
   seir_soar_response_agent ──► DynamoDB (security_incidents) + SNS notification
          │
          ▼
   report_executive (on demand / scheduled) ──► S3 (PDF + JSON executive reports)
```

## Post-apply steps
- Run `sql/schema.sql` against the RDS instance from inside the VPC (the DB
  has no public endpoint) — see `sql/README.md`.
- `scripts/gate_env.sh` must be **sourced** (not executed) to populate the env
  vars the `scripts/gate_*.sh` checks expect, pulled live from this stack's
  `terraform output`.

## Note on naming
Resource names like `chewbacca-intake-lambda-11a` and the `lab11` DB default
carry forward from lab11 on purpose (see `scripts/gate_env.sh`'s header) —
this stack consolidates that earlier lab's resources rather than renaming
them.
