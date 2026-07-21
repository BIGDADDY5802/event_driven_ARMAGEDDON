# Lab 11A — Chewbacca Serverless Intake Pipeline

Terraform build of the API Gateway → Lambda → RDS MySQL serverless pipeline
from the dawgs-armageddon "Chewbacca" track (SEIR Foundations, Lab 11A).
This replaces the manual CLI walkthrough with a repeatable IaC deployment,
verified by the same gate scripts.

**Status:** functional, intentionally unhardened. See [Known gaps](#known-gaps)
below — these are tracked, not accidental, and are being worked through one
at a time in follow-up passes.

## Architecture

```
Client
  │  POST /intake
  ▼
API Gateway (HTTP API)
  │  AWS_PROXY integration
  ▼
Lambda (Python, VPC-attached)
  │  GetSecretValue (scoped to one ARN)
  ▼
Secrets Manager ──► RDS MySQL (private, SG-scoped to Lambda only)
```

## Repo structure

```
lab11a-chewbacca/
├── terraform/              # All infra as code
│   ├── versions.tf         # Provider + S3 backend config
│   ├── variables.tf
│   ├── vpc.tf               # Default VPC + subnet data sources
│   ├── security_groups.tf   # Lambda SG + RDS SG (group-referenced ingress)
│   ├── rds.tf                # RDS MySQL instance, generated password
│   ├── secrets.tf            # Secrets Manager secret + version
│   ├── iam.tf                 # Lambda execution role (trust + 3 scoped grants)
│   ├── lambda.tf               # Packaging (pip + zip) + function resource
│   ├── apigateway.tf           # HTTP API, route, stage, invoke permission
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── lambda/                  # Lambda source, packaged separately from infra
│   ├── lambda_function.py
│   └── requirements.txt
├── sql/
│   └── schema.sql            # audit_events table DDL (run manually, see below)
├── scripts/                  # Evidence-based verification gates
│   ├── gate_11a_lambda_secret_vpc.sh
│   ├── gate_11a_rds_sg_private.sh
│   ├── gate_11a_apigw_route_invoke.sh
│   └── run_all_gates_11a.sh
└── README.md
```

Lambda code lives in its own top-level directory, separate from the
Terraform that deploys it — `terraform/lambda.tf` builds the deployment
package from `lambda/` via `pip install` + `archive_file` rather than
Lambda source living inline in HCL.

## Prerequisites

- Terraform >= 1.7
- AWS CLI configured with credentials that can create VPC/EC2/RDS/Lambda/
  IAM/API Gateway/Secrets Manager resources
- `pip` on the machine running `terraform apply` (packages `pymysql` into
  the Lambda zip at apply time)
- An S3 bucket for remote state (this repo assumes `11-9-backend`, edit
  `terraform/versions.tf` if using a different bucket)

## Usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # edit as needed
terraform init
terraform plan
terraform apply
```

## Post-apply steps

Terraform cannot reach the database directly — it's intentionally private,
reachable only from inside the VPC. Two manual steps remain:

**1. Create the schema.** From a bastion/temporary EC2/CloudShell that can
reach the RDS endpoint (`terraform output db_endpoint`):

```bash
mysql -h <db_endpoint> -u admin -p < ../sql/schema.sql
```

Pull the generated password from Secrets Manager, not from anywhere in
this repo:

```bash
aws secretsmanager get-secret-value \
  --secret-id "$(terraform -chdir=../terraform output -raw db_secret_arn)" \
  --query SecretString --output text | jq -r .password
```

**2. Run the verification gates:**

```bash
cd ../scripts
export REGION=us-east-1
export LAMBDA_NAME=$(terraform -chdir=../terraform output -raw lambda_function_name)
export SECRET_ARN=$(terraform -chdir=../terraform output -raw db_secret_arn)
export DB_NAME=lab11
export DB_ID=$(terraform -chdir=../terraform output -raw db_instance_id)
export RDS_SG_ID=$(terraform -chdir=../terraform output -raw rds_security_group_id)
export LAMBDA_SG_ID=$(terraform -chdir=../terraform output -raw lambda_security_group_id)
export API_ID=$(terraform -chdir=../terraform output -raw api_id)
export STAGE_NAME=prod

./run_all_gates_11a.sh
```

Produces `badge.txt` (GREEN/YELLOW/RED), `gate_result.json`, `pr_comment.md`,
and the three individual gate JSON files.

## Design decisions

| Decision | Why |
|---|---|
| Password generated via `random_password`, fed into RDS creation | Avoids ever having a known/guessable placeholder password on a live instance, even briefly |
| Two security groups, connected by group ID not CIDR | Lambda's network address isn't static — the RDS SG trusts the Lambda SG's identity |
| `PubliclyAccessible=false` **and** SG scoping | Two independent layers; neither alone is trusted as sufficient |
| IAM role: 3 narrow grants, one scoped to a single secret ARN | Blast radius of a compromised function is one secret + one VPC attachment, not the account |
| Lambda code in its own directory | Infra and application code have different review/change cadences; packaging is explicit, not implicit |
| Parameterized SQL, capped input lengths, generic error responses | Prevents injection and prevents error messages from being used for reconnaissance |

## Known gaps

Tracked deliberately, not accidental — this is the "as-is" build before a
hardening pass. Each is called out with a `GAP-N` comment at the relevant
resource in the Terraform.

| # | Gap | File |
|---|---|---|
| 2 | No Secrets Manager rotation configured | `terraform/secrets.tf` |
| 3 | Secret fetched on every Lambda invocation, no in-memory caching | `lambda/lambda_function.py` |
| 4 | `backup_retention_period = 0` — no automated backups for audit data | `terraform/rds.tf` |
| 5 | No connection pooling / RDS Proxy — risk of exhausting `max_connections` under concurrency | `terraform/rds.tf`, `terraform/lambda.tf` |
| 6 | API Gateway stage uses `auto_deploy = true`, no manual/canary gate | `terraform/apigateway.tf` |
| 7 | No WAF or throttling in front of `/intake` | `terraform/apigateway.tf` |
| — | No idempotency key — API Gateway retries could produce duplicate `audit_events` rows | `lambda/lambda_function.py`, `sql/schema.sql` |

Gap 1 (placeholder master password) from the original manual walkthrough is
already closed in this Terraform version — see the Design decisions table.

## Teardown

```bash
cd terraform
terraform destroy
```
