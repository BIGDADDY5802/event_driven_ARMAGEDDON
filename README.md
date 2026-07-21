# event_driven_ARMAGEDDON

# Chewbacca — Serverless Intake Pipeline (Lab 11A)

![Status](https://img.shields.io/badge/status-GREEN%20PASS-brightgreen)
![Terraform](https://img.shields.io/badge/IaC-Terraform-623CE4?logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-us--east--1-FF9900?logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Lambda-Python%203.12-3776AB?logo=python&logoColor=white)
![Serverless](https://img.shields.io/badge/architecture-serverless-blueviolet)
![Gate 1](https://img.shields.io/badge/gate_lambda%2Fsecret%2Fvpc-PASS-brightgreen)
![Gate 2](https://img.shields.io/badge/gate_rds%2Fsg%2Fprivate-PASS-brightgreen)
![Gate 3](https://img.shields.io/badge/gate_apigw%2Finvoke-PASS-brightgreen)
![License](https://img.shields.io/badge/license-educational%20use-lightgrey)

A fully Terraformed, evidence-verified serverless pipeline —
**API Gateway → Lambda → RDS MySQL**, with credentials brokered through
Secrets Manager and no direct database exposure — built as part of the
`dawgs-armageddon` AWS infrastructure lab series.

No console click-ops. Every resource, every credential handoff, and every
verification step in this repo is code, not a screenshot.

---

## What this demonstrates

- **Infrastructure as code, end to end** — VPC networking, IAM, RDS,
  Secrets Manager, Lambda packaging, and API Gateway all provisioned via
  Terraform, with Lambda source code kept in its own directory rather
  than inlined into HCL.
- **Least-privilege IAM in practice** — a scoped trust policy plus three
  narrow permission grants, one of them tied to a single Secrets Manager
  ARN rather than a wildcard.
- **Defense-in-depth network isolation** — RDS is both
  `PubliclyAccessible=false` *and* security-group-scoped to the Lambda's
  security group by group reference (not CIDR), so two independent
  controls have to both be correct, not just one.
- **Evidence over assumption** — three automated gate scripts don't just
  check that resources exist; they perform a live invoke against the
  deployed API and verify the actual response body, not just an HTTP
  status code.
- **Real debugging, not a clean first try** — see
  [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the full chronological log of
  seven distinct root causes hit and resolved during deployment, each
  isolated with an actual diagnostic step before being fixed.

---

## Architecture

```
Client
  │  POST /intake
  ▼
API Gateway (HTTP API)
  │  AWS_PROXY integration
  ▼
Lambda (Python 3.12, VPC-attached)
  │  GetSecretValue (scoped to one ARN, via private VPC endpoint)
  ▼
Secrets Manager ──► RDS MySQL (private, SG-scoped to Lambda only)
```

Lambda reaches Secrets Manager through a **VPC Interface Endpoint**, not
the public internet — Lambda ENIs never receive public IP addresses, so
without this endpoint there is no path out of the VPC at all.

---

## Repo structure

```
lab11a-chewbacca/
├── terraform/                    # All infra as code
│   ├── versions.tf                # Provider + S3 backend config
│   ├── variables.tf
│   ├── vpc.tf                      # Default VPC + subnet data sources
│   ├── security_groups.tf          # Lambda SG + RDS SG (group-referenced ingress)
│   ├── vpc_endpoints.tf             # Secrets Manager interface endpoint
│   ├── rds.tf                        # RDS MySQL instance, generated password
│   ├── secrets.tf                     # Secrets Manager secret + version
│   ├── iam.tf                          # Lambda execution role (trust + 3 scoped grants)
│   ├── lambda.tf                        # Packaging (pip + zip) + function resource
│   ├── apigateway.tf                     # HTTP API, route, stage, invoke permission
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── lambda/                       # Lambda source, packaged separately from infra
│   ├── lambda_function.py
│   └── requirements.txt
├── sql/
│   └── schema.sql                 # audit_events table DDL
├── scripts/                      # Deployment automation + evidence-based gates
│   ├── bootstrap_schema.sh         # One-shot: password → bastion → schema → teardown
│   ├── teardown_bastion_role.sh    # Deletes the reusable bastion IAM role/profile
│   ├── gate_11a_lambda_secret_vpc.sh
│   ├── gate_11a_rds_sg_private.sh
│   ├── gate_11a_apigw_route_invoke.sh
│   └── run_all_gates_11a.sh
├── docs/
│   ├── RUNBOOK.md                  # Full deployment + debugging chronology
│   ├── workflow-redacted.md        # Redacted command/output log
│   └── gate-evidence-redacted.md   # Redacted final gate JSON evidence
└── README.md
```

---

## Prerequisites

- Terraform >= 1.7
- AWS CLI v2, authenticated with permissions for VPC/EC2/RDS/Lambda/IAM/
  API Gateway/Secrets Manager
- `pip` on the machine running `terraform apply` (packages `pymysql` into
  the Lambda zip at apply time)
- An S3 bucket for remote state

## Quickstart

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # edit as needed
terraform init
terraform apply
```

Then create the schema and verify the deployment:

```bash
../scripts/bootstrap_schema.sh      # password → bastion → schema → teardown, automated
cd ../scripts
./run_all_gates_11a.sh              # produces badge.txt, gate_result.json, pr_comment.md
```

Full step-by-step usage, environment variable setup for the gates, and
manual fallback instructions are in the sections below.

---

## Design decisions

| Decision | Why |
|---|---|
| Password generated via `random_password`, fed into RDS creation | Avoids ever having a known/guessable placeholder password on a live instance, even briefly |
| Two security groups, connected by group ID not CIDR | Lambda's network address isn't static — the RDS SG trusts the Lambda SG's identity |
| `PubliclyAccessible=false` **and** SG scoping | Two independent layers; neither alone is trusted as sufficient |
| IAM role: 3 narrow grants, one scoped to a single secret ARN | Blast radius of a compromised function is one secret + one VPC attachment, not the account |
| VPC Interface Endpoint for Secrets Manager | Lambda ENIs have no public IP path; this avoids a NAT Gateway just for one service call |
| Lambda code in its own directory | Infra and application code have different review/change cadences; packaging is explicit, not implicit |
| Parameterized SQL, capped input lengths, generic error responses | Prevents injection and prevents error messages from being used for reconnaissance |
| `recovery_window_in_days = 0` on the secret | Immediate deletion on `terraform destroy` — avoids name collisions on rapid re-apply during iteration |

---

## Post-apply steps

Terraform cannot reach the database directly — it's intentionally
private, reachable only from inside the VPC.

**1. Create the schema.** `scripts/bootstrap_schema.sh` automates this:
pulls the generated password from Secrets Manager, launches a temporary
EC2 bastion (reusing the Lambda security group, so it's already trusted
by the RDS SG), runs `sql/schema.sql` over SSM Run Command (no SSH keys,
no public exposure), then terminates the bastion automatically.

```bash
cd terraform
../scripts/bootstrap_schema.sh
```

Set `KEEP_BASTION=1` to leave the instance running for debugging. The
script creates a small reusable IAM role/instance profile on first run;
remove it afterward with:

```bash
../scripts/teardown_bastion_role.sh --yes
```

**2. Run the verification gates:**

```bash
cd scripts
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

Produces `badge.txt` (GREEN/YELLOW/RED), `gate_result.json`,
`pr_comment.md`, and the three individual gate JSON files.

---

## Known gaps

Tracked deliberately, not accidental — this is the "as-is" build before
a hardening pass. Each is called out with a `GAP-N` comment at the
relevant resource in the Terraform.

| # | Gap | File |
|---|---|---|
| 2 | No Secrets Manager rotation configured | `terraform/secrets.tf` |
| 3 | Secret fetched on every Lambda invocation, no in-memory caching | `lambda/lambda_function.py` |
| 4 | `backup_retention_period = 0` — no automated backups for audit data | `terraform/rds.tf` |
| 5 | No connection pooling / RDS Proxy — risk of exhausting `max_connections` under concurrency | `terraform/rds.tf`, `terraform/lambda.tf` |
| 6 | API Gateway stage uses `auto_deploy = true`, no manual/canary gate | `terraform/apigateway.tf` |
| 7 | No WAF or throttling in front of `/intake` | `terraform/apigateway.tf` |
| — | No idempotency key — API Gateway retries could produce duplicate `audit_events` rows | `lambda/lambda_function.py`, `sql/schema.sql` |

Gap 1 (placeholder master password from the original manual walkthrough)
is already closed in this Terraform version — see Design decisions above.

---

## Teardown

```bash
cd terraform
terraform destroy
```

---

## Further reading

- [`docs/RUNBOOK.md`](lab11a/lab11adocumentation.md) — full deployment chronology: every
  failure hit, its root cause, and the fix, in order
- [`docs/gate-evidence-redacted.md`](lab11a/2026.7.20actions.txt) —
  final gate JSON output, redacted for public sharing
- [`docs/workflow-redacted.md`](lab11a/lab11a.txt) — the complete
  redacted command/output log behind this build

Part of the **dawgs-armageddon** cloud engineering lab series.

