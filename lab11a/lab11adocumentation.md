# Lab 11A Runbook — Chewbacca Serverless Intake Pipeline

![Terraform Apply](https://img.shields.io/badge/terraform_apply-success-brightgreen)
![Gate 1](https://img.shields.io/badge/gate_1_lambda%2Fsecret%2Fvpc-PASS-brightgreen)
![Gate 2](https://img.shields.io/badge/gate_2_rds%2Fsg%2Fprivate-PASS-brightgreen)
![Gate 3](https://img.shields.io/badge/gate_3_apigw%2Finvoke-PASS-brightgreen)
![Overall](https://img.shields.io/badge/lab_11a-GREEN%20PASS-brightgreen)
![IaC](https://img.shields.io/badge/IaC-Terraform-623CE4)
![Cloud](https://img.shields.io/badge/AWS-us--east--1-orange)

Deployed via Terraform, end to end, no console click-ops. This runbook
documents the deployment sequence, every failure hit along the way, its
root cause, and the fix — kept intact rather than cleaned up, because the
debugging trail is the actual evidence of understanding the system, not
just a green badge at the end.

---

## Architecture

```
Client → API Gateway (POST /intake) → Lambda (Python, VPC-attached) → RDS MySQL (private)
                                              │
                                              ▼
                                      Secrets Manager (DB credentials)
                                              ▲
                                              │
                              VPC Interface Endpoint (private path, no NAT)
```

Repo: `lab11a-chewbacca/` — Terraform in `terraform/`, Lambda source in
`lambda/` (packaged separately from infra), gate scripts and automation
in `scripts/`.

---

## Deployment sequence

1. `terraform apply` — provisions VPC data sources, security groups, RDS,
   Secrets Manager secret, IAM role, Lambda, API Gateway.
2. `scripts/bootstrap_schema.sh` — one-shot: pulls the generated DB
   password, launches a temporary EC2 bastion (SSM-only, no SSH keys),
   applies `sql/schema.sql` against the private RDS instance, tears the
   bastion down automatically.
3. `scripts/run_all_gates_11a.sh` — runs all three verification gates and
   produces a pass/fail badge plus evidence JSON.

---

## Debug log

Six distinct root causes, each isolated with an actual diagnostic step
rather than guessed at. Kept in order — this is the real value of the
exercise, not the final green badge.

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | `Error: creating Security Group ... Invalid security group description` | Apostrophe in `lambda_sg` description — AWS SG descriptions only allow a specific character set (`a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*`) | Removed the apostrophe from the description string |
| 2 | `bash: aws: command not found` after previously working fine | AWS CLI v2 install was corrupted/partial — top-level `aws.exe` missing, only raw Python package internals present in `AWSCLIV2/` | Removed the broken install directory, reinstalled the MSI cleanly, reopened Git Bash |
| 3 | `terraform output` returned empty → downstream `ParamValidation: Invalid length for parameter SecretId, value: 0` | Command was run from the home directory, not the `terraform/` directory with state present | `cd` into `terraform/` before running `terraform output` |
| 4 | `aws: [ERROR]: An error occurred (ParameterNotFound) when calling the GetParameter operation` | Guessed SSM public parameter path for the latest Amazon Linux AMI was incorrect | Replaced with `aws ec2 describe-images` sorted by `CreationDate` — no guessed path required |
| 5 | Bastion launched, but `SSM agent never came online` | AMI filter (`al2023-ami-*-x86_64`) matched the **minimal** AL2023 variant, which ships without the SSM Agent preinstalled. Ruled out routing, DNS, security groups, IAM instance-profile association, and NACLs first — all confirmed clean — before finding the actual cause | Tightened the AMI filter to `al2023-ami-2*-kernel-*-x86_64`, which excludes the `minimal` and `ecs` variants by requiring the version number to immediately follow `ami-` |
| 6 | `aws: [ERROR]: Unable to load paramfile file:///tmp/tmp.xxxx: No such file or directory` | Git Bash auto-converts standalone POSIX path arguments to Windows paths when calling a native `.exe`, but does **not** convert paths embedded inside a larger string like `file://...` | Explicitly converted the temp file path with `cygpath -m` before building the `file://` argument |
| 7 | Gate 3 failed: API returned `HTTP 500`, Lambda logs showed `Status: timeout` at exactly the 10s ceiling, no exception thrown | Lambda ENIs never receive public IP addresses, even in a subnet with an Internet Gateway route. With no NAT Gateway and no VPC endpoint, the VPC-attached Lambda had no path to the public Secrets Manager endpoint — `GetSecretValue` hung until Lambda's own timeout killed it | Added a VPC Interface Endpoint for Secrets Manager (private DNS enabled), giving Lambda a private path to the service without NAT Gateway cost |

Also fixed along the way, found through code review rather than a failed
run:

- `db_instance_id` output was mapped to `aws_db_instance.this.id` (the
  internal RDS resource ID, e.g. `db-FHF3...`) instead of `.identifier`
  (the actual instance identifier the AWS CLI and gate scripts need)
- `local-exec` provisioner for the Lambda packaging step defaulted to
  `cmd.exe` on Windows, which doesn't understand `rm -rf`/`mkdir -p` —
  fixed by explicitly setting `interpreter = ["bash", "-c"]`
- Rollup script's `jq` invocation referenced `env.RC1`/`env.RC2`/`env.RC3`
  etc. without ever exporting those shell variables — replaced with
  explicit `--arg`/`--argjson` flags

---

## Final gate evidence

```
$ ../scripts/run_all_gates_11a.sh
Gate 11A Lambda/Secret/VPC: PASS
Gate 11A RDS/SG/Private: PASS
Gate 11A API route/invoke: PASS
Lab 11A Gate complete: GREEN (PASS)
```

**Gate 1 — Lambda/Secret/VPC:** confirms Lambda is VPC-attached, its
`DB_SECRET_ARN`/`DB_NAME` env vars match the deployed secret exactly, and
the secret is reachable.

**Gate 2 — RDS/SG/Private:** confirms `PubliclyAccessible=False`, the RDS
security group allows 3306 only from the Lambda security group by group
reference (not CIDR), and explicitly fails if 3306 is ever open to
`0.0.0.0/0`.

**Gate 3 — API Gateway route/invoke:** confirms the API, route, and stage
exist, then performs a live `curl` against `/intake` and checks for both
HTTP 200 and `"ok": true` in the response body — not just a status code,
which would have missed a disguised failure.

CloudWatch confirms a successful end-to-end request:
```
REPORT RequestId: ... Duration: <10000ms  Status: (no error — success)
```

---

## Cleanup performed

- Temporary bastion IAM role/instance profile removed via
  `scripts/teardown_bastion_role.sh` after schema apply completed
- No EC2 instances left running — `bootstrap_schema.sh` terminates the
  bastion automatically in a `trap ... EXIT`, even on failure paths
- Secrets Manager secret set to `recovery_window_in_days = 0` — immediate
  deletion on `terraform destroy`, no orphaned 30-day recovery windows
  blocking re-apply during iteration

---

## Known gaps (tracked, not accidental)

This build is intentionally left unhardened past this point — see
`README.md` → "Known gaps" for the full list (no secret rotation, no
connection pooling/RDS Proxy, no backup retention, API Gateway
auto-deploy with no canary gate, no WAF/throttling, no idempotency key).
Each is tagged `GAP-N` at its resource in the Terraform. Working through
these one at a time is the next phase of this lab, not part of this
runbook.

---

## Status

**Lab 11A: done.**
