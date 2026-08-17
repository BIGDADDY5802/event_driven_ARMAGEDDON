# Compliance Agent — Launch Guide

This guide walks through deploying, verifying, and testing the
Compliance Agent from a clean checkout. It assumes the surrounding
infrastructure (VPC, RDS, the WAF-fronted intake API, the SEIR
detection/correlation pipeline, and the executive report generator)
is already deployed, since the Compliance Agent evaluates evidence
produced by those components.

---

## 1. Prerequisites

- AWS CLI configured (`aws configure`) with credentials that can
  create Lambda, DynamoDB, IAM, and read/write the shared reports S3
  bucket
- Terraform `>= 1.7.0`
- Python 3.12 available locally, for local testing of validator logic
  if needed
- Amazon Bedrock model access enabled in-region for the model this
  agent invokes (verify under the Bedrock console's **Model access**
  page before first invocation)
- The following already exist in the target AWS account and Terraform
  state, since the Compliance Agent's IAM policy and Terraform
  references depend on them:
  - The shared reports S3 bucket
  - `data.aws_caller_identity.current`, `data.aws_region.current`
  - `var.log_retention_days`

Confirm the repository layout matches what Terraform expects before
proceeding:

```
dev12b/
├── terraform/                       ← run all commands from here
├── lab12c/
│   └── compliance_agent/
│       ├── lambda/
│       │   ├── compliance.py
│       │   └── requirements.txt
│       ├── json/
│       │   ├── controls.json
│       │   └── compliance_test_event.json
│       ├── env/
│       ├── install.md
│       └── playbook.md
```

---

## 2. Deploy

All commands below run from the `terraform/` directory.

```bash
terraform init
terraform validate
terraform plan -out=tfplan
```

**Before applying, read the plan output.** Confirm it shows only
additions for the Compliance Agent's own resources — the DynamoDB
evidence table, the Lambda function, its IAM role and policy, and its
log group — and no changes to unrelated existing resources. If the
plan shows changes or destroys outside these new resources, stop and
investigate before applying; that's a sign of drift or a
misconfiguration elsewhere, not something this deployment should be
causing.

```bash
terraform apply "tfplan"
```

Confirm the new resources landed:

```bash
terraform state list | grep -E "compliance_agent|compliance_evidence"
```

Expect to see, at minimum: `aws_dynamodb_table.compliance_evidence`,
`aws_iam_role.compliance_agent`, `aws_iam_role_policy.compliance_agent`,
`aws_cloudwatch_log_group.compliance_agent`,
`aws_lambda_function.compliance_agent`.

---

## 3. Smoke test — first invocation

```bash
aws lambda invoke \
  --function-name compliance-agent \
  --payload file://../lab12c/compliance_agent/json/compliance_test_event.json \
  --cli-binary-format raw-in-base64-out \
  response.json

cat response.json
```

A healthy first response looks like:

```json
{
  "statusCode": 200,
  "body": "{ \"message\": \"Compliance evidence report generated and published.\", \"overall_status\": \"...\", \"score_percent\": ..., \"controls_evaluated\": N, \"evidence_records_written\": N, \"certification_claimed\": false, ... }"
}
```

`controls_evaluated` and `evidence_records_written` should match —
if they don't, some controls are erroring before they can write
evidence at all, which is worth investigating directly in CloudWatch
Logs before trusting anything else about the run.

**A `REVIEW` or `FAIL` status on first run is not itself a failure of
this deployment.** It means the agent ran correctly and found a real
gap, a missing permission, or a dependency that hasn't produced
evidence yet. Treat the first run's result as data, not as a pass/fail
gate on the deployment itself.

---

## 4. Verification tests

### Test 1 — Evidence table population

```bash
aws dynamodb scan --table-name compliance-evidence --select COUNT
```

`Count` should equal the invocation's `evidence_records_written`
value. A mismatch means some controls are failing before the evidence
write step — check logs for the specific control.

### Test 2 — Report artifacts published

```bash
aws s3 ls s3://<bucket>/compliance-reports/ --recursive
```

Confirm both a `pdf/` and matching `json/` object exist under
today's date path, with the same `report_id` in both filenames.

### Test 3 — JSON/PDF synchronization

```bash
aws s3 cp s3://<bucket>/compliance-reports/YYYY/MM/DD/json/<report_id>.json - | python3 -m json.tool
```

Confirm this parses as valid JSON and its `controls_evaluated` count
matches the PDF's stated total (open the PDF directly to confirm).

### Test 4 — Investigate any REVIEW or FAIL result

```bash
aws dynamodb scan --table-name compliance-evidence --output json \
  --query "Items[?status.S=='REVIEW']"

aws dynamodb scan --table-name compliance-evidence --output json \
  --query "Items[?status.S=='FAIL']"
```

For any `REVIEW` result, read the `error` field in that item — this
will typically point to a specific missing IAM permission on a
validator's target resource. For `FAIL`, read `observation` — this
describes what was actually checked and what was found, in plain
language.

### Test 5 — Least-privilege boundary check

Confirm the agent's role cannot write outside its own report prefix
(should fail with `AccessDenied`):

```bash
aws sts get-caller-identity  # confirm you are NOT testing as the Lambda's own role
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account-id>:role/compliance-agent-role \
  --action-names s3:PutObject \
  --resource-arns "arn:aws:s3:::<bucket>/executive-reports/should-not-be-writable.txt"
```

Expect `EvalDecision: implicitDeny`. This confirms the write scope is
actually enforced, not just declared in Terraform and never verified.

### Test 6 — Idempotent re-run

Re-invoke the Lambda a second time with the same test event:

```bash
aws lambda invoke \
  --function-name compliance-agent \
  --payload file://../lab12c/compliance_agent/json/compliance_test_event.json \
  --cli-binary-format raw-in-base64-out \
  response2.json

aws dynamodb scan --table-name compliance-evidence --select COUNT
```

Confirm the count increased by exactly the number of controls
evaluated in the second run (each invocation should produce a new,
distinct set of evidence records with new `evidence_id` and
`report_id` values — evidence is additive and historical, not
overwritten in place).

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `KeyError: 'COMPLIANCE_EVIDENCE_TABLE'` on every invocation | Required environment variable missing | Confirm the Lambda's `environment` block in Terraform includes both required variables, then redeploy |
| `ImportError: No module named 'reportlab'` | Dependency not packaged, or wrong-platform wheel bundled | Confirm the packaging step used `--platform manylinux_2_28_x86_64 --only-binary=:all:` rather than a plain `pip install`, especially if building on Windows |
| `FileNotFoundError: Control library was not found` | `controls.json` missing from the deployment package root | Confirm the build step copies `controls.json` into the zip root, not a subdirectory |
| `No controls matched the requested framework(s)` | Framework name in the invocation payload doesn't match `controls.json` | Check exact framework name spelling (case-insensitive, but otherwise exact), or pass `"frameworks": "ALL"` |
| Bedrock `AccessDeniedException` in logs | Model access not enabled in-region, or IAM role missing the correct model/inference-profile grant | Enable model access in the Bedrock console; confirm the IAM policy's Bedrock statements reference the exact model ID the Lambda's environment variable specifies |
| A specific control unexpectedly shows `REVIEW` | The validator's IAM permission for that specific resource is missing or too narrowly scoped | Read the `error` field on that evidence record; broaden the specific IAM statement, redeploy, re-invoke |
| `overall_status` changes between otherwise-identical runs | Underlying evidence genuinely changed between runs (a table gained/lost records, a report was or wasn't published in the interim) | Expected behavior — the agent reports current state each time, not a cached result |

---

## 6. Rollback / teardown

To remove only the Compliance Agent's resources without affecting the
rest of the stack:

```bash
terraform plan -destroy -target=aws_lambda_function.compliance_agent \
  -target=aws_iam_role_policy.compliance_agent \
  -target=aws_iam_role.compliance_agent \
  -target=aws_cloudwatch_log_group.compliance_agent \
  -target=aws_dynamodb_table.compliance_evidence \
  -out=tfplan-destroy

terraform apply "tfplan-destroy"
```

Review the plan carefully before applying — a `-target` destroy plan
should list only these five resources. If anything else appears,
stop and investigate before proceeding; that would indicate an
unexpected dependency on one of these resources from elsewhere in the
stack.

Evidence and report artifacts already written to DynamoDB and S3 are
**not** removed by this teardown — they persist independently of the
Lambda that created them, by design, since they represent historical
evidence rather than live application state.