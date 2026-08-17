# Gen2X Security Engineering Platform

# INSTALL.md

## `/lab12c` — Agent 9: Compliance Agent

---

## Overview

The Compliance Agent converts operational security evidence into
repeatable compliance results.

It follows one simple rule:

> Python evaluates controls.
>
> Bedrock explains the results.

The agent workflow (see `playbook.md` for the full story):

```text
Load the Book
(controls.json)

↓

Choose Controls

↓

Evaluate Controls

↓

Save Evidence

↓

Calculate Score

↓

Bedrock Explains

↓

Generate PDF + JSON

↓

Chewbacca Guards the Archive
```

---

# Folder Structure

```text
lab12c/

├── install.md                          ← you are here
├── playbook.md                         ← how the agent thinks
│
├── lambda/
│   ├── compliance.py                   ← the Lambda function
│   └── requirements.txt                ← boto3, reportlab
│
├── json/
│   ├── controls.json                   ← the control library
│   └── compliance_test_event.json      ← sample invocation event
│
└── env/
    └── env                             ← sample environment variables
```

One naming note:

The playbook refers to the agent as `compliance_agent.py`.

The file in this repository is `lambda/compliance.py`.

They are the same agent. The Lambda handler below uses the
repository filename.

---

# Prerequisites

1. An AWS account with permission to create Lambda, DynamoDB, S3,
   and IAM resources.

2. AWS CLI configured (`aws configure`).

3. Python 3.12 available locally for packaging.

4. **Amazon Bedrock model access.**

   The agent uses Claude 3 Haiku by default:

   ```text
   anthropic.claude-3-haiku-20240307-v1:0
   ```

   Enable model access in the Bedrock console for your region
   before invoking, or set `ENABLE_BEDROCK=false` to run with the
   deterministic fallback narrative.

---

# Step 1 — Create the DynamoDB Evidence Table

Each control evaluation writes one immutable evidence record.

```bash
aws dynamodb create-table \
  --table-name compliance-evidence \
  --attribute-definitions AttributeName=evidence_id,AttributeType=S \
  --key-schema AttributeName=evidence_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

Example evidence record:

```json
{
  "evidence_id": "uuid",
  "report_id": "compliance-20260811T190000Z",
  "control_id": "DE.AE-03",
  "status": "PASS",
  "severity": "MEDIUM",
  "observation": "AWS WAF blocked malicious requests.",
  "evaluated_at": "2026-08-11T19:00:00+00:00"
}
```

Note

The playbook also describes a future `compliance-findings` table.

The current agent writes only to `compliance-evidence`.

Create the findings table when a later lab introduces it.

---

# Step 2 — Create the Report Bucket

Reports are published in two synchronized formats:

    One for humans (PDF).

    One for platforms (JSON).

```bash
aws s3 mb s3://chewbacca-s3-<YOUR_ACCOUNT_ID>
```

Reports land under:

```text
s3://<bucket>/compliance-reports/YYYY/MM/DD/pdf/<report_id>.pdf
s3://<bucket>/compliance-reports/YYYY/MM/DD/json/<report_id>.json
```

---

# Step 3 — Package the Lambda

ReportLab is **not** part of the AWS Lambda Python runtime.

Package it with the function (or provide it through a Lambda layer).

```bash
cd lab12c/lambda

pip install -r requirements.txt -t package/

cp compliance.py package/
cp ../json/controls.json package/

cd package
zip -r ../compliance_agent.zip .
cd ..
```

The control library must sit at `/var/task/controls.json`
inside the deployment package — copying it into the ZIP root
(as above) achieves exactly that.

---

# Step 4 — Create the Lambda Function

```bash
aws lambda create-function \
  --function-name compliance-agent \
  --runtime python3.12 \
  --handler compliance.lambda_handler \
  --zip-file fileb://compliance_agent.zip \
  --role arn:aws:iam::<YOUR_ACCOUNT_ID>:role/compliance-agent-role \
  --timeout 120 \
  --memory-size 512
```

Why these settings:

    timeout 120     Bedrock narration plus DynamoDB scans
                    take longer than the 3-second default.

    memory 512      ReportLab PDF generation is memory-hungry.

---

# Step 5 — Environment Variables

A sample file lives at `env/env`.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `COMPLIANCE_EVIDENCE_TABLE` | **Yes** | — | DynamoDB evidence table name |
| `REPORT_BUCKET` | **Yes** | — | S3 bucket for published reports |
| `CONTROLS_FILE` | No | `/var/task/controls.json` | Control library path |
| `REPORT_PREFIX` | No | `compliance-reports` | S3 key prefix |
| `COMPLIANCE_FRAMEWORKS` | No | `NIST CSF 2.0` | Default frameworks (comma-separated, or `ALL`) |
| `BEDROCK_MODEL_ID` | No | `anthropic.claude-3-haiku-20240307-v1:0` | Narration model |
| `ENABLE_BEDROCK` | No | `true` | `false` uses the deterministic fallback |
| `ORGANIZATION_NAME` | No | `SEIR Cloud Security` | Report header |
| `REPORT_TITLE` | No | `Compliance Evidence Report` | Report title |
| `UNEVALUATED_STATUS` | No | `REVIEW` | Status for unsupported validators (keep `REVIEW`) |

Important

The two required variables are read at **import time**.

If either is missing, the function fails immediately on cold start
with a `KeyError` — before your handler ever runs.

```bash
aws lambda update-function-configuration \
  --function-name compliance-agent \
  --environment "Variables={
    COMPLIANCE_EVIDENCE_TABLE=compliance-evidence,
    REPORT_BUCKET=chewbacca-s3-<YOUR_ACCOUNT_ID>
  }"
```

---

# Step 6 — IAM Permissions

The execution role needs exactly what the validators touch —
nothing more.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EvidenceTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:Scan",
        "dynamodb:BatchWriteItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:*:<YOUR_ACCOUNT_ID>:table/*"
    },
    {
      "Sid": "ReportBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::chewbacca-s3-<YOUR_ACCOUNT_ID>",
        "arn:aws:s3:::chewbacca-s3-<YOUR_ACCOUNT_ID>/*"
      ]
    },
    {
      "Sid": "BedrockNarration",
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-*"
    },
    {
      "Sid": "ValidatorReadOnly",
      "Effect": "Allow",
      "Action": [
        "events:DescribeRule",
        "scheduler:GetSchedule",
        "sns:GetTopicAttributes",
        "lambda:GetFunctionConfiguration"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Logging",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

Note

A validator that lacks permission does not crash the report.

The affected control becomes `REVIEW` — a permission problem
should be visible, never translated into `PASS`.

---

# Step 7 — Invoke and Verify

Use the provided test event:

```bash
aws lambda invoke \
  --function-name compliance-agent \
  --payload file://../json/compliance_test_event.json \
  --cli-binary-format raw-in-base64-out \
  response.json

cat response.json
```

A successful response contains:

```json
{
  "statusCode": 200,
  "body": "{ \"message\": \"Compliance evidence report generated and published.\", ... }"
}
```

Then verify all three artifacts:

1. Evidence records in DynamoDB:

   ```bash
   aws dynamodb scan --table-name compliance-evidence --select COUNT
   ```

2. The PDF and JSON reports in S3:

   ```bash
   aws s3 ls s3://chewbacca-s3-<YOUR_ACCOUNT_ID>/compliance-reports/ --recursive
   ```

3. CloudWatch logs showing each control evaluation.

---

# Supported Validators

Each control in `controls.json` declares a `validation.type`.

| Type | PASS condition |
|---|---|
| `table_exists` | DynamoDB table exists and is ACTIVE |
| `table_not_empty` | Table exists and holds at least one record |
| `minimum_records` | Table holds at least `minimum` records |
| `s3_prefix` | At least one object exists under the prefix |
| `bedrock_enabled` | Bedrock configuration matches `expected` |
| `eventbridge_rule_exists` | Rule exists and is ENABLED |
| `eventbridge_schedule_exists` | Schedule exists and is ENABLED |
| `sns_topic_exists` | Topic exists and is accessible |
| `lambda_exists` | Function is Active and last update Successful |

Teaching the engine a new validator requires one function and one
registry entry. The engine never changes.

---

# Troubleshooting

**`KeyError: 'COMPLIANCE_EVIDENCE_TABLE'` on every invocation**

The required environment variables are missing. See Step 5.

**`ImportError: No module named 'reportlab'`**

ReportLab was not packaged. Repeat Step 3, or attach a Lambda
layer containing ReportLab.

**`FileNotFoundError: Control library was not found`**

`controls.json` is not inside the deployment package at
`/var/task/controls.json`. Repeat Step 3.

**`No controls matched the requested framework(s).`**

The framework names in your event do not match the `frameworks`
mappings inside `controls.json`. Matching is case-insensitive but
otherwise exact. Use `"frameworks": "ALL"` to evaluate everything.

**Bedrock `AccessDeniedException` in the logs**

Model access is not enabled in this region, or the role lacks
`bedrock:InvokeModel`. The agent automatically falls back to the
deterministic narrative — the report is still produced.

**Report says REVIEW for a control you expected to PASS**

Read the `error` field in the control's DynamoDB evidence record.
Most commonly the execution role lacks a read permission used by
that validator.

---

# What This Agent Never Does

It never says "We are PCI compliant."

It never says "You passed the audit."

It never says "You are secure."

It only says:

> "Based on the evidence currently available, these controls
> passed, failed, or require review."

The report provides control evidence.

It is not a certification, legal opinion, or guarantee of
continuous compliance.

---

# The Rule Worth Remembering

Python evaluates.

Bedrock explains.

Evidence is written before prose.

Chewbacca guards the archive. 🐾