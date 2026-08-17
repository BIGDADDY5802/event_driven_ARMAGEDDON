# Compliance Agent — Technical Runbook

## Overview

The Compliance Agent is an automated evidence-collection and evaluation
system that converts operational security telemetry into structured,
auditable compliance results. It is the third component in a security
event pipeline that also includes automated threat correlation and
executive incident reporting.

The agent follows one governing principle: **Python evaluates controls
deterministically; a language model only explains results that have
already been calculated.** This separation exists specifically to
prevent non-deterministic output from ever influencing a pass/fail
compliance decision.

---

## Business Problem

Organizations subject to security or regulatory frameworks (NIST CSF,
CIS Benchmarks, SOC 2, HIPAA, PCI-DSS, and similar) face a recurring
operational cost: **compliance evidence is expensive to collect, easy
to let go stale, and difficult to prove after the fact.**

Manual compliance verification typically involves:

- An analyst periodically checking whether required controls (logging
  enabled, encryption configured, access properly restricted, incident
  response actually functioning) are still true
- Evidence captured inconsistently, often screenshots or ad hoc notes
- No reliable answer to "prove this control was met on a specific
  date" months after an audit period has closed
- Real risk of a control silently regressing between audit cycles with
  nobody noticing until the next audit

This system addresses each of these directly:

| Manual process | This system |
|---|---|
| Periodic, human-triggered checks | Can run on any schedule or on demand, consistently |
| Evidence inconsistently recorded | Every check writes a structured, timestamped record immediately |
| No historical trail | Evidence is retained in DynamoDB independent of the summary report |
| Human interpretation of raw logs | Deterministic pass/fail/review logic, explained afterward in plain language |
| Audit prep is a scramble | Evidence already exists continuously, in machine-readable form |

**The system explicitly does not claim compliance certification.** Its
output is evidence of control status at a point in time — the
distinction matters both technically and legally, and the agent is
designed to never blur that line, even when every control passes.

---

## Architecture

```
controls.json  (the control library — framework-agnostic)
      │
      ▼
Select applicable controls (by requested framework, or ALL)
      │
      ▼
Evaluate each control via a registered validator
      │
      ▼
Write evidence immediately, per control (not batched at the end)
      │
      ▼
Calculate PASS / FAIL / REVIEW deterministically (counting, not AI)
      │
      ▼
Bedrock generates narrative explanation from already-computed results
      │
      ▼
Publish synchronized PDF (human-readable) + JSON (machine-readable)
      │
      ▼
Both artifacts land in S3, evidence lands in DynamoDB
```

### Why evidence is written immediately, not at the end

If the Lambda fails partway through a run (timeout, crash, throttling),
every control evaluated up to that point has already been durably
recorded. Nothing is lost to an incomplete run — the evidence table
reflects exactly what was checked and what wasn't, rather than an
all-or-nothing report.

### Why scoring is deterministic

PASS/FAIL/REVIEW is computed by counting validator results, not by
asking a language model to judge compliance. This is a deliberate
constraint: a compliance decision needs to be reproducible and
explainable independent of model behavior, temperature, or prompt
drift. The language model's only role is narrating a decision that has
already been made.

### Why both PDF and JSON are produced, from the same source

The JSON is generated first; the PDF is rendered from it, not the
reverse. This guarantees the human-readable and machine-readable
artifacts can never drift out of sync with each other. The JSON exists
specifically so future systems (data lakes, BI tooling, other
automated agents) can consume compliance results without parsing a
PDF.

---

## Components

| Component | Type | Purpose |
|---|---|---|
| `compliance-evidence` | DynamoDB table | One immutable record per control evaluation |
| `compliance-agent` | Lambda function | Loads controls, dispatches validators, generates reports |
| Report bucket (shared, `*/compliance-reports/` prefix) | S3 | Stores the PDF/JSON report pair |
| Bedrock (Claude, via cross-Region inference profile) | Model | Generates the narrative explanation only |

### Validator registry

Each control in `controls.json` declares a `validation.type`. The
Lambda dispatches to a matching, reusable validator function:

| Validator type | What it checks |
|---|---|
| `table_exists` | A DynamoDB table exists and is `ACTIVE` |
| `table_not_empty` | A table exists and holds at least one record |
| `minimum_records` | A table holds at least a specified number of records |
| `s3_prefix` | At least one object exists under a given S3 prefix |
| `bedrock_enabled` | Bedrock configuration matches expected values |
| `eventbridge_rule_exists` | An EventBridge rule exists and is enabled |
| `sns_topic_exists` | An SNS topic exists and is accessible |
| `lambda_exists` | A Lambda function exists, is active, and last deployed successfully |

Adding support for a new kind of control requires one new validator
function and one registry entry. The evaluation engine itself never
changes — this is what allows the same code to evaluate NIST controls
today and a different framework (PCI, HIPAA, or an internal policy
set) later, by editing `controls.json` rather than the Lambda.

### IAM permission model

Permissions are split by purpose, not granted broadly by default:

- **Writes** (evidence records, published reports) are scoped tightly
  to the exact resources this agent owns.
- **Reads** used by validators are necessarily broader — a generic
  compliance engine has to be able to check the state of *other*
  components (a DynamoDB table it doesn't own, an S3 prefix another
  service publishes to) as directed by `controls.json`, not just its
  own resources. This breadth is intentional and documented at the
  point it's granted, not accidental.
- A validator that lacks a needed permission does not fail the whole
  run — the affected control resolves to `REVIEW` with the underlying
  error recorded in that control's evidence record. A permissions gap
  is meant to be visible, never silently converted into a `PASS`.

---

## Evidence record schema

```json
{
  "evidence_id": "uuid",
  "report_id": "compliance-<timestamp>",
  "control_id": "CTRL-004",
  "category": "Governance",
  "title": "Executive Reporting",
  "frameworks": [{ "framework": "NIST CSF 2.0", "control": "GV.OV-01" }],
  "status": "PASS | FAIL | REVIEW",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "validator": "compliance_agent.py",
  "observation": "Human-readable statement of what was found",
  "evidence": { "...validator-specific structured detail..." },
  "evidence_sources": ["..."],
  "error": "Populated only when status is REVIEW due to a validator failure",
  "evaluated_at": "ISO 8601 timestamp"
}
```

---

## Report artifact locations

```
s3://<bucket>/compliance-reports/YYYY/MM/DD/pdf/<report_id>.pdf
s3://<bucket>/compliance-reports/YYYY/MM/DD/json/<report_id>.json
```

---

## Known limitations

- `compliance-findings` (a planned second table for tracked
  remediation items, distinct from evidence) is not yet implemented.
  The current agent writes only to `compliance-evidence`.
- Validators check current-state resource existence and basic
  configuration; they do not currently verify time-series properties
  (e.g., "has this control been continuously true for 90 days").
- The system reports on evidence *currently available* to it. A
  validator lacking permission to check something correctly resolves
  to `REVIEW`, not a false `PASS` — but a `REVIEW` still requires
  human follow-up before the underlying control can be considered
  verified either way.

---

## What this system never does

It never states that an organization "is compliant," "passed an
audit," or "is secure." Its output is always framed as:

> "Based on the evidence currently available, these controls passed,
> failed, or require review."

This is not a certification, a legal opinion, or a guarantee of
continuous compliance — it is a structured, timestamped, reproducible
record of control status at the moment it was checked.

---

## Documentation references

- [AWS Lambda developer guide](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)
- [Amazon DynamoDB developer guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html)
- [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Amazon S3 user guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html)
- [Amazon Bedrock user guide](https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html)
- [Amazon Bedrock cross-Region inference profiles](https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)