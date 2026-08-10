# SEIR-I Lab 11B — Human Incident Notes

**Student:** Jerome · firstofmyname5802@gmail.com · SEIR-I
**Account:** `7781********` (redacted) · **Region:** us-east-1
**System:** Client → API Gateway `<API_ID>` → Lambda `chewbacca-intake-lambda-11a` → RDS MySQL `chewbacca-11a-mysql`
**Incident window:** 2026-07-25T07:39:56Z → 07:49:55Z (UTC)

### Redaction key

Identifiers below are redacted for external distribution. Unredacted values are
present in the evidence pack, which is **not** modified — see *Note on redaction*
at the end.

| Token | Meaning |
|---|---|
| `7781********` | AWS account ID |
| `<API_ID>` | API Gateway HTTP API ID |
| `sg-0a26…b06de` | RDS security group |
| `sg-0f92…e3f3f` | Lambda security group |
| `<RDS_ENDPOINT>` | RDS instance DNS name |
| `AKIA****…` / `AIDA****…` | IAM access key ID / principal ID |
| `174.252.xxx.xxx` | operator source IP |

---

## 1. What was the initial symptom?

A POST to the `/intake` route returned **HTTP 502** with the body
`{"ok": false, "error": "DB_WRITE_FAILED", "request_id": "cc4adae5-…"}`. The same
request had returned HTTP 200 fifty-two seconds earlier. From a caller's
perspective the API was reachable and responding — it accepted the request,
answered in about five seconds, and reported an opaque failure code plus a
correlation ID. Nothing in the client-facing response identified a database, a
network path, or which component had failed.

Recorded in `invoke_baseline.json` (200 at 07:39:56Z) and `invoke_failure.json`
(502 at 07:40:48Z).

---

## 2. What evidence showed the system was failing?

The HTTP code proved *that* it failed; four other artifacts were needed to
establish *what* failed.

`logs_tail.out` showed the Lambda executing and returning on every attempt —
`START`, `END`, `REPORT` — with durations of 5185.28 ms, 5170.11 ms and
5059.70 ms across three separate cold-start containers. Healthy invocations in the
same file run 164–213 ms. Three failures repeating to within roughly 15 ms of each
other is not variable latency; it is a fixed deadline being reached, which
indicates a connection attempt expiring at the client's ~5 second connect timeout
rather than a server actively refusing. That distinction narrowed the problem to
the network path before any configuration was inspected.

`sg_after_revoke_3306.out` returned `[]`: no inbound TCP/3306 rule existed on the
RDS security group `sg-0a26…b06de`.

`tf_plan_failure.out` stated the cause directly —
`aws_security_group_rule.rds_ingress_from_lambda will be created`. Terraform
compared its recorded configuration against live infrastructure and reported the
rule as absent. This was the decisive artifact: the tool, not the operator,
identified the missing component.

`cloudtrail_revoke_3306.json` established chain of custody. A
`RevokeSecurityGroupIngress` call at 07:40:16Z by IAM user `awscli`
(`AKIA****…`, source `174.252.xxx.xxx`) removed rule `sgr-08df…ce37e`:
tcp/3306 on `sg-0a26…b06de` referencing `sg-0f92…e3f3f`. Thirty-two seconds later
the API returned 502.

Alarm state per phase is recorded in `alarms_baseline.out`, `alarms_failure.out`
and `alarms_recovery.out`.

---

## 3. What was the root cause?

The TCP/3306 ingress rule on the RDS security group that referenced the Lambda
security group was revoked, so Lambda's connection attempts reached no listener
and expired at the client's five-second connect timeout, causing the handler to
return `DB_WRITE_FAILED` and API Gateway to surface HTTP 502.

---

## 4. What change fixed the issue?

`terraform apply -input=false -auto-approve` was run against the existing
Lab 11A configuration. The plan reported `1 to add, 0 to change, 0 to destroy`
and recreated a single resource, `aws_security_group_rule.rds_ingress_from_lambda`
— tcp/3306 on `sg-0a26…b06de` referencing `sg-0f92…e3f3f`, matching the
description `Allow MySQL from the Lambda SG only`.

No other change was made. Lambda code, the Secrets Manager secret, VPC and subnet
configuration, IAM policies and the API Gateway integration were untouched. The
recovery was a declarative re-application of committed configuration rather than a
manual console edit, so the change set is reviewable and the blast radius —
one rule — is visible in `tf_plan_failure.out`.

Terraform reported the new resource under its synthetic ID `sgrule-1674847057`,
identical to the pre-incident value because that ID is a hash of the rule's
attributes. AWS issued a new underlying rule ID (`sgr-…`), so the recovered
object is equivalent in configuration but is not the original object.

---

## 5. How did you verify recovery?

Three independent confirmations, in different layers.

**Behaviour:** the same POST returned HTTP 200 at 07:49:55Z
(`invoke_recovery.json`), and Lambda duration fell from ~5100 ms to 213.52 ms —
the timing signature that identified the fault, now inverted.

**Configuration:** `sg_after_restore.out` shows the tcp/3306 rule present with
`ReferencedGroupInfo.GroupId` equal to the Lambda security group, confirming the
rule is scoped to the Lambda's identity rather than to an address range.

**Declared intent:** `tf_plan_recovery.out` reports `No changes`, meaning live
infrastructure again matches the committed configuration with no residual drift.

The pack was then validated by `make_manifest.sh`, which passed four gates —
required files present, phase timestamps in ascending order, HTTP codes matching
the expected 200 / non-200 / 200 pattern, and security-group snapshots consistent
with the narrative — before writing hashes and the manifest.

This verification is not a formality: an earlier recovery attempt was **rejected**
by the same tooling. See disclosure B.

---

## 6. What would you monitor next time to catch this faster?

Two gaps surfaced during this exercise, and the monitoring plan follows from them.

The first is an observability gap in the application. A total loss of database
connectivity produced no diagnostic output whatsoever — only `START`, `END` and a
duration. Root cause was recoverable from Terraform drift and security-group
state, but not from application logs. An engineer without prior knowledge of the
injected fault would have had a five-second duration and an opaque error code to
work from. The remediation is to log the caught exception server-side with the
same `request_id` already returned to the client, which makes the existing error
contract traceable end to end.

The second gap was in monitoring itself, and was found before the incident: the
API 5xx alarm had been created with dimension `ApiId = "yes"`, a value accepted
from an interactive Terraform prompt. It was evaluating metrics for an API that
does not exist and would have remained silent throughout. A detector pointed at
the wrong dimension is worse than no detector, because it reports healthy. It was
corrected before the baseline was established.

In priority order:

1. Log caught exceptions with `request_id`; alarm on a metric filter for
   `DB_WRITE_FAILED` so failures are detected by class, not only by count.
2. Alarm on Lambda `Duration` p95. The five-second plateau appeared before any
   error-count threshold would have been meaningful and is the earliest signal.
3. Scheduled drift detection (`terraform plan` on a timer, alerting on non-zero
   changes). This incident was a configuration change, and drift detection would
   have caught it independent of traffic — including during a quiet period when no
   invocation would have triggered an error alarm.
4. Bind alarm dimensions to Terraform resource references rather than to supplied
   values, so a detector cannot silently outlive or mismatch the resource it
   watches.
5. Retain the existing `AWS/Lambda Errors` and `AWS/ApiGateway 5xx` alarms at
   60-second periods with SNS notification; both are appropriate for user-visible
   failure, and both were in place for this incident.

---

## Disclosures

Included because omitting them would misrepresent the pack.

**A. Two incident cycles exist in the evidence.** CloudTrail records
`RevokeSecurityGroupIngress` at 07:03:14Z (rule `sgr-0f63…16340`) and at 07:40:16Z
(rule `sgr-08df…ce37e`). The first cycle was run before the evidence collector
existed and produced no `sg_before_revoke_3306.out`. Rather than reconstruct that
file after the fact, the full cycle was re-run under the collector between 07:39
and 07:49; all six spec-required files are live captures from that second cycle.
`logs_tail.out` deliberately retains both cycles as one continuous timeline.

**B. A false recovery was produced and rejected.** At 07:30:02Z a recovery phase
recorded HTTP 502, because the preceding `terraform apply` had failed with
`Error: No value for required variable "api_id"` and the two commands had not been
chained — so evidence collection ran against a system that was still broken. The
collector's expectation check flagged it in real time
(`WARNING: expected 200 for phase 'recovery' but got 502`). A subsequent manifest
attempt then produced a chronologically impossible pack: recovery timestamped
07:36:29Z, preceding the 07:40:48Z failure it claimed to resolve. The files were
authentic and their hashes were correct; only the timestamps exposed the problem.
A chronology gate was added to `make_manifest.sh`, which now refuses to emit a
manifest whose phase timestamps are out of order, and subsequent commands were
chained with `&&` so a failed recovery cannot generate recovery evidence.

**C. Pre-existing Lab 11A defect, not part of this incident.** Before Lab 11B
began, the API returned HTTP 500 because the Lambda deployment package omitted the
`cryptography` module, so PyMySQL could not complete `caching_sha2_password`
authentication. That failure took ~237 ms. It was resolved before the 11B baseline
was established and is **not** the root cause in section 3. It is recorded here
because the timing contrast — a ~237 ms authentication rejection versus a ~5100 ms
connection timeout — is what made the 11B diagnosis fast, and because the schema
bootstrap was also outstanding at that time and was likewise not implicated in
either failure.

---

## Evidence index

| File | Proves |
|---|---|
| `invoke_baseline.json` / `.http_code` | system healthy before the incident (200) |
| `invoke_failure.json` / `.http_code` | system failing during the incident (502) |
| `invoke_recovery.json` / `.http_code` | system healthy after recovery (200) |
| `logs_tail.out` | continuous Lambda log timeline, all phases, with durations |
| `sg_before_revoke_3306.out` | the 3306 rule existed before the incident |
| `sg_after_revoke_3306.out` | the rule was absent during the incident |
| `sg_after_restore.out` | the rule was present after recovery |
| `tf_plan_baseline.out` | no drift before the incident |
| `tf_plan_failure.out` | drift: the SG rule is missing — root cause, stated by the tool |
| `tf_plan_recovery.out` | no drift after recovery |
| `cloudtrail_revoke_3306.json` | who removed the rule, when, and from where |
| `alarms_*.out` | CloudWatch alarm state per phase |
| `resolved_inputs_*.json` | which resource IDs each collection run actually used |
| `t_*.txt` | UTC timestamp per phase, supporting the chronology gate |
| `hashes.txt` | sha256 of every file in the pack |
| `evidence_manifest.json` | signed index of the six spec-required files |

Integrity check: `( cd evidence_11b && sha256sum -c hashes.txt )`

---

## Note on redaction

Redaction is applied to **this narrative only**. The evidence pack is left
unmodified, because every file is fingerprinted in `hashes.txt` and listed in
`evidence_manifest.json`; editing a file to remove an identifier would change its
hash and invalidate the manifest that proves the pack was not altered.

If the pack itself must be distributed outside the account boundary, the correct
procedure is to copy it, redact the copy, and generate a **separate** hash set and
manifest for the redacted copy — retaining the original pack and its original
hashes as the authoritative record. Redacting in place destroys the property the
hashes exist to establish.