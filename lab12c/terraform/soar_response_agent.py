#!/usr/bin/env python3
"""
soar_response_agent.py

WHAT THIS LAMBDA DOES (in plain English):
    1. EventBridge taps us on the shoulder and says "hey, check out
       finding #1234."
    2. We go look up the FULL finding record in DynamoDB (we don't
       trust the small EventBridge message to have everything).
    3. We "claim" the finding immediately, like punching a raffle
       ticket, so nobody else can process the same finding twice.
    4. We pick a response plan (playbook) based on severity. This
       is a simple lookup table -- no AI involved in this decision.
    5. We ask Bedrock (Claude) to write a human-readable summary.
       If Bedrock fails or is turned off, we write our own summary.
    6. We create an "incident" record, send an SNS notification,
       and mark the finding as fully processed.

WHY THE "CLAIM FIRST" STEP MATTERS:
    EventBridge sometimes delivers the SAME event twice (this is
    normal AWS behavior, not a bug). Lambda can also get invoked
    twice for the same event if a retry happens. Without claiming
    the finding FIRST, two invocations could both race through this
    whole function, both call expensive Bedrock, and both send a
    duplicate SNS notification to your security team. Claiming the
    finding first, using a DynamoDB "conditional write," guarantees
    only ONE invocation ever makes it past that first checkpoint.
"""

import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# ============================================================
# AWS clients
# ------------------------------------------------------------
# These are created ONCE, when the Lambda "cold starts" (the very
# first time this container spins up). AWS Lambda then reuses this
# same container (and these same client objects) for later
# invocations, which saves time. This is the "module-level caching"
# pattern you've already been using -- good instinct, keep it.
# ============================================================

dynamodb = boto3.resource("dynamodb")
bedrock_client = boto3.client("bedrock-runtime")
sns_client = boto3.client("sns")


# ============================================================
# Environment variables
# ------------------------------------------------------------
# These come from your Terraform Lambda resource (the `environment`
# block). Using os.environ["X"] (no default) means: if this variable
# is missing, CRASH LOUDLY at cold start instead of silently
# misbehaving later. That's intentional for required config.
# os.environ.get("X", "default") is used only for truly optional
# settings where a default makes sense.
# ============================================================

CORRELATION_FINDINGS_TABLE = os.environ["CORRELATION_FINDINGS_TABLE"]
SECURITY_INCIDENTS_TABLE = os.environ["SECURITY_INCIDENTS_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    # Haiku 4.5 requires a cross-Region inference profile, not
    # direct on-demand invocation -- confirmed via a live
    # ValidationException on the Correlation Agent. Fixing here
    # too before SOAR hits the identical error on first real use.
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)

ENABLE_BEDROCK = os.environ.get("ENABLE_BEDROCK", "true").lower() == "true"

findings_table = dynamodb.Table(CORRELATION_FINDINGS_TABLE)
incidents_table = dynamodb.Table(SECURITY_INCIDENTS_TABLE)


# ============================================================
# Status values for a finding
# ------------------------------------------------------------
# Think of this like the stages of a food delivery order:
#   OPEN        -> order placed, nobody's cooking it yet
#   PROCESSING  -> a cook has claimed it, they're cooking right now
#   RESPONSE_COMPLETED / ESCALATED / CLOSED / RESOLVED -> done, in
#                  some final state. Don't cook it again.
# Centralizing these strings here (instead of retyping them all over
# the file) means if you ever rename a status, you only change it
# in ONE place.
# ============================================================

STATUS_OPEN = "OPEN"
STATUS_PROCESSING = "PROCESSING"
STATUS_COMPLETED = "RESPONSE_COMPLETED"

# Statuses that mean "this finding is fully done, do not touch it."
TERMINAL_STATUSES = {
    "RESPONSE_COMPLETED",
    "ESCALATED",
    "CLOSED",
    "RESOLVED",
}


# ============================================================
# Custom exceptions
# ------------------------------------------------------------
# Python lets you make your own error "types." We use these so that
# lambda_handler can tell the difference between "this is totally
# normal, someone already handled this finding, no big deal" versus
# "something actually broke." That distinction matters because we
# return a different HTTP-style status code for each case.
# ============================================================

class AlreadyProcessedError(Exception):
    """Raised when a finding is already claimed or fully processed
    by another invocation. This is NOT a failure -- it's the
    idempotency guard working as intended."""


class InvalidSeverityError(Exception):
    """Raised when a finding has a severity value we don't
    recognize. We deliberately STOP here instead of guessing,
    because guessing wrong on a security severity is dangerous
    (see the 'fail closed, not open' explanation below)."""


# ============================================================
# Playbooks
# ------------------------------------------------------------
# This is just a lookup table (a Python dict). Given a severity
# string, it tells us: do we notify someone? Do we create an
# incident? What priority number does it get? This is 100%
# deterministic -- Bedrock never touches this decision. Bedrock only
# writes the human-readable explanation AFTER this table has already
# decided what's going to happen.
# ============================================================

PLAYBOOKS = {
    "LOW": {
        "name": "RECORD_ONLY",
        "notify": False,
        "create_incident": True,
        "priority": 4,
        "description": (
            "Record the finding for historical analysis. "
            "No immediate analyst notification is required."
        ),
    },
    "MEDIUM": {
        "name": "NOTIFY_ANALYST",
        "notify": True,
        "create_incident": True,
        "priority": 3,
        "description": (
            "Create an incident and notify the security "
            "operations team for review."
        ),
    },
    "HIGH": {
        "name": "CREATE_AND_ESCALATE_INCIDENT",
        "notify": True,
        "create_incident": True,
        "priority": 2,
        "description": (
            "Create a high-priority incident and escalate "
            "the finding to the security operations team."
        ),
    },
    "CRITICAL": {
        "name": "REQUEST_URGENT_REVIEW",
        "notify": True,
        "create_incident": True,
        "priority": 1,
        "description": (
            "Create a critical incident and request urgent "
            "human review. No containment action is performed."
        ),
    },
}


# ============================================================
# General helpers
# ============================================================

def utc_now() -> str:
    """Return the current UTC time as a text timestamp, like
    '2026-08-09T14:32:00+00:00'. We always store timestamps in
    UTC (not local time) so that logs from different AWS regions
    line up correctly."""

    return datetime.now(timezone.utc).isoformat()


def decimal_to_native(value: Any) -> Any:
    """DynamoDB stores numbers as a special 'Decimal' type, not
    normal Python int/float. This function walks through a dict
    or list and converts every Decimal it finds into a plain int
    or float, so the rest of our code (and json.dumps) doesn't
    choke on it. This is a recursive function: it calls itself on
    nested lists/dicts until everything is converted."""

    if isinstance(value, list):
        return [decimal_to_native(item) for item in value]

    if isinstance(value, dict):
        return {key: decimal_to_native(item) for key, item in value.items()}

    if isinstance(value, Decimal):
        # A Decimal like 5.0 is really a whole number -> return int.
        # A Decimal like 5.5 has a fraction -> return float.
        if value % 1 == 0:
            return int(value)
        return float(value)

    return value


def normalize_severity(value: Any) -> str:
    """
    Validate a severity value from the finding.

    IMPORTANT CHANGE FROM THE ORIGINAL VERSION:
    The old code treated any unrecognized severity as "LOW" and
    kept going. That's called "failing open" -- if something's
    wrong, we quietly do the LEAST cautious thing. For a security
    system, that's backwards. If the Correlation Agent ever sends
    a typo'd severity, or a brand-new severity tier gets added
    upstream that this Lambda doesn't know about yet, we want to
    STOP LOUDLY and raise an error ("fail closed"), not silently
    downgrade a possibly-serious finding to "just record it."
    """

    severity = str(value or "").upper()

    if severity not in PLAYBOOKS:
        raise InvalidSeverityError(
            f"Unrecognized severity '{severity}'. Refusing to guess "
            f"a playbook. Valid values are: {sorted(PLAYBOOKS.keys())}"
        )

    return severity


# ============================================================
# EventBridge event parsing
# ============================================================

def extract_finding_id(event: dict[str, Any]) -> str:
    """
    Pull finding_id out of the incoming event.

    EventBridge wraps the useful data inside a "detail" key, like:
        { "detail-type": "...", "detail": { "finding_id": "..." } }

    We also allow finding_id at the very top level of the event,
    which is handy when you're manually testing this Lambda in the
    AWS Console instead of triggering it through real EventBridge.
    """

    detail = event.get("detail", {})
    finding_id = detail.get("finding_id") or event.get("finding_id")

    if not finding_id:
        raise ValueError("The event does not contain finding_id.")

    return str(finding_id)


# ============================================================
# Finding retrieval and validation
# ============================================================

def get_finding(finding_id: str) -> dict[str, Any]:
    """Fetch the full finding record from DynamoDB.

    ConsistentRead=True means: give me the absolute latest data,
    don't serve me a slightly-stale cached copy. This matters here
    because we're about to make a decision based on this data, and
    a stale read could show us an old status."""

    print(f"Retrieving finding {finding_id}.")

    response = findings_table.get_item(
        Key={"finding_id": finding_id},
        ConsistentRead=True,
    )

    finding = response.get("Item")

    if not finding:
        raise ValueError(f"Finding {finding_id} does not exist.")

    return decimal_to_native(finding)


def validate_finding(finding: dict[str, Any]) -> None:
    """Check that this finding is actually safe to process:
    it has all the fields we need, and it isn't already finished."""

    required_fields = ["finding_id", "severity", "created_at", "bedrock_report"]
    missing_fields = [f for f in required_fields if not finding.get(f)]

    if missing_fields:
        raise ValueError(
            "Finding is missing required fields: " + ", ".join(missing_fields)
        )

    current_status = str(finding.get("status", STATUS_OPEN)).upper()

    if current_status in TERMINAL_STATUSES:
        raise AlreadyProcessedError(
            f"Finding is already in status {current_status}."
        )


# ============================================================
# THE KEY FIX: claim the finding BEFORE doing any expensive work
# ------------------------------------------------------------
# This is the "punch the raffle ticket at the front door" step from
# the explanation above. We use DynamoDB's ConditionExpression,
# which means: "only perform this write if the condition is true
# AT THE EXACT MOMENT of the write." DynamoDB checks and writes as
# ONE atomic operation -- there's no gap in time where a second
# Lambda invocation could sneak in between "check" and "write."
#
# If two invocations both try to claim the same finding at nearly
# the same instant, DynamoDB guarantees exactly one of them wins.
# The loser gets a ClientError with code
# "ConditionalCheckFailedException" -- we catch that specifically
# and turn it into our friendly AlreadyProcessedError.
# ============================================================

def claim_finding(finding_id: str) -> None:
    """Atomically mark a finding as PROCESSING. Raises
    AlreadyProcessedError if some other invocation already claimed
    it first. Call this BEFORE calling Bedrock or sending
    notifications."""

    now = utc_now()

    try:
        findings_table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression=(
                "SET #status = :processing, claimed_at = :now"
            ),
            # This is the guard: only write if there is currently
            # NO status field at all, OR the status is still OPEN.
            # If someone else already flipped it to PROCESSING or
            # further, this condition is false and the write is
            # rejected.
            ConditionExpression=(
                "attribute_not_exists(#status) OR #status = :open_status"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":processing": STATUS_PROCESSING,
                ":open_status": STATUS_OPEN,
                ":now": now,
            },
        )

        print(f"Claimed finding {finding_id} for processing.")

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "ConditionalCheckFailedException":
            raise AlreadyProcessedError(
                f"Finding {finding_id} is already claimed or "
                "processed by another invocation."
            )

        # Any OTHER kind of AWS error (network blip, permissions
        # issue, etc.) is a real problem -- let it bubble up so the
        # generic error handler in lambda_handler catches it and
        # returns a proper 500.
        raise


# ============================================================
# Playbook selection
# ============================================================

def select_playbook(finding: dict[str, Any]) -> dict[str, Any]:
    """Look up the deterministic response plan for this severity.
    Bedrock is never involved in this decision -- it's a plain
    dictionary lookup, which means it's predictable and testable."""

    severity = normalize_severity(finding.get("severity"))

    playbook = {**PLAYBOOKS[severity], "severity": severity}

    print(f"Selected playbook {playbook['name']} for severity {severity}.")

    return playbook


# ============================================================
# Bedrock informational enrichment
# ------------------------------------------------------------
# Bedrock's ONLY job here is to turn our structured data into a
# nicely-written summary for a human analyst. It never decides
# severity, never decides the playbook, and is explicitly told in
# the prompt not to recommend automatic containment actions.
# ============================================================

def build_finding_context(
    finding: dict[str, Any],
    playbook: dict[str, Any],
) -> dict[str, Any]:
    """Build a small, clean dictionary of just the fields Bedrock
    actually needs. We don't hand Bedrock the entire raw DynamoDB
    item -- only what's relevant to writing a good summary."""

    evidence = finding.get("evidence", {})

    return {
        "finding_id": finding.get("finding_id"),
        "created_at": finding.get("created_at"),
        "severity": playbook["severity"],
        "risk_score": finding.get("risk_score"),
        "primary_source_ip": finding.get("primary_source_ip"),
        "primary_target": finding.get("primary_target"),
        "event_count": finding.get("event_count"),
        "correlation_report": finding.get("bedrock_report"),
        "deterministic_findings": evidence.get("deterministic_findings", []),
        "selected_playbook": {
            "name": playbook["name"],
            "description": playbook["description"],
        },
    }


def call_bedrock(finding_context: dict[str, Any]) -> dict[str, Any]:
    """Ask Claude (via Bedrock) to write the human-facing summary.
    Raises an exception if anything goes wrong -- the caller
    (lambda_handler) is responsible for catching that and falling
    back to create_fallback_summary()."""

    prompt = f"""
You are assisting a Security Operations Center.

A deterministic SOAR workflow has already selected the response
playbook. You must not change the severity, risk score, evidence,
or selected playbook.

Threat finding:
{json.dumps(finding_context, indent=2, default=str)}

Create a response using exactly these headings:

Incident Title:
SOC Alert:
Manager Summary:
Analyst Investigation Checklist:
Why This Playbook Was Selected:
Limitations and Unknowns:

Requirements:
- Base the response only on the supplied evidence.
- Separate observed facts from possible interpretations.
- Do not claim that an exploit succeeded.
- Do not claim that the source IP is malicious unless the evidence
  explicitly proves that.
- Do not recommend automatic IP blocking, account disabling,
  credential revocation, or destructive containment.
- State clearly that a human analyst must review the finding.
- Keep the output concise and operationally useful.
""".strip()

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 900,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}],
            }
        ],
    }

    print(f"Invoking Bedrock model {BEDROCK_MODEL_ID}.")

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(request_body),
    )

    response_body = json.loads(response["body"].read())
    content = response_body.get("content", [])

    if not content:
        raise ValueError("Bedrock returned no response content.")

    response_text = content[0].get("text")

    if not response_text:
        raise ValueError("Bedrock response contained no text.")

    print("Bedrock SOAR summary generated.")

    return {
        "generated": True,
        "model_id": BEDROCK_MODEL_ID,
        "text": response_text,
    }


def create_fallback_summary(finding_context: dict[str, Any]) -> dict[str, Any]:
    """A plain-Python, no-AI summary. Used when ENABLE_BEDROCK is
    false, or when call_bedrock() throws an exception. This
    guarantees the workflow can ALWAYS produce a usable incident
    record even if Bedrock is down, over quota, or misconfigured."""

    severity = finding_context["severity"]
    finding_id = finding_context["finding_id"]
    source_ip = finding_context.get("primary_source_ip") or "unknown"
    target = finding_context.get("primary_target") or "unknown"
    event_count = finding_context.get("event_count") or 0
    playbook = finding_context["selected_playbook"]["name"]

    text = f"""
Incident Title:
{severity} WAF Threat Finding {finding_id}

SOC Alert:
The threat-correlation workflow identified {event_count} related
WAF event(s). The primary observed source IP was {source_ip}, and
the primary target was {target}.

Manager Summary:
A {severity.lower()}-severity correlation finding requires review
under playbook {playbook}.

Analyst Investigation Checklist:
1. Review the correlated WAF events.
2. Confirm the source IP and targeted resources.
3. Review API Gateway and application logs.
4. Check related authentication activity.
5. Document analyst conclusions.

Why This Playbook Was Selected:
The deterministic workflow selected {playbook} based on the
stored severity.

Limitations and Unknowns:
This summary does not prove successful exploitation. Human review
is required.
""".strip()

    return {"generated": False, "model_id": None, "text": text}


# ============================================================
# Incident creation
# ============================================================

def build_incident_id(finding_id: str) -> str:
    """Build a predictable incident ID from the finding ID, like
    'INC-<finding_id>'. Because it's predictable (not random), if
    EventBridge redelivers the same finding, we compute the SAME
    incident ID both times -- which is what makes the conditional
    put_item below able to detect 'oh, this incident already
    exists' instead of creating a duplicate."""

    return f"INC-{finding_id}"


def create_incident(
    finding: dict[str, Any],
    playbook: dict[str, Any],
    response_summary: dict[str, Any],
) -> tuple[str, bool]:
    """Create the incident record in DynamoDB.

    Returns a tuple: (incident_id, was_newly_created).
    was_newly_created is False if the incident already existed --
    that's not an error, just useful info for our logs/response."""

    finding_id = finding["finding_id"]
    incident_id = build_incident_id(finding_id)
    now = utc_now()

    incident = {
        "incident_id": incident_id,
        "finding_id": finding_id,
        "created_at": now,
        "updated_at": now,
        "severity": playbook["severity"],
        "priority": playbook["priority"],
        "status": "OPEN",
        "assigned_team": "SOC",
        "playbook": playbook["name"],
        "playbook_description": playbook["description"],
        "primary_source_ip": finding.get("primary_source_ip", "UNKNOWN"),
        "primary_target": finding.get("primary_target", "UNKNOWN"),
        "event_count": finding.get("event_count", 0),
        "risk_score": finding.get("risk_score", 0),
        "analyst_summary": response_summary["text"],
        "bedrock_summary_generated": response_summary["generated"],
        "bedrock_model_id": response_summary["model_id"] or "NONE",
        "containment_performed": False,
        "human_review_required": True,
    }

    try:
        # ConditionExpression here means "only create this item if
        # incident_id does NOT already exist." This is a second,
        # independent safety net on top of claim_finding() -- belt
        # and suspenders.
        incidents_table.put_item(
            Item=incident,
            ConditionExpression="attribute_not_exists(incident_id)",
        )

        print(f"Created security incident {incident_id}.")
        return incident_id, True

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "ConditionalCheckFailedException":
            print(f"Incident {incident_id} already exists. Reusing it.")
            return incident_id, False

        raise


# ============================================================
# SNS notification
# ============================================================

def publish_notification(
    finding: dict[str, Any],
    incident_id: str,
    playbook: dict[str, Any],
    response_summary: dict[str, Any],
) -> str | None:
    """Send an SNS notification, but only if this playbook actually
    calls for one (LOW severity's RECORD_ONLY playbook does not)."""

    if not playbook["notify"]:
        print(f"Playbook {playbook['name']} does not require an SNS notification.")
        return None

    severity = playbook["severity"]
    subject = f"[{severity}] WAF Security Incident {incident_id}"

    message = {
        "incident_id": incident_id,
        "finding_id": finding["finding_id"],
        "severity": severity,
        "risk_score": finding.get("risk_score"),
        "playbook": playbook["name"],
        "source_ip": finding.get("primary_source_ip"),
        "target": finding.get("primary_target"),
        "event_count": finding.get("event_count"),
        "human_review_required": True,
        "containment_performed": False,
        "analyst_summary": response_summary["text"],
    }

    response = sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        # SNS subjects have a hard 100-character limit -- truncate
        # defensively so a long incident_id can never cause an error.
        Subject=subject[:100],
        Message=json.dumps(message, indent=2, default=str),
        MessageAttributes={
            "severity": {"DataType": "String", "StringValue": severity},
            "playbook": {"DataType": "String", "StringValue": playbook["name"]},
        },
    )

    message_id = response.get("MessageId")
    print(f"Published SNS notification {message_id}.")

    return message_id


# ============================================================
# Finding workflow update (final step)
# ============================================================

def update_finding_status(
    finding_id: str,
    incident_id: str,
    playbook: dict[str, Any],
    sns_message_id: str | None,
) -> None:
    """Mark the finding as fully processed. This is now the LAST
    checkpoint, not the ONLY checkpoint -- claim_finding() already
    did the real duplicate-prevention work at the start."""

    now = utc_now()

    try:
        findings_table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression=(
                "SET #status = :response_status, "
                "incident_id = :incident_id, "
                "response_playbook = :playbook, "
                "response_processed_at = :processed_at, "
                "sns_message_id = :sns_message_id"
            ),
            # We now allow this transition from EITHER "OPEN" (the
            # old behavior, kept for safety) OR "PROCESSING" (the
            # new normal path, since claim_finding() already moved
            # it there).
            ConditionExpression=(
                "attribute_not_exists(#status) "
                "OR #status = :open_status "
                "OR #status = :processing_status"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":response_status": STATUS_COMPLETED,
                ":incident_id": incident_id,
                ":playbook": playbook["name"],
                ":processed_at": now,
                ":sns_message_id": sns_message_id or "NOT_SENT",
                ":open_status": STATUS_OPEN,
                ":processing_status": STATUS_PROCESSING,
            },
        )

        print(f"Updated finding {finding_id} to {STATUS_COMPLETED}.")

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        # Because claim_finding() already guarantees only ONE
        # invocation gets this far, hitting this condition failure
        # here would be unexpected -- but we still handle it
        # gracefully instead of throwing a scary 500, since the
        # incident and notification have already gone out
        # successfully at this point.
        if error_code == "ConditionalCheckFailedException":
            print(
                f"Finding {finding_id} status changed unexpectedly "
                "during final update. Incident and notification "
                "already succeeded, so treating this as non-fatal."
            )
            return

        raise


# ============================================================
# Lambda handler -- this is the function AWS actually calls
# ============================================================

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process one correlated threat finding, start to finish."""

    print("=" * 60)
    print("Starting SOAR Response Agent")
    print("=" * 60)
    print("Received event:")
    print(json.dumps(event, indent=2, default=str))

    try:
        finding_id = extract_finding_id(event)

        finding = get_finding(finding_id)
        print("Retrieved finding:")
        print(json.dumps(finding, indent=2, default=str))

        # STEP 1: make sure this finding is even eligible to run
        # (right fields present, not already in a terminal state).
        validate_finding(finding)

        # STEP 2 (THE FIX): claim it BEFORE doing anything expensive
        # or anything with a side effect (Bedrock call, SNS send).
        # If another invocation already claimed it, this raises
        # AlreadyProcessedError and we stop immediately -- no
        # wasted Bedrock call, no duplicate notification.
        claim_finding(finding_id)

        # STEP 3: pick the deterministic playbook. If severity is
        # garbage, this now raises InvalidSeverityError instead of
        # silently defaulting to LOW.
        playbook = select_playbook(finding)

        finding_context = build_finding_context(finding=finding, playbook=playbook)

        # STEP 4: get a human-readable summary, from Bedrock if
        # enabled and working, otherwise from our deterministic
        # fallback template.
        if ENABLE_BEDROCK:
            try:
                response_summary = call_bedrock(finding_context)
            except Exception as bedrock_error:
                print("Bedrock enrichment failed. Using deterministic fallback.")
                print(f"Bedrock error: {type(bedrock_error).__name__}: {bedrock_error}")
                response_summary = create_fallback_summary(finding_context)
        else:
            print("Bedrock enrichment is disabled. Using deterministic fallback.")
            response_summary = create_fallback_summary(finding_context)

        print("\n===== SOAR RESPONSE SUMMARY =====")
        print(response_summary["text"])
        print("=================================\n")

        # STEP 5: create the incident record.
        incident_id, incident_created = create_incident(
            finding=finding,
            playbook=playbook,
            response_summary=response_summary,
        )

        # STEP 6: notify the SOC, if this playbook calls for it.
        sns_message_id = publish_notification(
            finding=finding,
            incident_id=incident_id,
            playbook=playbook,
            response_summary=response_summary,
        )

        # STEP 7: final checkpoint -- mark the finding fully done.
        update_finding_status(
            finding_id=finding_id,
            incident_id=incident_id,
            playbook=playbook,
            sns_message_id=sns_message_id,
        )

        result = {
            "message": "SOAR response workflow completed.",
            "finding_id": finding_id,
            "incident_id": incident_id,
            "incident_created": incident_created,
            "severity": playbook["severity"],
            "playbook": playbook["name"],
            "notification_sent": sns_message_id is not None,
            "sns_message_id": sns_message_id,
            "bedrock_summary_generated": response_summary["generated"],
            "containment_performed": False,
            "human_review_required": True,
        }

        print("SOAR workflow result:")
        print(json.dumps(result, indent=2, default=str))

        return {"statusCode": 200, "body": json.dumps(result)}

    except AlreadyProcessedError as error:
        # Not a real failure -- this is the idempotency guard doing
        # exactly its job. We return 200 (success) because, from
        # the outside, the finding IS in a handled state.
        print(str(error))
        return {
            "statusCode": 200,
            "body": json.dumps({"message": str(error), "workflow_skipped": True}),
        }

    except InvalidSeverityError as error:
        # A real problem, but a specific and expected kind: the
        # data coming in doesn't match what we know how to handle.
        # We return 400 (bad input) rather than 500 (our fault),
        # since the issue is with the finding's data, not our code.
        print(str(error))
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Invalid finding data.", "error": str(error)}),
        }

    except (ClientError, BotoCoreError) as error:
        # Something went wrong talking to AWS itself (DynamoDB,
        # SNS, Bedrock, etc.) -- a genuine infrastructure failure.
        print(f"AWS service error: {type(error).__name__}: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": "SOAR workflow failed because an AWS service returned an error.",
                    "error": str(error),
                }
            ),
        }

    except Exception as error:
        # Catch-all for anything we didn't specifically anticipate.
        # Keeping this last and broad means the Lambda always
        # returns a clean JSON error instead of crashing with a raw
        # Python traceback.
        print(f"Unexpected SOAR error: {type(error).__name__}: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "SOAR response workflow failed.", "error": str(error)}),
        }