"""
waf_bedrock_analyzer.py

WHAT THIS LAMBDA DOES:
    1. Reads recent WAF logs from CloudWatch (pull, on a schedule --
       not push/subscription-filter-driven).
    2. Normalizes each WAF event into the flat shape the rest of
       the pipeline expects.
    3. Stores each normalized event in DynamoDB, keyed on WAF's own
       request_id -- this is what makes step 4/5 idempotent even
       though LOOKBACK_MINUTES intentionally overlaps between runs.
    4. Sends the individual event to Bedrock for a short incident
       summary (skipped for events already processed by a prior
       run's overlapping window).
    5. Writes the Bedrock summary to CloudWatch (a print() IS
       "writing to CloudWatch" for a Lambda -- every print() call
       becomes a log line in this function's own log group).

WHY PULL INSTEAD OF PUSH:
    This spec calls for the Lambda itself to decide its own read
    window (LOOKBACK_MINUTES) and read cap (MAX_LOG_EVENTS) on a
    schedule, rather than reacting to whatever CloudWatch happens
    to push moment-to-moment. That's a deliberate trade: pull gives
    you precise control over batch size and cost per run, at the
    cost of guaranteed overlap between consecutive runs' windows
    (see "IDEMPOTENCY" below for why that's handled, not ignored).

IDEMPOTENCY (READ THIS BEFORE CHANGING LOOKBACK_MINUTES):
    Unlike the earlier push-based design (which only risked
    duplicates on rare CloudWatch redelivery), a pull design on a
    fixed schedule reading "the last N minutes" WILL re-read
    overlapping log lines between consecutive runs, every single
    run, by construction -- there's no way to guarantee zero-gap
    coverage without some overlap margin. That's not a bug to
    eliminate; it's handled by writing each event keyed on its own
    request_id with a DynamoDB conditional put. A duplicate read
    just means the conditional write is rejected and that event is
    skipped -- no duplicate row, no duplicate Bedrock call.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logs_client = boto3.client("logs")
dynamodb = boto3.resource("dynamodb")
bedrock_client = boto3.client("bedrock-runtime")

WAF_LOG_GROUP = os.environ["WAF_LOG_GROUP"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    # Same CRIS-aware Haiku 4.5 profile ID learned the hard way on
    # the Correlation Agent earlier this session -- Claude 3 Haiku
    # is Legacy, and Haiku 4.5 requires a cross-Region inference
    # profile rather than direct on-demand invocation.
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)

LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "10"))
MAX_LOG_EVENTS = int(os.environ.get("MAX_LOG_EVENTS", "500"))

# Same reasoning as the Correlation Agent's raw-event TTL: keep
# normalized events around long enough for the Correlation Agent's
# own lookback window plus manual investigation room, not forever.
EVENT_TTL_DAYS = int(os.environ.get("EVENT_TTL_DAYS", "7"))

events_table = dynamodb.Table(DYNAMODB_TABLE)


# ============================================================
# Step 1: pull recent log lines from CloudWatch
# ============================================================

def fetch_recent_log_events() -> list[dict[str, Any]]:
    """Read raw WAF log lines from the last LOOKBACK_MINUTES,
    capped at MAX_LOG_EVENTS, paginating as needed."""

    now = datetime.now(timezone.utc)
    start_time_ms = int((now.timestamp() - LOOKBACK_MINUTES * 60) * 1000)
    end_time_ms = int(now.timestamp() * 1000)

    print(
        f"Reading WAF logs from {WAF_LOG_GROUP} for the last "
        f"{LOOKBACK_MINUTES} minute(s), capped at {MAX_LOG_EVENTS} events."
    )

    collected: list[dict[str, Any]] = []
    next_token = None

    while len(collected) < MAX_LOG_EVENTS:
        kwargs: dict[str, Any] = {
            "logGroupName": WAF_LOG_GROUP,
            "startTime": start_time_ms,
            "endTime": end_time_ms,
            "limit": min(MAX_LOG_EVENTS - len(collected), 1000),
        }
        if next_token:
            kwargs["nextToken"] = next_token

        response = logs_client.filter_log_events(**kwargs)
        collected.extend(response.get("events", []))

        next_token = response.get("nextToken")
        if not next_token:
            break

    print(f"Retrieved {len(collected)} raw log line(s).")

    return collected


# ============================================================
# Step 2: normalize each event
# ============================================================

def normalize_event(raw_message: str) -> dict[str, Any] | None:
    """Parse one raw WAF log JSON line into the flat schema the
    rest of the pipeline expects. Returns None for a malformed
    line rather than raising, so one bad line can't take down the
    whole batch."""

    try:
        waf_record = json.loads(raw_message)
    except json.JSONDecodeError:
        print(f"Skipping non-JSON log line (first 200 chars): {raw_message[:200]}")
        return None

    http_request = waf_record.get("httpRequest") or {}

    timestamp_ms = waf_record.get("timestamp")
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    event_epoch = int(timestamp_ms) // 1000
    timestamp_iso = datetime.fromtimestamp(event_epoch, tz=timezone.utc).isoformat()

    # request_id is about to become this event's DynamoDB PRIMARY
    # KEY -- it must be unique no matter what. WAF's own requestId
    # should always be present and unique per real request, but if
    # it's ever missing, falling back to a fixed string like
    # "UNKNOWN" would make every request-id-less event collide with
    # every other one (each treated as a "duplicate" of the first).
    # A fresh UUID fallback guarantees uniqueness holds even in
    # that edge case.
    request_id = http_request.get("requestId") or str(uuid.uuid4())

    return {
        "request_id": request_id,
        "source_ip": http_request.get("clientIp", "UNKNOWN"),
        "uri": http_request.get("uri", "UNKNOWN"),
        "rule": waf_record.get("terminatingRuleId", "DEFAULT"),
        "action": waf_record.get("action", "UNKNOWN"),
        "country": http_request.get("country", "UNKNOWN"),
        "timestamp": timestamp_iso,
        "event_epoch": event_epoch,
        "http_method": http_request.get("httpMethod", "UNKNOWN"),
    }


# ============================================================
# Step 3: idempotent write, keyed on request_id
# ============================================================

def write_event_if_new(fields: dict[str, Any]) -> bool:
    """Write a normalized event to DynamoDB, but ONLY if this
    request_id hasn't been written by a previous (overlapping) run.

    Returns True if this was a genuinely new write, False if it was
    already there. This return value is what step 4 uses to decide
    whether to spend a Bedrock call on this event at all."""

    now_epoch = int(time.time())
    expires_at = now_epoch + (EVENT_TTL_DAYS * 86400)

    item = {
        "expires_at": expires_at,
        **fields,
    }

    try:
        events_table.put_item(
            Item=item,
            # The atomic guard: only succeeds if NO item with this
            # request_id (the table's own primary key) already
            # exists. DynamoDB evaluates and writes as one
            # operation -- there's no gap for two overlapping runs
            # to both "see" the row as absent and both write it.
            ConditionExpression="attribute_not_exists(request_id)",
        )
        return True

    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


# ============================================================
# Step 4: per-event Bedrock incident summary
# ============================================================

def call_bedrock_for_event(fields: dict[str, Any]) -> str | None:
    """Ask Bedrock for a short, single-event incident summary.

    BEST-EFFORT: this is called only AFTER the event is already
    safely written to DynamoDB. A Bedrock failure here means one
    event doesn't get a narrative summary in the logs -- it does
    NOT mean the underlying evidence is lost, since the DynamoDB
    write already succeeded."""

    prompt = f"""
You are assisting a Security Operations Center with a single WAF
log event. Do not alter the supplied facts.

Event:
{json.dumps(fields, indent=2, default=str)}

Write a brief (3-5 sentence) incident note covering: what happened,
whether it was allowed or blocked, and whether anything about this
single event looks worth a human's attention. Do not speculate
about attacker intent beyond what this one event supports -- a
single event rarely proves a pattern on its own.
""".strip()

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "temperature": 0.2,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": prompt}]}
        ],
    }

    try:
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(request_body),
        )

        response_body = json.loads(response["body"].read())
        content = response_body.get("content", [])

        if not content:
            print(f"Bedrock returned no content for request {fields['request_id']}.")
            return None

        return content[0].get("text")

    except Exception as error:
        print(
            f"Bedrock per-event call failed for request "
            f"{fields['request_id']}: {type(error).__name__}: {error}"
        )
        return None


# ============================================================
# Lambda handler
# ============================================================

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Pull recent WAF logs, normalize, store, and summarize each
    newly-seen event."""

    print("=" * 60)
    print("Starting WAF Bedrock Analyzer")
    print("=" * 60)

    try:
        raw_log_events = fetch_recent_log_events()

        written = 0
        skipped_duplicate = 0
        skipped_malformed = 0
        bedrock_summaries = 0
        bedrock_failures = 0

        for raw_log_event in raw_log_events:
            fields = normalize_event(raw_log_event.get("message", ""))

            if fields is None:
                skipped_malformed += 1
                continue

            is_new = write_event_if_new(fields)

            if not is_new:
                skipped_duplicate += 1
                continue

            written += 1

            # Only spend a Bedrock call on events we actually wrote
            # for the first time -- calling Bedrock again on an
            # already-summarized duplicate would waste money and
            # produce a redundant log line for no benefit.
            summary = call_bedrock_for_event(fields)

            if summary:
                bedrock_summaries += 1
                print(
                    f"----- Bedrock summary for request "
                    f"{fields['request_id']} -----"
                )
                print(summary)
                print("-" * 60)
            else:
                bedrock_failures += 1

        result = {
            "message": "WAF Bedrock Analyzer run completed.",
            "raw_log_events_read": len(raw_log_events),
            "events_written": written,
            "events_skipped_duplicate": skipped_duplicate,
            "events_skipped_malformed": skipped_malformed,
            "bedrock_summaries_generated": bedrock_summaries,
            "bedrock_failures": bedrock_failures,
        }

        print("Analyzer run result:")
        print(json.dumps(result, indent=2))

        return {"statusCode": 200, "body": json.dumps(result)}

    except (ClientError, BotoCoreError) as error:
        print(f"AWS service error: {type(error).__name__}: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": "Analyzer run failed because an AWS service returned an error.",
                    "error": str(error),
                }
            ),
        }

    except Exception as error:
        print(f"Unexpected analyzer error: {type(error).__name__}: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Analyzer run failed.", "error": str(error)}),
        }