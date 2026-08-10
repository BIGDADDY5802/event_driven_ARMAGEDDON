import json
import os
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError


# ============================================================
# AWS clients
# ============================================================

bedrock_client = boto3.client("bedrock-runtime")
dynamodb = boto3.resource("dynamodb")
eventbridge_client = boto3.client("events")


# ============================================================
# Environment variables
# ============================================================

WAF_EVENTS_TABLE = os.environ["WAF_EVENTS_TABLE"]
CORRELATION_FINDINGS_TABLE = os.environ[
    "CORRELATION_FINDINGS_TABLE"
]

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    # Haiku 4.5 does not support direct on-demand invocation --
    # Bedrock requires going through a cross-Region inference
    # profile instead (confirmed via a real ValidationException:
    # "Invocation of model ID ... with on-demand throughput isn't
    # supported"). The "us." prefix selects the US geography
    # profile, which load-balances across us-east-1/us-east-2/
    # us-west-2.
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)

# NEW: same toggle SOAR already has, for the same reason -- lets
# you run this Lambda with Bedrock deliberately off (cost control,
# local testing, Bedrock region outage) without it counting as a
# "failure" that needs the fallback-and-log path.
ENABLE_BEDROCK = os.environ.get("ENABLE_BEDROCK", "true").lower() == "true"

CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("CORRELATION_WINDOW_MINUTES", "60")
)

MINIMUM_EVENT_COUNT = int(
    os.environ.get("MINIMUM_EVENT_COUNT", "3")
)

MAX_EVENTS = int(
    os.environ.get("MAX_EVENTS", "500")
)

# NEW: how long a "claimed run" lock sticks around. This only needs
# to outlive the longest plausible single execution (Bedrock call +
# a Scan loop), not days. 15 minutes gives generous headroom over
# a typical Lambda timeout while still expiring on its own via
# DynamoDB TTL, so we don't need a separate cleanup job.
RUN_LOCK_TTL_SECONDS = int(
    os.environ.get("RUN_LOCK_TTL_SECONDS", "900")
)

# The bus SOAR listens on. Publishing here is what actually turns
# "a finding got saved" into "SOAR knows a finding got saved" --
# this is the missing link the original design called for but the
# code never implemented until now.
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME", "seir-security-bus")

ADMIN_URI_KEYWORDS = [
    keyword.strip().lower()
    for keyword in os.environ.get(
        "ADMIN_URI_KEYWORDS",
        "admin,login,signin,auth,token,cognito",
    ).split(",")
    if keyword.strip()
]

waf_events_table = dynamodb.Table(WAF_EVENTS_TABLE)
findings_table = dynamodb.Table(CORRELATION_FINDINGS_TABLE)


# ============================================================
# Custom exceptions
# ------------------------------------------------------------
# Same idea as soar_response_agent.py: give the "this run was
# already claimed" case its own exception type, so the handler
# can return a calm 200 instead of treating it as a real failure.
# ============================================================

class RunAlreadyClaimedError(Exception):
    """Raised when another invocation already claimed this same
    scheduled run. Not a failure -- the idempotency guard doing
    exactly its job."""


# ============================================================
# THE FIRST FIX: claim the run BEFORE doing any expensive work
# ------------------------------------------------------------
# ANALOGY: this is the exact same "punch the raffle ticket at the
# front door" idea from soar_response_agent.py's claim_finding().
# Here the "ticket number" is the EventBridge event's own id --
# EventBridge guarantees that if Lambda has to retry a delivery
# (a timeout, a throttle, an error), it retries with the SAME
# event, which carries the SAME id. Two DIFFERENT scheduled ticks
# (this run and the next one 60 minutes later) get DIFFERENT ids,
# so this only blocks true duplicates, never legitimate new runs.
#
# We reuse the findings table for the lock record itself (no new
# table needed) by giving it a finding_id that starts with "RUN#"
# -- a prefix nothing else in the system ever generates, so it can
# never collide with or be mistaken for a real finding. A DynamoDB
# TTL attribute means the lock record deletes itself automatically
# after RUN_LOCK_TTL_SECONDS -- no separate cleanup job required.
# ============================================================

def build_run_id(event: dict[str, Any]) -> str:
    """
    Build the idempotency key for this invocation.

    Prefers the real EventBridge event id (stable across retries
    of the SAME delivery). Falls back to a random id for manual
    console-test invocations, which don't carry a real EventBridge
    id and don't need duplicate protection anyway -- a human
    clicking "Test" twice is a deliberate choice, not a retry.
    """

    event_id = event.get("id")

    if event_id:
        return str(event_id)

    return f"manual-{uuid.uuid4()}"


def claim_run(run_id: str) -> None:
    """Atomically claim this run. Raises RunAlreadyClaimedError if
    another invocation already claimed the same run_id. Call this
    BEFORE scanning waf-events or calling Bedrock."""

    now = datetime.now(timezone.utc)
    expires_at = int((now + timedelta(seconds=RUN_LOCK_TTL_SECONDS)).timestamp())

    try:
        findings_table.put_item(
            Item={
                "finding_id": f"RUN#{run_id}",
                "claimed_at": now.isoformat(),
                "expires_at": expires_at,  # DynamoDB TTL attribute
            },
            # Only succeed if nothing with this exact lock key
            # exists yet. This is the atomic "only one winner"
            # check -- DynamoDB evaluates and writes as a single
            # operation, so there's no gap for a second invocation
            # to sneak through between "check" and "write."
            ConditionExpression="attribute_not_exists(finding_id)",
        )

        print(f"Claimed run {run_id}.")

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "ConditionalCheckFailedException":
            raise RunAlreadyClaimedError(
                f"Run {run_id} was already claimed by another invocation."
            )

        raise


# ============================================================
# DynamoDB helpers
# ============================================================

def decimal_to_native(value: Any) -> Any:
    """Convert DynamoDB Decimal values into Python numbers."""

    if isinstance(value, list):
        return [decimal_to_native(item) for item in value]

    if isinstance(value, dict):
        return {
            key: decimal_to_native(item)
            for key, item in value.items()
        }

    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)

        return float(value)

    return value


def native_to_decimal(value: Any) -> Any:
    """
    The write-side mirror of decimal_to_native() above.

    boto3's DynamoDB Table resource (put_item/update_item) flatly
    REJECTS native Python floats -- DynamoDB's number type only
    understands Decimal. This only bites you the moment a real
    float actually shows up in data being written (e.g.
    active_span_minutes from round(seconds / 60, 2) in
    build_source_ip_correlations()) -- nothing about that is a
    syntax error, so py_compile / terraform plan / terraform apply
    all stay silent about it. It only ever surfaces as a runtime
    ClientError the first time a real float reaches put_item.

    We convert via str(value) first, not Decimal(value) directly --
    floats have binary representation artifacts (e.g. 0.1 isn't
    exactly 0.1 in binary), and going through the string form
    avoids baking that imprecision into the stored Decimal.
    """

    if isinstance(value, list):
        return [native_to_decimal(item) for item in value]

    if isinstance(value, dict):
        return {
            key: native_to_decimal(item)
            for key, item in value.items()
        }

    if isinstance(value, float):
        return Decimal(str(value))

    return value


def get_recent_events(
    window_minutes: int,
) -> tuple[list[dict[str, Any]], datetime, datetime]:
    """
    Read WAF records inside the correlation window.

    This first lab version uses Scan with a filter. A later version can
    replace this with Query against a time-oriented secondary index.
    """

    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(
        minutes=window_minutes
    )

    minimum_epoch = int(window_start.timestamp())

    print(
        f"Reading WAF events from {window_start.isoformat()} "
        f"through {window_end.isoformat()}."
    )

    scan_kwargs: dict[str, Any] = {
        "FilterExpression": Attr("event_epoch").gte(
            minimum_epoch
        ),
        "Limit": min(MAX_EVENTS, 100),
    }

    items: list[dict[str, Any]] = []

    while True:
        response = waf_events_table.scan(**scan_kwargs)

        items.extend(response.get("Items", []))

        if len(items) >= MAX_EVENTS:
            items = items[:MAX_EVENTS]
            break

        last_evaluated_key = response.get(
            "LastEvaluatedKey"
        )

        if not last_evaluated_key:
            break

        scan_kwargs["ExclusiveStartKey"] = (
            last_evaluated_key
        )

    events = [
        decimal_to_native(item)
        for item in items
    ]

    events.sort(
        key=lambda item: item.get("event_epoch", 0)
    )

    print(
        f"Retrieved {len(events)} event(s) "
        "inside the correlation window."
    )

    return events, window_start, window_end


# ============================================================
# Deterministic correlation
# ============================================================

def contains_sensitive_uri(uri: str) -> bool:
    """Return True if a URI appears identity- or admin-related."""

    normalized_uri = uri.lower()

    return any(
        keyword in normalized_uri
        for keyword in ADMIN_URI_KEYWORDS
    )


def calculate_risk_score(
    event_count: int,
    unique_uris: int,
    unique_rules: int,
    blocked_count: int,
    sensitive_uri_targeted: bool,
    active_span_minutes: float,
) -> tuple[int, list[str]]:
    """Create a transparent deterministic risk score."""

    score = 0
    reasons: list[str] = []

    if event_count >= 5:
        score += 20
        reasons.append(
            "Source generated at least five WAF events."
        )

    if event_count >= 15:
        score += 10
        reasons.append(
            "Source generated at least fifteen WAF events."
        )

    if unique_uris >= 3:
        score += 20
        reasons.append(
            "Source targeted at least three unique URIs."
        )

    if unique_rules >= 2:
        score += 20
        reasons.append(
            "Source triggered at least two WAF rule types."
        )

    if sensitive_uri_targeted:
        score += 15
        reasons.append(
            "Source targeted an identity, authentication, "
            "or administrative URI."
        )

    if blocked_count == event_count and event_count > 0:
        score += 5
        reasons.append(
            "All observed requests were blocked by WAF."
        )

    if event_count >= 5 and active_span_minutes <= 5:
        score += 10
        reasons.append(
            "At least five events occurred within five minutes."
        )

    return min(score, 100), reasons


def classify_severity(score: int) -> str:
    """Translate risk score into a severity label."""

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def build_source_ip_correlations(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group WAF events by source IP and calculate risk."""

    grouped_events: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        source_ip = event.get("source_ip", "UNKNOWN")
        grouped_events[source_ip].append(event)

    correlations: list[dict[str, Any]] = []

    for source_ip, source_events in grouped_events.items():
        source_events.sort(
            key=lambda item: item.get("event_epoch", 0)
        )

        event_count = len(source_events)

        blocked_count = sum(
            1
            for item in source_events
            if item.get("action") == "BLOCK"
        )

        uris = {
            item.get("uri", "UNKNOWN")
            for item in source_events
        }

        rules = {
            item.get("rule", "UNKNOWN")
            for item in source_events
        }

        countries = {
            item.get("country", "UNKNOWN")
            for item in source_events
        }

        first_epoch = source_events[0].get(
            "event_epoch",
            0,
        )

        last_epoch = source_events[-1].get(
            "event_epoch",
            first_epoch,
        )

        active_span_seconds = max(
            last_epoch - first_epoch,
            0,
        )

        active_span_minutes = round(
            active_span_seconds / 60,
            2,
        )

        sensitive_uri_targeted = any(
            contains_sensitive_uri(uri)
            for uri in uris
        )

        risk_score, score_reasons = calculate_risk_score(
            event_count=event_count,
            unique_uris=len(uris),
            unique_rules=len(rules),
            blocked_count=blocked_count,
            sensitive_uri_targeted=sensitive_uri_targeted,
            active_span_minutes=active_span_minutes,
        )

        correlations.append(
            {
                "source_ip": source_ip,
                "event_count": event_count,
                "blocked_count": blocked_count,
                "allowed_count": (
                    event_count - blocked_count
                ),
                "unique_uris": len(uris),
                "uris": sorted(uris),
                "unique_rules": len(rules),
                "rules": sorted(rules),
                "countries": sorted(countries),
                "first_seen": source_events[0].get(
                    "timestamp"
                ),
                "last_seen": source_events[-1].get(
                    "timestamp"
                ),
                "active_span_minutes": (
                    active_span_minutes
                ),
                "sensitive_uri_targeted": (
                    sensitive_uri_targeted
                ),
                "risk_score": risk_score,
                "severity": classify_severity(
                    risk_score
                ),
                "score_reasons": score_reasons,
            }
        )

    correlations.sort(
        key=lambda item: (
            item["risk_score"],
            item["event_count"],
        ),
        reverse=True,
    )

    return correlations


def build_target_correlations(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Summarize activity by targeted URI."""

    uri_events: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        uri = event.get("uri", "UNKNOWN")
        uri_events[uri].append(event)

    target_correlations: list[dict[str, Any]] = []

    for uri, related_events in uri_events.items():
        source_ips = {
            item.get("source_ip", "UNKNOWN")
            for item in related_events
        }

        rule_counter = Counter(
            item.get("rule", "UNKNOWN")
            for item in related_events
        )

        most_common_rule = (
            rule_counter.most_common(1)[0][0]
            if rule_counter
            else "UNKNOWN"
        )

        target_correlations.append(
            {
                "uri": uri,
                "event_count": len(related_events),
                "unique_source_ips": len(source_ips),
                "most_common_rule": most_common_rule,
                "sensitive_uri": contains_sensitive_uri(
                    uri
                ),
            }
        )

    target_correlations.sort(
        key=lambda item: item["event_count"],
        reverse=True,
    )

    return target_correlations


def build_rule_correlations(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Summarize activity by terminating WAF rule."""

    rule_events: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        rule = event.get("rule", "UNKNOWN")
        rule_events[rule].append(event)

    correlations: list[dict[str, Any]] = []

    for rule, related_events in rule_events.items():
        correlations.append(
            {
                "rule": rule,
                "event_count": len(related_events),
                "unique_source_ips": len(
                    {
                        item.get(
                            "source_ip",
                            "UNKNOWN",
                        )
                        for item in related_events
                    }
                ),
                "targeted_uris": sorted(
                    {
                        item.get("uri", "UNKNOWN")
                        for item in related_events
                    }
                ),
            }
        )

    correlations.sort(
        key=lambda item: item["event_count"],
        reverse=True,
    )

    return correlations


def build_evidence_package(
    events: list[dict[str, Any]],
    window_start: datetime,
    window_end: datetime,
) -> dict[str, Any]:
    """Build the compact evidence package sent to Bedrock."""

    source_correlations = (
        build_source_ip_correlations(events)
    )

    target_correlations = (
        build_target_correlations(events)
    )

    rule_correlations = (
        build_rule_correlations(events)
    )

    blocked_count = sum(
        1
        for item in events
        if item.get("action") == "BLOCK"
    )

    unique_source_ips = {
        item.get("source_ip", "UNKNOWN")
        for item in events
    }

    unique_uris = {
        item.get("uri", "UNKNOWN")
        for item in events
    }

    deterministic_findings: list[str] = []

    if source_correlations:
        top_source = source_correlations[0]

        deterministic_findings.append(
            f"Highest-risk source IP "
            f"{top_source['source_ip']} generated "
            f"{top_source['event_count']} event(s), "
            f"targeted {top_source['unique_uris']} URI(s), "
            f"and triggered "
            f"{top_source['unique_rules']} rule type(s)."
        )

    if target_correlations:
        top_target = target_correlations[0]

        deterministic_findings.append(
            f"Most targeted URI was "
            f"{top_target['uri']} with "
            f"{top_target['event_count']} event(s) "
            f"from {top_target['unique_source_ips']} "
            "unique source IP(s)."
        )

    if rule_correlations:
        top_rule = rule_correlations[0]

        deterministic_findings.append(
            f"Most frequently triggered WAF rule was "
            f"{top_rule['rule']} with "
            f"{top_rule['event_count']} event(s)."
        )

    return {
        "analysis_window": {
            "start": window_start.isoformat(),
            "end": window_end.isoformat(),
            "minutes": CORRELATION_WINDOW_MINUTES,
        },
        "summary": {
            "total_events": len(events),
            "blocked_events": blocked_count,
            "allowed_events": (
                len(events) - blocked_count
            ),
            "unique_source_ips": len(
                unique_source_ips
            ),
            "unique_uris": len(unique_uris),
        },
        "top_source_ips": source_correlations[:10],
        "top_targeted_uris": (
            target_correlations[:10]
        ),
        "top_waf_rules": rule_correlations[:10],
        "deterministic_findings": (
            deterministic_findings
        ),
    }


# ============================================================
# Bedrock interpretation
# ============================================================

def call_bedrock(
    evidence_package: dict[str, Any],
) -> dict[str, Any]:
    """
    Ask Bedrock to interpret deterministic findings.

    CHANGED: now returns a dict with a "generated" flag, matching
    the shape soar_response_agent.py already uses, instead of a
    bare string. This lets the caller tell a real Bedrock report
    apart from the fallback one without a separate flag variable.
    """

    prompt = f"""
You are a senior SOC analyst assisting with AWS WAF threat correlation.

The following evidence was calculated deterministically by Python.
Do not alter the supplied counts or risk scores.

Evidence:
{json.dumps(evidence_package, indent=2, default=str)}

Return the response using exactly these headings:

Threat Classification:
Overall Severity:
Confidence:
Correlated Indicators:
Likely Activity:
Business Impact:
Recommended Analyst Actions:
Executive Summary:

Requirements:
- Separate observed facts from possible interpretations.
- Do not claim that exploitation succeeded.
- Do not invent IP reputation, geolocation, identity, or attack data.
- Explain why the events may or may not represent coordinated activity.
- Keep the response suitable for both a SOC analyst and a manager.
""".strip()

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 900,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt,
                    }
                ],
            }
        ],
    }

    print(
        f"Invoking Bedrock correlation model "
        f"{BEDROCK_MODEL_ID}."
    )

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(request_body),
    )

    response_body = json.loads(response["body"].read())

    content = response_body.get("content", [])

    if not content:
        raise ValueError(
            "Bedrock returned no correlation content."
        )

    report = content[0].get("text")

    if not report:
        raise ValueError(
            "Bedrock response did not contain report text."
        )

    print("Bedrock correlation invocation successful.")

    return {
        "generated": True,
        "model_id": BEDROCK_MODEL_ID,
        "text": report,
    }


# ============================================================
# THE SECOND FIX: deterministic fallback report
# ------------------------------------------------------------
# ANALOGY: the photographer's notebook. If the camera (Bedrock)
# jams, you don't throw away the crime scene notes you already
# took by hand -- you write up what you directly observed instead.
# This builds a plain-Python report straight from the
# deterministic_findings list that's ALREADY computed and correct
# by this point in the code, so save_finding() always has
# something real to write, Bedrock or no Bedrock.
# ============================================================

def create_fallback_report(
    evidence_package: dict[str, Any],
) -> dict[str, Any]:
    """A plain-Python, no-AI correlation report. Used when
    ENABLE_BEDROCK is false, or when call_bedrock() throws an
    exception. Guarantees a finding always gets saved."""

    summary = evidence_package["summary"]
    findings_list = evidence_package.get("deterministic_findings", [])

    top_sources = evidence_package.get("top_source_ips", [])
    top_severity = top_sources[0]["severity"] if top_sources else "LOW"
    top_score = top_sources[0]["risk_score"] if top_sources else 0

    findings_text = (
        "\n".join(f"- {line}" for line in findings_list)
        if findings_list
        else "- No standout source, target, or rule pattern identified."
    )

    text = f"""
Threat Classification:
Deterministic correlation only (Bedrock unavailable for this run).

Overall Severity:
{top_severity} (risk score {top_score}/100)

Confidence:
Low-to-moderate -- based solely on rule-based scoring, no AI-assisted
interpretation was available for this window.

Correlated Indicators:
{findings_text}

Likely Activity:
Not assessed. Bedrock interpretation was unavailable; a human analyst
should review the raw evidence package directly.

Business Impact:
Not assessed automatically. See event counts and severity above for
raw scale of activity in this window.

Recommended Analyst Actions:
1. Review the {summary['total_events']} event(s) in this window directly.
2. Confirm whether the highest-risk source IP requires escalation.
3. Re-run Bedrock interpretation manually once available, if needed.

Executive Summary:
{summary['total_events']} WAF event(s) observed across
{summary['unique_source_ips']} source IP(s) and
{summary['unique_uris']} URI(s) in this window. Automated AI narrative
was unavailable; deterministic scoring above stands on its own.
""".strip()

    return {"generated": False, "model_id": None, "text": text}


# ============================================================
# Finding persistence
# ============================================================

def determine_overall_risk(
    evidence_package: dict[str, Any],
) -> tuple[int, str, str | None]:
    """Determine the highest deterministic risk in the window."""

    source_findings = evidence_package.get(
        "top_source_ips",
        [],
    )

    if not source_findings:
        return 0, "LOW", None

    highest = source_findings[0]

    return (
        highest.get("risk_score", 0),
        highest.get("severity", "LOW"),
        highest.get("source_ip"),
    )


# ============================================================
# EventBridge notification -- the missing link
# ------------------------------------------------------------
# ANALOGY: saving the finding to DynamoDB is like filing a police
# report in a cabinet. That report existing doesn't mean anyone
# gets notified -- someone still has to pick up the phone and call
# dispatch. This function is that phone call: it announces "a
# finding just got filed" onto the shared event bus, which is what
# lets SOAR (subscribed via an EventBridge rule) actually find out
# in near-real-time instead of never knowing at all.
#
# BEST-EFFORT BY DESIGN: by the time this runs, the finding is
# ALREADY safely saved in waf-correlation-findings -- that's the
# source of truth, not this event. If the publish itself fails
# (a transient EventBridge issue, a permissions gap), we log it and
# move on rather than raising and losing an already-successful
# save. The cost of a missed notification is a delayed human
# response; the cost of losing the underlying finding would be
# losing the evidence itself, which matters far more.
# ============================================================

def publish_finding_event(
    finding_id: str,
    severity: str,
    risk_score: int,
) -> None:
    """Announce a saved finding on the SEIR event bus, matching the
    exact envelope SOAR's extract_finding_id() expects."""

    try:
        response = eventbridge_client.put_events(
            Entries=[
                {
                    "Source": "seir.waf.correlation",
                    "DetailType": "WAF Threat Finding Created",
                    "Detail": json.dumps(
                        {
                            "finding_id": finding_id,
                            "severity": severity,
                            "risk_score": risk_score,
                        }
                    ),
                    "EventBusName": EVENT_BUS_NAME,
                }
            ]
        )

        # put_events can return HTTP 200 while still failing
        # individual entries -- FailedEntryCount is the real
        # success signal, not the absence of a raised exception.
        if response.get("FailedEntryCount", 0) > 0:
            failure = response.get("Entries", [{}])[0]
            print(
                f"EventBridge publish failed for finding {finding_id}: "
                f"{failure.get('ErrorCode')}: {failure.get('ErrorMessage')}"
            )
        else:
            print(f"Published finding-created event for {finding_id}.")

    except Exception as publish_error:
        print(
            f"EventBridge publish raised an exception for finding "
            f"{finding_id}: {type(publish_error).__name__}: {publish_error}. "
            "Finding was already saved successfully -- continuing."
        )


def save_finding(
    evidence_package: dict[str, Any],
    report: dict[str, Any],
) -> str:
    """Store the final correlation finding."""

    finding_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    risk_score, severity, primary_source_ip = (
        determine_overall_risk(evidence_package)
    )

    targeted_uris = evidence_package.get(
        "top_targeted_uris",
        [],
    )

    primary_target = (
        targeted_uris[0].get("uri")
        if targeted_uris
        else None
    )

    item = {
        "finding_id": finding_id,
        "created_at": created_at,
        "window_start": evidence_package[
            "analysis_window"
        ]["start"],
        "window_end": evidence_package[
            "analysis_window"
        ]["end"],
        "severity": severity,
        "risk_score": risk_score,
        "event_count": evidence_package["summary"][
            "total_events"
        ],
        "primary_source_ip": (
            primary_source_ip or "NONE"
        ),
        "primary_target": primary_target or "NONE",
        "status": "OPEN",
        "bedrock_report": report["text"],
        "bedrock_report_generated": report["generated"],
        "evidence": evidence_package,
    }

    # Convert any native floats (e.g. active_span_minutes, buried
    # inside evidence_package) to Decimal right before the write --
    # this is the only place in the whole flow a float can reach
    # DynamoDB, so it's the right single point to guard.
    findings_table.put_item(Item=native_to_decimal(item))

    print(
        f"Saved correlation finding {finding_id} "
        f"with severity {severity} "
        f"(bedrock_generated={report['generated']})."
    )

    return finding_id


# ============================================================
# Lambda handler
# ============================================================

def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Correlate recent WAF telemetry and generate a finding."""

    print("=" * 60)
    print("Starting WAF Threat Correlation Agent")
    print("=" * 60)

    requested_window = event.get(
        "correlation_window_minutes"
    )

    window_minutes = (
        int(requested_window)
        if requested_window is not None
        else CORRELATION_WINDOW_MINUTES
    )

    try:
        # STEP 0 (THE FIRST FIX): claim this run before touching
        # waf-events or Bedrock. If this exact scheduled delivery
        # already ran (a Lambda retry), stop here -- no wasted
        # Scan, no wasted Bedrock call, no duplicate finding.
        run_id = build_run_id(event)
        claim_run(run_id)

        events, window_start, window_end = (
            get_recent_events(window_minutes)
        )

        if len(events) < MINIMUM_EVENT_COUNT:
            message = (
                f"Only {len(events)} event(s) found. "
                f"At least {MINIMUM_EVENT_COUNT} are "
                "required for correlation."
            )

            print(message)

            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": message,
                        "events_found": len(events),
                        "finding_created": False,
                    }
                ),
            }

        evidence_package = build_evidence_package(
            events=events,
            window_start=window_start,
            window_end=window_end,
        )

        print("\n===== DETERMINISTIC EVIDENCE =====")
        print(
            json.dumps(
                evidence_package,
                indent=2,
                default=str,
            )
        )
        print("==================================\n")

        # STEP (THE SECOND FIX): get a report from Bedrock if
        # enabled and working, otherwise fall back to a
        # deterministic report -- but ALWAYS save a finding either
        # way. The evidence package above is already correct and
        # complete; losing it because Bedrock hiccuped is the bug
        # we're fixing.
        if ENABLE_BEDROCK:
            try:
                report = call_bedrock(evidence_package)
            except Exception as bedrock_error:
                print(
                    "Bedrock correlation call failed. "
                    "Using deterministic fallback report."
                )
                print(
                    f"Bedrock error: "
                    f"{type(bedrock_error).__name__}: {bedrock_error}"
                )
                report = create_fallback_report(evidence_package)
        else:
            print(
                "Bedrock enrichment is disabled. "
                "Using deterministic fallback report."
            )
            report = create_fallback_report(evidence_package)

        print("\n===== THREAT REPORT =====")
        print(report["text"])
        print("=========================\n")

        finding_id = save_finding(
            evidence_package=evidence_package,
            report=report,
        )

        risk_score, severity, primary_source_ip = (
            determine_overall_risk(evidence_package)
        )

        # The finding is safely saved at this point regardless of
        # what happens next -- publish_finding_event() is
        # deliberately best-effort (see its own docstring).
        publish_finding_event(
            finding_id=finding_id,
            severity=severity,
            risk_score=risk_score,
        )

        result = {
            "message": (
                "Threat correlation completed."
            ),
            "finding_created": True,
            "finding_id": finding_id,
            "events_correlated": len(events),
            "severity": severity,
            "risk_score": risk_score,
            "primary_source_ip": primary_source_ip,
            "bedrock_report_generated": report["generated"],
        }

        print("Correlation result:")
        print(json.dumps(result, indent=2))

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }

    except RunAlreadyClaimedError as error:
        # Not a real failure -- the idempotency guard doing its job.
        print(str(error))
        return {
            "statusCode": 200,
            "body": json.dumps(
                {"message": str(error), "run_skipped": True}
            ),
        }

    except (ClientError, BotoCoreError) as error:
        print(f"AWS service error: {error}")

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "Threat correlation failed "
                        "because an AWS service returned "
                        "an error."
                    ),
                    "error": str(error),
                }
            ),
        }

    except Exception as error:
        print(
            f"Unexpected correlation error: "
            f"{type(error).__name__}: {error}"
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "Threat correlation failed."
                    ),
                    "error": str(error),
                }
            ),
        }