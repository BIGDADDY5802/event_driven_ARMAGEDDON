#!/usr/bin/env python3

"""
Executive Security Dashboard Agent

Business objective:
Transform WAF telemetry, correlated threat findings, and SOAR incident
records into:

1. A human-readable executive PDF report
2. A machine-readable JSON report

Both artifacts are uploaded to Amazon S3.

This agent is informational only. It does not perform containment.
"""

import io
import json
import os
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError

# ReportLab is not included in the standard Lambda Python runtime.
# Package it with the deployment ZIP or provide it through a Lambda layer.
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ============================================================
# AWS clients
# ============================================================

dynamodb = boto3.resource("dynamodb")
bedrock_client = boto3.client("bedrock-runtime")
s3_client = boto3.client("s3")


# ============================================================
# Environment variables
# ============================================================

WAF_EVENTS_TABLE = os.environ["WAF_EVENTS_TABLE"]

CORRELATION_FINDINGS_TABLE = os.environ[
    "CORRELATION_FINDINGS_TABLE"
]

SECURITY_INCIDENTS_TABLE = os.environ[
    "SECURITY_INCIDENTS_TABLE"
]

REPORT_BUCKET = os.environ["REPORT_BUCKET"]

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-haiku-20240307-v1:0",
)

REPORT_PERIOD_HOURS = int(
    os.environ.get("REPORT_PERIOD_HOURS", "24")
)

REPORT_PREFIX = os.environ.get(
    "REPORT_PREFIX",
    "executive-reports",
).strip("/")

ORGANIZATION_NAME = os.environ.get(
    "ORGANIZATION_NAME",
    "SEIR Cloud Security",
)

REPORT_TITLE = os.environ.get(
    "REPORT_TITLE",
    "Executive Security Report",
)

ENABLE_BEDROCK = (
    os.environ.get("ENABLE_BEDROCK", "true").lower()
    == "true"
)

MAX_ITEMS_PER_TABLE = int(
    os.environ.get("MAX_ITEMS_PER_TABLE", "5000")
)


# ============================================================
# DynamoDB tables
# ============================================================

waf_events_table = dynamodb.Table(WAF_EVENTS_TABLE)

findings_table = dynamodb.Table(
    CORRELATION_FINDINGS_TABLE
)

incidents_table = dynamodb.Table(
    SECURITY_INCIDENTS_TABLE
)


# ============================================================
# General helpers
# ============================================================

def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime) -> str:
    """Return a UTC datetime in ISO-8601 format."""

    return value.astimezone(timezone.utc).isoformat()


def decimal_to_native(value: Any) -> Any:
    """Convert DynamoDB Decimal objects into native Python values."""

    if isinstance(value, list):
        return [
            decimal_to_native(item)
            for item in value
        ]

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


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float without failing the report."""

    try:
        return float(value)

    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to int without failing the report."""

    try:
        return int(value)

    except (TypeError, ValueError):
        return default


def calculate_percentage(
    numerator: int | float,
    denominator: int | float,
) -> float:
    """Calculate a percentage while avoiding division by zero."""

    if not denominator:
        return 0.0

    return round((numerator / denominator) * 100, 2)


def calculate_change_percent(
    current: int | float,
    previous: int | float,
) -> float | None:
    """
    Calculate percentage change.

    Returns None when there is no meaningful previous baseline.
    """

    if previous == 0:
        if current == 0:
            return 0.0

        return None

    return round(
        ((current - previous) / previous) * 100,
        2,
    )


def normalize_timestamp(value: Any) -> datetime | None:
    """Convert supported timestamp values into a UTC datetime."""

    if value is None:
        return None

    if isinstance(value, (int, float, Decimal)):
        numeric_value = float(value)

        # WAF timestamps may be milliseconds.
        if numeric_value > 10_000_000_000:
            numeric_value /= 1000

        try:
            return datetime.fromtimestamp(
                numeric_value,
                tz=timezone.utc,
            )

        except (OSError, OverflowError, ValueError):
            return None

    if isinstance(value, str):
        normalized = value.strip()

        if not normalized:
            return None

        try:
            parsed = datetime.fromisoformat(
                normalized.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(timezone.utc)

        except ValueError:
            return None

    return None


def item_timestamp(
    item: dict[str, Any],
    candidate_fields: list[str],
) -> datetime | None:
    """Find the first valid timestamp in a DynamoDB item."""

    for field in candidate_fields:
        parsed = normalize_timestamp(item.get(field))

        if parsed:
            return parsed

    return None


def top_counter_values(
    counter: Counter,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Convert Counter results into JSON-ready dictionaries."""

    return [
        {
            "name": str(name),
            "count": count,
        }
        for name, count in counter.most_common(limit)
    ]


# ============================================================
# DynamoDB retrieval
# ============================================================

def scan_table(
    table: Any,
    filter_expression: Any | None = None,
) -> list[dict[str, Any]]:
    """
    Scan a DynamoDB table with pagination.

    This scan-based approach is acceptable for the instructional lab.
    A later production revision should use reporting-oriented indexes
    and Query operations.
    """

    scan_arguments: dict[str, Any] = {}

    if filter_expression is not None:
        scan_arguments["FilterExpression"] = (
            filter_expression
        )

    items: list[dict[str, Any]] = []

    while True:
        response = table.scan(**scan_arguments)

        items.extend(response.get("Items", []))

        if len(items) >= MAX_ITEMS_PER_TABLE:
            print(
                f"Reached report limit of "
                f"{MAX_ITEMS_PER_TABLE} items."
            )

            items = items[:MAX_ITEMS_PER_TABLE]
            break

        last_evaluated_key = response.get(
            "LastEvaluatedKey"
        )

        if not last_evaluated_key:
            break

        scan_arguments["ExclusiveStartKey"] = (
            last_evaluated_key
        )

    return [
        decimal_to_native(item)
        for item in items
    ]


def retrieve_reporting_data(
    current_start: datetime,
    current_end: datetime,
    previous_start: datetime,
) -> dict[str, list[dict[str, Any]]]:
    """Retrieve records required for both reporting periods."""

    minimum_epoch = int(previous_start.timestamp())

    print("Reading WAF event records.")

    waf_events = scan_table(
        waf_events_table,
        Attr("event_epoch").gte(minimum_epoch),
    )

    print("Reading correlation findings.")

    findings = scan_table(findings_table)

    print("Reading security incidents.")

    incidents = scan_table(incidents_table)

    print(
        f"Retrieved {len(waf_events)} WAF event(s), "
        f"{len(findings)} finding(s), and "
        f"{len(incidents)} incident(s)."
    )

    return {
        "waf_events": waf_events,
        "findings": findings,
        "incidents": incidents,
    }


def filter_records_by_period(
    records: list[dict[str, Any]],
    start: datetime,
    end: datetime,
    timestamp_fields: list[str],
) -> list[dict[str, Any]]:
    """Return records whose timestamps fall within the period."""

    filtered_records: list[dict[str, Any]] = []

    for record in records:
        timestamp = item_timestamp(
            record,
            timestamp_fields,
        )

        if timestamp and start <= timestamp < end:
            filtered_records.append(record)

    return filtered_records


# ============================================================
# WAF metrics
# ============================================================

def calculate_waf_metrics(
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate deterministic WAF activity metrics."""

    action_counter = Counter(
        str(event.get("action", "UNKNOWN")).upper()
        for event in events
    )

    source_counter = Counter(
        str(event.get("source_ip", "UNKNOWN"))
        for event in events
    )

    uri_counter = Counter(
        str(event.get("uri", "UNKNOWN"))
        for event in events
    )

    rule_counter = Counter(
        str(event.get("rule", "UNKNOWN"))
        for event in events
    )

    country_counter = Counter(
        str(event.get("country", "UNKNOWN"))
        for event in events
    )

    blocked = action_counter.get("BLOCK", 0)
    allowed = action_counter.get("ALLOW", 0)

    total = len(events)

    repeated_sources = sum(
        1
        for count in source_counter.values()
        if count > 1
    )

    return {
        "total_events": total,
        "blocked_requests": blocked,
        "allowed_requests": allowed,
        "other_actions": max(
            total - blocked - allowed,
            0,
        ),
        "block_percentage": calculate_percentage(
            blocked,
            total,
        ),
        "unique_source_ips": len(source_counter),
        "repeat_source_ips": repeated_sources,
        "unique_targeted_uris": len(uri_counter),
        "top_source_ips": top_counter_values(
            source_counter
        ),
        "top_targeted_uris": top_counter_values(
            uri_counter
        ),
        "top_waf_rules": top_counter_values(
            rule_counter
        ),
        "top_countries": top_counter_values(
            country_counter
        ),
    }


# ============================================================
# Finding metrics
# ============================================================

def calculate_finding_metrics(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate deterministic threat-finding metrics."""

    severity_counter = Counter(
        str(
            finding.get("severity", "UNKNOWN")
        ).upper()
        for finding in findings
    )

    status_counter = Counter(
        str(
            finding.get("status", "UNKNOWN")
        ).upper()
        for finding in findings
    )

    risk_scores = [
        safe_float(finding.get("risk_score"))
        for finding in findings
        if finding.get("risk_score") is not None
    ]

    highest_risk_finding = None

    if findings:
        highest_risk_finding = max(
            findings,
            key=lambda item: safe_float(
                item.get("risk_score")
            ),
        )

    return {
        "total_findings": len(findings),
        "low": severity_counter.get("LOW", 0),
        "medium": severity_counter.get(
            "MEDIUM",
            0,
        ),
        "high": severity_counter.get("HIGH", 0),
        "critical": severity_counter.get(
            "CRITICAL",
            0,
        ),
        "unknown": severity_counter.get(
            "UNKNOWN",
            0,
        ),
        "open": status_counter.get("OPEN", 0),
        "response_completed": status_counter.get(
            "RESPONSE_COMPLETED",
            0,
        ),
        "average_risk_score": round(
            statistics.mean(risk_scores),
            2,
        )
        if risk_scores
        else 0.0,
        "highest_risk_score": max(
            risk_scores,
            default=0.0,
        ),
        "highest_risk_source": (
            highest_risk_finding.get(
                "primary_source_ip"
            )
            if highest_risk_finding
            else None
        ),
        "highest_risk_target": (
            highest_risk_finding.get(
                "primary_target"
            )
            if highest_risk_finding
            else None
        ),
    }


# ============================================================
# Incident metrics
# ============================================================

def calculate_incident_metrics(
    incidents: list[dict[str, Any]],
    report_end: datetime,
) -> dict[str, Any]:
    """Calculate deterministic SOAR incident metrics."""

    severity_counter = Counter(
        str(
            incident.get("severity", "UNKNOWN")
        ).upper()
        for incident in incidents
    )

    status_counter = Counter(
        str(
            incident.get("status", "UNKNOWN")
        ).upper()
        for incident in incidents
    )

    playbook_counter = Counter(
        str(
            incident.get("playbook", "UNKNOWN")
        )
        for incident in incidents
    )

    open_statuses = {
        "OPEN",
        "INVESTIGATING",
        "ESCALATED",
    }

    open_incidents = [
        incident
        for incident in incidents
        if str(
            incident.get("status", "UNKNOWN")
        ).upper()
        in open_statuses
    ]

    awaiting_review = sum(
        1
        for incident in open_incidents
        if bool(
            incident.get(
                "human_review_required",
                False,
            )
        )
    )

    oldest_open_incident_hours = 0.0
    oldest_open_incident_id = None

    for incident in open_incidents:
        created_at = item_timestamp(
            incident,
            ["created_at"],
        )

        if not created_at:
            continue

        age_hours = (
            report_end - created_at
        ).total_seconds() / 3600

        if age_hours > oldest_open_incident_hours:
            oldest_open_incident_hours = age_hours
            oldest_open_incident_id = incident.get(
                "incident_id"
            )

    return {
        "total_incidents": len(incidents),
        "open_incidents": len(open_incidents),
        "awaiting_human_review": awaiting_review,
        "resolved_incidents": (
            status_counter.get("RESOLVED", 0)
            + status_counter.get("CLOSED", 0)
        ),
        "critical_incidents": severity_counter.get(
            "CRITICAL",
            0,
        ),
        "high_incidents": severity_counter.get(
            "HIGH",
            0,
        ),
        "medium_incidents": severity_counter.get(
            "MEDIUM",
            0,
        ),
        "low_incidents": severity_counter.get(
            "LOW",
            0,
        ),
        "oldest_open_incident_hours": round(
            oldest_open_incident_hours,
            2,
        ),
        "oldest_open_incident_id": (
            oldest_open_incident_id
        ),
        "playbooks_invoked": top_counter_values(
            playbook_counter,
            limit=10,
        ),
    }


# ============================================================
# Comparative reporting
# ============================================================

def build_period_metrics(
    data: dict[str, list[dict[str, Any]]],
    period_start: datetime,
    period_end: datetime,
) -> dict[str, Any]:
    """Build all metrics for one reporting period."""

    waf_events = filter_records_by_period(
        data["waf_events"],
        period_start,
        period_end,
        ["timestamp", "event_epoch"],
    )

    findings = filter_records_by_period(
        data["findings"],
        period_start,
        period_end,
        ["created_at", "window_end"],
    )

    incidents = filter_records_by_period(
        data["incidents"],
        period_start,
        period_end,
        ["created_at"],
    )

    return {
        "period": {
            "start": isoformat_utc(period_start),
            "end": isoformat_utc(period_end),
        },
        "waf": calculate_waf_metrics(waf_events),
        "findings": calculate_finding_metrics(
            findings
        ),
        "incidents": calculate_incident_metrics(
            incidents,
            period_end,
        ),
    }


def build_period_changes(
    current: dict[str, Any],
    previous: dict[str, Any],
) -> dict[str, Any]:
    """Compare major current-period metrics to the prior period."""

    return {
        "waf_events_percent": calculate_change_percent(
            current["waf"]["total_events"],
            previous["waf"]["total_events"],
        ),
        "blocked_requests_percent": (
            calculate_change_percent(
                current["waf"][
                    "blocked_requests"
                ],
                previous["waf"][
                    "blocked_requests"
                ],
            )
        ),
        "unique_source_ips_percent": (
            calculate_change_percent(
                current["waf"][
                    "unique_source_ips"
                ],
                previous["waf"][
                    "unique_source_ips"
                ],
            )
        ),
        "high_findings_change": (
            current["findings"]["high"]
            - previous["findings"]["high"]
        ),
        "critical_findings_change": (
            current["findings"]["critical"]
            - previous["findings"]["critical"]
        ),
        "open_incidents_change": (
            current["incidents"]["open_incidents"]
            - previous["incidents"]["open_incidents"]
        ),
    }


def determine_security_posture(
    current_metrics: dict[str, Any],
) -> str:
    """Derive a deterministic overall posture label."""

    findings = current_metrics["findings"]
    incidents = current_metrics["incidents"]

    if (
        findings["critical"] > 0
        or incidents["critical_incidents"] > 0
    ):
        return "CRITICAL"

    if (
        findings["high"] > 0
        or incidents["high_incidents"] > 0
    ):
        return "ELEVATED"

    if (
        findings["medium"] > 0
        or incidents["open_incidents"] > 0
    ):
        return "GUARDED"

    return "NORMAL"


# ============================================================
# Bedrock executive narrative
# ============================================================

def build_bedrock_evidence(
    current_metrics: dict[str, Any],
    previous_metrics: dict[str, Any],
    period_changes: dict[str, Any],
    posture: str,
) -> dict[str, Any]:
    """Build a compact, deterministic evidence package."""

    return {
        "overall_security_posture": posture,
        "current_period": current_metrics,
        "previous_period": previous_metrics,
        "period_changes": period_changes,
    }


def call_bedrock(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Generate executive and SOC-management narratives."""

    prompt = f"""
You are preparing an executive cloud-security report.

All counts, percentages, statuses, rankings, and risk values below
were calculated deterministically by Python. Do not change them.

Evidence:
{json.dumps(evidence, indent=2, default=str)}

Return valid JSON using exactly this structure:

{{
  "overall_security_posture": "string",
  "executive_summary": "string",
  "material_changes": ["string"],
  "business_impact": "string",
  "leadership_attention_required": ["string"],
  "soc_management_summary": "string",
  "recommended_priorities": ["string"],
  "limitations_and_unknowns": ["string"]
}}

Requirements:
- Base every statement only on supplied evidence.
- Separate observations from interpretations.
- Do not claim that exploitation succeeded.
- Do not invent threat intelligence, IP reputation, identities,
  geolocation, losses, or business impact.
- Explain when no historical baseline exists.
- Do not recommend automatic containment.
- State clearly when human review is needed.
- Use concise language suitable for executives and SOC leadership.
""".strip()

    request_body = {
        "anthropic_version": (
            "bedrock-2023-05-31"
        ),
        "max_tokens": 1200,
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
        f"Invoking Bedrock model "
        f"{BEDROCK_MODEL_ID}."
    )

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(request_body),
    )

    response_body = json.loads(
        response["body"].read()
    )

    content = response_body.get("content", [])

    if not content:
        raise ValueError(
            "Bedrock returned no report content."
        )

    response_text = content[0].get("text", "").strip()

    if response_text.startswith("```"):
        response_text = response_text.strip("`")

        if response_text.startswith("json"):
            response_text = response_text[4:].strip()

    narrative = json.loads(response_text)

    print("Bedrock executive narrative generated.")

    return {
        "generated": True,
        "model_id": BEDROCK_MODEL_ID,
        "content": narrative,
    }


def create_fallback_narrative(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create a deterministic report if Bedrock is unavailable."""

    current = evidence["current_period"]
    changes = evidence["period_changes"]
    posture = evidence[
        "overall_security_posture"
    ]

    waf = current["waf"]
    findings = current["findings"]
    incidents = current["incidents"]

    executive_summary = (
        f"The security posture is {posture}. "
        f"The reporting period contained "
        f"{waf['total_events']} WAF event(s), "
        f"of which {waf['blocked_requests']} were blocked. "
        f"There were {findings['high']} high-severity and "
        f"{findings['critical']} critical finding(s). "
        f"{incidents['open_incidents']} incident(s) remain open."
    )

    return {
        "generated": False,
        "model_id": None,
        "content": {
            "overall_security_posture": posture,
            "executive_summary": executive_summary,
            "material_changes": [
                (
                    "WAF event change: "
                    f"{changes['waf_events_percent']}"
                ),
                (
                    "Open incident change: "
                    f"{changes['open_incidents_change']}"
                ),
            ],
            "business_impact": (
                "No confirmed business impact can be "
                "established from the available telemetry."
            ),
            "leadership_attention_required": [
                (
                    "Review critical and high-severity "
                    "findings."
                ),
                (
                    "Confirm that open incidents receive "
                    "human review."
                ),
            ],
            "soc_management_summary": (
                "Review the current findings and incident "
                "backlog using the deterministic metrics."
            ),
            "recommended_priorities": [
                "Review critical findings.",
                "Review high-severity findings.",
                "Assess the oldest open incident.",
            ],
            "limitations_and_unknowns": [
                (
                    "The available evidence does not prove "
                    "successful exploitation."
                ),
                (
                    "No external threat-intelligence data "
                    "was used."
                ),
            ],
        },
    }


# ============================================================
# Final report document
# ============================================================

def build_report_document(
    current_metrics: dict[str, Any],
    previous_metrics: dict[str, Any],
    period_changes: dict[str, Any],
    posture: str,
    narrative: dict[str, Any],
    generated_at: datetime,
) -> dict[str, Any]:
    """Build the synchronized JSON/PDF source document."""

    report_id = generated_at.strftime(
        "executive-security-%Y%m%dT%H%M%SZ"
    )

    return {
        "schema_version": "1.0",
        "report_id": report_id,
        "report_type": "EXECUTIVE_SECURITY",
        "organization": ORGANIZATION_NAME,
        "title": REPORT_TITLE,
        "generated_at": isoformat_utc(
            generated_at
        ),
        "overall_security_posture": posture,
        "current_period": current_metrics,
        "previous_period": previous_metrics,
        "period_changes": period_changes,
        "narrative": narrative["content"],
        "generation_metadata": {
            "bedrock_used": narrative["generated"],
            "bedrock_model_id": (
                narrative["model_id"]
            ),
            "containment_performed": False,
            "human_review_required": True,
        },
    }


# ============================================================
# PDF generation
# ============================================================

def paragraph_text(value: Any) -> str:
    """Escape simple values for ReportLab Paragraphs."""

    text = str(value or "")

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def add_bullet_list(
    story: list[Any],
    values: list[Any],
    body_style: ParagraphStyle,
) -> None:
    """Append a list of bullet paragraphs to the PDF story."""

    if not values:
        story.append(
            Paragraph(
                "No items reported.",
                body_style,
            )
        )
        return

    for value in values:
        story.append(
            Paragraph(
                f"\u2022 {paragraph_text(value)}",
                body_style,
            )
        )


def top_items_table(
    title: str,
    items: list[dict[str, Any]],
    heading_style: ParagraphStyle,
) -> list[Any]:
    """Build a small top-items table for the PDF."""

    elements: list[Any] = [
        Paragraph(title, heading_style),
        Spacer(1, 0.08 * inch),
    ]

    if not items:
        elements.append(
            Paragraph(
                "No data available.",
                getSampleStyleSheet()["BodyText"],
            )
        )

        return elements

    data = [["Item", "Count"]]

    for item in items:
        data.append(
            [
                paragraph_text(item.get("name")),
                str(item.get("count", 0)),
            ]
        )

    table = Table(
        data,
        colWidths=[5.6 * inch, 1.0 * inch],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#D9EAF7"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1F2937"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "RIGHT",
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#F6F8FA"),
                    ],
                ),
            ]
        )
    )

    elements.append(table)

    return elements


def generate_pdf(
    report: dict[str, Any],
) -> bytes:
    """Generate the executive PDF entirely in memory."""

    output = io.BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
        title=report["title"],
        author=ORGANIZATION_NAME,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ExecutiveTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=24,
        spaceAfter=12,
    )

    subtitle_style = ParagraphStyle(
        "ExecutiveSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4B5563"),
        spaceAfter=16,
    )

    heading_style = ParagraphStyle(
        "ExecutiveHeading",
        parent=styles["Heading2"],
        alignment=TA_LEFT,
        fontSize=14,
        leading=17,
        spaceBefore=10,
        spaceAfter=6,
        textColor=colors.HexColor("#1F3A5F"),
    )

    body_style = ParagraphStyle(
        "ExecutiveBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=13,
        spaceAfter=5,
    )

    posture_style = ParagraphStyle(
        "Posture",
        parent=styles["Heading1"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#7A1F1F"),
        spaceAfter=12,
    )

    story: list[Any] = []

    narrative = report["narrative"]
    current = report["current_period"]

    story.append(
        Paragraph(
            paragraph_text(report["title"]),
            title_style,
        )
    )

    story.append(
        Paragraph(
            (
                f"{paragraph_text(report['organization'])}<br/>"
                f"Generated: "
                f"{paragraph_text(report['generated_at'])}"
            ),
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            (
                "Overall Security Posture: "
                f"{paragraph_text(report['overall_security_posture'])}"
            ),
            posture_style,
        )
    )

    story.append(
        Paragraph(
            "Executive Summary",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            paragraph_text(
                narrative.get(
                    "executive_summary",
                    "No executive summary was generated.",
                )
            ),
            body_style,
        )
    )

    story.append(
        Paragraph(
            "Key Security Metrics",
            heading_style,
        )
    )

    metrics_data = [
        ["Metric", "Value"],
        [
            "Total WAF events",
            current["waf"]["total_events"],
        ],
        [
            "Blocked requests",
            current["waf"]["blocked_requests"],
        ],
        [
            "Block percentage",
            f"{current['waf']['block_percentage']}%",
        ],
        [
            "Unique source IPs",
            current["waf"]["unique_source_ips"],
        ],
        [
            "High-severity findings",
            current["findings"]["high"],
        ],
        [
            "Critical findings",
            current["findings"]["critical"],
        ],
        [
            "Open incidents",
            current["incidents"]["open_incidents"],
        ],
        [
            "Awaiting human review",
            current["incidents"][
                "awaiting_human_review"
            ],
        ],
    ]

    metrics_table = Table(
        metrics_data,
        colWidths=[4.7 * inch, 1.9 * inch],
        repeatRows=1,
    )

    metrics_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1F3A5F"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "RIGHT",
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#F6F8FA"),
                    ],
                ),
            ]
        )
    )

    story.append(metrics_table)

    story.append(
        Paragraph(
            "Material Changes",
            heading_style,
        )
    )

    add_bullet_list(
        story,
        narrative.get("material_changes", []),
        body_style,
    )

    story.append(
        Paragraph(
            "Business Impact",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            paragraph_text(
                narrative.get(
                    "business_impact",
                    "No business-impact statement available.",
                )
            ),
            body_style,
        )
    )

    story.append(
        Paragraph(
            "Leadership Attention Required",
            heading_style,
        )
    )

    add_bullet_list(
        story,
        narrative.get(
            "leadership_attention_required",
            [],
        ),
        body_style,
    )

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Security Operations Detail",
            title_style,
        )
    )

    story.extend(
        top_items_table(
            "Top Targeted URIs",
            current["waf"]["top_targeted_uris"],
            heading_style,
        )
    )

    story.append(Spacer(1, 0.15 * inch))

    story.extend(
        top_items_table(
            "Top WAF Rules",
            current["waf"]["top_waf_rules"],
            heading_style,
        )
    )

    story.append(Spacer(1, 0.15 * inch))

    story.extend(
        top_items_table(
            "Top Source IPs",
            current["waf"]["top_source_ips"],
            heading_style,
        )
    )

    story.append(
        Paragraph(
            "SOC Management Summary",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            paragraph_text(
                narrative.get(
                    "soc_management_summary",
                    "No SOC summary available.",
                )
            ),
            body_style,
        )
    )

    story.append(
        Paragraph(
            "Recommended Priorities",
            heading_style,
        )
    )

    add_bullet_list(
        story,
        narrative.get(
            "recommended_priorities",
            [],
        ),
        body_style,
    )

    story.append(
        Paragraph(
            "Limitations and Unknowns",
            heading_style,
        )
    )

    add_bullet_list(
        story,
        narrative.get(
            "limitations_and_unknowns",
            [],
        ),
        body_style,
    )

    story.append(Spacer(1, 0.25 * inch))

    story.append(
        Paragraph(
            (
                "This report is informational. No containment "
                "action was performed. Human review is required."
            ),
            body_style,
        )
    )

    document.build(story)

    pdf_bytes = output.getvalue()
    output.close()

    return pdf_bytes


# ============================================================
# S3 publication
# ============================================================

def build_s3_keys(
    generated_at: datetime,
    report_id: str,
) -> tuple[str, str]:
    """Build parallel PDF and JSON object keys."""

    year = generated_at.strftime("%Y")
    month = generated_at.strftime("%m")
    day = generated_at.strftime("%d")

    common_path = (
        f"{REPORT_PREFIX}/{year}/{month}/{day}"
    )

    pdf_key = (
        f"{common_path}/pdf/{report_id}.pdf"
    )

    json_key = (
        f"{common_path}/json/{report_id}.json"
    )

    return pdf_key, json_key


def upload_report_artifacts(
    report: dict[str, Any],
    pdf_bytes: bytes,
    generated_at: datetime,
) -> dict[str, Any]:
    """Upload synchronized PDF and JSON artifacts to S3."""

    report_id = report["report_id"]

    pdf_key, json_key = build_s3_keys(
        generated_at,
        report_id,
    )

    json_bytes = json.dumps(
        report,
        indent=2,
        default=str,
    ).encode("utf-8")

    common_metadata = {
        "report-id": report_id,
        "report-type": "executive-security",
        "generated-at": generated_at.strftime(
            "%Y-%m-%dT%H-%M-%SZ"
        ),
        "security-posture": report[
            "overall_security_posture"
        ].lower(),
    }

    print(
        f"Uploading PDF report to "
        f"s3://{REPORT_BUCKET}/{pdf_key}"
    )

    s3_client.put_object(
        Bucket=REPORT_BUCKET,
        Key=pdf_key,
        Body=pdf_bytes,
        ContentType="application/pdf",
        Metadata=common_metadata,
        ServerSideEncryption="AES256",
    )

    print(
        f"Uploading JSON report to "
        f"s3://{REPORT_BUCKET}/{json_key}"
    )

    s3_client.put_object(
        Bucket=REPORT_BUCKET,
        Key=json_key,
        Body=json_bytes,
        ContentType="application/json",
        Metadata=common_metadata,
        ServerSideEncryption="AES256",
    )

    return {
        "bucket": REPORT_BUCKET,
        "pdf": {
            "key": pdf_key,
            "uri": f"s3://{REPORT_BUCKET}/{pdf_key}",
            "size_bytes": len(pdf_bytes),
        },
        "json": {
            "key": json_key,
            "uri": f"s3://{REPORT_BUCKET}/{json_key}",
            "size_bytes": len(json_bytes),
        },
    }


# ============================================================
# Lambda handler
# ============================================================

def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Generate and publish an executive security report."""

    print("=" * 64)
    print("Starting Executive Dashboard Agent")
    print("Patron Saint of Storage: Chewbacca")
    print("=" * 64)

    print("Received event:")
    print(
        json.dumps(
            event,
            indent=2,
            default=str,
        )
    )

    try:
        requested_period = event.get(
            "report_period_hours"
        )

        report_period_hours = (
            int(requested_period)
            if requested_period is not None
            else REPORT_PERIOD_HOURS
        )

        if report_period_hours <= 0:
            raise ValueError(
                "report_period_hours must be greater than zero."
            )

        generated_at = utc_now()

        current_end = generated_at

        current_start = current_end - timedelta(
            hours=report_period_hours
        )

        previous_end = current_start

        previous_start = previous_end - timedelta(
            hours=report_period_hours
        )

        print(
            f"Current reporting period: "
            f"{isoformat_utc(current_start)} through "
            f"{isoformat_utc(current_end)}"
        )

        print(
            f"Comparison period: "
            f"{isoformat_utc(previous_start)} through "
            f"{isoformat_utc(previous_end)}"
        )

        reporting_data = retrieve_reporting_data(
            current_start=current_start,
            current_end=current_end,
            previous_start=previous_start,
        )

        current_metrics = build_period_metrics(
            data=reporting_data,
            period_start=current_start,
            period_end=current_end,
        )

        previous_metrics = build_period_metrics(
            data=reporting_data,
            period_start=previous_start,
            period_end=previous_end,
        )

        period_changes = build_period_changes(
            current=current_metrics,
            previous=previous_metrics,
        )

        posture = determine_security_posture(
            current_metrics
        )

        evidence = build_bedrock_evidence(
            current_metrics=current_metrics,
            previous_metrics=previous_metrics,
            period_changes=period_changes,
            posture=posture,
        )

        print("\n===== EXECUTIVE REPORT EVIDENCE =====")
        print(
            json.dumps(
                evidence,
                indent=2,
                default=str,
            )
        )
        print("=====================================\n")

        if ENABLE_BEDROCK:
            try:
                narrative = call_bedrock(evidence)

            except Exception as bedrock_error:
                print(
                    "Bedrock report generation failed. "
                    "Using deterministic fallback."
                )

                print(
                    f"Bedrock error: "
                    f"{type(bedrock_error).__name__}: "
                    f"{bedrock_error}"
                )

                narrative = create_fallback_narrative(
                    evidence
                )

        else:
            print(
                "Bedrock is disabled. "
                "Using deterministic fallback."
            )

            narrative = create_fallback_narrative(
                evidence
            )

        report = build_report_document(
            current_metrics=current_metrics,
            previous_metrics=previous_metrics,
            period_changes=period_changes,
            posture=posture,
            narrative=narrative,
            generated_at=generated_at,
        )

        print("\n===== EXECUTIVE SUMMARY =====")
        print(
            report["narrative"][
                "executive_summary"
            ]
        )
        print("=============================\n")

        pdf_bytes = generate_pdf(report)

        uploaded_artifacts = upload_report_artifacts(
            report=report,
            pdf_bytes=pdf_bytes,
            generated_at=generated_at,
        )

        result = {
            "message": (
                "Executive security report generated "
                "and published."
            ),
            "report_id": report["report_id"],
            "overall_security_posture": posture,
            "report_period_hours": (
                report_period_hours
            ),
            "bedrock_used": narrative["generated"],
            "artifacts": uploaded_artifacts,
            "containment_performed": False,
            "human_review_required": True,
        }

        print("Executive Dashboard Agent result:")
        print(
            json.dumps(
                result,
                indent=2,
                default=str,
            )
        )

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }

    except (
        ClientError,
        BotoCoreError,
    ) as error:
        print(
            f"AWS service error: "
            f"{type(error).__name__}: {error}"
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "Executive report generation "
                        "failed because an AWS service "
                        "returned an error."
                    ),
                    "error": str(error),
                }
            ),
        }

    except Exception as error:
        print(
            f"Unexpected report error: "
            f"{type(error).__name__}: {error}"
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "Executive report generation failed."
                    ),
                    "error": str(error),
                }
            ),
        }