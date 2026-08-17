#!/usr/bin/env python3

"""
compliance_agent.py

Agent 9: Compliance Agent

Business objective
------------------
Convert operational security evidence into repeatable compliance results.

The agent follows one simple rule:

    Python evaluates controls.
    Bedrock explains the results.

That separation matters. A language model may summarize evidence, but it should
not silently decide whether a control passed or failed.

High-level workflow
-------------------
1. Load controls.json.
2. Filter controls for the requested framework(s).
3. Evaluate each control using deterministic Python validators.
4. Store one evidence record per control in DynamoDB.
5. Ask Amazon Bedrock to explain the already-computed results.
6. Generate synchronized JSON and PDF reports.
7. Upload both reports to S3.

This Lambda does not modify security controls and performs no containment.
"""

from __future__ import annotations

import io
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ReportLab is not part of the standard AWS Lambda Python runtime.
# Package it in the deployment ZIP or provide it through a Lambda layer.
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
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


# ============================================================================
# AWS clients
# ============================================================================

dynamodb_client = boto3.client("dynamodb")
dynamodb_resource = boto3.resource("dynamodb")
s3_client = boto3.client("s3")
bedrock_client = boto3.client("bedrock-runtime")
events_client = boto3.client("events")
scheduler_client = boto3.client("scheduler")
sns_client = boto3.client("sns")
lambda_client = boto3.client("lambda")


# ============================================================================
# Environment variables
# ============================================================================

CONTROLS_FILE = os.environ.get(
    "CONTROLS_FILE",
    "/var/task/controls.json",
)

COMPLIANCE_EVIDENCE_TABLE = os.environ["COMPLIANCE_EVIDENCE_TABLE"]
REPORT_BUCKET = os.environ["REPORT_BUCKET"]

REPORT_PREFIX = os.environ.get(
    "REPORT_PREFIX",
    "compliance-reports",
).strip("/")

# Examples:
#   NIST CSF 2.0
#   CIS Controls v8
#   NIST CSF 2.0,CIS Controls v8
#   ALL
DEFAULT_FRAMEWORKS = os.environ.get(
    "COMPLIANCE_FRAMEWORKS",
    "NIST CSF 2.0",
)

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-haiku-20240307-v1:0",
)

ENABLE_BEDROCK = (
    os.environ.get("ENABLE_BEDROCK", "true").lower() == "true"
)

ORGANIZATION_NAME = os.environ.get(
    "ORGANIZATION_NAME",
    "SEIR Cloud Security",
)

REPORT_TITLE = os.environ.get(
    "REPORT_TITLE",
    "Compliance Evidence Report",
)

# A control that cannot be evaluated should not silently pass.
# REVIEW is safer and more honest than guessing.
UNEVALUATED_STATUS = os.environ.get(
    "UNEVALUATED_STATUS",
    "REVIEW",
).upper()


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class ValidationResult:
    """
    Standard result returned by every validator.

    Keeping one shared shape makes the rest of the agent simple. The reporting
    code does not need to understand how DynamoDB, S3, SNS, or EventBridge work.
    """

    status: str
    observation: str
    evidence: dict[str, Any]
    error: str | None = None


# ============================================================================
# Small general-purpose helpers
# ============================================================================

def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime) -> str:
    """Return a consistent ISO-8601 timestamp."""

    return value.astimezone(timezone.utc).isoformat()


def decimal_to_native(value: Any) -> Any:
    """
    Convert DynamoDB Decimal values so they can be serialized as JSON.

    DynamoDB uses Decimal for numbers. Standard json.dumps does not.
    """

    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)

    if isinstance(value, list):
        return [decimal_to_native(item) for item in value]

    if isinstance(value, dict):
        return {
            key: decimal_to_native(item)
            for key, item in value.items()
        }

    return value


def json_bytes(value: Any) -> bytes:
    """Serialize an object as readable UTF-8 JSON."""

    return json.dumps(
        value,
        indent=2,
        default=str,
    ).encode("utf-8")


def safe_text(value: Any) -> str:
    """Escape basic characters before placing text in a PDF Paragraph."""

    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def normalize_frameworks(value: Any) -> list[str]:
    """
    Convert event or environment input into a clean framework list.

    Accepted values:
      "NIST CSF 2.0"
      "NIST CSF 2.0,CIS Controls v8"
      ["NIST CSF 2.0", "CIS Controls v8"]
      "ALL"
    """

    if value is None:
        value = DEFAULT_FRAMEWORKS

    if isinstance(value, str):
        frameworks = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]
    elif isinstance(value, list):
        frameworks = [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]
    else:
        raise ValueError(
            "Frameworks must be a comma-separated string or a list."
        )

    return frameworks or [DEFAULT_FRAMEWORKS]


# ============================================================================
# Stage 1: Load the control library
# ============================================================================

def load_controls(path: str) -> list[dict[str, Any]]:
    """
    Load and perform basic validation on controls.json.

    We fail early here because a malformed control library would make every
    later result questionable.
    """

    controls_path = Path(path)

    if not controls_path.exists():
        raise FileNotFoundError(
            f"Control library was not found: {controls_path}"
        )

    with controls_path.open("r", encoding="utf-8") as file_handle:
        document = json.load(file_handle)

    controls = document.get("controls")

    if not isinstance(controls, list):
        raise ValueError(
            "controls.json must contain a top-level 'controls' list."
        )

    required_fields = {
        "control_id",
        "title",
        "description",
        "frameworks",
        "validation",
    }

    for position, control in enumerate(controls, start=1):
        missing = required_fields - set(control)

        if missing:
            raise ValueError(
                f"Control #{position} is missing: {sorted(missing)}"
            )

    print(f"Loaded {len(controls)} control definition(s).")

    return controls


def select_controls(
    controls: list[dict[str, Any]],
    requested_frameworks: list[str],
) -> list[dict[str, Any]]:
    """
    Select only controls mapped to the requested frameworks.

    The technical control remains framework-neutral. Framework references are
    mappings attached to the control.
    """

    request_all = any(
        framework.upper() == "ALL"
        for framework in requested_frameworks
    )

    if request_all:
        return controls

    requested_lookup = {
        framework.casefold()
        for framework in requested_frameworks
    }

    selected: list[dict[str, Any]] = []

    for control in controls:
        mapped_frameworks = {
            str(mapping.get("framework", "")).casefold()
            for mapping in control.get("frameworks", [])
        }

        if requested_lookup.intersection(mapped_frameworks):
            selected.append(control)

    return selected


# ============================================================================
# Stage 2 and 3: Deterministic validators
# ============================================================================

def resolve_reference(value: Any) -> Any:
    """
    Resolve environment-variable references used in controls.json.

    Example:
        "bucket": "REPORT_BUCKET"

    If REPORT_BUCKET exists as an environment variable, its value is used.
    Ordinary literal values are returned unchanged.
    """

    if isinstance(value, str) and value in os.environ:
        return os.environ[value]

    return value


def validate_table_exists(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when the named DynamoDB table exists and is active."""

    table_name = str(resolve_reference(validation["table"]))

    try:
        response = dynamodb_client.describe_table(
            TableName=table_name
        )

        table_status = response["Table"]["TableStatus"]
        passed = table_status == "ACTIVE"

        return ValidationResult(
            status="PASS" if passed else "REVIEW",
            observation=(
                f"DynamoDB table '{table_name}' exists with "
                f"status '{table_status}'."
            ),
            evidence={
                "table": table_name,
                "table_status": table_status,
                "table_arn": response["Table"].get("TableArn"),
            },
        )

    except dynamodb_client.exceptions.ResourceNotFoundException:
        return ValidationResult(
            status="FAIL",
            observation=(
                f"DynamoDB table '{table_name}' does not exist."
            ),
            evidence={"table": table_name},
        )


def get_table_record_count(table_name: str) -> int:
    """
    Count table records using a paginated Scan with Select='COUNT'.

    This is intentionally simple for the lab. At enterprise scale, use a
    reporting index, metrics, or a precomputed evidence pipeline rather than
    scanning large operational tables.
    """

    count = 0
    scan_arguments: dict[str, Any] = {
        "TableName": table_name,
        "Select": "COUNT",
    }

    while True:
        response = dynamodb_client.scan(**scan_arguments)
        count += int(response.get("Count", 0))

        last_key = response.get("LastEvaluatedKey")

        if not last_key:
            break

        scan_arguments["ExclusiveStartKey"] = last_key

    return count


def validate_table_not_empty(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when the DynamoDB table exists and contains at least one record."""

    table_name = str(resolve_reference(validation["table"]))

    try:
        dynamodb_client.describe_table(TableName=table_name)
        record_count = get_table_record_count(table_name)

        return ValidationResult(
            status="PASS" if record_count > 0 else "FAIL",
            observation=(
                f"DynamoDB table '{table_name}' contains "
                f"{record_count} record(s)."
            ),
            evidence={
                "table": table_name,
                "record_count": record_count,
            },
        )

    except dynamodb_client.exceptions.ResourceNotFoundException:
        return ValidationResult(
            status="FAIL",
            observation=(
                f"DynamoDB table '{table_name}' does not exist."
            ),
            evidence={"table": table_name},
        )


def validate_minimum_records(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when a DynamoDB table contains the configured minimum records."""

    table_name = str(resolve_reference(validation["table"]))
    minimum = int(validation.get("minimum", 1))

    try:
        dynamodb_client.describe_table(TableName=table_name)
        record_count = get_table_record_count(table_name)
        passed = record_count >= minimum

        return ValidationResult(
            status="PASS" if passed else "FAIL",
            observation=(
                f"DynamoDB table '{table_name}' contains "
                f"{record_count} record(s); minimum required is {minimum}."
            ),
            evidence={
                "table": table_name,
                "record_count": record_count,
                "minimum_required": minimum,
            },
        )

    except dynamodb_client.exceptions.ResourceNotFoundException:
        return ValidationResult(
            status="FAIL",
            observation=(
                f"DynamoDB table '{table_name}' does not exist."
            ),
            evidence={
                "table": table_name,
                "minimum_required": minimum,
            },
        )


def validate_s3_prefix(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when at least one object exists under the configured S3 prefix."""

    bucket = str(resolve_reference(validation["bucket"]))
    prefix = str(resolve_reference(validation.get("prefix", "")))

    response = s3_client.list_objects_v2(
        Bucket=bucket,
        Prefix=prefix,
        MaxKeys=1,
    )

    object_count = int(response.get("KeyCount", 0))
    passed = object_count > 0

    evidence: dict[str, Any] = {
        "bucket": bucket,
        "prefix": prefix,
        "object_found": passed,
    }

    if passed:
        evidence["sample_object_key"] = response["Contents"][0]["Key"]

    return ValidationResult(
        status="PASS" if passed else "FAIL",
        observation=(
            f"S3 prefix 's3://{bucket}/{prefix}' "
            f"{'contains report evidence' if passed else 'contains no objects'}."
        ),
        evidence=evidence,
    )


def validate_bedrock_enabled(
    validation: dict[str, Any],
) -> ValidationResult:
    """
    Evaluate whether Bedrock use is enabled for this application.

    This checks the application's configuration, not the health of every model.
    """

    expected = bool(validation.get("expected", True))
    passed = ENABLE_BEDROCK == expected

    return ValidationResult(
        status="PASS" if passed else "FAIL",
        observation=(
            f"Bedrock enabled state is {ENABLE_BEDROCK}; "
            f"expected state is {expected}."
        ),
        evidence={
            "bedrock_enabled": ENABLE_BEDROCK,
            "expected": expected,
            "model_id": BEDROCK_MODEL_ID,
        },
    )


def validate_eventbridge_rule_exists(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when an EventBridge rule exists and is enabled."""

    rule_name = str(resolve_reference(validation["rule_name"]))
    event_bus_name = str(
        resolve_reference(
            validation.get("event_bus_name", "default")
        )
    )

    try:
        response = events_client.describe_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
        )

        state = response.get("State", "UNKNOWN")
        passed = state == "ENABLED"

        return ValidationResult(
            status="PASS" if passed else "REVIEW",
            observation=(
                f"EventBridge rule '{rule_name}' exists with "
                f"state '{state}'."
            ),
            evidence={
                "rule_name": rule_name,
                "event_bus_name": event_bus_name,
                "state": state,
                "arn": response.get("Arn"),
            },
        )

    except events_client.exceptions.ResourceNotFoundException:
        return ValidationResult(
            status="FAIL",
            observation=(
                f"EventBridge rule '{rule_name}' does not exist."
            ),
            evidence={
                "rule_name": rule_name,
                "event_bus_name": event_bus_name,
            },
        )


def validate_scheduler_exists(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when an EventBridge Scheduler schedule exists and is enabled."""

    schedule_name = str(
        resolve_reference(validation["schedule_name"])
    )
    group_name = str(
        resolve_reference(
            validation.get("group_name", "default")
        )
    )

    try:
        response = scheduler_client.get_schedule(
            Name=schedule_name,
            GroupName=group_name,
        )

        state = response.get("State", "UNKNOWN")
        passed = state == "ENABLED"

        return ValidationResult(
            status="PASS" if passed else "REVIEW",
            observation=(
                f"EventBridge Scheduler schedule '{schedule_name}' "
                f"exists with state '{state}'."
            ),
            evidence={
                "schedule_name": schedule_name,
                "group_name": group_name,
                "state": state,
                "arn": response.get("Arn"),
                "schedule_expression": response.get(
                    "ScheduleExpression"
                ),
            },
        )

    except scheduler_client.exceptions.ResourceNotFoundException:
        return ValidationResult(
            status="FAIL",
            observation=(
                f"EventBridge Scheduler schedule "
                f"'{schedule_name}' does not exist."
            ),
            evidence={
                "schedule_name": schedule_name,
                "group_name": group_name,
            },
        )


def validate_sns_topic_exists(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when the configured SNS topic can be retrieved."""

    topic_arn = str(resolve_reference(validation["topic_arn"]))

    try:
        attributes = sns_client.get_topic_attributes(
            TopicArn=topic_arn
        )["Attributes"]

        return ValidationResult(
            status="PASS",
            observation=(
                f"SNS topic '{topic_arn}' exists and is accessible."
            ),
            evidence={
                "topic_arn": topic_arn,
                "owner": attributes.get("Owner"),
                "subscriptions_confirmed": attributes.get(
                    "SubscriptionsConfirmed"
                ),
            },
        )

    except ClientError as error:
        error_code = error.response["Error"].get("Code", "Unknown")

        if error_code in {
            "NotFound",
            "NotFoundException",
            "InvalidParameter",
        }:
            return ValidationResult(
                status="FAIL",
                observation=(
                    f"SNS topic '{topic_arn}' was not found."
                ),
                evidence={"topic_arn": topic_arn},
                error=error_code,
            )

        raise


def validate_lambda_exists(
    validation: dict[str, Any],
) -> ValidationResult:
    """PASS when the configured Lambda function exists and is active."""

    function_name = str(
        resolve_reference(validation["function_name"])
    )

    try:
        response = lambda_client.get_function_configuration(
            FunctionName=function_name
        )

        state = response.get("State", "Unknown")
        last_update_status = response.get(
            "LastUpdateStatus",
            "Unknown",
        )
        passed = (
            state == "Active"
            and last_update_status == "Successful"
        )

        return ValidationResult(
            status="PASS" if passed else "REVIEW",
            observation=(
                f"Lambda function '{function_name}' has state "
                f"'{state}' and last update status "
                f"'{last_update_status}'."
            ),
            evidence={
                "function_name": function_name,
                "function_arn": response.get("FunctionArn"),
                "runtime": response.get("Runtime"),
                "state": state,
                "last_update_status": last_update_status,
            },
        )

    except lambda_client.exceptions.ResourceNotFoundException:
        return ValidationResult(
            status="FAIL",
            observation=(
                f"Lambda function '{function_name}' does not exist."
            ),
            evidence={"function_name": function_name},
        )


# The registry connects JSON validation types to Python functions.
# Adding a new validator later requires one function and one registry entry.
VALIDATORS: dict[
    str,
    Callable[[dict[str, Any]], ValidationResult],
] = {
    "table_exists": validate_table_exists,
    "table_not_empty": validate_table_not_empty,
    "minimum_records": validate_minimum_records,
    "s3_prefix": validate_s3_prefix,
    "bedrock_enabled": validate_bedrock_enabled,
    "eventbridge_rule_exists": validate_eventbridge_rule_exists,
    "eventbridge_schedule_exists": validate_scheduler_exists,
    "sns_topic_exists": validate_sns_topic_exists,
    "lambda_exists": validate_lambda_exists,
}


def evaluate_control(
    control: dict[str, Any],
    evaluated_at: datetime,
) -> dict[str, Any]:
    """
    Evaluate one control and return a report-ready result.

    Unknown validation types become REVIEW instead of crashing the whole report.
    That is useful during labs while students gradually add new validators.
    """

    validation = control["validation"]
    validation_type = str(validation.get("type", "")).strip()

    validator = VALIDATORS.get(validation_type)

    if validator is None:
        result = ValidationResult(
            status=UNEVALUATED_STATUS,
            observation=(
                f"Validation type '{validation_type}' is not supported."
            ),
            evidence={
                "validation_type": validation_type,
            },
            error="Unsupported validation type",
        )
    else:
        try:
            result = validator(validation)

        except (ClientError, BotoCoreError, KeyError, ValueError) as error:
            # A permission problem or malformed definition should be visible.
            # It should never be translated into PASS.
            result = ValidationResult(
                status="REVIEW",
                observation=(
                    "The control could not be fully evaluated and "
                    "requires human review."
                ),
                evidence={
                    "validation_type": validation_type,
                },
                error=f"{type(error).__name__}: {error}",
            )

    return {
        "control_id": control["control_id"],
        "title": control["title"],
        "description": control["description"],
        "category": control.get("category", "Uncategorized"),
        "severity": str(
            control.get("severity", "Medium")
        ).upper(),
        "service": control.get("service"),
        "resource_type": control.get("resource_type"),
        "frameworks": control.get("frameworks", []),
        "evidence_sources": control.get(
            "evidence_sources",
            []
        ),
        "validation": validation,
        "status": result.status,
        "observation": result.observation,
        "evidence": decimal_to_native(result.evidence),
        "error": result.error,
        "evaluated_at": isoformat_utc(evaluated_at),
        "bedrock_prompt": control.get("bedrock_prompt"),
    }


def evaluate_controls(
    controls: list[dict[str, Any]],
    evaluated_at: datetime,
) -> list[dict[str, Any]]:
    """Evaluate every selected control."""

    results: list[dict[str, Any]] = []

    for control in controls:
        print(
            f"Evaluating {control['control_id']}: "
            f"{control['title']}"
        )

        result = evaluate_control(
            control=control,
            evaluated_at=evaluated_at,
        )

        print(
            f"Result for {control['control_id']}: "
            f"{result['status']}"
        )

        results.append(result)

    return results


# ============================================================================
# Evidence storage
# ============================================================================

def write_evidence_records(
    results: list[dict[str, Any]],
    report_id: str,
) -> int:
    """
    Store one immutable evidence record per control evaluation.

    The PDF is useful for humans. These records are more useful when an auditor
    asks exactly why a control passed on a specific date.
    """

    table = dynamodb_resource.Table(
        COMPLIANCE_EVIDENCE_TABLE
    )

    written = 0

    with table.batch_writer() as batch:
        for result in results:
            evidence_id = str(uuid.uuid4())

            item = {
                "evidence_id": evidence_id,
                "report_id": report_id,
                "control_id": result["control_id"],
                "title": result["title"],
                "status": result["status"],
                "severity": result["severity"],
                "category": result["category"],
                "evaluated_at": result["evaluated_at"],
                "validator": "compliance_agent.py",
                "observation": result["observation"],
                "frameworks": result["frameworks"],
                "evidence_sources": result[
                    "evidence_sources"
                ],
                "evidence": result["evidence"],
            }

            if result.get("error"):
                item["error"] = result["error"]

            batch.put_item(Item=item)
            written += 1

    return written


# ============================================================================
# Compliance scoring
# ============================================================================

def calculate_summary(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate a transparent control score.

    REVIEW is not counted as PASS. This prevents unavailable evidence from
    improving the score.
    """

    counts = {
        "PASS": 0,
        "FAIL": 0,
        "REVIEW": 0,
    }

    for result in results:
        status = result["status"].upper()
        counts[status] = counts.get(status, 0) + 1

    total = len(results)
    score = (
        round((counts["PASS"] / total) * 100, 2)
        if total
        else 0.0
    )

    if counts["FAIL"] > 0:
        overall_status = "FAIL"
    elif counts["REVIEW"] > 0:
        overall_status = "REVIEW"
    elif total > 0:
        overall_status = "PASS"
    else:
        overall_status = "NO_CONTROLS"

    return {
        "total_controls": total,
        "passed_controls": counts["PASS"],
        "failed_controls": counts["FAIL"],
        "review_controls": counts["REVIEW"],
        "score_percent": score,
        "overall_status": overall_status,
    }


def build_framework_scorecards(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Calculate scorecards independently for every mapped framework.

    One technical control can contribute evidence to several frameworks.
    """

    grouped: dict[str, list[dict[str, Any]]] = {}

    for result in results:
        for mapping in result.get("frameworks", []):
            framework = str(
                mapping.get("framework", "Unknown")
            )

            grouped.setdefault(framework, []).append(
                result
            )

    scorecards: list[dict[str, Any]] = []

    for framework, framework_results in sorted(
        grouped.items()
    ):
        summary = calculate_summary(framework_results)
        summary["framework"] = framework
        scorecards.append(summary)

    return scorecards


# ============================================================================
# Bedrock explanation
# ============================================================================

def build_bedrock_payload(
    report_id: str,
    summary: dict[str, Any],
    scorecards: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a compact evidence package for Bedrock.

    Raw secrets, tokens, and complete logs should not be placed in this prompt.
    The agent sends only control conclusions and supporting observations.
    """

    compact_results = []

    for result in results:
        compact_results.append(
            {
                "control_id": result["control_id"],
                "title": result["title"],
                "category": result["category"],
                "severity": result["severity"],
                "status": result["status"],
                "observation": result["observation"],
                "frameworks": result["frameworks"],
                "control_explanation_instruction": (
                    result.get("bedrock_prompt")
                ),
                "error": result.get("error"),
            }
        )

    return {
        "report_id": report_id,
        "summary": summary,
        "framework_scorecards": scorecards,
        "control_results": compact_results,
    }


def invoke_bedrock(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Ask Bedrock to explain the deterministic control results.

    The prompt explicitly prohibits Bedrock from changing a control status.
    """

    prompt = f"""
You are writing a compliance evidence report for executives, security
leadership, and auditors.

Python has already evaluated every control. You must not change, recalculate,
or override any status or score.

Evidence package:
{json.dumps(payload, indent=2, default=str)}

Return valid JSON using exactly this structure:

{{
  "executive_summary": "string",
  "overall_assessment": "string",
  "material_failures": ["string"],
  "items_requiring_review": ["string"],
  "strengths": ["string"],
  "recommended_actions": ["string"],
  "evidence_limitations": ["string"],
  "auditor_note": "string"
}}

Rules:
- Use only the supplied evidence.
- Never claim legal, regulatory, or certification compliance.
- Say that the report provides control evidence, not a certification.
- Do not turn REVIEW into PASS or FAIL.
- Do not claim a control operated continuously unless the evidence proves it.
- Do not invent logs, resources, incidents, ownership, or remediation.
- Clearly distinguish missing evidence from failed control operation.
- Keep the language concise and suitable for management and auditors.
""".strip()

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1400,
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
            "Bedrock returned no narrative content."
        )

    response_text = content[0].get("text", "").strip()

    # Models occasionally wrap JSON in a Markdown code fence.
    if response_text.startswith("```"):
        response_text = response_text.strip("`")

        if response_text.startswith("json"):
            response_text = response_text[4:].strip()

    return json.loads(response_text)


def fallback_narrative(
    summary: dict[str, Any],
) -> dict[str, Any]:
    """
    Produce a useful report even when Bedrock is disabled or unavailable.

    Compliance evidence should never disappear because an AI service failed.
    """

    return {
        "executive_summary": (
            f"{summary['total_controls']} control(s) were evaluated. "
            f"{summary['passed_controls']} passed, "
            f"{summary['failed_controls']} failed, and "
            f"{summary['review_controls']} require review."
        ),
        "overall_assessment": (
            f"The deterministic control score is "
            f"{summary['score_percent']}%, with overall status "
            f"{summary['overall_status']}."
        ),
        "material_failures": [
            "Review all controls marked FAIL."
        ] if summary["failed_controls"] else [],
        "items_requiring_review": [
            "Review controls that could not be conclusively evaluated."
        ] if summary["review_controls"] else [],
        "strengths": [
            "Control evaluations were produced using deterministic validators."
        ],
        "recommended_actions": [
            "Resolve failed controls.",
            "Collect missing evidence for controls marked REVIEW.",
            "Preserve the generated evidence records for audit review.",
        ],
        "evidence_limitations": [
            "This report evaluates only the controls and evidence sources "
            "defined in controls.json.",
            "This report is not a certification or legal opinion.",
        ],
        "auditor_note": (
            "Each control result has a corresponding DynamoDB evidence record."
        ),
    }


# ============================================================================
# Report construction
# ============================================================================

def build_report(
    report_id: str,
    generated_at: datetime,
    requested_frameworks: list[str],
    summary: dict[str, Any],
    scorecards: list[dict[str, Any]],
    results: list[dict[str, Any]],
    narrative: dict[str, Any],
    bedrock_used: bool,
) -> dict[str, Any]:
    """Build the shared source document used by both JSON and PDF."""

    return {
        "schema_version": "1.0",
        "report_id": report_id,
        "report_type": "COMPLIANCE_EVIDENCE",
        "organization": ORGANIZATION_NAME,
        "title": REPORT_TITLE,
        "generated_at": isoformat_utc(generated_at),
        "requested_frameworks": requested_frameworks,
        "summary": summary,
        "framework_scorecards": scorecards,
        "control_results": results,
        "narrative": narrative,
        "generation_metadata": {
            "validator": "compliance_agent.py",
            "controls_file": CONTROLS_FILE,
            "bedrock_used": bedrock_used,
            "bedrock_model_id": (
                BEDROCK_MODEL_ID if bedrock_used else None
            ),
            "certification_claimed": False,
            "human_review_required": (
                summary["failed_controls"] > 0
                or summary["review_controls"] > 0
            ),
        },
    }


# ============================================================================
# PDF generation
# ============================================================================

def add_bullet_list(
    story: list[Any],
    values: list[Any],
    body_style: ParagraphStyle,
) -> None:
    """Add simple bullet paragraphs to the report."""

    if not values:
        story.append(
            Paragraph("None reported.", body_style)
        )
        return

    for value in values:
        story.append(
            Paragraph(
                f"• {safe_text(value)}",
                body_style,
            )
        )


def generate_pdf(report: dict[str, Any]) -> bytes:
    """Generate the compliance PDF in memory."""

    output = io.BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        title=report["title"],
        author=report["organization"],
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ComplianceTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=19,
        leading=23,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "ComplianceSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#4B5563"),
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        "ComplianceHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1F3A5F"),
        spaceBefore=9,
        spaceAfter=5,
    )

    body_style = ParagraphStyle(
        "ComplianceBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=4,
    )

    story: list[Any] = []

    summary = report["summary"]
    narrative = report["narrative"]

    story.append(
        Paragraph(
            safe_text(report["title"]),
            title_style,
        )
    )

    story.append(
        Paragraph(
            (
                f"{safe_text(report['organization'])}<br/>"
                f"Report ID: {safe_text(report['report_id'])}<br/>"
                f"Generated: {safe_text(report['generated_at'])}"
            ),
            subtitle_style,
        )
    )

    summary_data = [
        ["Overall Status", summary["overall_status"]],
        ["Control Score", f"{summary['score_percent']}%"],
        ["Controls Evaluated", summary["total_controls"]],
        ["Passed", summary["passed_controls"]],
        ["Failed", summary["failed_controls"]],
        ["Requires Review", summary["review_controls"]],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[3.4 * inch, 3.2 * inch],
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#D9EAF7"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
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
                    (1, 0),
                    (1, -1),
                    "RIGHT",
                ),
            ]
        )
    )

    story.append(summary_table)

    story.append(
        Paragraph("Executive Summary", heading_style)
    )
    story.append(
        Paragraph(
            safe_text(
                narrative.get("executive_summary", "")
            ),
            body_style,
        )
    )

    story.append(
        Paragraph("Overall Assessment", heading_style)
    )
    story.append(
        Paragraph(
            safe_text(
                narrative.get("overall_assessment", "")
            ),
            body_style,
        )
    )

    story.append(
        Paragraph("Framework Scorecards", heading_style)
    )

    scorecard_data = [
        [
            "Framework",
            "Score",
            "Pass",
            "Fail",
            "Review",
            "Status",
        ]
    ]

    for scorecard in report["framework_scorecards"]:
        scorecard_data.append(
            [
                safe_text(scorecard["framework"]),
                f"{scorecard['score_percent']}%",
                scorecard["passed_controls"],
                scorecard["failed_controls"],
                scorecard["review_controls"],
                scorecard["overall_status"],
            ]
        )

    scorecard_table = Table(
        scorecard_data,
        colWidths=[
            2.25 * inch,
            0.75 * inch,
            0.65 * inch,
            0.65 * inch,
            0.75 * inch,
            0.85 * inch,
        ],
        repeatRows=1,
    )

    scorecard_table.setStyle(
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
                    (-1, -1),
                    "CENTER",
                ),
            ]
        )
    )

    story.append(scorecard_table)

    story.append(
        Paragraph("Material Failures", heading_style)
    )
    add_bullet_list(
        story,
        narrative.get("material_failures", []),
        body_style,
    )

    story.append(
        Paragraph("Items Requiring Review", heading_style)
    )
    add_bullet_list(
        story,
        narrative.get(
            "items_requiring_review",
            [],
        ),
        body_style,
    )

    story.append(
        Paragraph("Recommended Actions", heading_style)
    )
    add_bullet_list(
        story,
        narrative.get("recommended_actions", []),
        body_style,
    )

    story.append(PageBreak())
    story.append(
        Paragraph("Control Evaluation Detail", title_style)
    )

    control_data = [
        [
            "Control",
            "Category",
            "Severity",
            "Status",
            "Observation",
        ]
    ]

    for result in report["control_results"]:
        control_data.append(
            [
                Paragraph(
                    (
                        f"<b>{safe_text(result['control_id'])}</b><br/>"
                        f"{safe_text(result['title'])}"
                    ),
                    body_style,
                ),
                safe_text(result["category"]),
                safe_text(result["severity"]),
                safe_text(result["status"]),
                Paragraph(
                    safe_text(result["observation"]),
                    body_style,
                ),
            ]
        )

    control_table = Table(
        control_data,
        colWidths=[
            1.45 * inch,
            1.05 * inch,
            0.7 * inch,
            0.65 * inch,
            2.75 * inch,
        ],
        repeatRows=1,
    )

    control_table.setStyle(
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
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
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

    story.append(control_table)

    story.append(
        Paragraph("Evidence Limitations", heading_style)
    )
    add_bullet_list(
        story,
        narrative.get("evidence_limitations", []),
        body_style,
    )

    story.append(
        Paragraph("Auditor Note", heading_style)
    )
    story.append(
        Paragraph(
            safe_text(narrative.get("auditor_note", "")),
            body_style,
        )
    )

    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            (
                "This document provides control evidence only. "
                "It is not a certification, legal opinion, or guarantee "
                "of continuous compliance."
            ),
            body_style,
        )
    )

    document.build(story)

    result = output.getvalue()
    output.close()

    return result


# ============================================================================
# S3 publication
# ============================================================================

def build_s3_keys(
    generated_at: datetime,
    report_id: str,
) -> tuple[str, str]:
    """Create parallel object paths for PDF and JSON."""

    date_path = generated_at.strftime("%Y/%m/%d")
    base_path = f"{REPORT_PREFIX}/{date_path}"

    return (
        f"{base_path}/pdf/{report_id}.pdf",
        f"{base_path}/json/{report_id}.json",
    )


def upload_report(
    report: dict[str, Any],
    pdf_data: bytes,
    generated_at: datetime,
) -> dict[str, Any]:
    """Upload the synchronized report artifacts to S3."""

    pdf_key, json_key = build_s3_keys(
        generated_at=generated_at,
        report_id=report["report_id"],
    )

    report_json = json_bytes(report)

    metadata = {
        "report-id": report["report_id"],
        "report-type": "compliance-evidence",
        "overall-status": report["summary"][
            "overall_status"
        ].lower(),
    }

    s3_client.put_object(
        Bucket=REPORT_BUCKET,
        Key=pdf_key,
        Body=pdf_data,
        ContentType="application/pdf",
        ServerSideEncryption="AES256",
        Metadata=metadata,
    )

    s3_client.put_object(
        Bucket=REPORT_BUCKET,
        Key=json_key,
        Body=report_json,
        ContentType="application/json",
        ServerSideEncryption="AES256",
        Metadata=metadata,
    )

    return {
        "bucket": REPORT_BUCKET,
        "pdf": {
            "key": pdf_key,
            "uri": f"s3://{REPORT_BUCKET}/{pdf_key}",
            "size_bytes": len(pdf_data),
        },
        "json": {
            "key": json_key,
            "uri": f"s3://{REPORT_BUCKET}/{json_key}",
            "size_bytes": len(report_json),
        },
    }


# ============================================================================
# Lambda entry point
# ============================================================================

def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """
    Generate a compliance evidence report.

    Optional test-event fields:
      frameworks:
        "NIST CSF 2.0"
        ["NIST CSF 2.0", "CIS Controls v8"]
        "ALL"

      controls_file:
        "/var/task/controls.json"

    Event values override environment defaults only for the current invocation.
    """

    print("=" * 68)
    print("Starting Agent 9: Compliance Agent")
    print("Chewbacca is guarding the evidence archive.")
    print("=" * 68)

    generated_at = utc_now()
    report_id = generated_at.strftime(
        "compliance-%Y%m%dT%H%M%SZ"
    )

    try:
        frameworks = normalize_frameworks(
            event.get("frameworks")
        )

        controls_file = str(
            event.get("controls_file", CONTROLS_FILE)
        )

        print(f"Requested frameworks: {frameworks}")
        print(f"Control library: {controls_file}")

        # Stage 1: Load and select controls.
        all_controls = load_controls(controls_file)

        selected_controls = select_controls(
            controls=all_controls,
            requested_frameworks=frameworks,
        )

        if not selected_controls:
            raise ValueError(
                "No controls matched the requested framework(s)."
            )

        print(
            f"Selected {len(selected_controls)} control(s) "
            f"for evaluation."
        )

        # Stages 2 and 3: Collect evidence and evaluate controls.
        results = evaluate_controls(
            controls=selected_controls,
            evaluated_at=generated_at,
        )

        summary = calculate_summary(results)
        scorecards = build_framework_scorecards(results)

        # Preserve the evidence trail before generating prose.
        evidence_records_written = write_evidence_records(
            results=results,
            report_id=report_id,
        )

        print(
            f"Wrote {evidence_records_written} evidence "
            f"record(s) to DynamoDB."
        )

        # Stage 4: Bedrock explains the results. It does not decide them.
        bedrock_used = False

        if ENABLE_BEDROCK:
            try:
                payload = build_bedrock_payload(
                    report_id=report_id,
                    summary=summary,
                    scorecards=scorecards,
                    results=results,
                )

                narrative = invoke_bedrock(payload)
                bedrock_used = True

                print("Bedrock narrative generated.")

            except Exception as error:
                print(
                    "Bedrock explanation failed. "
                    "Using deterministic fallback."
                )
                print(
                    f"{type(error).__name__}: {error}"
                )

                narrative = fallback_narrative(summary)

        else:
            print(
                "Bedrock is disabled. "
                "Using deterministic fallback."
            )

            narrative = fallback_narrative(summary)

        report = build_report(
            report_id=report_id,
            generated_at=generated_at,
            requested_frameworks=frameworks,
            summary=summary,
            scorecards=scorecards,
            results=results,
            narrative=narrative,
            bedrock_used=bedrock_used,
        )

        pdf_data = generate_pdf(report)

        artifacts = upload_report(
            report=report,
            pdf_data=pdf_data,
            generated_at=generated_at,
        )

        response_body = {
            "message": (
                "Compliance evidence report generated and published."
            ),
            "report_id": report_id,
            "overall_status": summary["overall_status"],
            "score_percent": summary["score_percent"],
            "controls_evaluated": summary["total_controls"],
            "evidence_records_written": evidence_records_written,
            "bedrock_used": bedrock_used,
            "artifacts": artifacts,
            "certification_claimed": False,
            "human_review_required": report[
                "generation_metadata"
            ]["human_review_required"],
        }

        print(json.dumps(response_body, indent=2))

        return {
            "statusCode": 200,
            "body": json.dumps(response_body),
        }

    except Exception as error:
        print(
            f"Compliance Agent failed: "
            f"{type(error).__name__}: {error}"
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "Compliance evidence report generation failed."
                    ),
                    "report_id": report_id,
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
            ),
        }