#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# gate_11b_incident.sh — Lab 11B Incident Gate (API→Lambda→RDS)
#
# Scenario: "DB connections fail" (security group rule altered)
# Students must:
#  1) Detect failure
#  2) Collect evidence pack
#  3) Recover (fix SG or config)
#  4) Prove recovery with re-test
#
# Exit codes:
#   0 PASS  (incident created, detected, and recovered)
#   2 FAIL  (missing evidence or recovery not proven)
#   1 ERROR (script/tooling error)
# ============================================================

REGION="${REGION:-us-east-1}"

# Required inputs from Lab 11A
LAMBDA_NAME="${LAMBDA_NAME:-}"
API_ID="${API_ID:-}"
STAGE_NAME="${STAGE_NAME:-prod}"
ROUTE_PATH="${ROUTE_PATH:-/intake}"

DB_ID="${DB_ID:-}"
RDS_SG_ID="${RDS_SG_ID:-}"
LAMBDA_SG_ID="${LAMBDA_SG_ID:-}"
SECRET_ARN="${SECRET_ARN:-}"

# Incident controls
INCIDENT_MODE="${INCIDENT_MODE:-sg_block_db}"   # sg_block_db | secret_break | none
AUTO_BREAK="${AUTO_BREAK:-true}"                # true breaks it; false assumes already broken
AUTO_RESTORE="${AUTO_RESTORE:-false}"           # false = students fix; true = script restores (instructor mode)

# Evidence outputs
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence_11b}"
OUT_JSON="${OUT_JSON:-gate_11b_incident.json}"
PR_COMMENT_MD="${PR_COMMENT_MD:-pr_comment.md}"

# Time window for logs (minutes)
LOG_SINCE_MIN="${LOG_SINCE_MIN:-15}"

# ------------------------------------------------------------
failures=(); warnings=(); details=()
add_failure(){ failures+=("$1"); }
add_warning(){ warnings+=("$1"); }
add_detail(){ details+=("$1"); }

mkdir -p "$EVIDENCE_DIR"

json_escape(){ sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'; }
make_json_array() {
  if (( $# == 0 )); then echo "[]"; return; fi
  printf '%s\n' "$@" | json_escape | awk 'BEGIN{print "["} {printf "%s\"%s\"", (NR>1?",":""), $0} END{print "]"}'
}

need() {
  local v="$1" name="$2"
  if [[ -z "$v" ]]; then
    add_failure "FAIL: missing required env var: $name"
  fi
}

need "$LAMBDA_NAME" "LAMBDA_NAME"
need "$API_ID" "API_ID"
need "$DB_ID" "DB_ID"
need "$RDS_SG_ID" "RDS_SG_ID"
need "$LAMBDA_SG_ID" "LAMBDA_SG_ID"
need "$SECRET_ARN" "SECRET_ARN"

if (( ${#failures[@]} > 0 )); then
  add_detail "INFO: Set required env vars and rerun."
  # Emit JSON then exit FAIL
  details_json="$(make_json_array "${details[@]}")"
  warnings_json="$(make_json_array "${warnings[@]}")"
  failures_json="$(make_json_array "${failures[@]}")"
  cat > "$OUT_JSON" <<EOF
{"schema_version":"1.0","gate":"11b_incident","timestamp_utc":"$(date -u +"%Y-%m-%dT%H:%M:%SZ")","status":"FAIL","exit_code":2,"details":$details_json,"warnings":$warnings_json,"failures":$failures_json}
EOF
  exit 2
fi

account_id="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")"
if [[ -z "$account_id" || "$account_id" == "None" ]]; then
  add_failure "FAIL: aws sts get-caller-identity failed (credentials?)."
fi

url="https://${API_ID}.execute-api.${REGION}.amazonaws.com/${STAGE_NAME}${ROUTE_PATH}"
payload='{"actor":"doctor.ny","action":"VIEW_PATIENT","resource":"patient/12345","note":"11B-incident-test"}'

# ------------------------------------------------------------
# Evidence helpers
save_cmd() {
  local name="$1"; shift
  #Chewbacca: Evidence or it didn’t happen.
  ( set +e; "$@" ) > "${EVIDENCE_DIR}/${name}.out" 2> "${EVIDENCE_DIR}/${name}.err" || true
}

invoke_api() {
  local out_file="$1"
  local code
  code="$(curl -sS -o "$out_file" -w "%{http_code}" -X POST "$url" -H "content-type: application/json" -d "$payload" || echo "000")"
  echo "$code"
}

tail_lambda_logs() {
  #Chewbacca: When the Wookiee is silent, check CloudWatch.
  save_cmd "logs_tail" aws logs tail "/aws/lambda/$LAMBDA_NAME" --since "${LOG_SINCE_MIN}m"
}

# ------------------------------------------------------------
# 0) Baseline evidence (before incident)
add_detail "INFO: Collecting baseline evidence."
save_cmd "rds_describe" aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json
save_cmd "sg_rds_describe" aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" --output json
save_cmd "lambda_cfg" aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --output json
save_cmd "secret_describe" aws secretsmanager describe-secret --secret-id "$SECRET_ARN" --region "$REGION" --output json
save_cmd "apigw_routes" aws apigatewayv2 get-routes --api-id "$API_ID" --region "$REGION" --output json

baseline_code="$(invoke_api "${EVIDENCE_DIR}/invoke_baseline.json")"
echo "$baseline_code" > "${EVIDENCE_DIR}/invoke_baseline.http_code"
tail_lambda_logs

if [[ "$baseline_code" == "200" ]]; then
  add_detail "PASS: Baseline API invoke returned 200 (system initially healthy)."
else
  add_warning "WARN: Baseline invoke not 200 (http_code=$baseline_code). Proceeding—system may already be broken."
fi

# ------------------------------------------------------------
# 1) Create incident (break something)
#Chewbacca: Welcome to the Temple. Now we remove one stone and see who panics.
if [[ "$INCIDENT_MODE" == "none" ]]; then
  add_detail "INFO: INCIDENT_MODE=none (no break injected)."
elif [[ "$AUTO_BREAK" != "true" ]]; then
  add_detail "INFO: AUTO_BREAK=false (assuming incident already exists)."
else
  if [[ "$INCIDENT_MODE" == "sg_block_db" ]]; then
    add_detail "INFO: Injecting incident: remove Lambda SG ingress on RDS (port 3306)."

    # Save current matching rule so we can restore (if instructor mode)
    save_cmd "sg_before_revoke_3306" aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" \
      --query "SecurityGroups[0].IpPermissions[?FromPort==\`3306\` && ToPort==\`3306\`]" --output json

    # Attempt to revoke the specific rule: 3306 from Lambda SG
    set +e
    aws ec2 revoke-security-group-ingress \
      --group-id "$RDS_SG_ID" --region "$REGION" \
      --ip-permissions "IpProtocol=tcp,FromPort=3306,ToPort=3306,UserIdGroupPairs=[{GroupId=$LAMBDA_SG_ID}]" \
      >/dev/null 2>&1
    rc=$?
    set -e

    if [[ "$rc" -eq 0 ]]; then
      add_detail "PASS: Incident injected (RDS SG ingress revoked for Lambda SG)."
    else
      add_warning "WARN: Could not revoke ingress rule (maybe it wasn't present or perms missing)."
    fi

    save_cmd "sg_after_revoke_3306" aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" --output json

  elif [[ "$INCIDENT_MODE" == "secret_break" ]]; then
    add_detail "INFO: Injecting incident: break secret password (rotate to wrong value)."

    # WARNING: This changes secret value; instructor-only.
    # We'll set password field to an invalid value.
    tmpfile="${EVIDENCE_DIR}/secret_bad.json"
    cat > "$tmpfile" <<EOF
{"username":"INVALID","password":"INVALID","host":"INVALID","port":3306,"dbname":"INVALID"}
EOF

    set +e
    aws secretsmanager put-secret-value --secret-id "$SECRET_ARN" --region "$REGION" --secret-string "file://$tmpfile" \
      >/dev/null 2>&1
    rc=$?
    set -e
    [[ "$rc" -eq 0 ]] && add_detail "PASS: Incident injected (secret overwritten with bad creds)." \
                      || add_warning "WARN: Could not overwrite secret (permissions?)."
    save_cmd "secret_after_break" aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "$REGION" --query '{ARN:ARN,VersionId:VersionId}' --output json
  else
    add_warning "WARN: Unknown INCIDENT_MODE=$INCIDENT_MODE (no incident injected)."
  fi
fi

# ------------------------------------------------------------
# 2) Prove failure (invoke should fail)
add_detail "INFO: Proving incident via API invoke."
fail_code="$(invoke_api "${EVIDENCE_DIR}/invoke_failure.json")"
echo "$fail_code" > "${EVIDENCE_DIR}/invoke_failure.http_code"
tail_lambda_logs

# We accept 502/500/504 as "failure proved" (depends on integration + lambda response)
if [[ "$fail_code" == "200" ]]; then
  add_failure "FAIL: Incident not proven—API still returns 200 (http_code=200)."
else
  add_detail "PASS: Incident proven—API does not return 200 (http_code=$fail_code)."
fi

# Collect focused evidence snapshots
add_detail "INFO: Collecting evidence pack for auditors."
save_cmd "rds_public_flag" aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" \
  --query "DBInstances[0].{PubliclyAccessible:PubliclyAccessible,Endpoint:Endpoint.Address,Port:Endpoint.Port}" --output json

save_cmd "sg_3306_pairs" aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`3306\` && ToPort==\`3306\`].UserIdGroupPairs[].GroupId" --output json

save_cmd "lambda_vpc_cfg" aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" \
  --query "{VpcConfig:VpcConfig,Env:Environment.Variables}" --output json

# ------------------------------------------------------------
# 3) Recovery requirement
# AUTO_RESTORE=false means students fix it, then rerun the gate (or run in "recovery check" mode)
#
# For one-shot grading, we support:
#   AUTO_RESTORE=true  (instructor run: break + restore + prove)
# ------------------------------------------------------------
if [[ "$AUTO_RESTORE" == "true" ]]; then
  add_detail "INFO: Instructor mode: attempting auto-restore."

  if [[ "$INCIDENT_MODE" == "sg_block_db" ]]; then
    #Chewbacca: Put the stone back in the Temple. Carefully.
    set +e
    aws ec2 authorize-security-group-ingress \
      --group-id "$RDS_SG_ID" --region "$REGION" \
      --ip-permissions "IpProtocol=tcp,FromPort=3306,ToPort=3306,UserIdGroupPairs=[{GroupId=$LAMBDA_SG_ID}]" \
      >/dev/null 2>&1
    rc=$?
    set -e
    [[ "$rc" -eq 0 ]] && add_detail "PASS: Auto-restore applied (re-added 3306 from Lambda SG)." \
                      || add_warning "WARN: Could not auto-restore SG rule (maybe already present)."
    save_cmd "sg_after_restore" aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" --output json
  elif [[ "$INCIDENT_MODE" == "secret_break" ]]; then
    add_warning "WARN: Auto-restore for secret_break is not implemented (restore requires original secret)."
  fi
else
  add_detail "INFO: Student mode: recovery not automatic. Fix the root cause, then rerun this gate OR run with AUTO_RESTORE=true (instructor only)."
fi

# ------------------------------------------------------------
# 4) Prove recovery (invoke must return 200)
add_detail "INFO: Proving recovery via API invoke."
recovery_code="$(invoke_api "${EVIDENCE_DIR}/invoke_recovery.json")"
echo "$recovery_code" > "${EVIDENCE_DIR}/invoke_recovery.http_code"
tail_lambda_logs

if [[ "$recovery_code" == "200" ]]; then
  add_detail "PASS: Recovery proven—API returns 200."
else
  add_failure "FAIL: Recovery not proven—API still failing (http_code=$recovery_code)."
fi

# Recovery checks: SG rule re-present?
pairs_after="$(aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`3306\` && ToPort==\`3306\`].UserIdGroupPairs[].GroupId" \
  --output text 2>/dev/null || echo "")"
echo "$pairs_after" | tr '\t' '\n' | grep -q "^${LAMBDA_SG_ID}$" \
  && add_detail "PASS: RDS SG again allows 3306 from Lambda SG." \
  || add_failure "FAIL: RDS SG still missing 3306 from Lambda SG after recovery."

# ------------------------------------------------------------
# Final status
status="PASS"; exit_code=0
(( ${#failures[@]} > 0 )) && status="FAIL" && exit_code=2

details_json="$(make_json_array "${details[@]}")"
warnings_json="$(make_json_array "${warnings[@]}")"
failures_json="$(make_json_array "${failures[@]}")"

cat > "$OUT_JSON" <<EOF
{
  "schema_version": "1.0",
  "gate": "11b_incident",
  "timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "region": "$(echo "$REGION" | json_escape)",
  "incident": {
    "mode": "$(echo "$INCIDENT_MODE" | json_escape)",
    "auto_break": "$(echo "$AUTO_BREAK" | json_escape)",
    "auto_restore": "$(echo "$AUTO_RESTORE" | json_escape)"
  },
  "inputs": {
    "lambda_name": "$(echo "$LAMBDA_NAME" | json_escape)",
    "api_id": "$(echo "$API_ID" | json_escape)",
    "stage": "$(echo "$STAGE_NAME" | json_escape)",
    "db_id": "$(echo "$DB_ID" | json_escape)",
    "rds_sg_id": "$(echo "$RDS_SG_ID" | json_escape)",
    "lambda_sg_id": "$(echo "$LAMBDA_SG_ID" | json_escape)",
    "secret_arn": "$(echo "$SECRET_ARN" | json_escape)"
  },
  "observed": {
    "invoke_url": "$(echo "$url" | json_escape)",
    "baseline_http_code": "$(cat "${EVIDENCE_DIR}/invoke_baseline.http_code" 2>/dev/null || echo "" | json_escape)",
    "failure_http_code": "$(cat "${EVIDENCE_DIR}/invoke_failure.http_code" 2>/dev/null || echo "" | json_escape)",
    "recovery_http_code": "$(cat "${EVIDENCE_DIR}/invoke_recovery.http_code" 2>/dev/null || echo "" | json_escape)"
  },
  "evidence_dir": "$(echo "$EVIDENCE_DIR" | json_escape)",
  "status": "$status",
  "exit_code": $exit_code,
  "details": $details_json,
  "warnings": $warnings_json,
  "failures": $failures_json
}
EOF

cat > "$PR_COMMENT_MD" <<EOF
### Lab 11B Incident Gate — **$status**

**Incident mode:** \`$INCIDENT_MODE\`  
**Baseline:** HTTP $(cat "${EVIDENCE_DIR}/invoke_baseline.http_code" 2>/dev/null || echo "?")  
**Failure proved:** HTTP $(cat "${EVIDENCE_DIR}/invoke_failure.http_code" 2>/dev/null || echo "?")  
**Recovery proved:** HTTP $(cat "${EVIDENCE_DIR}/invoke_recovery.http_code" 2>/dev/null || echo "?")  

**Evidence pack:** \`$EVIDENCE_DIR/\`

If recovery is failing:
- Check **RDS SG** has 3306 from **Lambda SG**
- Check Lambda VPC subnets + SG
- Check secret fields match endpoint/user/pass/dbname
- Check CloudWatch logs: \`/aws/lambda/$LAMBDA_NAME\`
EOF

echo "Lab 11B Incident Gate: $status"
echo "Evidence pack: $EVIDENCE_DIR/"
exit "$exit_code"