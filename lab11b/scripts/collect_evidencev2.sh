#!/usr/bin/env bash
#
# collect_evidence.sh — capture one PHASE of the Lab 11B incident
#
# It does NOT break anything and does NOT fix anything. It only
# observes and records. You decide when to break and when to heal;
# this makes sure every observation lands in a file with the exact
# name the manifest expects.
#
# All identifiers are DISCOVERED, not typed:
#   1. an env var, if you set one (escape hatch)
#   2. otherwise `terraform output`  (single source of truth)
#   3. otherwise an AWS API lookup   (works even without state)
# If all three fail, the script stops. It never guesses and never
# prompts — a wrong ID silently "succeeds" and poisons your evidence.
#
# Usage (run from your terraform/ directory):
#   ../scripts/collect_evidence.sh baseline    # BEFORE you break it
#   ../scripts/collect_evidence.sh failure     # AFTER you break it
#   ../scripts/collect_evidence.sh recovery    # AFTER you terraform apply
#
# Overrides:
#   TF_DIR=../11a  EVIDENCE_DIR=/abs/path  RUN_TF_PLAN=0
#
set -uo pipefail   # NOTE: no -e on purpose. A failing curl during the
                   # incident is EXPECTED evidence, not a script error.

PHASE="${1:-}"
case "$PHASE" in
  baseline|failure|recovery) ;;
  *) echo "usage: $0 {baseline|failure|recovery}" >&2; exit 64 ;;
esac

TF_DIR="${TF_DIR:-.}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence_11b}"
LOG_SINCE_MIN="${LOG_SINCE_MIN:-15}"
RUN_TF_PLAN="${RUN_TF_PLAN:-1}"

log()  { echo "[evidence:$PHASE] $*"; }
die()  { echo "[evidence:$PHASE] ERROR: $*" >&2; exit 1; }

# ------------------------------------------------------------------
# Discovery helpers
# ------------------------------------------------------------------

# tf_out <output_name> -> value, or empty string if absent.
# Errors are swallowed: a missing output is a normal condition we
# fall through on, not a crash.
tf_out() {
  terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null || true
}

# resolve <VARNAME> <tf_output_name> <fallback_command...>
# Precedence: existing env value > terraform output > fallback cmd.
resolve() {
  local varname="$1" tfname="$2"; shift 2
  local current="${!varname:-}"
  if [[ -n "$current" ]]; then
    log "$varname = $current (from env)"
    return
  fi
  local v; v="$(tf_out "$tfname")"
  if [[ -n "$v" && "$v" != *"No outputs found"* ]]; then
    printf -v "$varname" '%s' "$v" 2>/dev/null || eval "$varname=\$v"
    log "$varname = $v (from terraform output $tfname)"
    return
  fi
  if (( $# > 0 )); then
    v="$("$@" 2>/dev/null || true)"
    if [[ -n "$v" && "$v" != "None" ]]; then
      eval "$varname=\$v"
      log "$varname = $v (from AWS lookup)"
      return
    fi
  fi
  die "could not resolve $varname (tried env, 'terraform output $tfname', AWS lookup)"
}

command -v aws >/dev/null 2>&1 || die "aws CLI not on PATH"
aws sts get-caller-identity >/dev/null 2>&1 || die "AWS credentials not working"

# ---- Region -------------------------------------------------------
REGION="${REGION:-$(aws configure get region 2>/dev/null || echo us-east-1)}"
log "REGION = $REGION"

# ---- The identifiers we need --------------------------------------
# Names on the right are the terraform OUTPUT names. If yours differ,
# either rename the output or set the env var.
API_ID="${API_ID:-}"
resolve API_ID api_id

LAMBDA_NAME="${LAMBDA_NAME:-}"
resolve LAMBDA_NAME lambda_function_name \
  aws lambda get-function --function-name chewbacca-intake-lambda-11a \
    --region "$REGION" --query 'Configuration.FunctionName' --output text

DB_ID="${DB_ID:-chewbacca-mysql-11a}"

# RDS security group: prefer an output, else read it off the DB itself.
RDS_SG="${RDS_SG:-}"
resolve RDS_SG rds_security_group_id \
  aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
    --region "$REGION" \
    --query 'DBInstances[0].VpcSecurityGroups[0].VpcSecurityGroupId' --output text

# Lambda security group: prefer an output, else read it off the Lambda.
LAMBDA_SG="${LAMBDA_SG:-}"
resolve LAMBDA_SG lambda_security_group_id \
  aws lambda get-function-configuration --function-name "$LAMBDA_NAME" \
    --region "$REGION" \
    --query 'VpcConfig.SecurityGroupIds[0]' --output text

STAGE_NAME="${STAGE_NAME:-prod}"
ROUTE_PATH="${ROUTE_PATH:-/intake}"
URL="https://${API_ID}.execute-api.${REGION}.amazonaws.com/${STAGE_NAME}${ROUTE_PATH}"
PAYLOAD='{"actor":"doctor.ny","action":"VIEW_PATIENT","resource":"patient/12345","note":"11B"}'

# Feed Terraform its variables via TF_VAR_* rather than -var.
# WHY: -var on an undeclared variable is a hard error, but an unused
# TF_VAR_* is silently ignored. So this keeps working whether or not
# you later delete var.api_id in favour of a resource reference.
export TF_VAR_api_id="$API_ID"
export TF_VAR_alarm_email="${TF_VAR_alarm_email:-${ALARM_EMAIL:-}}"

# Per-phase security-group filename. The manifest asks for
# "before_revoke" and "after_restore" specifically, so the phase
# picks the name rather than you remembering it at 2am.
case "$PHASE" in
  baseline) SG_FILE="sg_before_revoke_3306.out" ;;
  failure)  SG_FILE="sg_after_revoke_3306.out"  ;;
  recovery) SG_FILE="sg_after_restore.out"      ;;
esac

mkdir -p "$EVIDENCE_DIR"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "$TS" > "${EVIDENCE_DIR}/t_${PHASE}.txt"
log "timestamp $TS"

# Record what we resolved, so the evidence explains its own inputs.
cat > "${EVIDENCE_DIR}/resolved_inputs_${PHASE}.json" <<EOF
{
  "phase": "$PHASE",
  "timestamp_utc": "$TS",
  "region": "$REGION",
  "api_id": "$API_ID",
  "invoke_url": "$URL",
  "lambda_name": "$LAMBDA_NAME",
  "db_id": "$DB_ID",
  "rds_sg_id": "$RDS_SG",
  "lambda_sg_id": "$LAMBDA_SG"
}
EOF

# ------------------------------------------------------------------
# 1. Invoke the API
# ------------------------------------------------------------------
# -w captures the HTTP code; -o captures the body. Both are evidence:
# the code proves the symptom, the body often names it.
log "POST $URL"
CODE="$(curl -sS -o "${EVIDENCE_DIR}/invoke_${PHASE}.json" -w "%{http_code}" \
  --max-time 40 \
  -X POST "$URL" -H "content-type: application/json" -d "$PAYLOAD" || echo "000")"
echo "$CODE" > "${EVIDENCE_DIR}/invoke_${PHASE}.http_code"
log "http_code=$CODE"

case "$PHASE" in
  baseline|recovery)
    [[ "$CODE" == "200" ]] && log "OK: healthy as expected." \
      || log "WARNING: expected 200 for phase '$PHASE' but got $CODE." ;;
  failure)
    [[ "$CODE" == "200" ]] && log "WARNING: expected a failure but got 200 — warm container still holding a connection? wait 60s and rerun." \
      || log "OK: failure proven ($CODE)." ;;
esac

# ------------------------------------------------------------------
# 2. Lambda logs
# ------------------------------------------------------------------
# Appended, not overwritten, so logs_tail.out is one continuous
# timeline across all three phases — what an auditor actually wants.
log "tailing /aws/lambda/${LAMBDA_NAME}"
{
  echo "==================== PHASE: $PHASE @ $TS ===================="
  MSYS_NO_PATHCONV=1 aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
    --region "$REGION" --since "${LOG_SINCE_MIN}m" --format short 2>&1
  echo
} >> "${EVIDENCE_DIR}/logs_tail.out"

# Pull out the Duration lines — the timing fingerprint. A rejected
# login fails in milliseconds; a blocked port burns seconds waiting.
grep -o "Duration: [0-9.]* ms" "${EVIDENCE_DIR}/logs_tail.out" \
  | tail -n 5 | sed 's/^/    /' || true

# ------------------------------------------------------------------
# 3. Security group state
# ------------------------------------------------------------------
log "snapshotting 3306 rules on $RDS_SG -> $SG_FILE"
aws ec2 describe-security-group-rules --region "$REGION" \
  --filters "Name=group-id,Values=${RDS_SG}" \
  --query "SecurityGroupRules[?FromPort==\`3306\` && IsEgress==\`false\`]" \
  --output json > "${EVIDENCE_DIR}/${SG_FILE}" 2>&1

# ------------------------------------------------------------------
# 4. Alarm state
# ------------------------------------------------------------------
log "capturing alarm states"
aws cloudwatch describe-alarms --region "$REGION" --alarm-name-prefix seir-11b \
  --query 'MetricAlarms[].{Name:AlarmName,State:StateValue,Reason:StateReason,Updated:StateUpdatedTimestamp}' \
  --output json > "${EVIDENCE_DIR}/alarms_${PHASE}.out" 2>&1

# ------------------------------------------------------------------
# 5. Terraform drift
# ------------------------------------------------------------------
# The star of the failure phase: Terraform comparing blueprint to
# reality. "will be created" on the SG rule IS the root cause,
# stated by the tool, in writing.
#
# -input=false is mandatory in automation. Without it, a missing
# variable makes Terraform print a prompt into the redirected file
# and wait on stdin forever — indistinguishable from a hang.
if [[ "$RUN_TF_PLAN" == "1" ]] && command -v terraform >/dev/null 2>&1; then
  log "running terraform plan (drift check)"
  terraform -chdir="$TF_DIR" plan -no-color -input=false -lock-timeout=60s \
    > "${EVIDENCE_DIR}/tf_plan_${PHASE}.out" 2>&1
  rc=$?
  if (( rc != 0 )); then
    log "terraform plan exited $rc — see tf_plan_${PHASE}.out"
    tail -n 15 "${EVIDENCE_DIR}/tf_plan_${PHASE}.out" | sed 's/^/    /'
  elif grep -q "No changes" "${EVIDENCE_DIR}/tf_plan_${PHASE}.out"; then
    log "terraform: no drift"
  else
    log "terraform: DRIFT DETECTED"
    grep -E "will be (created|destroyed|updated)|must be replaced" \
      "${EVIDENCE_DIR}/tf_plan_${PHASE}.out" | sed 's/^/    /' || true
  fi
else
  log "skipping terraform plan"
fi

log "done. files in ${EVIDENCE_DIR}/"