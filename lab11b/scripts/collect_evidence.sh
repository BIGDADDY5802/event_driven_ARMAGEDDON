#!/usr/bin/env bash
#
# collect_evidence.sh — capture one PHASE of the Lab 11B incident
#
# It does NOT break anything and does NOT fix anything. It only
# observes and records. You decide when to break and when to heal;
# this just makes sure every observation lands in a file with the
# exact name the manifest expects.
#
# Usage (run from your terraform/ directory):
#   ./collect_evidence.sh baseline    # BEFORE you break it
#   ./collect_evidence.sh failure     # AFTER you break it
#   ./collect_evidence.sh recovery    # AFTER you terraform apply
#
# Filenames produced per phase (these map to the manifest):
#   baseline -> invoke_baseline.json  + sg_before_revoke_3306.out
#   failure  -> invoke_failure.json   + sg_after_revoke_3306.out
#   recovery -> invoke_recovery.json  + sg_after_restore.out
#
set -uo pipefail   # NOTE: no -e on purpose. A failing curl during the
                   # incident is EXPECTED evidence, not a script error.

PHASE="${1:-}"
case "$PHASE" in
  baseline|failure|recovery) ;;
  *) echo "usage: $0 {baseline|failure|recovery}" >&2; exit 64 ;;
esac

# ---- config (override via env if your names differ) ----------
REGION="${REGION:-us-east-1}"
LAMBDA_NAME="${LAMBDA_NAME:-chewbacca-intake-lambda-11a}"
API_ID="${API_ID:-53urjf9cxb}"
STAGE_NAME="${STAGE_NAME:-prod}"
ROUTE_PATH="${ROUTE_PATH:-/intake}"
RDS_SG="${RDS_SG:-sg-0a26f4b37042b06de}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence_11b}"
LOG_SINCE_MIN="${LOG_SINCE_MIN:-15}"
RUN_TF_PLAN="${RUN_TF_PLAN:-1}"   # set 0 to skip terraform plan

URL="https://${API_ID}.execute-api.${REGION}.amazonaws.com/${STAGE_NAME}${ROUTE_PATH}"
PAYLOAD='{"actor":"doctor.ny","action":"VIEW_PATIENT","resource":"patient/12345","note":"11B"}'

# Per-phase security-group filename. The manifest asks for
# "before_revoke" and "after_restore" specifically, so the phase
# picks the name rather than you remembering it at 2am.
case "$PHASE" in
  baseline) SG_FILE="sg_before_revoke_3306.out" ;;
  failure)  SG_FILE="sg_after_revoke_3306.out"  ;;
  recovery) SG_FILE="sg_after_restore.out"      ;;
esac

mkdir -p "$EVIDENCE_DIR"
log() { echo "[evidence:$PHASE] $*"; }

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "$TS" > "${EVIDENCE_DIR}/t_${PHASE}.txt"
log "timestamp $TS"

# ---- 1. Invoke the API ---------------------------------------
# -w captures the HTTP code; -o captures the body. Both are
# evidence: the code proves the symptom, the body often names it.
log "POST $URL"
CODE="$(curl -sS -o "${EVIDENCE_DIR}/invoke_${PHASE}.json" -w "%{http_code}" \
  --max-time 40 \
  -X POST "$URL" -H "content-type: application/json" -d "$PAYLOAD" || echo "000")"
echo "$CODE" > "${EVIDENCE_DIR}/invoke_${PHASE}.http_code"
log "http_code=$CODE"

# Sanity commentary so you notice a surprise immediately.
case "$PHASE" in
  baseline|recovery)
    [[ "$CODE" == "200" ]] && log "OK: healthy as expected." \
      || log "WARNING: expected 200 for phase '$PHASE' but got $CODE." ;;
  failure)
    [[ "$CODE" == "200" ]] && log "WARNING: expected a failure but got 200 — is it actually broken?" \
      || log "OK: failure proven ($CODE)." ;;
esac

# ---- 2. Lambda logs -----------------------------------------
# Appended, not overwritten, so logs_tail.out is one continuous
# timeline across all three phases — that is what an auditor wants.
log "tailing /aws/lambda/${LAMBDA_NAME}"
{
  echo "==================== PHASE: $PHASE @ $TS ===================="
  MSYS_NO_PATHCONV=1 aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
    --region "$REGION" --since "${LOG_SINCE_MIN}m" --format short 2>&1
  echo
} >> "${EVIDENCE_DIR}/logs_tail.out"

# ---- 3. Security group state --------------------------------
log "snapshotting 3306 rules on $RDS_SG -> $SG_FILE"
aws ec2 describe-security-group-rules --region "$REGION" \
  --filters "Name=group-id,Values=${RDS_SG}" \
  --query "SecurityGroupRules[?FromPort==\`3306\` && IsEgress==\`false\`]" \
  --output json > "${EVIDENCE_DIR}/${SG_FILE}" 2>&1

# ---- 4. Alarm state -----------------------------------------
log "capturing alarm states"
aws cloudwatch describe-alarms --region "$REGION" --alarm-name-prefix seir-11b \
  --query 'MetricAlarms[].{Name:AlarmName,State:StateValue,Reason:StateReason,Updated:StateUpdatedTimestamp}' \
  --output json > "${EVIDENCE_DIR}/alarms_${PHASE}.out" 2>&1

# ---- 5. Terraform drift -------------------------------------
# This is the star of the failure phase: Terraform comparing the
# blueprint to reality. "will be created" on the SG rule IS the
# root cause, stated by the tool, in writing.
if [[ "$RUN_TF_PLAN" == "1" ]] && command -v terraform >/dev/null 2>&1; then
  log "running terraform plan (drift check)"
  terraform plan -no-color -refresh=true \
    > "${EVIDENCE_DIR}/tf_plan_${PHASE}.out" 2>&1
  if grep -q "No changes" "${EVIDENCE_DIR}/tf_plan_${PHASE}.out"; then
    log "terraform: no drift"
  else
    log "terraform: DRIFT DETECTED (see tf_plan_${PHASE}.out)"
    grep -E "will be (created|destroyed|updated)|must be replaced" \
      "${EVIDENCE_DIR}/tf_plan_${PHASE}.out" | sed 's/^/    /' || true
  fi
else
  log "skipping terraform plan"
fi

log "done. files in ${EVIDENCE_DIR}/"
