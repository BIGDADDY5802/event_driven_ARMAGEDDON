#!/usr/bin/env bash
# ============================================================
# run_all_gates.sh
#
# Runs every gate script in order, captures each one's pass/fail
# independently, and writes one aggregated summary — so "are we
# actually passing right now" is a single command instead of
# scrolling back through separate runs.
#
# DESIGN NOTES:
#   - Continues through ALL gates even if one fails, so you get
#     the full picture in one pass instead of stopping at the
#     first red light and re-running repeatedly.
#   - Each gate's full stdout/stderr is saved to its own log file
#     under gate_logs/ - nothing is lost even though the summary
#     table only shows pass/fail.
#   - MSYS_NO_PATHCONV is NOT set globally here on purpose - it's a
#     per-command workaround, scoped inside gate_11b_incident.sh
#     itself for its one `aws logs tail` call on a leading-slash
#     log group name. A blanket export here broke unrelated curl
#     calls in other gates; don't reintroduce it at this level.
#   - Exit code of THIS script is 0 only if every gate passed -
#     safe to chain after `terraform apply` in a larger pipeline.
#
# USAGE: run from the terraform directory, same as you'd run an
# individual gate script:
#   ../scripts/run_all_gates.sh
# ============================================================

set -uo pipefail   # NOTE: no -e - we want to keep going after a gate fails

# NOTE: deliberately NOT exporting MSYS_NO_PATHCONV=1 here. It needs to be
# scoped to the ONE command inside gate_11b_incident.sh that has the path-
# mangling issue (its `aws logs tail` call on a leading-slash log group
# name), not blanket-applied to every gate. A global export here previously
# broke gate_11a_cognito_auth.sh's curl calls by disabling MSYS's normal
# /dev/null -> NUL translation for its -o argument. Prefix the individual
# command inside gate_11b_incident.sh itself if it isn't already doing so.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="gate_logs"
SUMMARY_FILE="run_all_gates_summary.json"
mkdir -p "$LOG_DIR"

# Ordered list: (script_name)
#
# gate_11a_apigw_route_invoke.sh — RETIRED as of 2026-08-15. It tested
# the original standalone HTTP API front door from 11A, which no longer
# exists post-consolidation into this dev12b stack (confirmed empty via
# `terraform state list | grep apigatewayv2` and `aws apigatewayv2
# get-apis`). gate_11a_cognito_auth.sh covers the same /intake endpoint's
# auth behavior against the current REST+WAF+Cognito architecture and is
# the active replacement. Script left on disk for historical reference,
# not deleted, but intentionally excluded from this list.
# gate_11b_incident.sh — EXCLUDED from automated runs as of 2026-08-15.
# Instructor-authored deliverable; its recovery check expects an
# unauthenticated /intake to return 200, which is structurally
# impossible now that Cognito auth is live (correct behavior is 401
# with no token). This is a stale success criterion in the gate
# itself, not a real infrastructure failure - the underlying SG
# break/detect/restore mechanics were independently verified working
# (see evidence_11b/sg_before_revoke_3306.out vs sg_after_restore.out).
# See GAP-9 in the README for full writeup. Also modifies live
# infrastructure (breaks/restores a real SG rule) even in
# AUTO_RESTORE=true mode, unlike every other gate in this list, which
# is a second, independent reason it doesn't belong in an unattended
# automated loop. Run manually and standalone when needed:
#   source ../scripts/gate_env.sh && ../scripts/gate_11b_incident.sh
GATES=(
  "gate_11a_lambda_secret_vpc.sh"
  "gate_11a_cognito_auth.sh"
)

RESULTS=()   # each entry: name|status|exit_code|log_file

echo "============================================================"
echo " Running ${#GATES[@]} gates"
echo "============================================================"

for gate in "${GATES[@]}"; do
  GATE_PATH="${SCRIPT_DIR}/${gate}"
  LOG_FILE="${LOG_DIR}/${gate%.sh}.log"

  echo ""
  echo "---- ${gate} ----"

  if [[ ! -f "$GATE_PATH" ]]; then
    echo "  SKIPPED - script not found at $GATE_PATH"
    RESULTS+=("${gate}|SKIPPED|-|-")
    continue
  fi

  if [[ ! -x "$GATE_PATH" ]]; then
    chmod +x "$GATE_PATH"
  fi

  # Run it, tee output to both screen and its own log file, capture real exit code
  set +o pipefail
  "$GATE_PATH" 2>&1 | tee "$LOG_FILE"
  EXIT_CODE=${PIPESTATUS[0]}
  set -o pipefail

  if [[ "$EXIT_CODE" -eq 0 ]]; then
    STATUS="PASS"
  else
    STATUS="FAIL"
  fi

  echo "  -> ${STATUS} (exit ${EXIT_CODE})"
  RESULTS+=("${gate}|${STATUS}|${EXIT_CODE}|${LOG_FILE}")
done

echo ""
echo "============================================================"
echo " Summary"
echo "============================================================"

ALL_PASS=true
{
  echo "{"
  echo "  \"run_timestamp_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"gates\": ["
  for i in "${!RESULTS[@]}"; do
    IFS='|' read -r name status code log <<< "${RESULTS[$i]}"
    printf '    { "name": "%s", "status": "%s", "exit_code": "%s", "log_file": "%s" }' "$name" "$status" "$code" "$log"
    if [[ "$i" -lt $((${#RESULTS[@]} - 1)) ]]; then echo ","; else echo ""; fi
    [[ "$status" == "FAIL" ]] && ALL_PASS=false
  done
  echo "  ],"
  echo "  \"all_passed\": ${ALL_PASS}"
  echo "}"
} > "$SUMMARY_FILE"

# Human-readable table
printf "%-40s %-10s %s\n" "GATE" "STATUS" "EXIT CODE"
for r in "${RESULTS[@]}"; do
  IFS='|' read -r name status code log <<< "$r"
  printf "%-40s %-10s %s\n" "$name" "$status" "$code"
done

echo ""
echo "Full summary written to: $SUMMARY_FILE"
echo "Per-gate logs in: $LOG_DIR/"

if [[ "$ALL_PASS" == "true" ]]; then
  echo ""
  echo "ALL GATES PASSED"
  exit 0
else
  echo ""
  echo "ONE OR MORE GATES FAILED - see table above and per-gate logs"
  exit 1
fi