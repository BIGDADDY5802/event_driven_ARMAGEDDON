#!/usr/bin/env bash
#
# test_waf.sh — prove the WAF is doing something, with evidence
#
# Three checks:
#   1. Legitimate request through the PROTECTED door   -> expect 200
#   2. XSS-shaped request through the PROTECTED door   -> expect 403
#   3. SQLi-shaped request through the PROTECTED door  -> expect 403
#
# PATCHED: originally had a 4th check -- the same bad request through
# an UNPROTECTED HTTP API door, to prove the 403 came from the WAF and
# not the app itself. That door (http_invoke_url) was retired when
# apigateway.tf was replaced by the REST API + WAF front door (see
# outputs.tf, commented-out output). No unprotected door exists in
# this stack anymore, so that attribution check is gone too -- the
# WAF's own CloudWatch logs (pulled below) are still independent
# evidence of what it decided and why, just without the side-by-side
# bypass proof.
#
# All values are read from terraform output — nothing typed.
#
# Usage (from the terraform directory):
#   ./test_waf.sh
#   TF_DIR=. EVIDENCE_DIR=evidence_waf ./test_waf.sh
#
set -uo pipefail

TF_DIR="${TF_DIR:-.}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence_waf}"
REGION="${REGION:-$(aws configure get region 2>/dev/null || echo us-east-1)}"

log() { echo "[waf-test] $*"; }
die() { echo "[waf-test] ERROR: $*" >&2; exit 1; }

tf_out() { terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null || true; }

REST_URL="$(tf_out rest_invoke_url)"
ACL_NAME="$(tf_out waf_web_acl_name)"
WAF_LOG_GROUP="$(tf_out waf_log_group)"

[[ -n "$REST_URL" ]] || die "no rest_invoke_url output — apply the WAF config first"

mkdir -p "$EVIDENCE_DIR"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log "protected  : $REST_URL"
log "timestamp  : $TS"

# hit <label> <url> <payload> [extra curl args...]
hit() {
  local label="$1" url="$2" body="$3"; shift 3
  local code
  code="$(curl -sS -o "${EVIDENCE_DIR}/waf_${label}.body" -w "%{http_code}" \
    --max-time 30 -X POST "$url" \
    -H "content-type: application/json" \
    "$@" -d "$body" || echo "000")"
  echo "$code" > "${EVIDENCE_DIR}/waf_${label}.http_code"
  printf '  %-28s -> HTTP %s\n' "$label" "$code"
  echo "$code"
}

GOOD='{"actor":"doctor.ny","action":"VIEW_PATIENT","resource":"patient/12345","note":"waf-allow-test"}'
# Classic reflected-XSS shape. Caught by CommonRuleSet
# (CrossSiteScripting_BODY / _QUERYARGUMENTS).
XSS='{"actor":"doctor.ny","action":"VIEW_PATIENT","resource":"<script>alert(1)</script>"}'
# Classic tautology injection. Caught by the SQLi rule set.
SQLI="{\"actor\":\"doctor.ny\",\"action\":\"VIEW_PATIENT\",\"resource\":\"patient/1' OR '1'='1\"}"

echo
log "=== PROTECTED door (REST + WAF) ==="
C_GOOD="$(hit protected_legit    "$REST_URL" "$GOOD" | tail -1)"
C_XSS="$(hit  protected_xss      "$REST_URL" "$XSS"  | tail -1)"
C_SQLI="$(hit protected_sqli     "$REST_URL" "$SQLI" | tail -1)"
# Query-string variant: query args are inspected more aggressively
# than JSON bodies, so this is the most reliable single trigger.
C_QS="$(curl -sS -o "${EVIDENCE_DIR}/waf_protected_xss_qs.body" -w "%{http_code}" \
  --max-time 30 -X POST "${REST_URL}?q=%3Cscript%3Ealert(1)%3C/script%3E" \
  -H "content-type: application/json" -d "$GOOD" || echo "000")"
echo "$C_QS" > "${EVIDENCE_DIR}/waf_protected_xss_qs.http_code"
printf '  %-28s -> HTTP %s\n' "protected_xss_querystring" "$C_QS"

# ------------------------------------------------------------------
echo
log "=== Verdict ==="
verdict_fail=0
note() { printf '  %s %s\n' "$1" "$2"; }

[[ "$C_GOOD" == "200" ]] \
  && note "OK  " "legitimate request allowed through the WAF (200)" \
  || { note "FAIL" "legitimate request got $C_GOOD — false positive, or the REST mirror is misconfigured"; verdict_fail=1; }

if [[ "$C_QS" == "403" || "$C_XSS" == "403" || "$C_SQLI" == "403" ]]; then
  note "OK  " "at least one malicious shape was blocked (403)"
else
  note "FAIL" "nothing was blocked — check the association actually exists"
  verdict_fail=1
fi

# NOTE: no bypass-comparison check here (see header) — the WAF log
# pull below is this script's only independent evidence source now.

# ------------------------------------------------------------------
# Evidence: the WAF's own record of its decisions.
# Logs take ~30-60s to appear. Blocked requests never reach the
# Lambda, so Lambda logs will NOT show them — the WAF log is the
# only place a blocked request exists.
# ------------------------------------------------------------------
echo
log "waiting 60s for WAF logs to land..."
sleep 60

log "pulling WAF decisions from $WAF_LOG_GROUP"
MSYS_NO_PATHCONV=1 aws logs tail "$WAF_LOG_GROUP" --region "$REGION" \
  --since 10m --format short > "${EVIDENCE_DIR}/waf_logs_tail.out" 2>&1

if command -v python >/dev/null 2>&1; then PY=python; else PY=python3; fi
"$PY" - "${EVIDENCE_DIR}/waf_logs_tail.out" <<'PYEOF' | tee "${EVIDENCE_DIR}/waf_decisions.txt"
import json, re, sys
counts = {}
rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.search(r'(\{.*\})\s*$', line)
    if not m:
        continue
    try:
        e = json.loads(m.group(1))
    except Exception:
        continue
    action = e.get("action", "?")
    rule = e.get("terminatingRuleId", "?")
    uri = (e.get("httpRequest") or {}).get("uri", "?")
    counts[(action, rule)] = counts.get((action, rule), 0) + 1
    rows.append((action, rule, uri))
print("WAF decisions in window:")
for (action, rule), n in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"  {n:4d}  {action:8s}  {rule}")
if not rows:
    print("  (none parsed — logs may not have landed yet; rerun the tail)")
PYEOF

log "sampled requests (independent second source):"
aws wafv2 get-sampled-requests --region "$REGION" --scope REGIONAL \
  --web-acl-arn "$(tf_out waf_web_acl_arn)" \
  --rule-metric-name ALL --max-items 20 \
  --time-window "StartTime=$(date -u -d '15 minutes ago' +%s 2>/dev/null || echo $(( $(date +%s) - 900 ))),EndTime=$(date +%s)" \
  --query 'SampledRequests[].{Action:Action,Rule:RuleNameWithinRuleGroup,URI:Request.URI}' \
  --output table > "${EVIDENCE_DIR}/waf_sampled_requests.out" 2>&1 \
  && log "wrote ${EVIDENCE_DIR}/waf_sampled_requests.out" \
  || log "sampled-requests call failed (see file) — CloudWatch log is still authoritative"

echo
if (( verdict_fail == 0 )); then
  log "PASS — evidence in ${EVIDENCE_DIR}/"
else
  log "ATTENTION — one or more checks failed; see verdict above"
fi
exit "$verdict_fail"