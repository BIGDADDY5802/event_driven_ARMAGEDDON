#!/usr/bin/env bash
set -euo pipefail

REGION="${REGION:-us-east-1}"
API_ID="${API_ID:-}"
STAGE_NAME="${STAGE_NAME:-prod}"
ROUTE_PATH="${ROUTE_PATH:-/intake}"
METHOD="${METHOD:-POST}"

OUT_JSON="${OUT_JSON:-gate_11a_apigw_route_invoke.json}"

failures=(); warnings=(); details=()
add_failure(){ failures+=("$1"); }
add_warning(){ warnings+=("$1"); }
add_detail(){ details+=("$1"); }

json_escape(){ sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'; }
make_json_array() {
  if (( $# == 0 )); then echo "[]"; return; fi
  printf '%s\n' "$@" | json_escape | awk 'BEGIN{print "["} {printf "%s\"%s\"", (NR>1?",":""), $0} END{print "]"}'
}

usage(){
  cat <<EOF
Required:
  REGION
  API_ID
Optional:
  STAGE_NAME (default: prod)

Example:
  REGION=us-east-1 API_ID=abc123 STAGE_NAME=prod ./gate_11a_apigw_route_invoke.sh
EOF
}

if [[ -z "$API_ID" ]]; then
  echo "ERROR: API_ID required." >&2
  usage >&2
  exit 1
fi

if aws apigatewayv2 get-api --api-id "$API_ID" --region "$REGION" >/dev/null 2>&1; then
  add_detail "PASS: API exists (API_ID=$API_ID)."
else
  add_failure "FAIL: API not found or not accessible (API_ID=$API_ID)."
fi

route_key="${METHOD} ${ROUTE_PATH}"
found="$(aws apigatewayv2 get-routes --api-id "$API_ID" --region "$REGION" \
  --query "Items[?RouteKey=='$route_key'].RouteId" --output text 2>/dev/null || echo "")"

[[ -n "$found" && "$found" != "None" ]] \
  && add_detail "PASS: Route exists ($route_key)." \
  || add_failure "FAIL: Route missing ($route_key)."

stage_found="$(aws apigatewayv2 get-stages --api-id "$API_ID" --region "$REGION" \
  --query "Items[?StageName=='$STAGE_NAME'].StageName" --output text 2>/dev/null || echo "")"
[[ "$stage_found" == "$STAGE_NAME" ]] && add_detail "PASS: Stage exists ($STAGE_NAME)." || add_failure "FAIL: Stage missing ($STAGE_NAME)."

url="https://${API_ID}.execute-api.${REGION}.amazonaws.com/${STAGE_NAME}${ROUTE_PATH}"

payload='{"actor":"doctor.ny","action":"VIEW_PATIENT","resource":"patient/12345","note":"gate-test"}'
http_code="$(curl -sS -o /tmp/chewbacca_gate_11a_resp.json -w "%{http_code}" \
  -X "$METHOD" "$url" -H "content-type: application/json" -d "$payload" || echo "000")"

if [[ "$http_code" == "200" ]]; then
  add_detail "PASS: API invoke returned HTTP 200."
  if grep -q '"ok": *true' /tmp/chewbacca_gate_11a_resp.json; then
    add_detail "PASS: Response body contains ok=true."
  else
    add_warning "WARN: Response missing ok=true (check response schema)."
  fi
else
  add_failure "FAIL: API invoke did not return 200 (http_code=$http_code)."
  add_detail "INFO: Response body saved at /tmp/chewbacca_gate_11a_resp.json"
fi

status="PASS"; exit_code=0
(( ${#failures[@]} > 0 )) && status="FAIL" && exit_code=2

details_json="$(make_json_array "${details[@]}")"
warnings_json="$(make_json_array "${warnings[@]}")"
failures_json="$(make_json_array "${failures[@]}")"

cat > "$OUT_JSON" <<EOF
{
  "schema_version": "1.0",
  "gate": "11a_apigw_route_invoke",
  "timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "region": "$(echo "$REGION" | json_escape)",
  "inputs": {
    "api_id": "$(echo "$API_ID" | json_escape)",
    "stage": "$(echo "$STAGE_NAME" | json_escape)",
    "route_key": "$(echo "$route_key" | json_escape)"
  },
  "observed": { "url": "$(echo "$url" | json_escape)", "http_code": "$(echo "$http_code" | json_escape)" },
  "status": "$status",
  "exit_code": $exit_code,
  "details": $details_json,
  "warnings": $warnings_json,
  "failures": $failures_json
}
EOF

echo "Gate 11A API route/invoke: $status"
exit "$exit_code"
