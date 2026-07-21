#!/usr/bin/env bash
set -euo pipefail

REGION="${REGION:-us-east-1}"
LAMBDA_NAME="${LAMBDA_NAME:-}"
SECRET_ARN="${SECRET_ARN:-}"
DB_NAME="${DB_NAME:-}"

OUT_JSON="${OUT_JSON:-gate_11a_lambda_secret_vpc.json}"

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
  LAMBDA_NAME
  SECRET_ARN
  DB_NAME

Example:
  REGION=us-east-1 LAMBDA_NAME=chewbacca-intake-lambda-11a SECRET_ARN=arn:aws:secretsmanager:... DB_NAME=lab11 ./gate_11a_lambda_secret_vpc.sh
EOF
}

if [[ -z "$LAMBDA_NAME" || -z "$SECRET_ARN" || -z "$DB_NAME" ]]; then
  echo "ERROR: missing required env vars." >&2
  usage >&2
  exit 1
fi

cfg="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" 2>/dev/null || true)"
if [[ -z "$cfg" ]]; then
  add_failure "FAIL: Lambda not found or not accessible ($LAMBDA_NAME)."
else
  add_detail "PASS: Lambda exists ($LAMBDA_NAME)."
fi

runtime="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --query Runtime --output text 2>/dev/null || echo "")"
handler="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --query Handler --output text 2>/dev/null || echo "")"
[[ "$runtime" == python* ]] && add_detail "PASS: Lambda runtime is Python ($runtime)." || add_warning "WARN: Lambda runtime is not Python ($runtime)."
[[ -n "$handler" ]] && add_detail "PASS: Lambda handler set ($handler)." || add_failure "FAIL: Lambda handler missing."

subnets="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --query "VpcConfig.SubnetIds" --output text 2>/dev/null || echo "")"
sgs="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --query "VpcConfig.SecurityGroupIds" --output text 2>/dev/null || echo "")"

if [[ -n "$subnets" && "$subnets" != "None" && -n "$sgs" && "$sgs" != "None" ]]; then
  add_detail "PASS: Lambda is VPC-attached (subnets + SG present)."
else
  add_failure "FAIL: Lambda is not VPC-attached (VpcConfig missing subnets/SG)."
fi

env_secret="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --query "Environment.Variables.DB_SECRET_ARN" --output text 2>/dev/null || echo "")"
env_dbname="$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --region "$REGION" --query "Environment.Variables.DB_NAME" --output text 2>/dev/null || echo "")"

[[ "$env_secret" == "$SECRET_ARN" ]] && add_detail "PASS: Lambda env DB_SECRET_ARN matches expected." || add_failure "FAIL: Lambda env DB_SECRET_ARN mismatch (expected=$SECRET_ARN actual=$env_secret)."
[[ "$env_dbname" == "$DB_NAME" ]] && add_detail "PASS: Lambda env DB_NAME matches expected." || add_failure "FAIL: Lambda env DB_NAME mismatch (expected=$DB_NAME actual=$env_dbname)."

if aws secretsmanager describe-secret --secret-id "$SECRET_ARN" --region "$REGION" >/dev/null 2>&1; then
  add_detail "PASS: Secret exists ($SECRET_ARN)."
else
  add_failure "FAIL: Secret not found or not accessible ($SECRET_ARN)."
fi

status="PASS"; exit_code=0
(( ${#failures[@]} > 0 )) && status="FAIL" && exit_code=2

details_json="$(make_json_array "${details[@]}")"
warnings_json="$(make_json_array "${warnings[@]}")"
failures_json="$(make_json_array "${failures[@]}")"

cat > "$OUT_JSON" <<EOF
{
  "schema_version": "1.0",
  "gate": "11a_lambda_secret_vpc",
  "timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "region": "$(echo "$REGION" | json_escape)",
  "inputs": {
    "lambda_name": "$(echo "$LAMBDA_NAME" | json_escape)",
    "secret_arn": "$(echo "$SECRET_ARN" | json_escape)",
    "db_name": "$(echo "$DB_NAME" | json_escape)"
  },
  "status": "$status",
  "exit_code": $exit_code,
  "details": $details_json,
  "warnings": $warnings_json,
  "failures": $failures_json
}
EOF

echo "Gate 11A Lambda/Secret/VPC: $status"
exit "$exit_code"
