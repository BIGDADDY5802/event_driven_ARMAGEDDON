#!/usr/bin/env bash
set -euo pipefail

REGION="${REGION:-us-east-1}"
DB_ID="${DB_ID:-}"
RDS_SG_ID="${RDS_SG_ID:-}"
LAMBDA_SG_ID="${LAMBDA_SG_ID:-}"

OUT_JSON="${OUT_JSON:-gate_11a_rds_sg_private.json}"

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
  DB_ID
  RDS_SG_ID
  LAMBDA_SG_ID

Example:
  REGION=us-east-1 DB_ID=chewbacca-mysql-11a RDS_SG_ID=sg-... LAMBDA_SG_ID=sg-... ./gate_11a_rds_sg_private.sh
EOF
}

if [[ -z "$DB_ID" || -z "$RDS_SG_ID" || -z "$LAMBDA_SG_ID" ]]; then
  echo "ERROR: missing required env vars." >&2
  usage >&2
  exit 1
fi

pub="$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" \
  --query "DBInstances[0].PubliclyAccessible" --output text 2>/dev/null || echo "Unknown")"

if [[ "$pub" == "False" ]]; then
  add_detail "PASS: RDS PubliclyAccessible=False."
else
  add_failure "FAIL: RDS is public or unknown (PubliclyAccessible=$pub)."
fi

endpoint="$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" \
  --query "DBInstances[0].Endpoint.Address" --output text 2>/dev/null || echo "")"
[[ -n "$endpoint" && "$endpoint" != "None" ]] && add_detail "PASS: RDS endpoint present." || add_failure "FAIL: RDS endpoint missing."

pairs="$(aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`3306\` && ToPort==\`3306\`].UserIdGroupPairs[].GroupId" \
  --output text 2>/dev/null || echo "")"

echo "$pairs" | tr '\t' '\n' | grep -q "^${LAMBDA_SG_ID}$" \
  && add_detail "PASS: RDS SG allows 3306 from Lambda SG." \
  || add_failure "FAIL: RDS SG does not allow 3306 from Lambda SG (expected=$LAMBDA_SG_ID actual=$pairs)."

world="$(aws ec2 describe-security-groups --group-ids "$RDS_SG_ID" --region "$REGION" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`3306\` && ToPort==\`3306\`].IpRanges[].CidrIp" \
  --output text 2>/dev/null || echo "")"

echo "$world" | grep -Eq '0\.0\.0\.0/0' \
  && add_failure "FAIL: RDS SG allows 0.0.0.0/0 on 3306." \
  || add_detail "PASS: RDS SG not world-open on 3306."

status="PASS"; exit_code=0
(( ${#failures[@]} > 0 )) && status="FAIL" && exit_code=2

details_json="$(make_json_array "${details[@]}")"
warnings_json="$(make_json_array "${warnings[@]}")"
failures_json="$(make_json_array "${failures[@]}")"

cat > "$OUT_JSON" <<EOF
{
  "schema_version": "1.0",
  "gate": "11a_rds_sg_private",
  "timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "region": "$(echo "$REGION" | json_escape)",
  "inputs": {
    "db_id": "$(echo "$DB_ID" | json_escape)",
    "rds_sg_id": "$(echo "$RDS_SG_ID" | json_escape)",
    "lambda_sg_id": "$(echo "$LAMBDA_SG_ID" | json_escape)"
  },
  "observed": { "endpoint": "$(echo "$endpoint" | json_escape)", "public": "$(echo "$pub" | json_escape)" },
  "status": "$status",
  "exit_code": $exit_code,
  "details": $details_json,
  "warnings": $warnings_json,
  "failures": $failures_json
}
EOF

echo "Gate 11A RDS/SG/Private: $status"
exit "$exit_code"
