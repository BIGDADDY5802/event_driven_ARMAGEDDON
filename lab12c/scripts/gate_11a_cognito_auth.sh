#!/usr/bin/env bash
# ============================================================
# gate_11a_cognito_auth.sh
#
# Evidence gate: proves the /intake REST endpoint actually
# enforces the Cognito authorizer, not just that it deployed.
#
# SECURITY DESIGN (why it's built this way, not simpler):
#   - Test user is UNIQUE per run (timestamp in username) so
#     repeated runs never collide with a leftover identity.
#   - Password is RANDOM per run, generated locally, never
#     hardcoded, never echoed to stdout or written to the
#     evidence file.
#   - `trap cleanup EXIT` guarantees the test user is deleted
#     from the pool even if the script fails partway through
#     (bad token, network blip, curl failure, etc.) - no manual
#     "did I remember to delete that" step.
#   - Pool ID / client ID / invoke URL are read live from
#     `terraform output`, never hardcoded, so the script stays
#     correct across future applies without editing.
#   - Sensitive shell vars are unset as soon as they're no
#     longer needed, shrinking the window they exist in memory.
#
# USAGE:
#   ./gate_11a_cognito_auth.sh [path-to-terraform-dir]
#   Defaults to the current directory if no path given.
#
# EXIT CODE: 0 = pass, 1 = fail (for CI / pre-flight chaining)
# ============================================================

set -euo pipefail

TF_DIR="${1:-.}"
EVIDENCE_FILE="gate_11a_cognito_auth_evidence.json"
TIMESTAMP_TAG="$(date +%s)"
TEST_USERNAME="gate-test-${TIMESTAMP_TAG}@example.com"
TEST_PASSWORD="$(openssl rand -base64 18)Aa1!"   # meets Cognito's 12+/upper/lower/num/symbol policy

USER_CREATED=""
ID_TOKEN=""

cleanup() {
  if [[ -n "$USER_CREATED" ]]; then
    echo "== Cleanup: deleting ephemeral test user =="
    aws cognito-idp admin-delete-user \
      --user-pool-id "$POOL_ID" \
      --username "$TEST_USERNAME" >/dev/null 2>&1 || \
      echo "WARNING: cleanup failed - manually delete '$TEST_USERNAME' from pool $POOL_ID" >&2
  fi
  unset TEST_PASSWORD ID_TOKEN
}
trap cleanup EXIT

echo "== Reading Terraform outputs from $TF_DIR =="
POOL_ID=$(terraform -chdir="$TF_DIR" output -raw cognito_user_pool_id)
CLIENT_ID=$(terraform -chdir="$TF_DIR" output -raw cognito_app_client_id)
INVOKE_URL=$(terraform -chdir="$TF_DIR" output -raw rest_invoke_url)

echo "== Step 1: unauthenticated request should be rejected (expect 401) =="
UNAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$INVOKE_URL" \
  -H "Content-Type: application/json" \
  -d '{"test":"unauthenticated"}')
echo "  -> got HTTP $UNAUTH_STATUS"

echo "== Step 2: create ephemeral test user =="
aws cognito-idp admin-create-user \
  --user-pool-id "$POOL_ID" \
  --username "$TEST_USERNAME" \
  --temporary-password "$TEST_PASSWORD" \
  --message-action SUPPRESS >/dev/null
USER_CREATED=1

aws cognito-idp admin-set-user-password \
  --user-pool-id "$POOL_ID" \
  --username "$TEST_USERNAME" \
  --password "$TEST_PASSWORD" \
  --permanent >/dev/null

echo "== Step 3: authenticate and retrieve a real JWT =="
ID_TOKEN=$(aws cognito-idp initiate-auth \
  --client-id "$CLIENT_ID" \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="$TEST_USERNAME",PASSWORD="$TEST_PASSWORD" \
  --query 'AuthenticationResult.IdToken' --output text)

if [[ -z "$ID_TOKEN" || "$ID_TOKEN" == "None" ]]; then
  echo "ERROR: failed to retrieve IdToken from initiate-auth" >&2
  exit 1
fi

echo "== Step 4: authenticated request should succeed (expect 200) =="
# NOTE: no "Bearer " prefix - Cognito's COGNITO_USER_POOLS authorizer
# reads the Authorization header raw.
AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$INVOKE_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: $ID_TOKEN" \
  -d '{"test":"authenticated"}')
echo "  -> got HTTP $AUTH_STATUS"

unset ID_TOKEN TEST_PASSWORD

echo "== Step 5: write evidence =="
PASS=false
if [[ "$UNAUTH_STATUS" == "401" && "$AUTH_STATUS" == "200" ]]; then
  PASS=true
fi

cat > "$EVIDENCE_FILE" <<EOF
{
  "gate": "11a_cognito_auth",
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "unauthenticated_status": "$UNAUTH_STATUS",
  "authenticated_status": "$AUTH_STATUS",
  "expected": { "unauthenticated_status": "401", "authenticated_status": "200" },
  "pass": $PASS
}
EOF

echo "Evidence written to $EVIDENCE_FILE:"
cat "$EVIDENCE_FILE"

if [[ "$PASS" != "true" ]]; then
  echo "GATE FAILED" >&2
  exit 1
fi

echo "GATE PASSED"