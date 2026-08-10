#!/usr/bin/env bash
#
# teardown_bastion_role.sh — removes the SSM-only IAM role + instance
# profile that bootstrap_schema.sh creates on first run.
#
# Safe to run any time after bootstrap_schema.sh has finished (the EC2
# instance itself is already gone by then — this only cleans up the
# reusable IAM objects). Each step checks whether the resource exists
# before touching it, so it's safe to re-run if something only partially
# deleted last time.
#
set -euo pipefail

ROLE_NAME="${ROLE_NAME:-chewbacca-11a-bastion-role}"
PROFILE_NAME="${PROFILE_NAME:-chewbacca-11a-bastion-profile}"
POLICY_ARN="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

log() { echo "[teardown_bastion_role] $*"; }

if [[ "${1:-}" != "--yes" ]]; then
  echo "This will delete:"
  echo "  - IAM instance profile: $PROFILE_NAME"
  echo "  - IAM role:             $ROLE_NAME"
  echo "  - Detach policy:        $POLICY_ARN"
  echo
  read -r -p "Proceed? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
fi

# 1. Detach the role from the instance profile, then delete the profile
if aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  log "Removing role from instance profile $PROFILE_NAME..."
  aws iam remove-role-from-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    --role-name "$ROLE_NAME" 2>/dev/null || true

  log "Deleting instance profile $PROFILE_NAME..."
  aws iam delete-instance-profile --instance-profile-name "$PROFILE_NAME"
else
  log "Instance profile $PROFILE_NAME not found, skipping."
fi

# 2. Detach the managed policy, then delete the role
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  log "Detaching $POLICY_ARN from $ROLE_NAME..."
  aws iam detach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN" 2>/dev/null || true

  log "Deleting role $ROLE_NAME..."
  aws iam delete-role --role-name "$ROLE_NAME"
else
  log "Role $ROLE_NAME not found, skipping."
fi

log "Done."
