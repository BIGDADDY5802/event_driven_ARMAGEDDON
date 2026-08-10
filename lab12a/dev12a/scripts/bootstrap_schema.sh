#!/usr/bin/env bash
#
# bootstrap_schema.sh — one-shot schema creation for Lab 11A
#
# Fetches the generated DB password from Secrets Manager, launches a
# temporary EC2 "bastion" (reusing the Lambda security group so it's
# already trusted by the RDS SG — no new SG rules needed), runs
# sql/schema.sql against RDS over SSM Run Command (no SSH keys, no
# public exposure beyond what already exists), then terminates the
# bastion.
#
# Run this from the terraform/ directory (it reads `terraform output`).
#
# Usage:
#   ./bootstrap_schema.sh              # normal run, terminates bastion when done
#   KEEP_BASTION=1 ./bootstrap_schema.sh   # leave the instance running for debugging
#
set -euo pipefail

REGION="${REGION:-us-east-1}"
ROLE_NAME="${ROLE_NAME:-chewbacca-11a-bastion-role}"
PROFILE_NAME="${PROFILE_NAME:-chewbacca-11a-bastion-profile}"
SCHEMA_FILE="${SCHEMA_FILE:-../sql/schema.sql}"
KEEP_BASTION="${KEEP_BASTION:-0}"

log() { echo "[bootstrap_schema] $*"; }
die() { echo "[bootstrap_schema] ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------
# 0. Preconditions
# ---------------------------------------------------------------------
command -v aws >/dev/null 2>&1 || die "aws CLI not found on PATH."
command -v python >/dev/null 2>&1 || die "python not found on PATH."
[[ -f "$SCHEMA_FILE" ]] || die "Schema file not found at $SCHEMA_FILE (run from terraform/ or set SCHEMA_FILE)."

aws sts get-caller-identity >/dev/null 2>&1 || die "AWS CLI is not authenticated. Run 'aws configure' or check credentials."

terraform output -raw db_secret_arn >/dev/null 2>&1 \
  || die "terraform output failed. Run this from the terraform/ directory with state present."

DB_SECRET_ARN="$(terraform output -raw db_secret_arn)"
DB_ENDPOINT="$(terraform output -raw db_endpoint)"
DB_NAME_OUT="$(terraform output -raw db_instance_id 2>/dev/null || echo "")"
LAMBDA_SG_ID="$(terraform output -raw lambda_security_group_id)"
TF_SUBNET_ID="$(terraform output -json subnet_ids | python -c "import sys,json; print(json.load(sys.stdin)[0])")"

# The bastion doesn't need to be in the same subnet as RDS/Lambda — SG
# references work at the VPC level, not the subnet level. Pick a subnet
# that's actually public (MapPublicIpOnLaunch=true) so the SSM agent has
# a route out, rather than blindly reusing Terraform's RDS-oriented pick,
# which may sit in a private/no-egress subnet.
VPC_ID="$(aws ec2 describe-subnets --subnet-ids "$TF_SUBNET_ID" --region "$REGION" \
  --query "Subnets[0].VpcId" --output text)"

SUBNET_ID="$(aws ec2 describe-subnets --region "$REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=map-public-ip-on-launch,Values=true" \
  --query "Subnets[0].SubnetId" --output text)"

if [[ -z "$SUBNET_ID" || "$SUBNET_ID" == "None" ]]; then
  log "WARNING: no public subnet found in $VPC_ID — falling back to Terraform's subnet ($TF_SUBNET_ID). SSM registration may fail if it has no internet route."
  SUBNET_ID="$TF_SUBNET_ID"
fi

log "Secret ARN:   $DB_SECRET_ARN"
log "DB endpoint:  $DB_ENDPOINT"
log "Lambda SG:    $LAMBDA_SG_ID"
log "Subnet:       $SUBNET_ID"

# ---------------------------------------------------------------------
# 1. Pull the DB master password
# ---------------------------------------------------------------------
log "Fetching DB password from Secrets Manager..."
DB_PASSWORD="$(MSYS_NO_PATHCONV=1 aws secretsmanager get-secret-value \
  --secret-id "$DB_SECRET_ARN" --region "$REGION" \
  --query SecretString --output text \
  | python -c "import sys,json; print(json.load(sys.stdin)['password'])")"

[[ -n "$DB_PASSWORD" ]] || die "Got an empty password from Secrets Manager."
log "Password retrieved (not printed)."

# ---------------------------------------------------------------------
# 2. Ensure the bastion IAM role + instance profile exist (idempotent)
# ---------------------------------------------------------------------
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  log "IAM role $ROLE_NAME already exists, reusing it."
else
  log "Creating IAM role $ROLE_NAME..."
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    >/dev/null
  aws iam attach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
fi

if aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  log "Instance profile $PROFILE_NAME already exists, reusing it."
else
  log "Creating instance profile $PROFILE_NAME..."
  aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "$PROFILE_NAME" --role-name "$ROLE_NAME"
  log "Waiting for IAM propagation..."
  sleep 15
fi

# ---------------------------------------------------------------------
# 3. Launch the bastion
# ---------------------------------------------------------------------
AMI_ID="$(aws ec2 describe-images --region "$REGION" --owners amazon \
  --filters "Name=name,Values=al2023-ami-2*-kernel-*-x86_64" "Name=state,Values=available" \
  --query "sort_by(Images, &CreationDate)[-1].ImageId" --output text)"
[[ -n "$AMI_ID" && "$AMI_ID" != "None" ]] || die "Could not resolve a current Amazon Linux 2023 AMI in $REGION."
AMI_NAME="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI_ID" --query "Images[0].Name" --output text)"
log "Using AMI: $AMI_ID ($AMI_NAME)"

log "Launching bastion instance..."
INSTANCE_ID=""
for attempt in 1 2 3 4 5; do
  INSTANCE_ID="$(aws ec2 run-instances \
    --region "$REGION" \
    --image-id "$AMI_ID" --instance-type t3.micro \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$LAMBDA_SG_ID" \
    --iam-instance-profile "Name=$PROFILE_NAME" \
    --associate-public-ip-address \
    --query "Instances[0].InstanceId" --output text 2>/dev/null || echo "")"
  [[ -n "$INSTANCE_ID" && "$INSTANCE_ID" != "None" ]] && break
  log "Instance profile may not have propagated yet, retrying ($attempt/5)..."
  sleep 10
done
[[ -n "$INSTANCE_ID" && "$INSTANCE_ID" != "None" ]] || die "Failed to launch bastion instance after retries."

log "Instance launched: $INSTANCE_ID"

cleanup() {
  if [[ "$KEEP_BASTION" == "1" ]]; then
    log "KEEP_BASTION=1 set — leaving $INSTANCE_ID running. Terminate it manually when done:"
    log "  aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region $REGION"
  else
    log "Terminating bastion $INSTANCE_ID..."
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$INSTANCE_ID" >/dev/null || true
  fi
}
trap cleanup EXIT

log "Waiting for instance status checks to pass (this can take a minute or two)..."
aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$INSTANCE_ID"

log "Waiting for SSM agent to register (up to ~6 minutes)..."
registered=""
for attempt in $(seq 1 72); do
  registered="$(aws ssm describe-instance-information --region "$REGION" \
    --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
    --query "InstanceInformationList[0].PingStatus" --output text 2>/dev/null || echo "")"
  [[ "$registered" == "Online" ]] && break
  sleep 5
done

if [[ "$registered" != "Online" ]]; then
  log "SSM agent never came online. Pulling diagnostics before teardown..."

  log "--- IAM instance-profile association state ---"
  aws ec2 describe-iam-instance-profile-associations --region "$REGION" \
    --filters "Name=instance-id,Values=$INSTANCE_ID" \
    --query "IamInstanceProfileAssociations[0].[State,IamInstanceProfile.Arn]" --output text || true

  log "--- Instance console output (tail) ---"
  aws ec2 get-console-output --region "$REGION" --instance-id "$INSTANCE_ID" \
    --query "Output" --output text 2>/dev/null | tail -n 40 || echo "(no console output yet)"

  die "SSM agent never came online on $INSTANCE_ID. Check outbound internet/route table on $SUBNET_ID and the diagnostics above."
fi
log "SSM agent online."

# ---------------------------------------------------------------------
# 4. Run the schema via SSM Run Command
# ---------------------------------------------------------------------
REMOTE_SCRIPT="$(mktemp)"
{
  echo '#!/bin/bash'
  echo 'set -e'
  echo 'dnf install -y mariadb105 >/dev/null'
  echo "mysql -h '${DB_ENDPOINT}' -u admin -p'${DB_PASSWORD}' <<'SQL'"
  cat "$SCHEMA_FILE"
  echo 'SQL'
  echo 'echo SCHEMA_APPLY_OK'
} > "$REMOTE_SCRIPT"

SSM_PARAMS_FILE="$(mktemp)"
python - "$REMOTE_SCRIPT" > "$SSM_PARAMS_FILE" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    lines = f.read().splitlines()
print(json.dumps({"commands": lines}))
PYEOF

log "Sending schema apply command over SSM..."
SSM_PARAMS_FILE_FOR_CLI="$SSM_PARAMS_FILE"
if command -v cygpath >/dev/null 2>&1; then
  SSM_PARAMS_FILE_FOR_CLI="$(cygpath -m "$SSM_PARAMS_FILE")"
fi

COMMAND_ID="$(aws ssm send-command \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters "file://$SSM_PARAMS_FILE_FOR_CLI" \
  --query "Command.CommandId" --output text)"

log "Command ID: $COMMAND_ID — waiting for completion..."
for attempt in $(seq 1 30); do
  status="$(aws ssm get-command-invocation --region "$REGION" \
    --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
    --query "Status" --output text 2>/dev/null || echo "Pending")"
  [[ "$status" != "Pending" && "$status" != "InProgress" ]] && break
  sleep 5
done

OUTPUT="$(aws ssm get-command-invocation --region "$REGION" \
  --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
  --query "StandardOutputContent" --output text)"
ERR_OUTPUT="$(aws ssm get-command-invocation --region "$REGION" \
  --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
  --query "StandardErrorContent" --output text)"

rm -f "$REMOTE_SCRIPT" "$SSM_PARAMS_FILE"

echo "--- remote stdout ---"
echo "$OUTPUT"
echo "--- remote stderr ---"
echo "$ERR_OUTPUT"

if [[ "$status" == "Success" && "$OUTPUT" == *"SCHEMA_APPLY_OK"* ]]; then
  log "Schema applied successfully."
  exit 0
else
  die "Schema apply failed (status=$status). See stderr above."
fi
