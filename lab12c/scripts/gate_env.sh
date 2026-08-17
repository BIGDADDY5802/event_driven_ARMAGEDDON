#!/usr/bin/env bash
# ============================================================
# gate_env.sh — source this before running gate_11a_lambda_secret_vpc.sh
# or gate_11a_apigw_route_invoke.sh.
#
# WHY THIS EXISTS: those two scripts were written when 11A had its
# own standalone Terraform state (lab11/dev11a). They take their
# target resources as env vars (LAMBDA_NAME, SECRET_ARN, API_ID,
# etc.) with no hardcoded defaults - meaning something used to set
# those before calling them. This file replaces that missing step,
# pulling live values from the CURRENT consolidated dev12b stack
# instead of anything stale.
#
# USAGE:  source ./gate_env.sh   (not ./gate_env.sh - must be
# sourced, not executed, or the exports vanish when it exits)
# ============================================================

export REGION="us-east-1"
export LAMBDA_NAME="$(terraform output -raw lambda_function_name)"
export SECRET_ARN="$(terraform output -raw db_secret_arn)"
export API_ID="$(terraform output -raw rest_invoke_url | sed -E 's#https://([^.]+)\..*#\1#')"
export STAGE_NAME="prod"
export ROUTE_PATH="/intake"
export METHOD="POST"

# DB_NAME: not currently exposed as a terraform output (var.db_name
# defaults to "lab11" in variables.tf but nothing surfaces it).
# Using the known default for now - VERIFIED against live RDS via
# `aws rds describe-db-instances ... --query DBInstances[0].DBName`.
export DB_NAME="lab11"

# ---- gate_11b_incident.sh specific vars ----
export DB_ID="chewbacca-11a-mysql"   # confirmed live via aws rds describe-db-instances
export RDS_SG_ID="$(terraform output -raw rds_security_group_id)"
export LAMBDA_SG_ID="$(terraform output -raw lambda_security_group_id)"

# SAFE VERIFICATION MODE: script will break the DB security group,
# detect the break, then AUTO-RESTORE it itself rather than leaving
# it broken for manual recovery. Use this to confirm the gate works
# end-to-end without taking down live DB connectivity. For actual
# "practice the recovery" runs, unset AUTO_RESTORE (or set to false)
# and fix the SG rule yourself when the gate reports the incident.
export AUTO_RESTORE="true"

echo "gate_env.sh loaded:"
echo "  LAMBDA_NAME  = $LAMBDA_NAME"
echo "  SECRET_ARN   = $SECRET_ARN"
echo "  API_ID       = $API_ID"
echo "  DB_NAME      = $DB_NAME"
echo "  DB_ID        = $DB_ID"
echo "  RDS_SG_ID    = $RDS_SG_ID"
echo "  LAMBDA_SG_ID = $LAMBDA_SG_ID"
echo "  AUTO_RESTORE = $AUTO_RESTORE (script will self-heal the SG after the incident test)"