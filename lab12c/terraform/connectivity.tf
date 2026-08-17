# ============================================================
# connectivity.tf — THE STAR OF LAB 11B
#
# This one rule is the "stone in the Temple" the gate script
# removes. It says: the database door (RDS security group)
# opens on port 3306, but ONLY for someone wearing the Lambda
# badge (Lambda security group).
#
# ANALOGY: A club with a bouncer. The rule isn't "door open" —
# it's "door open FOR people on this exact guest list."
# Remove the rule and Lambda knocks forever (connection
# timeout → Lambda error → API returns 500/502).
#
# WHY TERRAFORM MATTERS HERE (the big lesson):
# Terraform keeps a "state file" — its memory of what SHOULD
# exist. When the incident script revokes this rule:
#
#   terraform plan   → shows the rule as MISSING (drift!)
#                      This is your detection evidence.
#   terraform apply  → puts the rule back, exactly as coded.
#                      This is your recovery — no guessing,
#                      no clicking around the console.
#
# "I fixed it" becomes "the blueprint fixed it, and here's
# the plan output proving what changed."
# ============================================================

resource "aws_vpc_security_group_ingress_rule" "lambda_to_rds_3306" {
  # Was data.aws_security_group.rds.id — now that RDS and its
  # security group are built directly in this same directory
  # (security_groups.tf), we reference the resource directly
  # instead of looking it up as if it were external.
  security_group_id = aws_security_group.rds_sg.id

  # referenced_security_group_id = the guest list is another
  # security group, not an IP range. This is the professional
  # pattern: identity-based, not address-based.
  referenced_security_group_id = aws_security_group.lambda_sg.id

  ip_protocol = "tcp"
  from_port   = 3306
  to_port     = 3306

  description = "Lab 11B: MySQL from Lambda SG only (managed by Terraform)"

  tags = {
    Lab       = "SEIR-I-11B"
    ManagedBy = "terraform"
    Purpose   = "incident-recovery-target"
  }
}
