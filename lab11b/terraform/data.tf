# ============================================================
# data.tf — Look, don't touch
#
# ANALOGY: A "resource" block is Terraform BUILDING something.
# A "data" block is Terraform just LOOKING at something that
# already exists — like reading a name off a mailbox instead
# of building the house.
#
# HISTORY NOTE (so future-you understands why this file is
# almost empty): this used to hold data-source lookups for the
# Lambda, RDS instance, both security groups, the DB secret, and
# the HTTP API — back when Lab 11B was its own separate Terraform
# root with its own state, reaching across to find Lab 11A's
# already-built resources by ID.
#
# Now that Lab 11A, 11B, and the WAF work all live in ONE
# directory with ONE state, those lookups became redundant: this
# same plan already builds the RDS instance (rds.tf), both
# security groups (security_groups.tf), the secret (secrets.tf),
# and the Lambda (lambda.tf) directly as `resource` blocks. Any
# file that needs those now references the resource directly
# (e.g. aws_security_group.rds_sg.id), not through a data lookup.
# The HTTP API lookup was removed for the same reason it's gone
# from apigateway.tf: retired in favor of the REST API + WAF
# front door.
#
# What's left here is only the one lookup nothing else in this
# directory builds: the calling account's own identity.
# ============================================================

data "aws_caller_identity" "current" {}
