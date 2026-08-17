# ============================================================
# compliance_evidence_table.tf — one immutable record per
# control evaluation, written immediately (not batched at the
# end), matching the playbook's "evidence before prose" rule.
#
# compliance-findings is deliberately NOT created here — install.md
# is explicit that it belongs to a later lab. Adding it now would be
# building ahead of spec.
# ============================================================

resource "aws_dynamodb_table" "compliance_evidence" {
  name         = "compliance-evidence"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "evidence_id"

  attribute {
    name = "evidence_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Lab     = "12C-compliance-agent"
    Purpose = "compliance-evidence-ledger"
  }
}
