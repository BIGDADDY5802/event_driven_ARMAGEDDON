# ============================================================
# seir_dynamodb_waf_correlation_findings.tf — the ledger the
# Correlation Agent writes to and SOAR reads from
#
# ANALOGY: if waf-events is the raw incoming mail, this table is
# the case file the Correlation Agent opens once it decides a
# pattern in that mail is worth a human's attention. One case file
# per correlation run that clears MINIMUM_EVENT_COUNT.
#
# TTL NOTE: only the Correlation Agent's own RUN# idempotency-lock
# items (from claim_run()) ever set expires_at -- real findings
# never do (see save_finding() in the Lambda code), so real
# findings persist indefinitely as an audit trail, while lock
# records self-clean after ~15 minutes. Same table, two different
# item shapes, distinguished by whether expires_at is present.
# ============================================================

resource "aws_dynamodb_table" "waf_correlation_findings" {
  name         = "waf-correlation-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Lab     = "SEIR-12A"
    Purpose = "correlation-findings-ledger"
  }
}
