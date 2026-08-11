# ============================================================
# seir_dynamodb_security_incidents.tf — SOAR's own ledger
#
# ANALOGY: waf-correlation-findings is the detective's case file.
# security-incidents is the front desk's incident log -- a
# separate record created only once a case gets escalated into
# something requiring tracked follow-up (SOAR creates one for
# every severity except LOW skips creation... actually check
# PLAYBOOKS: every severity including LOW sets create_incident:
# True, so an incident record gets made every time, just with
# different notify/priority behavior per severity).
# ============================================================

resource "aws_dynamodb_table" "security_incidents" {
  name         = "security-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  tags = {
    Lab     = "SEIR-12A"
    Purpose = "soar-incident-ledger"
  }
}
