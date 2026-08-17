# ============================================================
# seir_eventbridge_bus.tf — the shared party line
#
# ANALOGY: this is a dedicated radio channel just for security
# events, separate from the default account-wide EventBridge bus
# that every other AWS service and Terraform-managed automation
# might also be listening to or publishing on. Keeping security
# events on their own bus means a rule written for "WAF Threat
# Finding Created" can never accidentally match noise from some
# unrelated service's default-bus event.
# ============================================================

resource "aws_cloudwatch_event_bus" "seir_security" {
  name = "seir-security-bus"

  tags = {
    Lab = "SEIR-12A"
  }
}
