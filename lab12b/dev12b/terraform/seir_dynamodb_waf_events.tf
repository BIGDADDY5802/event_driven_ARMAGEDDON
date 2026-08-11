# ============================================================
# seir_dynamodb_waf_events.tf — the analyzer's mailbox for
# normalized WAF events
#
# ANALOGY: WAF writes letters (raw JSON log lines) to a mailbox
# (the CloudWatch log group in waf.tf). The analyzer Lambda reads
# each letter, translates it into a standard index card (the exact
# fields the Correlation Agent needs), and files that card here.
# The Correlation Agent never touches the raw mailbox at all --
# it only ever reads these standardized cards.
#
# NAMING NOTE: this file and everything else prefixed seir_ belongs
# to Lab 12A's SOAR/SEIR pipeline, sharing this directory's state
# with Lab 11B on purpose (see conversation), but kept visually
# separate by the prefix so it's obvious at a glance which lab a
# file belongs to.
# ============================================================

resource "aws_dynamodb_table" "waf_events" {
  name         = "waf-events"
  billing_mode = "PAY_PER_REQUEST" # no capacity planning needed for a lab-scale event stream

  # CHANGED from event_id (a random UUID) to request_id (WAF's own
  # unique-per-real-request identifier). This is what makes the
  # pull-based waf_bedrock_analyzer.py's idempotency guard truly
  # atomic: DynamoDB's ConditionExpression on put_item only
  # evaluates against the item at the KEY you're writing to, so
  # "only write if nobody has processed this request before" is
  # only race-free if request_id IS the key, not a side attribute
  # checked separately beforehand.
  #
  # CONSEQUENCE: hash keys are immutable in DynamoDB, so this
  # change forces Terraform to destroy and recreate the table --
  # any existing rows are gone. For a lab-scale table backed by
  # curl-loop test traffic, that's a one-line regeneration, not a
  # real loss.
  hash_key = "request_id"

  attribute {
    name = "request_id"
    type = "S"
  }

  # DynamoDB auto-deletes an item once its "expires_at" epoch
  # timestamp is in the past. The analyzer Lambda sets this on
  # every item it writes (EVENT_TTL_DAYS, default 7) -- raw events
  # only need to outlive the Correlation Agent's lookback window
  # (default 60 minutes) by a comfortable margin for manual
  # investigation, not forever.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Lab     = "SEIR-12A"
    Purpose = "raw-waf-event-store"
  }
}
