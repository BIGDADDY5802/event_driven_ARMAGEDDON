# ============================================================
# report_executive_bucket.tf — where finished reports land
#
# ANALOGY: this bucket is the filing cabinet the report Lambda
# drops finished folders into. Two documents per report run (the
# PDF for a human to read, the JSON for a machine to parse), same
# facts, same timestamp, filed under the same date path.
#
# LAB 12B — new lab, deliberately NOT tagged SEIR-12A even though
# it reads SEIR-12A's tables. It's its own component with its own
# lifecycle.
# ============================================================

resource "aws_s3_bucket" "executive_reports" {
  bucket = "event-driven-arm-bucket"

  # Lab-scale convenience, matching the same reasoning as
  # recovery_window_in_days=0 on Secrets Manager: this bucket only
  # ever holds regeneratable report artifacts, not source-of-truth
  # data, so easy teardown beats accidental-delete protection here.
  force_destroy = true

  tags = {
    Lab     = "12B-executive-report"
    Purpose = "executive-report-storage"
  }
}

# Least-privilege-by-default even though nothing in the spec asked
# for this explicitly: no reason this bucket should ever be
# reachable from outside the account.
resource "aws_s3_bucket_public_access_block" "executive_reports" {
  bucket = aws_s3_bucket.executive_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "executive_reports" {
  bucket = aws_s3_bucket.executive_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
