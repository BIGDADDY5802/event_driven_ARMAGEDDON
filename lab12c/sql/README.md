# sql/

| File | What it defines | Applied by |
|---|---|---|
| `schema.sql` | The `lab11.audit_events` table — one row per request handled by the `chewbacca_intake` Lambda (`id`, `ts_utc`, `actor`, `action`, `resource`, `note`, `source_ip`, `request_id`). | `../scripts/bootstrap_schema.sh`, run manually post-`apply` (the RDS instance is VPC-private, so Terraform can't reach it directly). |
