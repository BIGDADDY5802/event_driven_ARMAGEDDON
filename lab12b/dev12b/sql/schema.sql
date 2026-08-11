CREATE DATABASE IF NOT EXISTS lab11;
USE lab11;

CREATE TABLE IF NOT EXISTS audit_events (
  id          VARCHAR(36) PRIMARY KEY,
  ts_utc      VARCHAR(30) NOT NULL,
  actor       VARCHAR(100) NOT NULL,
  action      VARCHAR(50) NOT NULL,
  resource    VARCHAR(200) NOT NULL,
  note        VARCHAR(500),
  source_ip   VARCHAR(60),
  request_id  VARCHAR(100)
);

-- Terraform does not run this for you (the DB is private-only, reachable
-- from inside the VPC). Run it from a bastion/temporary EC2/CloudShell
-- that can reach the RDS endpoint. See README "Post-apply steps".
