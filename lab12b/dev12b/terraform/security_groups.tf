# Two separate security groups, connected by GROUP REFERENCE rather than
# IP range — Lambda's network address isn't static, so the RDS SG trusts
# the Lambda SG's identity, not a CIDR block.

resource "aws_security_group" "lambda_sg" {
  name        = "${var.project_name}-lambda-sg"
  description = "Attached to the intake Lambda ENIs inside the VPC"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "Allow all outbound (Secrets Manager, RDS, CloudWatch)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-lambda-sg"
  }
}

resource "aws_security_group" "rds_sg" {
  name        = "${var.project_name}-rds-sg"
  description = "Attached to the intake RDS instance"
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name = "${var.project_name}-rds-sg"
  }
}

# MySQL (3306) inbound from the Lambda security group is intentionally
# NOT declared here. It's owned by connectivity.tf's
# aws_vpc_security_group_ingress_rule.lambda_to_rds_3306 instead — that
# resource is the specific one Lab 11B's incident-response gate script
# revokes and restores. Declaring the same rule twice (once permanently
# here, once as the "breakable" copy in connectivity.tf) caused a
# duplicate-rule error on apply, and would have quietly defeated Lab
# 11B's exercise anyway: revoking connectivity.tf's copy wouldn't
# actually break connectivity if this permanent copy were still here.
