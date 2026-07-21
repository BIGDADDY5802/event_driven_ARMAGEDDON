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

# MySQL (3306) inbound ONLY from the Lambda security group — never a CIDR.
resource "aws_security_group_rule" "rds_ingress_from_lambda" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.rds_sg.id
  source_security_group_id = aws_security_group.lambda_sg.id
  description               = "Allow MySQL from the Lambda SG only"
}
