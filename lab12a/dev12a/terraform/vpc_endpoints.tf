resource "aws_security_group" "secretsmanager_endpoint_sg" {
  name        = "${var.project_name}-secretsmanager-endpoint-sg"
  description = "Allows the Lambda SG to reach the Secrets Manager VPC endpoint on 443"
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name = "${var.project_name}-secretsmanager-endpoint-sg"
  }
}

resource "aws_security_group_rule" "endpoint_ingress_from_lambda" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.secretsmanager_endpoint_sg.id
  source_security_group_id = aws_security_group.lambda_sg.id
  description               = "Allow HTTPS from the Lambda SG only"
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = data.aws_vpc.default.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.selected_subnet_ids
  security_group_ids  = [aws_security_group.secretsmanager_endpoint_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-secretsmanager-endpoint"
  }
}