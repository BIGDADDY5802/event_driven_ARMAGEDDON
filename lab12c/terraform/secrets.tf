# One secret holds everything the Lambda needs to connect: username,
# password, host, port, dbname. Lambda only ever holds a pointer to this
# ARN — never the credentials themselves — via an env var.
#
# GAP-2 (tracked): no rotation configured (aws_secretsmanager_secret_rotation
# + a rotation Lambda). See README "Known gaps".

resource "aws_secretsmanager_secret" "db_secret" {
  name                    = "${var.project_name}-db-secret"
  description             = "MySQL connection info for the Lab 11A intake Lambda"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_secret" {
  secret_id = aws_secretsmanager_secret.db_secret.id

  secret_string = jsonencode({
    username = var.db_master_username
    password = random_password.db_master_password.result
    host     = aws_db_instance.this.address
    port     = 3306
    dbname   = var.db_name
  })
}
