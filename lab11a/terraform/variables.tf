variable "aws_region" {
  description = "AWS region to deploy the Lab 11A stack into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name prefixed onto resource names for this lab."
  type        = string
  default     = "chewbacca-11a"
}

variable "environment" {
  description = "Environment tag, e.g. lab / dev / prod."
  type        = string
  default     = "lab"
}

variable "db_name" {
  description = "Database name created inside the RDS instance."
  type        = string
  default     = "lab11"
}

variable "db_master_username" {
  description = "Master username for the RDS instance."
  type        = string
  default     = "admin"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "Allocated storage (GB) for the RDS instance."
  type        = number
  default     = 20
}

# GAP-4 (tracked): backup_retention_period=0 is inappropriate for audit
# data and is called out explicitly as a future hardening pass, not an
# oversight. See README "Known gaps" section.
variable "db_backup_retention_period" {
  description = "RDS backup retention in days. 0 disables backups (lab default, see GAP-4)."
  type        = number
  default     = 0
}

variable "lambda_function_name" {
  description = "Name of the intake Lambda function."
  type        = string
  default     = "chewbacca-intake-lambda-11a"
}

variable "lambda_runtime" {
  description = "Lambda runtime for the intake function."
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds."
  type        = number
  default     = 10
}

variable "lambda_memory_size" {
  description = "Lambda function memory in MB."
  type        = number
  default     = 256
}

variable "db_connect_timeout" {
  description = "pymysql connect/read/write timeout in seconds, passed to Lambda as env var."
  type        = number
  default     = 5
}

variable "api_name" {
  description = "Name of the API Gateway HTTP API."
  type        = string
  default     = "chewbacca-intake-api-11a"
}

variable "stage_name" {
  description = "API Gateway stage name."
  type        = string
  default     = "prod"
}

variable "route_path" {
  description = "Route path the intake Lambda is invoked on."
  type        = string
  default     = "/intake"
}

variable "subnet_count" {
  description = "Number of default-VPC subnets to select for the DB subnet group (min 2, different AZs preferred)."
  type        = number
  default     = 2
}

variable "tags" {
  description = "Common tags applied to all resources via provider default_tags."
  type        = map(string)
  default = {
    Project = "dawgs-armageddon"
    Lab     = "11A-chewbacca"
    Track   = "serverless"
    ManagedBy = "terraform"
  }
}
