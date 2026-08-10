terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Same backend bucket used across the dawgs-armageddon labs, unique key per
  # lab so state stays isolated. State locking intentionally omitted (solo
  # work, no DynamoDB table configured) — matches the rest of the class labs.
  #
  # NOTE: backend blocks cannot use variables. Edit bucket/key below before
  # `terraform init` if you're standing this up under a different account.
  backend "s3" {
    bucket = "11-9-backend"
    key    = "lab11a-chewbacca/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}
