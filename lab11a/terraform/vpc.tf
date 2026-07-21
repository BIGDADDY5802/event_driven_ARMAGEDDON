# Lab 11A reuses the account's Default VPC (matches the manual walkthrough).
# No new VPC is created here — see README if you want to swap this for a
# dedicated VPC later.

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Pick N subnets, preferring spread across AZs. `slice` keeps this
# deterministic across applies instead of relying on set ordering.
locals {
  selected_subnet_ids = slice(
    sort(data.aws_subnets.default.ids),
    0,
    min(var.subnet_count, length(data.aws_subnets.default.ids))
  )
}

data "aws_caller_identity" "current" {}
