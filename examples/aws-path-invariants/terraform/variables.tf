variable "aws_region" {
  description = "AWS region for all lab resources."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to all resource names."
  type        = string
  default     = "physarum-path-invariants"
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC. This should also be passed to physarum-maze as --llm-allowed-cidr."
  type        = string
  default     = "10.50.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "operator_cidr" {
  description = "Public laptop/operator CIDR allowed to SSH into nodes and open the seed dashboard on 8443. Use <public-ip>/32. Never use 0.0.0.0/0."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0)) && var.operator_cidr != "0.0.0.0/0"
    error_message = "operator_cidr must be a valid CIDR and must not be 0.0.0.0/0."
  }
}

variable "instance_type" {
  description = "EC2 instance type for all lab nodes."
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t3.micro", "t3.small", "t2.micro"], var.instance_type)
    error_message = "Use t3.micro, t3.small, or t2.micro to keep lab cost controlled."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the local SSH public key material used to create the EC2 key pair."
  type        = string
  default     = "../.keys/physarum-path-invariants.pub"

  validation {
    condition     = fileexists(var.ssh_public_key_path)
    error_message = "ssh_public_key_path does not exist. Generate it first, for example: ssh-keygen -t ed25519 -f examples/aws-path-invariants/.keys/physarum-path-invariants -N ''."
  }
}

variable "ami_id_override" {
  description = "Optional AMI ID override. Leave empty to use the latest Amazon Linux 2023 x86_64 AMI from SSM."
  type        = string
  default     = ""
}

variable "artifact_bucket" {
  description = "S3 bucket holding the physarum-maze binary for the seed bootstrap."
  type        = string
  default     = "physarum-artifacts-168740128169"
}

variable "artifact_prefix" {
  description = "S3 key prefix containing the physarum-maze binary, without trailing slash."
  type        = string
  default     = "physarum-attack-paths/issue-201/aws-path-invariants/amazonlinux2023-x86_64"
}

variable "artifact_region" {
  description = "AWS region where the artifact bucket lives."
  type        = string
  default     = "us-east-1"
}

variable "enable_seed_artifact_download" {
  description = "When true, seed user_data downloads physarum-maze from S3 using the EC2 IAM instance profile."
  type        = bool
  default     = true
}
