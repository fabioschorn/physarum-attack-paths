variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for all nodes. Default: t3.micro."
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t3.micro", "t3.small", "t4g.micro", "t4g.small", "t2.micro"], var.instance_type)
    error_message = "Only t3.micro/small, t4g.micro/small, or t2.micro are allowed to control cost."
  }
}

variable "architecture" {
  description = "CPU architecture. Must match instance_type: t4g.* requires arm64; t3.*/t2.* require x86_64."
  type        = string
  default     = "x86_64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be arm64 or x86_64."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the operator ed25519 public key. Used for operator SSH access to all hosts."
  type        = string
  default     = "../.keys/physarum-lab-devlead.pub"

  validation {
    condition     = fileexists(var.ssh_public_key_path)
    error_message = "ssh_public_key_path does not exist. Generate with: ssh-keygen -t ed25519 -f examples/aws-lab/.keys/physarum-lab-devlead -N ''"
  }
}

variable "operator_cidr" {
  description = "CIDR allowed SSH access (port 22) to all maze hosts from the operator workstation. Must be /32. Never use 0.0.0.0/0."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0)) && var.operator_cidr != "0.0.0.0/0"
    error_message = "operator_cidr must be a valid CIDR block and must not be 0.0.0.0/0."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the PF-1 VPC. Uses 10.60.0.0/16 to avoid overlap with existing labs (10.50.0.0/16)."
  type        = string
  default     = "10.60.0.0/16"
}

variable "ami_id_override" {
  description = "Optional AMI ID override. If set, skips the SSM lookup."
  type        = string
  default     = ""
}

variable "artifact_bucket" {
  description = "S3 bucket holding the physarum-maze binary. Must be in the same AWS account (168740128169)."
  type        = string
  default     = "physarum-artifacts-168740128169"
}

variable "artifact_prefix" {
  description = "S3 key prefix for PF-1 artifacts (no trailing slash)."
  type        = string
  default     = "physarum-attack-paths/pf-1/linux-x86_64"
}

variable "artifact_region" {
  description = "AWS region where the artifact bucket lives."
  type        = string
  default     = "us-east-1"
}
