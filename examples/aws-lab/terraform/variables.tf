variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to all resource names and tags for easy identification and cleanup"
  type        = string
  default     = "physarum"
}

variable "instance_type" {
  description = "EC2 instance type for all nodes. Prefer t4g.micro (ARM/Graviton, Free Tier eligible). Use t3.micro or t2.micro as fallback if Graviton is not viable in the target account/region."
  type        = string
  default     = "t4g.micro"

  validation {
    condition     = contains(["t4g.micro", "t4g.small", "t3.micro", "t3.small", "t2.micro"], var.instance_type)
    error_message = "Only t4g.micro/small, t3.micro/small, or t2.micro are allowed to control cost."
  }
}

variable "architecture" {
  description = "CPU architecture for AMI selection. Must match instance_type: t4g.* requires arm64; t3.* and t2.* require x86_64."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be arm64 (for t4g.*) or x86_64 (for t3.*/t2.*)."
  }
}

variable "key_name" {
  description = "EC2 key pair name for SSH access (leave empty to skip key-based SSH)"
  type        = string
  default     = ""
}

variable "operator_cidr" {
  description = "CIDR allowed to reach coordinator port 8080 and SSH port 22. Must be set to your operator IP, e.g. 203.0.113.10/32. Never use 0.0.0.0/0."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0)) && var.operator_cidr != "0.0.0.0/0"
    error_message = "operator_cidr must be a valid CIDR block and must not be 0.0.0.0/0."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.50.0.0/16"
}
