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
  description = "EC2 instance type for all nodes"
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t3.micro", "t3.small"], var.instance_type)
    error_message = "Only t3.micro or t3.small are allowed to control cost."
  }
}

variable "key_name" {
  description = "EC2 key pair name for SSH access (leave empty to skip key-based SSH)"
  type        = string
  default     = ""
}

variable "operator_cidr" {
  description = "CIDR allowed to reach coordinator port 8080 and SSH port 22. Must be set to your operator IP, e.g. 203.0.113.10/32"
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0))
    error_message = "operator_cidr must be a valid CIDR block."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.50.0.0/16"
}

variable "ami_id" {
  description = "AMI to use for all EC2 instances. Defaults to Amazon Linux 2023 in us-east-1. Override for other regions."
  type        = string
  default     = "ami-0c02fb55956c7d316" # Amazon Linux 2023, us-east-1
}
