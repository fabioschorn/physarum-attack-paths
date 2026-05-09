variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "lab_phase" {
  description = "AWS lab validation phase. phase1 = Mode 1 full mesh. phase2 = Mode 2 segmented B→C→D. weighted-paths = competing B→C→D vs B→E→D with tc/netem degradation (Issue #58)."
  type        = string
  default     = "phase1"

  validation {
    condition     = contains(["phase1", "phase2", "weighted-paths"], var.lab_phase)
    error_message = "lab_phase must be phase1, phase2, or weighted-paths."
  }
}

variable "agent_b_probe_targets" {
  description = "Comma-separated list of agent IDs that agent-b will probe. Empty = probe all peers (default for phase1/phase2). Set to 'agent-c,agent-e' for weighted-paths gate to prevent a direct B→D edge."
  type        = string
  default     = ""
}

variable "name_prefix" {
  description = "Prefix applied to all resource names and tags for easy identification and cleanup"
  type        = string
  default     = "physarum"
}

variable "instance_type" {
  description = "EC2 instance type for all nodes. Default: t3.micro (Intel/x86_64, Free Tier-oriented). Optional Graviton path: t4g.micro (arm64). t2.micro may be used where Free Tier eligible."
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t4g.micro", "t4g.small", "t3.micro", "t3.small", "t2.micro"], var.instance_type)
    error_message = "Only t4g.micro/small, t3.micro/small, or t2.micro are allowed to control cost."
  }
}

variable "architecture" {
  description = "CPU architecture for AMI selection. Must match instance_type: t4g.* requires arm64; t3.* and t2.* require x86_64. Default: x86_64 to match t3.micro."
  type        = string
  default     = "x86_64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be arm64 (for t4g.*) or x86_64 (for t3.*/t2.*)."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the local ed25519 public key file. Terraform creates an AWS key pair from this material only. Generate the key BEFORE terraform plan/apply with: ssh-keygen -t ed25519 -f examples/aws-lab/.keys/physarum-lab-devlead -N ''"
  type        = string
  default     = "../.keys/physarum-lab-devlead.pub"

  validation {
    condition     = fileexists(var.ssh_public_key_path)
    error_message = "ssh_public_key_path does not exist: '${var.ssh_public_key_path}'. Generate the SSH key before terraform plan/apply: ssh-keygen -t ed25519 -f examples/aws-lab/.keys/physarum-lab-devlead -N ''"
  }
}

variable "operator_cidr" {
  description = "CIDR allowed SSH access (port 22) to all lab nodes. Must be set to your operator IP, e.g. 203.0.113.10/32. Never use 0.0.0.0/0. Port 8080 is not publicly exposed."
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

variable "artifact_bucket" {
  description = "Name of the pre-existing S3 bucket holding compiled binaries. Required when enable_artifact_download = true. Leave empty when enable_artifact_download = false."
  type        = string
  default     = ""
}

variable "artifact_prefix" {
  description = "S3 key prefix for compiled binaries. Binaries are expected at s3://<artifact_bucket>/<artifact_prefix>/physarum-{server,agent}."
  type        = string
  default     = "physarum-attack-paths/dev/linux-x86_64"
}

variable "artifact_region" {
  description = "AWS region of the artifact S3 bucket. Defaults to aws_region if left empty."
  type        = string
  default     = ""
}

variable "enable_artifact_download" {
  description = "When true, user_data downloads physarum-server and physarum-agent from S3 and starts real systemd services. When false (default), placeholder units are used and no S3 access is attempted."
  type        = bool
  default     = false
}
