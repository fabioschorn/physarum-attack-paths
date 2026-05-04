# Resolve the latest Amazon Linux 2023 AMI for the selected architecture via
# the AWS SSM public parameter store. This avoids hard-coding region/arch-specific
# AMI IDs that go stale and silently mismatch instance architecture.
#
# t4g.micro (arm64) uses: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
# t3.micro  (x86_64) uses: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
#
# To override (e.g. custom AMI), set ami_id_override in a .tfvars file:
#   ami_id_override = "ami-0123456789abcdef0"

variable "ami_id_override" {
  description = "Optional AMI ID override. If set, skips the SSM lookup. Must match the selected architecture."
  type        = string
  default     = ""
}

data "aws_ssm_parameter" "al2023_ami" {
  count = var.ami_id_override == "" ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${var.architecture}"
}

locals {
  ami_id = var.ami_id_override != "" ? var.ami_id_override : data.aws_ssm_parameter.al2023_ami[0].value
}
