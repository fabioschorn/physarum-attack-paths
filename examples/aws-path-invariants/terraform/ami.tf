data "aws_ssm_parameter" "al2023_x86_64" {
  count = var.ami_id_override == "" ? 1 : 0

  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

locals {
  ami_id = var.ami_id_override != "" ? var.ami_id_override : data.aws_ssm_parameter.al2023_x86_64[0].value
}
