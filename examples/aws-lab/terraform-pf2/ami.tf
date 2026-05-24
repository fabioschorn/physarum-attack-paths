data "aws_ssm_parameter" "al2023_ami" {
  count = var.ami_id_override == "" ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${var.architecture}"
}

locals {
  ami_id = var.ami_id_override != "" ? var.ami_id_override : data.aws_ssm_parameter.al2023_ami[0].value
}
