resource "aws_key_pair" "lab" {
  key_name_prefix = "${var.name_prefix}-"
  public_key      = file(var.ssh_public_key_path)

  tags = {
    Name = "${var.name_prefix}-key"
  }
}
