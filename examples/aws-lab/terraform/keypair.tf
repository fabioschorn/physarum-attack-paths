resource "aws_key_pair" "lab" {
  key_name   = "${var.name_prefix}-lab-key"
  public_key = file(var.ssh_public_key_path)

  tags = {
    Name = "${var.name_prefix}-lab-key"
  }
}
