resource "aws_key_pair" "lab" {
  key_name   = "${local.effective_name_prefix}-lab-key"
  public_key = file(var.ssh_public_key_path)

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-lab-key"
  })
}
