# Operator key pair — used by the Dev Lead to SSH into any maze host for validation.
resource "aws_key_pair" "operator" {
  key_name   = "physarum-pf1-operator"
  public_key = file(var.ssh_public_key_path)
  tags       = { Name = "physarum-pf1-operator" }
}
