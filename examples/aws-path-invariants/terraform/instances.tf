locals {
  target_bootstrap_script = <<-EOT
    #!/usr/bin/env bash
    set -euxo pipefail
    dnf update -y
    dnf install -y jq python3
    echo "aws-path-invariants bootstrap complete" > /etc/physarum-lab-bootstrap.txt
  EOT
}

resource "aws_instance" "seed" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.lab["outer"].id
  private_ip                  = local.seed_private_ip
  vpc_security_group_ids      = [aws_security_group.seed.id]
  key_name                    = aws_key_pair.lab.key_name
  iam_instance_profile        = aws_iam_instance_profile.seed_ec2.name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/seed.sh", {
    enable_seed_artifact_download = var.enable_seed_artifact_download
    artifact_bucket               = var.artifact_bucket
    artifact_prefix               = var.artifact_prefix
    artifact_region               = var.artifact_region
    vpc_cidr                      = var.vpc_cidr
  })

  tags = {
    Name    = "${var.name_prefix}-seed-b"
    Role    = "physarum-maze-seed"
    LabNode = "B"
  }
}

resource "aws_instance" "target_c" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.lab["middle"].id
  private_ip                  = local.target_c_private_ip
  vpc_security_group_ids      = [aws_security_group.target_c.id]
  key_name                    = aws_key_pair.lab.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data                   = local.target_bootstrap_script

  tags = {
    Name    = "${var.name_prefix}-target-c"
    Role    = "target"
    LabNode = "C"
  }
}

resource "aws_instance" "target_d" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.lab["inner"].id
  private_ip                  = local.target_d_private_ip
  vpc_security_group_ids      = [aws_security_group.target_d.id]
  key_name                    = aws_key_pair.lab.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data                   = local.target_bootstrap_script

  tags = {
    Name    = "${var.name_prefix}-target-d"
    Role    = "target"
    LabNode = "D"
  }
}

resource "aws_instance" "target_e" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.lab["secondary"].id
  private_ip                  = local.target_e_private_ip
  vpc_security_group_ids      = [aws_security_group.target_e.id]
  key_name                    = aws_key_pair.lab.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data                   = local.target_bootstrap_script

  tags = {
    Name    = "${var.name_prefix}-target-e"
    Role    = "target"
    LabNode = "E"
  }
}
