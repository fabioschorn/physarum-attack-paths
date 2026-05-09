locals {
  server_private_ip  = cidrhost(local.subnets.management.cidr, 10)
  agent_b_private_ip = cidrhost(local.subnets.outer.cidr, 10)
  agent_c_private_ip = cidrhost(local.subnets.middle.cidr, 10)
  agent_d_private_ip = cidrhost(local.subnets.inner.cidr, 10)
  agent_e_private_ip = cidrhost(local.subnets.secondary.cidr, 10)

  resolved_artifact_region = var.artifact_region != "" ? var.artifact_region : var.aws_region

  # Phase-aware naming: physarum-phase1-*, physarum-phase2-*, physarum-weighted-paths-*
  effective_name_prefix = "${var.name_prefix}-${var.lab_phase}"

  phase_mode = {
    "phase1"         = "full-mesh"
    "phase2"         = "segmented-b-c-d"
    "weighted-paths" = "weighted-competing-paths"
  }

  # Common tags applied to all taggable resources.
  phase_tags = {
    Project   = "physarum-attack-paths"
    Lab       = "aws-lab"
    Phase     = var.lab_phase
    Mode      = local.phase_mode[var.lab_phase]
    ManagedBy = "terraform"
  }

  # For weighted-paths: default to agent-c,agent-e if operator did not override.
  # Prevents a direct B→D edge from forming when the operator forgets to pass the variable.
  effective_probe_targets = (
    var.lab_phase == "weighted-paths" && var.agent_b_probe_targets == ""
    ? "agent-c,agent-e"
    : var.agent_b_probe_targets
  )
}

resource "aws_instance" "server_a" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["management"].id
  private_ip             = local.server_private_ip
  vpc_security_group_ids = [aws_security_group.server_a.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/server.sh", {
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-server-a"
    Role = "coordinator"
  })
}

resource "aws_instance" "agent_b" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["outer"].id
  private_ip             = local.agent_b_private_ip
  vpc_security_group_ids = [aws_security_group.agent_b.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id                 = "agent-b"
    listen_port              = 9001
    coordinator_ip           = local.server_private_ip
    advertise_address        = local.agent_b_private_ip
    probe_targets            = local.effective_probe_targets
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-b"
    Role = "agent"
  })
}

resource "aws_instance" "agent_c" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["middle"].id
  private_ip             = local.agent_c_private_ip
  vpc_security_group_ids = [aws_security_group.agent_c.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id                 = "agent-c"
    listen_port              = 9002
    coordinator_ip           = local.server_private_ip
    advertise_address        = local.agent_c_private_ip
    probe_targets            = ""
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-c"
    Role = "agent"
  })
}

resource "aws_instance" "agent_d" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["inner"].id
  private_ip             = local.agent_d_private_ip
  vpc_security_group_ids = [aws_security_group.agent_d.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id                 = "agent-d"
    listen_port              = 9003
    coordinator_ip           = local.server_private_ip
    advertise_address        = local.agent_d_private_ip
    probe_targets            = ""
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-d"
    Role = "agent"
  })
}

resource "aws_instance" "agent_e" {
  count = var.lab_phase == "weighted-paths" ? 1 : 0

  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["secondary"].id
  private_ip             = local.agent_e_private_ip
  vpc_security_group_ids = [aws_security_group.agent_e[0].id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id                 = "agent-e"
    listen_port              = 9004
    coordinator_ip           = local.server_private_ip
    advertise_address        = local.agent_e_private_ip
    probe_targets            = ""
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-e"
    Role = "agent"
  })
}
