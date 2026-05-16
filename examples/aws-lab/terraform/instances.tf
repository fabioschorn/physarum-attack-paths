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
    "gate-k"         = "segmented-adaptive-flow-path"
    "gate-l"         = "blind-candidate-discovery"
  }

  # Common tags applied to all taggable resources.
  phase_tags = {
    Project   = "physarum-attack-paths"
    Lab       = "aws-lab"
    Phase     = var.lab_phase
    Mode      = local.phase_mode[var.lab_phase]
    ManagedBy = "terraform"
  }

  # For weighted-paths and gate-k: default agent-b probe targets to agent-c,agent-e.
  # gate-k: B probes C (peer) and E (direct path); no direct B→D edge.
  # weighted-paths: B probes C and E (two competing multi-hop paths).
  effective_probe_targets = (
    contains(["weighted-paths", "gate-k"], var.lab_phase) && var.agent_b_probe_targets == ""
    ? "agent-c,agent-e"
    : var.agent_b_probe_targets
  )

  # gate-k probe targets per agent:
  #   agent-c: probes B (peer) and D (intermediary); C→E is blocked by SG.
  #   agent-d: probes E only (D is the intermediary delivering to the destination).
  effective_agent_c_probe_targets = var.lab_phase == "gate-k" ? "agent-b,agent-d" : ""
  effective_agent_d_probe_targets = var.lab_phase == "gate-k" ? "agent-e" : ""
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
    enable_observer          = var.enable_observer
    enable_discovery         = var.enable_discovery
    discovery_cidrs          = var.discovery_cidrs
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
    probe_targets            = local.effective_agent_c_probe_targets
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
    enable_observer          = false
    enable_discovery         = false
    discovery_cidrs          = ""
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
    probe_targets            = local.effective_agent_d_probe_targets
    name_prefix              = var.name_prefix
    enable_artifact_download = var.enable_artifact_download
    artifact_bucket          = var.artifact_bucket
    artifact_prefix          = var.artifact_prefix
    artifact_region          = local.resolved_artifact_region
    enable_observer          = false
    enable_discovery         = false
    discovery_cidrs          = ""
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-d"
    Role = "agent"
  })
}

resource "aws_instance" "agent_e" {
  count = contains(["weighted-paths", "gate-k"], var.lab_phase) ? 1 : 0

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
    enable_observer          = false
    enable_discovery         = false
    discovery_cidrs          = ""
  })

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-e"
    Role = "agent"
  })
}
