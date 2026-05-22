locals {
  server_private_ip  = cidrhost(local.subnets.management.cidr, 10)
  agent_b_private_ip = cidrhost(local.subnets.outer.cidr, 10)
  # gate-l2/gate-l3: agent-b hosts both coordinator and agent; all peers point to agent-b's IP.
  effective_coordinator_ip = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? cidrhost(local.subnets.outer.cidr, 10) : local.server_private_ip
  # Gate L.2/L.3: place B and C in the outer /24 so A's local-interface derivation covers them.
  # All other phases: use the original middle/inner subnets.
  agent_c_private_ip = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? cidrhost(local.subnets.outer.cidr, 20) : cidrhost(local.subnets.middle.cidr, 10)
  agent_d_private_ip = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? cidrhost(local.subnets.outer.cidr, 30) : cidrhost(local.subnets.inner.cidr, 10)
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
    "gate-l2"        = "local-interface-scope-inbound-ebpf"
    "gate-l3"        = "icmp-packet-level-sensing"
    "gate-m"         = "node-capability-runtime-supervisor"
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
  # gate-l2/gate-l3/gate-m: coordinator is co-located on agent-b; no separate server instance needed.
  count = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? 0 : 1

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
    Name    = "${local.effective_name_prefix}-server-a"
    Role    = "coordinator"
    LabNode = "coordinator"
    LabRole = "infrastructure"
  })
}

resource "aws_instance" "agent_b" {
  # gate-l2/gate-l3: use coordinator-agent*.sh (runs physarum-server + physarum-agent on node A).
  # All other phases: use agent.sh only.
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["outer"].id
  private_ip             = local.agent_b_private_ip
  vpc_security_group_ids = [aws_security_group.agent_b.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = (
    var.lab_phase == "gate-m" ? templatefile("${path.module}/user-data/node.sh", {
      agent_id                 = "agent-b"
      listen_port              = 9001
      advertise_address        = local.agent_b_private_ip
      capabilities             = "probe,observe-flow"
      name_prefix              = var.name_prefix
      enable_artifact_download = var.enable_artifact_download
      artifact_bucket          = var.artifact_bucket
      artifact_prefix          = var.artifact_prefix
      artifact_region          = local.resolved_artifact_region
    }) : var.lab_phase == "gate-l3" ? templatefile("${path.module}/user-data/coordinator-agent-l3.sh", {
      agent_id                 = "agent-b"
      listen_port              = 9001
      advertise_address        = local.agent_b_private_ip
      probe_targets            = local.effective_probe_targets
      name_prefix              = var.name_prefix
      enable_artifact_download = var.enable_artifact_download
      artifact_bucket          = var.artifact_bucket
      artifact_prefix          = var.artifact_prefix
      artifact_region          = local.resolved_artifact_region
      enable_observer          = var.enable_observer
      enable_packet_observer   = var.enable_packet_observer
      enable_discovery         = var.enable_discovery
      discovery_cidrs          = var.discovery_cidrs
      discovery_scope_mode     = var.discovery_scope_mode
    }) : var.lab_phase == "gate-l2" ? templatefile("${path.module}/user-data/coordinator-agent.sh", {
      agent_id                 = "agent-b"
      listen_port              = 9001
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
      discovery_scope_mode     = var.discovery_scope_mode
    }) : templatefile("${path.module}/user-data/agent.sh", {
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
      discovery_scope_mode     = var.discovery_scope_mode
    })
  )

  tags = merge(local.phase_tags, {
    Name    = "${local.effective_name_prefix}-agent-b"
    Role    = "agent"
    LabNode = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "A" : "B"
    LabRole = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "coordinator_agent" : "agent"
  })
}

resource "aws_instance" "agent_c" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? aws_subnet.lab["outer"].id : aws_subnet.lab["middle"].id
  private_ip             = local.agent_c_private_ip
  vpc_security_group_ids = [aws_security_group.agent_c.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id                 = "agent-c"
    listen_port              = 9002
    coordinator_ip           = local.effective_coordinator_ip
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
    discovery_scope_mode     = "explicit"
  })

  tags = merge(local.phase_tags, {
    Name    = "${local.effective_name_prefix}-agent-c"
    Role    = "agent"
    LabNode = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "B" : "C"
    LabRole = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "stimulus" : "agent"
  })
}

resource "aws_instance" "agent_d" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? aws_subnet.lab["outer"].id : aws_subnet.lab["inner"].id
  private_ip             = local.agent_d_private_ip
  vpc_security_group_ids = [aws_security_group.agent_d.id]
  key_name               = aws_key_pair.lab.key_name
  iam_instance_profile   = aws_iam_instance_profile.physarum_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id                 = "agent-d"
    listen_port              = 9003
    coordinator_ip           = local.effective_coordinator_ip
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
    discovery_scope_mode     = "explicit"
  })

  tags = merge(local.phase_tags, {
    Name    = "${local.effective_name_prefix}-agent-d"
    Role    = "agent"
    LabNode = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "C" : "D"
    LabRole = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "stimulus" : "agent"
  })
}

resource "aws_instance" "agent_e" {
  count = contains(["weighted-paths", "gate-k", "gate-l"], var.lab_phase) ? 1 : 0

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
    discovery_scope_mode     = "explicit"
  })

  tags = merge(local.phase_tags, {
    Name    = "${local.effective_name_prefix}-agent-e"
    Role    = "agent"
    LabNode = "E"
    LabRole = "agent"
  })
}
