locals {
  # Fixed private IPs — known at plan time, used in sshd AllowUsers config.
  host_a_ip  = cidrhost(local.subnets.front.cidr, 10)  # 10.60.10.10
  host_a1_ip = cidrhost(local.subnets.front.cidr, 20)  # 10.60.10.20  (PF-2: lateral discovery)
  host_b_ip  = cidrhost(local.subnets.layer1.cidr, 10) # 10.60.20.10
  host_c_ip  = cidrhost(local.subnets.layer1.cidr, 20) # 10.60.20.20
  host_d_ip  = cidrhost(local.subnets.layer2.cidr, 10) # 10.60.30.10
  host_e_ip  = cidrhost(local.subnets.layer2.cidr, 20) # 10.60.30.20
  host_f_ip  = cidrhost(local.subnets.layer2.cidr, 30) # 10.60.30.30
  host_g_ip  = cidrhost(local.subnets.layer3.cidr, 10) # 10.60.40.10
  host_x_ip  = cidrhost(local.subnets.cross.cidr, 10)  # 10.60.50.10  (PF-2: adaptive probe)

  operator_ip = cidrhost(var.operator_cidr, 0)

  # /etc/hosts entries — all 9 PF-2 hosts for name resolution.
  maze_hosts_entries = <<-EOH
    ${local.host_a_ip}  host-a
    ${local.host_a1_ip} host-a1
    ${local.host_b_ip}  host-b
    ${local.host_c_ip}  host-c
    ${local.host_d_ip}  host-d
    ${local.host_e_ip}  host-e
    ${local.host_f_ip}  host-f
    ${local.host_g_ip}  host-g
    ${local.host_x_ip}  host-x
  EOH
}

# ── Host A — seed (front subnet) ──────────────────────────────────────────────
resource "aws_instance" "host_a" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["front"].id
  private_ip             = local.host_a_ip
  vpc_security_group_ids = [aws_security_group.host_a.id]
  key_name               = aws_key_pair.operator.key_name
  iam_instance_profile   = aws_iam_instance_profile.pf2_ec2.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/host-a.sh.tpl", {
    hostname           = "host-a"
    operator_ip        = local.operator_ip
    maze_hosts_entries = local.maze_hosts_entries
    artifact_bucket    = var.artifact_bucket
    artifact_prefix    = var.artifact_prefix
    artifact_region    = var.artifact_region
  })

  tags = {
    Name      = "physarum-pf2-host-a"
    LabNode   = "A"
    LabRole   = "seed"
    MazeLayer = "front"
  }
}

# ── 5-minute gate — A.1 and X launch only after A-G are up ───────────────────
# The PF-2 scenario requires X to appear after the primary path (A→B/C→E/F→G)
# has had time to colonize.  We enforce this at provisioning time rather than
# relying solely on X's internal boot timer.
resource "time_sleep" "wait_for_primary_hosts" {
  depends_on = [
    aws_instance.host_a,
    aws_instance.host_b,
    aws_instance.host_c,
    aws_instance.host_d,
    aws_instance.host_e,
    aws_instance.host_f,
    aws_instance.host_g,
  ]
  create_duration = "5m"
}

# ── Host A.1 — front subnet lateral (PF-2) ────────────────────────────────────
# Same subnet as A (10.60.10.0/24).  Discovered by A via periodic /24 nmap scan.
# Accepts propagation from A (empty-password SSH).
# Receives TCP SYN from X as stimulus → discovers X → propagates to X.
resource "aws_instance" "host_a1" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["front"].id
  private_ip             = local.host_a1_ip
  vpc_security_group_ids = [aws_security_group.host_a1.id]
  key_name               = aws_key_pair.operator.key_name
  depends_on             = [time_sleep.wait_for_primary_hosts]

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname           = "host-a1"
    maze_hosts_entries = local.maze_hosts_entries
    operator_ip        = local.operator_ip
    # A propagates to A.1; sshd AllowUsers accepts A's IP with empty password.
    allowed_source_ips  = local.host_a_ip
    allow_users_entries = "ec2-user@${local.host_a_ip}"
    # B and C ping A.1 (same as they ping A) — ICMP stimulus keeps agent alive
    # while waiting for X's TCP stimulus (which starts at T+5min).
    ping_targets = ""
    maze_role    = "front-lateral"
    maze_note    = "Discovered by A via /24 nmap; receives TCP SYN from X as secondary stimulus"
  })

  tags = {
    Name      = "physarum-pf2-host-a1"
    LabNode   = "A1"
    LabRole   = "front-lateral"
    MazeLayer = "front"
  }
}

# ── Host B — layer-1 ──────────────────────────────────────────────────────────
resource "aws_instance" "host_b" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer1"].id
  private_ip             = local.host_b_ip
  vpc_security_group_ids = [aws_security_group.host_b.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname            = "host-b"
    maze_hosts_entries  = local.maze_hosts_entries
    operator_ip         = local.operator_ip
    allowed_source_ips  = local.host_a_ip
    allow_users_entries = "ec2-user@${local.host_a_ip}"
    # PF-2: B pings both A and A.1 — ICMP stimulus reaches both front hosts.
    ping_targets = "host-a host-a1"
    maze_role    = "layer-1"
    maze_note    = "A can propagate to B; B pings A+A.1 for ICMP stimulus"
  })

  tags = {
    Name      = "physarum-pf2-host-b"
    LabNode   = "B"
    LabRole   = "layer1"
    MazeLayer = "layer1"
  }
}

# ── Host C — layer-1 ──────────────────────────────────────────────────────────
resource "aws_instance" "host_c" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer1"].id
  private_ip             = local.host_c_ip
  vpc_security_group_ids = [aws_security_group.host_c.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname            = "host-c"
    maze_hosts_entries  = local.maze_hosts_entries
    operator_ip         = local.operator_ip
    allowed_source_ips  = local.host_a_ip
    allow_users_entries = "ec2-user@${local.host_a_ip}"
    # PF-2: C pings both A and A.1 — ICMP stimulus keeps A.1's agent alive.
    ping_targets = "host-a host-a1"
    maze_role    = "layer-1-bifurcation"
    maze_note    = "A can reach C; C sees D/E/F candidates; C pings A+A.1"
  })

  tags = {
    Name      = "physarum-pf2-host-c"
    LabNode   = "C"
    LabRole   = "layer1"
    MazeLayer = "layer1"
  }
}

# ── Host D — layer-2 dead end ─────────────────────────────────────────────────
resource "aws_instance" "host_d" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer2"].id
  private_ip             = local.host_d_ip
  vpc_security_group_ids = [aws_security_group.host_d.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname            = "host-d"
    maze_hosts_entries  = local.maze_hosts_entries
    operator_ip         = local.operator_ip
    allowed_source_ips  = ""
    allow_users_entries = ""
    ping_targets        = "host-b host-c"
    maze_role           = "layer-2-dead-end"
    maze_note           = "ICMP visible from layer-1; no valid propagation corridor"
  })

  tags = {
    Name      = "physarum-pf2-host-d"
    LabNode   = "D"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host E — layer-2 loop risk ────────────────────────────────────────────────
resource "aws_instance" "host_e" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer2"].id
  private_ip             = local.host_e_ip
  vpc_security_group_ids = [aws_security_group.host_e.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname            = "host-e"
    maze_hosts_entries  = local.maze_hosts_entries
    operator_ip         = local.operator_ip
    allowed_source_ips  = local.host_c_ip
    allow_users_entries = "ec2-user@${local.host_c_ip}"
    ping_targets        = "host-b host-c"
    maze_role           = "layer-2-loop-risk"
    maze_note           = "C can reach E; organism penalizes backward paths via lineage"
  })

  tags = {
    Name      = "physarum-pf2-host-e"
    LabNode   = "E"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host F — layer-2 valid corridor ───────────────────────────────────────────
resource "aws_instance" "host_f" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer2"].id
  private_ip             = local.host_f_ip
  vpc_security_group_ids = [aws_security_group.host_f.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname            = "host-f"
    maze_hosts_entries  = local.maze_hosts_entries
    operator_ip         = local.operator_ip
    allowed_source_ips  = local.host_c_ip
    allow_users_entries = "ec2-user@${local.host_c_ip}"
    ping_targets        = "host-b host-c"
    maze_role           = "layer-2-valid-corridor"
    maze_note           = "C→F valid; F→G valid corridor"
  })

  tags = {
    Name      = "physarum-pf2-host-f"
    LabNode   = "F"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host G — layer-3 expansion milestone ──────────────────────────────────────
# PF-2: G also accepts SSH from X (for the already-colonized check).
# G pings X in addition to D/E/F — ICMP stimulus reaches X → X discovers G.
resource "aws_instance" "host_g" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer3"].id
  private_ip             = local.host_g_ip
  vpc_security_group_ids = [aws_security_group.host_g.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname           = "host-g"
    maze_hosts_entries = local.maze_hosts_entries
    operator_ip        = local.operator_ip
    # F (primary propagation) and X (secondary conduit check: X SSHes in to
    # test for the running agent; sshd accepts X so the check succeeds).
    allowed_source_ips  = "${local.host_f_ip},${local.host_x_ip}"
    allow_users_entries = "ec2-user@${local.host_f_ip} ec2-user@${local.host_x_ip}"
    # G pings D, E, F (existing) and X (PF-2) — ICMP stimulus to cross subnet.
    ping_targets = "host-d host-e host-f host-x"
    maze_role    = "layer-3-milestone"
    maze_note    = "Colonized via F; X discovers G via ICMP and records it as secondary conduit"
  })

  tags = {
    Name      = "physarum-pf2-host-g"
    LabNode   = "G"
    LabRole   = "layer3"
    MazeLayer = "layer3"
  }
}

# ── Host X — cross subnet adaptive probe (PF-2) ───────────────────────────────
# Appears ~5 minutes after PF-2 start (simulated by delayed systemd timer).
# Sends TCP SYN to A.1:22 every 30s → A.1 captures SYN → discovers X.
# Receives ICMP from G → discovers G → finds G already colonized → secondary conduit.
resource "aws_instance" "host_x" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["cross"].id
  private_ip             = local.host_x_ip
  vpc_security_group_ids = [aws_security_group.host_x.id]
  key_name               = aws_key_pair.operator.key_name
  depends_on             = [time_sleep.wait_for_primary_hosts]

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/host-x.sh.tpl", {
    hostname           = "host-x"
    maze_hosts_entries = local.maze_hosts_entries
    operator_ip        = local.operator_ip
    # A.1 propagates to X via empty-password SSH from A.1's IP.
    allowed_source_ips  = local.host_a1_ip
    allow_users_entries = "ec2-user@${local.host_a1_ip}"
    # X itself doesn't need to ping anyone for ICMP stimulus — G pings X.
    ping_targets = ""
    # TCP stimulus: X connects to A.1:22 every 30s, starting 5min after boot.
    tcp_stimulus_target = local.host_a1_ip
  })

  tags = {
    Name      = "physarum-pf2-host-x"
    LabNode   = "X"
    LabRole   = "cross-probe"
    MazeLayer = "cross"
  }
}
