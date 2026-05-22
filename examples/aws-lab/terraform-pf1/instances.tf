locals {
  # Fixed private IPs — known at plan time, used in sshd AllowUsers config.
  host_a_ip = cidrhost(local.subnets.front.cidr, 10)  # 10.60.10.10
  host_b_ip = cidrhost(local.subnets.layer1.cidr, 10) # 10.60.20.10
  host_c_ip = cidrhost(local.subnets.layer1.cidr, 20) # 10.60.20.20
  host_d_ip = cidrhost(local.subnets.layer2.cidr, 10) # 10.60.30.10
  host_e_ip = cidrhost(local.subnets.layer2.cidr, 20) # 10.60.30.20
  host_f_ip = cidrhost(local.subnets.layer2.cidr, 30) # 10.60.30.30
  host_g_ip = cidrhost(local.subnets.layer3.cidr, 10) # 10.60.40.10

  # Operator IP extracted from CIDR (expected /32 workstation address).
  operator_ip = cidrhost(var.operator_cidr, 0)

  # /etc/hosts entries injected into every maze host for name resolution.
  maze_hosts_entries = <<-EOH
    ${local.host_a_ip} host-a
    ${local.host_b_ip} host-b
    ${local.host_c_ip} host-c
    ${local.host_d_ip} host-d
    ${local.host_e_ip} host-e
    ${local.host_f_ip} host-f
    ${local.host_g_ip} host-g
  EOH
}

# ── Host A — seed (front subnet) ──────────────────────────────────────────────
# Only host that receives the physarum-node binary at PF-1 start.
# Propagation uses IP-based trust only — no SSH key is held or distributed.

resource "aws_instance" "host_a" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["front"].id
  private_ip             = local.host_a_ip
  vpc_security_group_ids = [aws_security_group.host_a.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/host-a.sh.tpl", {
    hostname           = "host-a"
    operator_ip        = local.operator_ip
    maze_hosts_entries = local.maze_hosts_entries
  })

  tags = {
    Name      = "physarum-pf1-host-a"
    LabNode   = "A"
    LabRole   = "seed"
    MazeLayer = "front"
  }
}

# ── Host B — layer-1 ──────────────────────────────────────────────────────────
# Reachable from A. sshd accepts empty-password SSH from A's IP (10.60.10.10).

resource "aws_instance" "host_b" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer1"].id
  private_ip             = local.host_b_ip
  vpc_security_group_ids = [aws_security_group.host_b.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname             = "host-b"
    maze_hosts_entries   = local.maze_hosts_entries
    operator_ip          = local.operator_ip
    # Source IP that may propagate to B (A's private IP)
    allowed_source_ips   = local.host_a_ip
    # AllowUsers entries appended after operator for Match Address block
    allow_users_entries  = "ec2-user@${local.host_a_ip}"
    maze_role            = "layer-1"
    maze_note            = "A can propagate to B via empty-password SSH"
  })

  tags = {
    Name      = "physarum-pf1-host-b"
    LabNode   = "B"
    LabRole   = "layer1"
    MazeLayer = "layer1"
  }
}

# ── Host C — layer-1 ──────────────────────────────────────────────────────────
# Reachable from A. Key bifurcation point — C can reach D, E, F.

resource "aws_instance" "host_c" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer1"].id
  private_ip             = local.host_c_ip
  vpc_security_group_ids = [aws_security_group.host_c.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname             = "host-c"
    maze_hosts_entries   = local.maze_hosts_entries
    operator_ip          = local.operator_ip
    allowed_source_ips   = local.host_a_ip
    allow_users_entries  = "ec2-user@${local.host_a_ip}"
    maze_role            = "layer-1-bifurcation"
    maze_note            = "A can reach C; C sees D/E/F as candidates"
  })

  tags = {
    Name      = "physarum-pf1-host-c"
    LabNode   = "C"
    LabRole   = "layer1"
    MazeLayer = "layer1"
  }
}

# ── Host D — layer-2 dead end ─────────────────────────────────────────────────
# Port 22 open at SG level (RustScan sees it from layer-1).
# No organism IP in AllowUsers — propagation from B/C fails at sshd.

resource "aws_instance" "host_d" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer2"].id
  private_ip             = local.host_d_ip
  vpc_security_group_ids = [aws_security_group.host_d.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname             = "host-d"
    maze_hosts_entries   = local.maze_hosts_entries
    operator_ip          = local.operator_ip
    # Dead end: no propagation source allowed
    allowed_source_ips   = ""
    allow_users_entries  = ""
    maze_role            = "layer-2-dead-end"
    maze_note            = "ICMP visible from layer-1; not a valid propagation corridor"
  })

  tags = {
    Name      = "physarum-pf1-host-d"
    LabNode   = "D"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host E — layer-2 loop risk ────────────────────────────────────────────────
# Reachable from C (empty-password SSH). sshd accepts C's IP.
# Organism must detect already-visited layer-1 via lineage and penalize.

resource "aws_instance" "host_e" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer2"].id
  private_ip             = local.host_e_ip
  vpc_security_group_ids = [aws_security_group.host_e.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname             = "host-e"
    maze_hosts_entries   = local.maze_hosts_entries
    operator_ip          = local.operator_ip
    allowed_source_ips   = local.host_c_ip
    allow_users_entries  = "ec2-user@${local.host_c_ip}"
    maze_role            = "layer-2-loop-risk"
    maze_note            = "C can reach E; organism must penalize backward paths via lineage"
  })

  tags = {
    Name      = "physarum-pf1-host-e"
    LabNode   = "E"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host F — layer-2 valid corridor ───────────────────────────────────────────
# Reachable from C. F can propagate to G (layer-3).

resource "aws_instance" "host_f" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer2"].id
  private_ip             = local.host_f_ip
  vpc_security_group_ids = [aws_security_group.host_f.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname             = "host-f"
    maze_hosts_entries   = local.maze_hosts_entries
    operator_ip          = local.operator_ip
    allowed_source_ips   = local.host_c_ip
    allow_users_entries  = "ec2-user@${local.host_c_ip}"
    maze_role            = "layer-2-valid-corridor"
    maze_note            = "C to F valid corridor; F to G valid corridor"
  })

  tags = {
    Name      = "physarum-pf1-host-f"
    LabNode   = "F"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host G — layer-3 expansion milestone ──────────────────────────────────────
# Port 22 open from layer-2 (D/E/F see it via RustScan).
# sshd only accepts F's IP — D and E are rejected at OS level.

resource "aws_instance" "host_g" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer3"].id
  private_ip             = local.host_g_ip
  vpc_security_group_ids = [aws_security_group.host_g.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname             = "host-g"
    maze_hosts_entries   = local.maze_hosts_entries
    operator_ip          = local.operator_ip
    # Only F can propagate to G
    allowed_source_ips   = local.host_f_ip
    allow_users_entries  = "ec2-user@${local.host_f_ip}"
    maze_role            = "layer-3-milestone"
    maze_note            = "G accepts propagation from F only; discovered autonomously by organism"
  })

  tags = {
    Name      = "physarum-pf1-host-g"
    LabNode   = "G"
    LabRole   = "layer3"
    MazeLayer = "layer3"
  }
}
