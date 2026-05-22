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
# Holds the propagation private key for organism SCP expansion.

resource "aws_instance" "host_a" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["front"].id
  private_ip             = local.host_a_ip
  vpc_security_group_ids = [aws_security_group.host_a.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/host-a.sh.tpl", {
    hostname             = "host-a"
    operator_ip          = local.operator_ip
    maze_hosts_entries   = local.maze_hosts_entries
    propagation_priv_key = tls_private_key.propagation.private_key_openssh
    propagation_pub_key  = tls_private_key.propagation.public_key_openssh
  })

  tags = {
    Name      = "physarum-pf1-host-a"
    LabNode   = "A"
    LabRole   = "seed"
    MazeLayer = "front"
  }
}

# ── Host B — layer-1 ──────────────────────────────────────────────────────────
# Reachable from A. sshd allows SSH from A (10.60.10.10) + operator.

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
    propagation_pub_key = tls_private_key.propagation.public_key_openssh
    # AllowUsers: A can propagate to B, operator can SSH for validation
    allowed_ssh_users   = "ec2-user@${local.host_a_ip} ec2-user@${local.operator_ip}"
    maze_role           = "layer-1"
    maze_note           = "A can validate corridors toward B"
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
# sshd allows SSH from A + operator.

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
    propagation_pub_key = tls_private_key.propagation.public_key_openssh
    allowed_ssh_users   = "ec2-user@${local.host_a_ip} ec2-user@${local.operator_ip}"
    maze_role           = "layer-1-bifurcation"
    maze_note           = "A can reach C; C can validate corridors toward D, E, F"
  })

  tags = {
    Name      = "physarum-pf1-host-c"
    LabNode   = "C"
    LabRole   = "layer1"
    MazeLayer = "layer1"
  }
}

# ── Host D — layer-2 dead end ─────────────────────────────────────────────────
# Visible by ICMP from layer-1. Port 22 open at SG level (RustScan sees it).
# sshd AllowUsers permits only the operator — propagation from B/C is rejected.

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
    propagation_pub_key = tls_private_key.propagation.public_key_openssh
    # Operator only — B/C see port 22 open but sshd rejects them (dead end)
    allowed_ssh_users   = "ec2-user@${local.operator_ip}"
    maze_role           = "layer-2-dead-end"
    maze_note           = "ICMP visible from layer-1; not a valid propagation corridor"
  })

  tags = {
    Name      = "physarum-pf1-host-d"
    LabNode   = "D"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host E — layer-2 loop risk ────────────────────────────────────────────────
# Reachable from C via SSH. sshd permits C + operator.
# E's unrestricted outbound allows it to reach back toward layer-1 (loop risk).
# Organism must detect and penalize the backward signal.

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
    propagation_pub_key = tls_private_key.propagation.public_key_openssh
    # C can propagate to E, but E sees layer-1 again — backtracking risk
    allowed_ssh_users   = "ec2-user@${local.host_c_ip} ec2-user@${local.operator_ip}"
    maze_role           = "layer-2-loop-risk"
    maze_note           = "C can reach E; E sees layer-1 again — organism must penalize backward movement"
  })

  tags = {
    Name      = "physarum-pf1-host-e"
    LabNode   = "E"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host F — layer-2 valid corridor ───────────────────────────────────────────
# Reachable from C. sshd permits C + operator. F can reach G (layer-3).

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
    propagation_pub_key = tls_private_key.propagation.public_key_openssh
    allowed_ssh_users   = "ec2-user@${local.host_c_ip} ec2-user@${local.operator_ip}"
    maze_role           = "layer-2-valid-corridor"
    maze_note           = "C → F valid corridor; F → G valid corridor"
  })

  tags = {
    Name      = "physarum-pf1-host-f"
    LabNode   = "F"
    LabRole   = "layer2"
    MazeLayer = "layer2"
  }
}

# ── Host G — layer-3 expansion milestone ──────────────────────────────────────
# Visible from layer-2 via ICMP and port 22 (SG allows layer-2 subnet).
# sshd AllowUsers permits only F + operator.
# D and E see port 22 open but sshd rejects them — G is not a dead end,
# just not reachable from D or E.

resource "aws_instance" "host_g" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.maze["layer3"].id
  private_ip             = local.host_g_ip
  vpc_security_group_ids = [aws_security_group.host_g.id]
  key_name               = aws_key_pair.operator.key_name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data/maze-node.sh.tpl", {
    hostname            = "host-g"
    maze_hosts_entries  = local.maze_hosts_entries
    propagation_pub_key = tls_private_key.propagation.public_key_openssh
    # Only F can propagate to G — D/E get rejected by sshd
    allowed_ssh_users   = "ec2-user@${local.host_f_ip} ec2-user@${local.operator_ip}"
    maze_role           = "layer-3-milestone"
    maze_note           = "G accepts from F only; not a configured destination — discovered by organism"
  })

  tags = {
    Name      = "physarum-pf1-host-g"
    LabNode   = "G"
    LabRole   = "layer3"
    MazeLayer = "layer3"
  }
}
