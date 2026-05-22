# PF-1 maze security groups — one per host.
#
# Layer visibility rules enforced by SGs:
#
#   Host A (front)
#     inbound:  SSH from operator only
#     outbound: all (reaches layer-1 for propagation + IGW for S3/SSM)
#
#   Host B (layer-1)
#     inbound:  SSH from operator + SSH/ICMP from front (A can reach B)
#     outbound: all
#
#   Host C (layer-1)
#     inbound:  SSH from operator + SSH/ICMP from front (A can reach C)
#     outbound: all
#
#   Host D (layer-2 — dead end)
#     inbound:  SSH from operator + SSH/ICMP from layer-1 (RustScan sees port 22 open)
#     outbound: all
#     sshd AllowUsers: operator only → SSH propagation from B/C fails at OS level
#
#   Host E (layer-2 — loop risk)
#     inbound:  SSH from operator + SSH/ICMP from layer-1
#     outbound: all (including layer-1 — creates feedback/loop signal)
#     sshd AllowUsers: C + operator → propagation from C works, but E sees layer-1 again
#
#   Host F (layer-2 — valid corridor)
#     inbound:  SSH from operator + SSH/ICMP from layer-1
#     outbound: all
#     sshd AllowUsers: C + operator → valid propagation corridor to G
#
#   Host G (layer-3 — expansion milestone)
#     inbound:  SSH from operator + SSH/ICMP from layer-2 (D/E/F can see it)
#     outbound: all
#     sshd AllowUsers: F + operator → only F can propagate to G

# ── Security group shells (no inline rules — avoids circular deps) ────────────

resource "aws_security_group" "host_a" {
  name        = "physarum-pf1-host-a"
  description = "PF-1 Host A - seed (front subnet)"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-a" }
}

resource "aws_security_group" "host_b" {
  name        = "physarum-pf1-host-b"
  description = "PF-1 Host B - layer-1"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-b" }
}

resource "aws_security_group" "host_c" {
  name        = "physarum-pf1-host-c"
  description = "PF-1 Host C - layer-1"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-c" }
}

resource "aws_security_group" "host_d" {
  name        = "physarum-pf1-host-d"
  description = "PF-1 Host D - layer-2 dead end"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-d" }
}

resource "aws_security_group" "host_e" {
  name        = "physarum-pf1-host-e"
  description = "PF-1 Host E - layer-2 loop risk"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-e" }
}

resource "aws_security_group" "host_f" {
  name        = "physarum-pf1-host-f"
  description = "PF-1 Host F - layer-2 valid corridor"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-f" }
}

resource "aws_security_group" "host_g" {
  name        = "physarum-pf1-host-g"
  description = "PF-1 Host G - layer-3 expansion milestone"
  vpc_id      = aws_vpc.maze.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "physarum-pf1-host-g" }
}

# ── Host A ingress rules ───────────────────────────────────────────────────────

resource "aws_security_group_rule" "host_a_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_a.id
}

# ── Host B ingress rules ───────────────────────────────────────────────────────

resource "aws_security_group_rule" "host_b_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_b.id
}

resource "aws_security_group_rule" "host_b_ssh_from_front" {
  type              = "ingress"
  description       = "SSH from front subnet (Host A propagation corridor)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.front.cidr]
  security_group_id = aws_security_group.host_b.id
}

resource "aws_security_group_rule" "host_b_icmp_from_front" {
  type              = "ingress"
  description       = "ICMP from front subnet (A can sense B)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.front.cidr]
  security_group_id = aws_security_group.host_b.id
}

# ── Host C ingress rules ───────────────────────────────────────────────────────

resource "aws_security_group_rule" "host_c_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_c.id
}

resource "aws_security_group_rule" "host_c_ssh_from_front" {
  type              = "ingress"
  description       = "SSH from front subnet (Host A propagation corridor)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.front.cidr]
  security_group_id = aws_security_group.host_c.id
}

resource "aws_security_group_rule" "host_c_icmp_from_front" {
  type              = "ingress"
  description       = "ICMP from front subnet (A can sense C)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.front.cidr]
  security_group_id = aws_security_group.host_c.id
}

# ── Host D ingress rules (dead end) ───────────────────────────────────────────
# Port 22 is open at SG level so RustScan from layer-1 sees it.
# sshd AllowUsers on D permits only the operator — propagation from B/C fails at OS level.

resource "aws_security_group_rule" "host_d_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_d.id
}

resource "aws_security_group_rule" "host_d_ssh_from_layer1" {
  type              = "ingress"
  description       = "SSH from layer-1 (RustScan sees port 22 open; sshd rejects propagation)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_d.id
}

resource "aws_security_group_rule" "host_d_icmp_from_layer1" {
  type              = "ingress"
  description       = "ICMP from layer-1 (D visible by ICMP; not a valid propagation corridor)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_d.id
}

# ── Host E ingress rules (loop risk) ──────────────────────────────────────────
# E accepts SSH from layer-1 at SG level and sshd AllowUsers permits C.
# E's outbound is unrestricted — it can reach back to layer-1 (loop risk).

resource "aws_security_group_rule" "host_e_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_e.id
}

resource "aws_security_group_rule" "host_e_ssh_from_layer1" {
  type              = "ingress"
  description       = "SSH from layer-1 (C can propagate to E; E sees layer-1 again - loop risk)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_e.id
}

resource "aws_security_group_rule" "host_e_icmp_from_layer1" {
  type              = "ingress"
  description       = "ICMP from layer-1 (E visible as candidate from B/C)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_e.id
}

# ── Host F ingress rules (valid corridor) ─────────────────────────────────────

resource "aws_security_group_rule" "host_f_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_f.id
}

resource "aws_security_group_rule" "host_f_ssh_from_layer1" {
  type              = "ingress"
  description       = "SSH from layer-1 (C to F valid propagation corridor)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_f.id
}

resource "aws_security_group_rule" "host_f_icmp_from_layer1" {
  type              = "ingress"
  description       = "ICMP from layer-1 (F visible as candidate from B/C)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_f.id
}

# ── Host G ingress rules (expansion milestone) ────────────────────────────────
# Port 22 open from layer-2 so D/E/F all see it via RustScan.
# sshd AllowUsers on G permits only F — D and E are rejected at OS level.

resource "aws_security_group_rule" "host_g_ssh_operator" {
  type              = "ingress"
  description       = "SSH from operator workstation"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.host_g.id
}

resource "aws_security_group_rule" "host_g_ssh_from_layer2" {
  type              = "ingress"
  description       = "SSH from layer-2 (D/E/F see port 22 open; only F accepted by sshd)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer2.cidr]
  security_group_id = aws_security_group.host_g.id
}

resource "aws_security_group_rule" "host_g_icmp_from_layer2" {
  type              = "ingress"
  description       = "ICMP from layer-2 (G visible as candidate from D/E/F)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer2.cidr]
  security_group_id = aws_security_group.host_g.id
}
