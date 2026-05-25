# PF-2 maze security groups.
#
# Design additions over PF-1:
#
#   Host A.1 (front lateral):
#     inbound:  SSH from A (propagation A→A.1)
#               SSH from X (TCP SYN stimulus: X connects to A.1:22; sshd rejects
#                           auth but raw TCP listener on A.1 captures the SYN)
#               ICMP from B, C (keep A.1's agent alive while waiting for X stimulus)
#               SSH from operator
#     outbound: all
#
#   Host X (cross probe):
#     inbound:  SSH from A.1 (propagation A.1→X)
#               ICMP from G (G pings X — ICMP stimulus for X to discover G)
#               SSH from operator
#     outbound: all (reaches A.1:22 for TCP stimulus; reaches G for colonized check)
#
#   Host G (PF-2 update):
#     Additional inbound TCP 22 from X (for the already-colonized SSH check;
#     sshd AllowUsers includes X's IP so the check can complete).
#
# All SGs use the shell pattern (no inline rules) to avoid circular dependencies.
# Rules are added as separate aws_security_group_rule resources.

# ── SG shells ─────────────────────────────────────────────────────────────────

resource "aws_security_group" "host_a" {
  name        = "physarum-pf2-host-a"
  description = "PF-2 Host A - seed (front subnet)"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-a" }
}

resource "aws_security_group" "host_a1" {
  name        = "physarum-pf2-host-a1"
  description = "PF-2 Host A.1 - front lateral"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-a1" }
}

resource "aws_security_group" "host_b" {
  name        = "physarum-pf2-host-b"
  description = "PF-2 Host B - layer-1"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-b" }
}

resource "aws_security_group" "host_c" {
  name        = "physarum-pf2-host-c"
  description = "PF-2 Host C - layer-1 bifurcation"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-c" }
}

resource "aws_security_group" "host_d" {
  name        = "physarum-pf2-host-d"
  description = "PF-2 Host D - layer-2 dead end"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-d" }
}

resource "aws_security_group" "host_e" {
  name        = "physarum-pf2-host-e"
  description = "PF-2 Host E - layer-2 loop risk"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-e" }
}

resource "aws_security_group" "host_f" {
  name        = "physarum-pf2-host-f"
  description = "PF-2 Host F - layer-2 valid corridor"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-f" }
}

resource "aws_security_group" "host_g" {
  name        = "physarum-pf2-host-g"
  description = "PF-2 Host G - layer-3 milestone"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-g" }
}

resource "aws_security_group" "host_x" {
  name        = "physarum-pf2-host-x"
  description = "PF-2 Host X - cross subnet adaptive probe"
  vpc_id      = aws_vpc.maze.id
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "physarum-pf2-host-x" }
}

# ── Operator SSH access (all hosts) ───────────────────────────────────────────

locals {
  all_maze_sgs = [
    aws_security_group.host_a.id,
    aws_security_group.host_a1.id,
    aws_security_group.host_b.id,
    aws_security_group.host_c.id,
    aws_security_group.host_d.id,
    aws_security_group.host_e.id,
    aws_security_group.host_f.id,
    aws_security_group.host_g.id,
    aws_security_group.host_x.id,
  ]
}

resource "aws_security_group_rule" "operator_ssh" {
  count             = length(local.all_maze_sgs)
  type              = "ingress"
  description       = "Operator SSH access"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = local.all_maze_sgs[count.index]
}

# ── ICMP stimulus rules ────────────────────────────────────────────────────────
# PF-2: B and C ping A and A.1 (ICMP IN on A and A.1 from layer-1).
# G pings D, E, F (existing) and X (PF-2 addition).

resource "aws_security_group_rule" "host_a_icmp_from_b" {
  type                     = "ingress"
  description              = "ICMP from B (B pings A - stimulus)"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_b.id
  security_group_id        = aws_security_group.host_a.id
}

resource "aws_security_group_rule" "host_a_icmp_from_c" {
  type                     = "ingress"
  description              = "ICMP from C (C pings A - stimulus)"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_c.id
  security_group_id        = aws_security_group.host_a.id
}

resource "aws_security_group_rule" "host_a1_icmp_from_b" {
  type                     = "ingress"
  description              = "ICMP from B (B pings A.1 - stimulus to keep A.1 agent alive)"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_b.id
  security_group_id        = aws_security_group.host_a1.id
}

resource "aws_security_group_rule" "host_a1_icmp_from_c" {
  type                     = "ingress"
  description              = "ICMP from C (C pings A.1 - stimulus)"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_c.id
  security_group_id        = aws_security_group.host_a1.id
}

resource "aws_security_group_rule" "host_b_icmp_from_d" {
  type                     = "ingress"
  description              = "ICMP from D"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_d.id
  security_group_id        = aws_security_group.host_b.id
}

resource "aws_security_group_rule" "host_b_icmp_from_e" {
  type                     = "ingress"
  description              = "ICMP from E"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_e.id
  security_group_id        = aws_security_group.host_b.id
}

resource "aws_security_group_rule" "host_b_icmp_from_f" {
  type                     = "ingress"
  description              = "ICMP from F"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_f.id
  security_group_id        = aws_security_group.host_b.id
}

resource "aws_security_group_rule" "host_c_icmp_from_d" {
  type                     = "ingress"
  description              = "ICMP from D"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_d.id
  security_group_id        = aws_security_group.host_c.id
}

resource "aws_security_group_rule" "host_c_icmp_from_e" {
  type                     = "ingress"
  description              = "ICMP from E"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_e.id
  security_group_id        = aws_security_group.host_c.id
}

resource "aws_security_group_rule" "host_c_icmp_from_f" {
  type                     = "ingress"
  description              = "ICMP from F"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_f.id
  security_group_id        = aws_security_group.host_c.id
}

resource "aws_security_group_rule" "host_d_icmp_from_g" {
  type                     = "ingress"
  description              = "ICMP from G"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_g.id
  security_group_id        = aws_security_group.host_d.id
}

resource "aws_security_group_rule" "host_e_icmp_from_g" {
  type                     = "ingress"
  description              = "ICMP from G"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_g.id
  security_group_id        = aws_security_group.host_e.id
}

resource "aws_security_group_rule" "host_f_icmp_from_g" {
  type                     = "ingress"
  description              = "ICMP from G"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_g.id
  security_group_id        = aws_security_group.host_f.id
}

# PF-2: G pings X — X captures ICMP from G and discovers G.
resource "aws_security_group_rule" "host_x_icmp_from_g" {
  type                     = "ingress"
  description              = "ICMP from G (G pings X - ICMP stimulus for X to discover G)"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.host_g.id
  security_group_id        = aws_security_group.host_x.id
}

# ── SSH propagation rules ──────────────────────────────────────────────────────

# front → layer-1: A propagates to B and C
resource "aws_security_group_rule" "host_b_ssh_from_a" {
  type                     = "ingress"
  description              = "SSH from A (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_a.id
  security_group_id        = aws_security_group.host_b.id
}

resource "aws_security_group_rule" "host_c_ssh_from_a" {
  type                     = "ingress"
  description              = "SSH from A (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_a.id
  security_group_id        = aws_security_group.host_c.id
}

# front: A propagates to A.1 (same subnet — PF-2)
resource "aws_security_group_rule" "host_a1_ssh_from_a" {
  type                     = "ingress"
  description              = "SSH from A (propagation A to A.1)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_a.id
  security_group_id        = aws_security_group.host_a1.id
}

# PF-2: X sends TCP SYN to A.1:22 as stimulus.
# A.1's sshd rejects X's auth (not in AllowUsers), but the raw TCP SYN is
# captured by A.1's tcp.rs listener. SG must allow the TCP connection to reach A.1.
resource "aws_security_group_rule" "host_a1_tcp22_from_x" {
  type                     = "ingress"
  description              = "TCP 22 from X (TCP SYN stimulus - sshd rejects auth; raw socket captures SYN)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_x.id
  security_group_id        = aws_security_group.host_a1.id
}

# layer-1 → layer-2: B and C can reach D, E, F
resource "aws_security_group_rule" "host_d_ssh_from_b" {
  type                     = "ingress"
  description              = "SSH from B (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_b.id
  security_group_id        = aws_security_group.host_d.id
}

resource "aws_security_group_rule" "host_d_ssh_from_c" {
  type                     = "ingress"
  description              = "SSH from C (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_c.id
  security_group_id        = aws_security_group.host_d.id
}

resource "aws_security_group_rule" "host_e_ssh_from_b" {
  type                     = "ingress"
  description              = "SSH from B (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_b.id
  security_group_id        = aws_security_group.host_e.id
}

resource "aws_security_group_rule" "host_e_ssh_from_c" {
  type                     = "ingress"
  description              = "SSH from C (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_c.id
  security_group_id        = aws_security_group.host_e.id
}

resource "aws_security_group_rule" "host_f_ssh_from_b" {
  type                     = "ingress"
  description              = "SSH from B (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_b.id
  security_group_id        = aws_security_group.host_f.id
}

resource "aws_security_group_rule" "host_f_ssh_from_c" {
  type                     = "ingress"
  description              = "SSH from C (propagation)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_c.id
  security_group_id        = aws_security_group.host_f.id
}

# layer-2 → layer-3: F (valid) and D, E (dead ends at sshd) can reach G at SG level
resource "aws_security_group_rule" "host_g_ssh_from_d" {
  type                     = "ingress"
  description              = "SSH from D (layer-2)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_d.id
  security_group_id        = aws_security_group.host_g.id
}

resource "aws_security_group_rule" "host_g_ssh_from_e" {
  type                     = "ingress"
  description              = "SSH from E (layer-2)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_e.id
  security_group_id        = aws_security_group.host_g.id
}

resource "aws_security_group_rule" "host_g_ssh_from_f" {
  type                     = "ingress"
  description              = "SSH from F (layer-2 valid corridor)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_f.id
  security_group_id        = aws_security_group.host_g.id
}

# PF-2: X SSHes into G to run the already-colonized check.
# G's sshd AllowUsers includes X so the check command can execute.
resource "aws_security_group_rule" "host_g_ssh_from_x" {
  type                     = "ingress"
  description              = "SSH from X (already-colonized check; G accepted in AllowUsers)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_x.id
  security_group_id        = aws_security_group.host_g.id
}

# PF-2: A.1 propagates to X
resource "aws_security_group_rule" "host_x_ssh_from_a1" {
  type                     = "ingress"
  description              = "SSH from A.1 (propagation A.1 to X)"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.host_a1.id
  security_group_id        = aws_security_group.host_x.id
}
