# PF-1 maze security groups — one per host.
#
# Design decisions (Issue #100):
#
#   ICMP stimulus — Option A (systemd timer, reversed direction):
#     Each host in a higher layer pings hosts in the lower layer every 30s.
#     The organism's eBPF sensor captures INCOMING echo requests and uses
#     the source IP as the discovery stimulus for the next propagation cycle.
#
#     Quem pinga    Quem recebe   eBPF captura em
#     ──────────────────────────────────────────────
#     B, C  → A     host-a        "B existe, C existe"
#     D,E,F → B, C  host-b/c      "D existe, E existe, F existe"
#     G     → D,E,F host-d/e/f    "G existe"
#     A     → (nenhum, so recebe — e o seed, organismo parte daqui)
#
#   Verification — Option B (lineage on disk + Ansible):
#     Each propagated organism instance writes /tmp/physarum-lineage.json.
#     Ansible reads all hosts after expansion and prints the full path graph.
#
# Two-layer access control:
#   SG (network level)  — controls which subnets can reach each host
#   sshd AllowUsers     — controls which source IPs can authenticate (OS level)
#
# SSH direction (unchanged — SG allows inbound TCP 22 from previous layer):
#   host-a SSH → host-b, host-c        (front → layer-1)
#   host-b/c SSH → host-d, host-e, host-f  (layer-1 → layer-2)
#   host-d/e/f SSH → host-g            (layer-2 → layer-3)
#
# Layer visibility summary:
#
#   Host A (front)
#     inbound:  SSH from operator
#               ICMP from layer-1 (B and C ping A — eBPF stimulus)
#     outbound: all
#
#   Host B (layer-1)
#     inbound:  SSH from operator + SSH from front (A propagates to B)
#               ICMP from layer-2 (D/E/F ping B — eBPF stimulus)
#     outbound: all
#
#   Host C (layer-1)
#     inbound:  SSH from operator + SSH from front (A propagates to C)
#               ICMP from layer-2 (D/E/F ping C — eBPF stimulus)
#     outbound: all
#
#   Host D (layer-2 - dead end)
#     inbound:  SSH from operator + SSH from layer-1 (port 22 open; sshd rejects)
#               ICMP from layer-3 (G pings D — eBPF stimulus)
#     outbound: all
#
#   Host E (layer-2 - loop risk)
#     inbound:  SSH from operator + SSH from layer-1 (C's IP accepted by sshd)
#               ICMP from layer-3 (G pings E — eBPF stimulus)
#     outbound: all
#
#   Host F (layer-2 - valid corridor)
#     inbound:  SSH from operator + SSH from layer-1 (C's IP accepted by sshd)
#               ICMP from layer-3 (G pings F — eBPF stimulus)
#     outbound: all
#
#   Host G (layer-3 - expansion milestone)
#     inbound:  SSH from operator + SSH from layer-2 (F's IP accepted by sshd)
#               no ICMP ingress (nothing above G pings it)
#     outbound: all (pings D/E/F continuously as stimulus)

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

resource "aws_security_group_rule" "host_a_icmp_from_layer1" {
  type              = "ingress"
  description       = "ICMP from layer-1 (B and C ping A - eBPF discovery stimulus)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer1.cidr]
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

resource "aws_security_group_rule" "host_b_icmp_from_layer2" {
  type              = "ingress"
  description       = "ICMP from layer-2 (D/E/F ping B - eBPF discovery stimulus)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer2.cidr]
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

resource "aws_security_group_rule" "host_c_icmp_from_layer2" {
  type              = "ingress"
  description       = "ICMP from layer-2 (D/E/F ping C - eBPF discovery stimulus)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer2.cidr]
  security_group_id = aws_security_group.host_c.id
}

# ── Host D ingress rules (dead end) ───────────────────────────────────────────
# Port 22 open at SG level so organism from layer-1 can attempt SSH.
# sshd AllowUsers on D permits only the operator — propagation fails at OS level.

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
  description       = "SSH from layer-1 (port 22 open; sshd rejects propagation - dead end)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_d.id
}

resource "aws_security_group_rule" "host_d_icmp_from_layer3" {
  type              = "ingress"
  description       = "ICMP from layer-3 (G pings D - eBPF discovery stimulus)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer3.cidr]
  security_group_id = aws_security_group.host_d.id
}

# ── Host E ingress rules (loop risk) ──────────────────────────────────────────

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
  description       = "SSH from layer-1 (C propagates to E - loop risk)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_e.id
}

resource "aws_security_group_rule" "host_e_icmp_from_layer3" {
  type              = "ingress"
  description       = "ICMP from layer-3 (G pings E - eBPF discovery stimulus)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer3.cidr]
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
  description       = "SSH from layer-1 (C propagates to F - valid corridor)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer1.cidr]
  security_group_id = aws_security_group.host_f.id
}

resource "aws_security_group_rule" "host_f_icmp_from_layer3" {
  type              = "ingress"
  description       = "ICMP from layer-3 (G pings F - eBPF discovery stimulus)"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = [local.subnets.layer3.cidr]
  security_group_id = aws_security_group.host_f.id
}

# ── Host G ingress rules (expansion milestone) ────────────────────────────────
# Port 22 open from layer-2 so D/E/F can attempt SSH after eBPF discovery.
# sshd AllowUsers on G permits only F — D and E are rejected at OS level.
# No ICMP ingress — nothing above G pings it.

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
  description       = "SSH from layer-2 (F propagates to G; D/E rejected by sshd)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.subnets.layer2.cidr]
  security_group_id = aws_security_group.host_g.id
}
