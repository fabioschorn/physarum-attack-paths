# Security groups for the physarum A/B/C/D/E lab.
#
# Security groups are created first (no inline ingress rules) to avoid
# circular dependencies. Rules are added separately via aws_security_group_rule.
#
# Phase identity is controlled by var.lab_phase:
#   phase1          — Mode 1 full mesh: B↔C, B↔D, C↔D all allowed
#   phase2          — Mode 2 segmented: B↔D rules omitted; only B↔C and C↔D allowed
#   weighted-paths  — B↔C, B↔E, C↔D, E↔D; agent-b restricted via --probe-targets (no SG block needed)
#
# The two B↔D rules (agent_b_from_d and agent_d_from_b) use
# count = var.lab_phase == "phase1" ? 1 : 0 to enforce the phase boundary.

resource "aws_security_group" "server_a" {
  name        = "${local.effective_name_prefix}-server-a"
  description = "physarum-server coordinator (A) - ${var.lab_phase}"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-server-a"
  })
}

resource "aws_security_group" "agent_b" {
  name        = "${local.effective_name_prefix}-agent-b"
  description = "physarum-agent-b (B, outer/perimeter) - ${var.lab_phase}"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-b"
  })
}

resource "aws_security_group" "agent_c" {
  name        = "${local.effective_name_prefix}-agent-c"
  description = "physarum-agent-c (C, middle/application) - ${var.lab_phase}"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-c"
  })
}

resource "aws_security_group" "agent_d" {
  name        = "${local.effective_name_prefix}-agent-d"
  description = "physarum-agent-d (D, inner/crown-jewel) - ${var.lab_phase}"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-d"
  })
}

# ── Server A ingress rules ────────────────────────────────────────────────────
# Port 8080 is NOT exposed publicly. Operator access uses SSH only.
# Agents reach the coordinator via internal Security Group references.

resource "aws_security_group_rule" "server_a_from_agent_b" {
  type                     = "ingress"
  description              = "Agent reports from agent-b"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_b.id
  security_group_id        = aws_security_group.server_a.id
}

resource "aws_security_group_rule" "server_a_from_agent_c" {
  type                     = "ingress"
  description              = "Agent reports from agent-c"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_c.id
  security_group_id        = aws_security_group.server_a.id
}

resource "aws_security_group_rule" "server_a_from_agent_d" {
  type                     = "ingress"
  description              = "Agent reports from agent-d"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_d.id
  security_group_id        = aws_security_group.server_a.id
}

resource "aws_security_group_rule" "server_a_ssh" {
  type              = "ingress"
  description       = "SSH from operator (Dev Lead workstation only)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.server_a.id
}

# ── Agent B ingress rules ─────────────────────────────────────────────────────

# Mode 2: remove agent_b_from_d to block D->B probes
resource "aws_security_group_rule" "agent_b_from_c" {
  type                     = "ingress"
  description              = "Probe from agent-c"
  from_port                = 9001
  to_port                  = 9001
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_c.id
  security_group_id        = aws_security_group.agent_b.id
}

resource "aws_security_group_rule" "agent_b_from_d" {
  count = var.lab_phase == "phase1" ? 1 : 0

  type                     = "ingress"
  description              = "Probe from agent-d (phase1/full-mesh only)"
  from_port                = 9001
  to_port                  = 9001
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_d.id
  security_group_id        = aws_security_group.agent_b.id
}

resource "aws_security_group_rule" "agent_b_ssh" {
  type              = "ingress"
  description       = "SSH from operator (Dev Lead workstation only)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.agent_b.id
}

# ── Agent C ingress rules ─────────────────────────────────────────────────────

resource "aws_security_group_rule" "agent_c_from_b" {
  type                     = "ingress"
  description              = "Probe from agent-b"
  from_port                = 9002
  to_port                  = 9002
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_b.id
  security_group_id        = aws_security_group.agent_c.id
}

resource "aws_security_group_rule" "agent_c_from_d" {
  type                     = "ingress"
  description              = "Probe from agent-d"
  from_port                = 9002
  to_port                  = 9002
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_d.id
  security_group_id        = aws_security_group.agent_c.id
}

resource "aws_security_group_rule" "agent_c_ssh" {
  type              = "ingress"
  description       = "SSH from operator (Dev Lead workstation only)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.agent_c.id
}

# ── Agent D ingress rules ─────────────────────────────────────────────────────

# Mode 2: remove agent_d_from_b to block B->D probes
resource "aws_security_group_rule" "agent_d_from_b" {
  count = var.lab_phase == "phase1" ? 1 : 0

  type                     = "ingress"
  description              = "Probe from agent-b (phase1/full-mesh only)"
  from_port                = 9003
  to_port                  = 9003
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_b.id
  security_group_id        = aws_security_group.agent_d.id
}

resource "aws_security_group_rule" "agent_d_from_c" {
  type                     = "ingress"
  description              = "Probe from agent-c"
  from_port                = 9003
  to_port                  = 9003
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_c.id
  security_group_id        = aws_security_group.agent_d.id
}

resource "aws_security_group_rule" "agent_d_from_e" {
  type                     = "ingress"
  description              = "Probe from agent-e"
  from_port                = 9003
  to_port                  = 9003
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_e.id
  security_group_id        = aws_security_group.agent_d.id
}

resource "aws_security_group_rule" "agent_d_ssh" {
  type              = "ingress"
  description       = "SSH from operator (Dev Lead workstation only)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.agent_d.id
}

# ── Agent E security group ────────────────────────────────────────────────────

resource "aws_security_group" "agent_e" {
  name        = "${local.effective_name_prefix}-agent-e"
  description = "physarum-agent-e (E, secondary/alternate path) - ${var.lab_phase}"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-agent-e"
  })
}

# ── Agent E ingress rules ─────────────────────────────────────────────────────

resource "aws_security_group_rule" "agent_e_from_b" {
  type                     = "ingress"
  description              = "Probe from agent-b"
  from_port                = 9004
  to_port                  = 9004
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_b.id
  security_group_id        = aws_security_group.agent_e.id
}

resource "aws_security_group_rule" "agent_e_from_d" {
  type                     = "ingress"
  description              = "Probe from agent-d"
  from_port                = 9004
  to_port                  = 9004
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_d.id
  security_group_id        = aws_security_group.agent_e.id
}

resource "aws_security_group_rule" "agent_e_from_c" {
  type                     = "ingress"
  description              = "Probe from agent-c"
  from_port                = 9004
  to_port                  = 9004
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_c.id
  security_group_id        = aws_security_group.agent_e.id
}

resource "aws_security_group_rule" "agent_e_ssh" {
  type              = "ingress"
  description       = "SSH from operator (Dev Lead workstation only)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.agent_e.id
}

# ── Server A ← Agent E reports ────────────────────────────────────────────────

resource "aws_security_group_rule" "server_a_from_agent_e" {
  type                     = "ingress"
  description              = "Agent reports from agent-e"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_e.id
  security_group_id        = aws_security_group.server_a.id
}

# ── Agent B ← Agent E probes ──────────────────────────────────────────────────

resource "aws_security_group_rule" "agent_b_from_e" {
  type                     = "ingress"
  description              = "Probe from agent-e"
  from_port                = 9001
  to_port                  = 9001
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_e.id
  security_group_id        = aws_security_group.agent_b.id
}

# ── Agent C ← Agent E probes ──────────────────────────────────────────────────

resource "aws_security_group_rule" "agent_c_from_e" {
  type                     = "ingress"
  description              = "Probe from agent-e"
  from_port                = 9002
  to_port                  = 9002
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_e.id
  security_group_id        = aws_security_group.agent_c.id
}
