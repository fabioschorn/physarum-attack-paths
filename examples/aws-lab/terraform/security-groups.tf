# Security groups for the physarum A/B/C/D lab.
#
# Security groups are created first (no inline ingress rules) to avoid
# circular dependencies. Rules are added separately via aws_security_group_rule.
#
# Current mode: Mode 1 — full mesh.
# All agents can probe all other agents on their respective ports.
#
# Mode 2 (segmented — B->D blocked, B->C->D only):
#   Remove or comment out:
#     aws_security_group_rule.agent_b_from_d (inbound to B from D)
#     aws_security_group_rule.agent_d_from_b (inbound to D from B)
#   This forces B->D probes to fail, decaying that edge, leaving only B->C->D.

resource "aws_security_group" "server_a" {
  name        = "${var.name_prefix}-server-a"
  description = "physarum-server coordinator (A)"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-server-a"
  }
}

resource "aws_security_group" "agent_b" {
  name        = "${var.name_prefix}-agent-b"
  description = "physarum-agent-b (B, outer/perimeter)"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-agent-b"
  }
}

resource "aws_security_group" "agent_c" {
  name        = "${var.name_prefix}-agent-c"
  description = "physarum-agent-c (C, middle/application)"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-agent-c"
  }
}

resource "aws_security_group" "agent_d" {
  name        = "${var.name_prefix}-agent-d"
  description = "physarum-agent-d (D, inner/crown-jewel)"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-agent-d"
  }
}

# ── Server A ingress rules ────────────────────────────────────────────────────

resource "aws_security_group_rule" "server_a_from_operator" {
  type              = "ingress"
  description       = "Coordinator API from operator"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.server_a.id
}

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
  count             = var.key_name != "" ? 1 : 0
  type              = "ingress"
  description       = "SSH from operator"
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
  type                     = "ingress"
  description              = "Probe from agent-d (Mode 1 only - remove for Mode 2)"
  from_port                = 9001
  to_port                  = 9001
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.agent_d.id
  security_group_id        = aws_security_group.agent_b.id
}

resource "aws_security_group_rule" "agent_b_ssh" {
  count             = var.key_name != "" ? 1 : 0
  type              = "ingress"
  description       = "SSH from operator"
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
  count             = var.key_name != "" ? 1 : 0
  type              = "ingress"
  description       = "SSH from operator"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.agent_c.id
}

# ── Agent D ingress rules ─────────────────────────────────────────────────────

# Mode 2: remove agent_d_from_b to block B->D probes
resource "aws_security_group_rule" "agent_d_from_b" {
  type                     = "ingress"
  description              = "Probe from agent-b (Mode 1 only - remove for Mode 2)"
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

resource "aws_security_group_rule" "agent_d_ssh" {
  count             = var.key_name != "" ? 1 : 0
  type              = "ingress"
  description       = "SSH from operator"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.agent_d.id
}
