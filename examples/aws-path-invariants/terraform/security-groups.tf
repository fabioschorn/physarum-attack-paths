resource "aws_security_group" "seed" {
  name        = "${var.name_prefix}-seed"
  description = "physarum-maze seed/source node"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "Outbound Internet and lab access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-seed"
  }
}

resource "aws_security_group" "target_c" {
  name        = "${var.name_prefix}-target-c"
  description = "Gate K.1 indirect-path target C"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "Outbound Internet and lab access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-target-c"
  }
}

resource "aws_security_group" "target_d" {
  name        = "${var.name_prefix}-target-d"
  description = "Gate K.1 indirect-path target D"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "Outbound Internet and lab access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-target-d"
  }
}

resource "aws_security_group" "target_e" {
  name        = "${var.name_prefix}-target-e"
  description = "Gate K.1 direct and final target E"
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "Outbound Internet and lab access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-target-e"
  }
}

# ── Operator access ──────────────────────────────────────────────────────────

resource "aws_security_group_rule" "seed_ssh_from_operator" {
  type              = "ingress"
  description       = "SSH from operator laptop only"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.seed.id
}

resource "aws_security_group_rule" "seed_dashboard_from_operator" {
  type              = "ingress"
  description       = "physarum-maze HTTPS dashboard from operator laptop only"
  from_port         = 8443
  to_port           = 8443
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.seed.id
}

resource "aws_security_group_rule" "target_c_ssh_from_operator" {
  type              = "ingress"
  description       = "SSH from operator laptop for Ansible bootstrap"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.target_c.id
}

resource "aws_security_group_rule" "target_d_ssh_from_operator" {
  type              = "ingress"
  description       = "SSH from operator laptop for Ansible bootstrap"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.target_d.id
}

resource "aws_security_group_rule" "target_e_ssh_from_operator" {
  type              = "ingress"
  description       = "SSH from operator laptop for Ansible bootstrap"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.operator_cidr]
  security_group_id = aws_security_group.target_e.id
}

# ── Internal seed services ───────────────────────────────────────────────────

resource "aws_security_group_rule" "seed_mtls_from_targets" {
  for_each = {
    target_c = aws_security_group.target_c.id
    target_d = aws_security_group.target_d.id
    target_e = aws_security_group.target_e.id
  }

  type                     = "ingress"
  description              = "mTLS/back-channel reports from propagated agents"
  from_port                = 8444
  to_port                  = 8444
  protocol                 = "tcp"
  source_security_group_id = each.value
  security_group_id        = aws_security_group.seed.id
}

resource "aws_security_group_rule" "seed_bootstrap_from_targets" {
  for_each = {
    target_c = aws_security_group.target_c.id
    target_d = aws_security_group.target_d.id
    target_e = aws_security_group.target_e.id
  }

  type                     = "ingress"
  description              = "temporary HTTP bootstrap fallback from propagated agents"
  from_port                = 8001
  to_port                  = 8001
  protocol                 = "tcp"
  source_security_group_id = each.value
  security_group_id        = aws_security_group.seed.id
}

resource "aws_security_group_rule" "seed_icmp_from_targets" {
  for_each = {
    target_c = aws_security_group.target_c.id
    target_d = aws_security_group.target_d.id
    target_e = aws_security_group.target_e.id
  }

  type                     = "ingress"
  description              = "ICMP stimulus from lab targets to physarum-maze seed"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = each.value
  security_group_id        = aws_security_group.seed.id
}

# ── Gate K.1-inspired internal path shape ───────────────────────────────────

resource "aws_security_group_rule" "target_c_from_seed" {
  type                     = "ingress"
  description              = "seed/source can reach target-c"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.seed.id
  security_group_id        = aws_security_group.target_c.id
}

resource "aws_security_group_rule" "target_e_from_seed" {
  type                     = "ingress"
  description              = "seed/source direct path to target-e"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.seed.id
  security_group_id        = aws_security_group.target_e.id
}

resource "aws_security_group_rule" "target_d_from_c" {
  type                     = "ingress"
  description              = "indirect path leg target-c to target-d"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.target_c.id
  security_group_id        = aws_security_group.target_d.id
}

resource "aws_security_group_rule" "target_e_from_d" {
  type                     = "ingress"
  description              = "indirect path leg target-d to target-e"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.target_d.id
  security_group_id        = aws_security_group.target_e.id
}

resource "aws_security_group_rule" "target_ssh_from_seed" {
  for_each = {
    target_c = aws_security_group.target_c.id
    target_d = aws_security_group.target_d.id
    target_e = aws_security_group.target_e.id
  }

  type                     = "ingress"
  description              = "SCP/SSH delivery from seed after policy-gated exploitation"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.seed.id
  security_group_id        = each.value
}
