locals {
  server_private_ip  = cidrhost(local.subnets.management.cidr, 10)
  agent_b_private_ip = cidrhost(local.subnets.outer.cidr, 10)
  agent_c_private_ip = cidrhost(local.subnets.middle.cidr, 10)
  agent_d_private_ip = cidrhost(local.subnets.inner.cidr, 10)
}

resource "aws_instance" "server_a" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["management"].id
  private_ip             = local.server_private_ip
  vpc_security_group_ids = [aws_security_group.server_a.id]
  key_name               = var.key_name != "" ? var.key_name : null

  user_data = templatefile("${path.module}/user-data/server.sh", {
    name_prefix = var.name_prefix
  })

  tags = {
    Name = "${var.name_prefix}-server-a"
    Role = "coordinator"
  }
}

resource "aws_instance" "agent_b" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["outer"].id
  private_ip             = local.agent_b_private_ip
  vpc_security_group_ids = [aws_security_group.agent_b.id]
  key_name               = var.key_name != "" ? var.key_name : null

  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id          = "agent-b"
    listen_port       = 9001
    coordinator_ip    = local.server_private_ip
    advertise_address = local.agent_b_private_ip
    name_prefix       = var.name_prefix
  })

  tags = {
    Name = "${var.name_prefix}-agent-b"
    Role = "agent"
  }
}

resource "aws_instance" "agent_c" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["middle"].id
  private_ip             = local.agent_c_private_ip
  vpc_security_group_ids = [aws_security_group.agent_c.id]
  key_name               = var.key_name != "" ? var.key_name : null

  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id          = "agent-c"
    listen_port       = 9002
    coordinator_ip    = local.server_private_ip
    advertise_address = local.agent_c_private_ip
    name_prefix       = var.name_prefix
  })

  tags = {
    Name = "${var.name_prefix}-agent-c"
    Role = "agent"
  }
}

resource "aws_instance" "agent_d" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab["inner"].id
  private_ip             = local.agent_d_private_ip
  vpc_security_group_ids = [aws_security_group.agent_d.id]
  key_name               = var.key_name != "" ? var.key_name : null

  user_data = templatefile("${path.module}/user-data/agent.sh", {
    agent_id          = "agent-d"
    listen_port       = 9003
    coordinator_ip    = local.server_private_ip
    advertise_address = local.agent_d_private_ip
    name_prefix       = var.name_prefix
  })

  tags = {
    Name = "${var.name_prefix}-agent-d"
    Role = "agent"
  }
}
