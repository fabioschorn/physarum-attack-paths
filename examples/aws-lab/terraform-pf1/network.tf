# PF-1 maze network — 4-subnet, 3-layer topology.
#
# Layer topology:
#   front   (10.60.10.0/24)  — Host A only (seed, isolated front)
#   layer-1 (10.60.20.0/24)  — Host B, C   (first expansion layer)
#   layer-2 (10.60.30.0/24)  — Host D, E, F (branching layer: dead-end, loop-risk, valid)
#   layer-3 (10.60.40.0/24)  — Host G only  (expansion milestone)
#
# Routing enforces layer isolation:
#   front → layer-1:  A can reach B, C
#   layer-1 → layer-2: B, C can reach D, E, F
#   layer-2 → layer-3: D, E, F can reach G
#   front → layer-2/layer-3: BLOCKED (A cannot reach D/E/F/G directly)
#   layer-1 → layer-3: BLOCKED (B/C cannot reach G directly)
#
# Fine-grained SSH propagation control is enforced by sshd_config AllowUsers
# on each host — see user-data scripts.

locals {
  subnets = {
    front  = { cidr = "10.60.10.0/24", az_index = 0 }
    layer1 = { cidr = "10.60.20.0/24", az_index = 0 }
    layer2 = { cidr = "10.60.30.0/24", az_index = 0 }
    layer3 = { cidr = "10.60.40.0/24", az_index = 0 }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "maze" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "physarum-pf1-vpc" }
}

resource "aws_subnet" "maze" {
  for_each = local.subnets

  vpc_id                  = aws_vpc.maze.id
  cidr_block              = each.value.cidr
  availability_zone       = data.aws_availability_zones.available.names[each.value.az_index]
  map_public_ip_on_launch = true

  tags = { Name = "physarum-pf1-${each.key}" }
}

resource "aws_internet_gateway" "maze" {
  vpc_id = aws_vpc.maze.id
  tags   = { Name = "physarum-pf1-igw" }
}

# Each subnet gets its own route table.
# All subnets have a default route to the IGW for operator SSH access (public IPs).
# Inter-subnet routing within the VPC is controlled by Security Groups.
resource "aws_route_table" "maze" {
  for_each = local.subnets

  vpc_id = aws_vpc.maze.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.maze.id
  }

  tags = { Name = "physarum-pf1-rt-${each.key}" }
}

resource "aws_route_table_association" "maze" {
  for_each = local.subnets

  subnet_id      = aws_subnet.maze[each.key].id
  route_table_id = aws_route_table.maze[each.key].id
}
