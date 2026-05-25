# PF-2 maze network — 5-subnet topology (extends PF-1 with a cross-subnet for Host X).
#
# Layer topology:
#   front   (10.60.10.0/24)  — Host A (seed) + Host A.1 (lateral discovery target)
#   layer-1 (10.60.20.0/24)  — Host B, C   (first expansion layer)
#   layer-2 (10.60.30.0/24)  — Host D, E, F (branching layer: dead-end, loop-risk, valid)
#   layer-3 (10.60.40.0/24)  — Host G only  (expansion milestone)
#   cross   (10.60.50.0/24)  — Host X       (adaptive re-routing probe; direct access to G)
#
# PF-2 behaviour additions:
#   - A discovers A.1 via periodic /24 nmap scan (same front subnet)
#   - X sends TCP SYN to A.1:22 every 30s (stimulus timer, starts at T+5min)
#   - A.1 captures TCP SYN → discovers X → propagates to X
#   - G pings X with ICMP → X captures stimulus → discovers G
#   - G is already colonized by PF-1 path (A→B/C→F→G) → X records secondary conduit

locals {
  subnets = {
    front  = { cidr = "10.60.10.0/24", az_index = 0 }
    layer1 = { cidr = "10.60.20.0/24", az_index = 0 }
    layer2 = { cidr = "10.60.30.0/24", az_index = 0 }
    layer3 = { cidr = "10.60.40.0/24", az_index = 0 }
    cross  = { cidr = "10.60.50.0/24", az_index = 0 }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "maze" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "physarum-pf2-vpc" }
}

resource "aws_subnet" "maze" {
  for_each = local.subnets

  vpc_id                  = aws_vpc.maze.id
  cidr_block              = each.value.cidr
  availability_zone       = data.aws_availability_zones.available.names[each.value.az_index]
  map_public_ip_on_launch = true

  tags = { Name = "physarum-pf2-${each.key}" }
}

resource "aws_internet_gateway" "maze" {
  vpc_id = aws_vpc.maze.id
  tags   = { Name = "physarum-pf2-igw" }
}

resource "aws_route_table" "maze" {
  for_each = local.subnets

  vpc_id = aws_vpc.maze.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.maze.id
  }

  tags = { Name = "physarum-pf2-rt-${each.key}" }
}

resource "aws_route_table_association" "maze" {
  for_each = local.subnets

  subnet_id      = aws_subnet.maze[each.key].id
  route_table_id = aws_route_table.maze[each.key].id
}
