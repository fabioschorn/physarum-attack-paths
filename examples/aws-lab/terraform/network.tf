locals {
  subnets = {
    management = { cidr = "10.50.10.0/24", az_index = 0 }
    outer      = { cidr = "10.50.20.0/24", az_index = 0 }
    middle     = { cidr = "10.50.30.0/24", az_index = 0 }
    inner      = { cidr = "10.50.40.0/24", az_index = 0 }
    secondary  = { cidr = "10.50.50.0/24", az_index = 0 }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-lab-vpc"
  })
}

resource "aws_subnet" "lab" {
  for_each = local.subnets

  vpc_id                  = aws_vpc.lab.id
  cidr_block              = each.value.cidr
  availability_zone       = data.aws_availability_zones.available.names[each.value.az_index]
  map_public_ip_on_launch = true

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-${each.key}"
  })
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-igw"
  })
}

resource "aws_route_table" "lab" {
  for_each = local.subnets

  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = merge(local.phase_tags, {
    Name = "${local.effective_name_prefix}-rt-${each.key}"
  })
}

resource "aws_route_table_association" "lab" {
  for_each = local.subnets

  subnet_id      = aws_subnet.lab[each.key].id
  route_table_id = aws_route_table.lab[each.key].id
}
