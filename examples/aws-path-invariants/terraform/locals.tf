locals {
  subnets = {
    outer = {
      cidr     = cidrsubnet(var.vpc_cidr, 8, 20)
      az_index = 0
    }
    middle = {
      cidr     = cidrsubnet(var.vpc_cidr, 8, 30)
      az_index = 0
    }
    inner = {
      cidr     = cidrsubnet(var.vpc_cidr, 8, 40)
      az_index = 0
    }
    secondary = {
      cidr     = cidrsubnet(var.vpc_cidr, 8, 50)
      az_index = 0
    }
  }

  seed_private_ip     = cidrhost(local.subnets.outer.cidr, 10)
  target_c_private_ip = cidrhost(local.subnets.middle.cidr, 10)
  target_d_private_ip = cidrhost(local.subnets.inner.cidr, 10)
  target_e_private_ip = cidrhost(local.subnets.secondary.cidr, 10)

  common_tags = {
    Project   = "physarum-attack-paths"
    Lab       = "aws-path-invariants"
    Issue     = "201"
    ManagedBy = "terraform"
  }
}
