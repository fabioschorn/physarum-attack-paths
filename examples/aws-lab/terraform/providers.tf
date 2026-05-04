provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "physarum-attack-paths"
      Prefix    = var.name_prefix
      ManagedBy = "terraform"
    }
  }
}
