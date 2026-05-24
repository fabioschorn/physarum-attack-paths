provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "physarum-attack-paths"
      Lab       = "aws-lab"
      Phase     = "pf-2"
      ManagedBy = "terraform"
    }
  }
}
