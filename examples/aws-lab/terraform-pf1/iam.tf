# IAM role + instance profile for PF-1 maze hosts.
# Grants least-privilege s3:GetObject on the artifact prefix so Host A can
# download the physarum-maze binary during cloud-init without static credentials.

resource "aws_iam_role" "pf1_ec2" {
  name = "physarum-pf1-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "physarum-pf1-ec2-role"
    Lab  = "pf-1"
  }
}

resource "aws_iam_instance_profile" "pf1_ec2" {
  name = "physarum-pf1-ec2-profile"
  role = aws_iam_role.pf1_ec2.name
}

resource "aws_iam_role_policy" "pf1_s3_artifact" {
  name = "physarum-pf1-s3-artifact"
  role = aws_iam_role.pf1_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.artifact_bucket}/${var.artifact_prefix}/*"
    }]
  })
}
