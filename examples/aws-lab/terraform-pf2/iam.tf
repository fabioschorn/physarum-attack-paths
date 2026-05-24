# IAM role + instance profile for PF-2 maze hosts.
# Same scope as PF-1: least-privilege s3:GetObject so Host A can download
# the physarum-maze binary during cloud-init without static credentials.

resource "aws_iam_role" "pf2_ec2" {
  name = "physarum-pf2-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "physarum-pf2-ec2-role"
    Lab  = "pf-2"
  }
}

resource "aws_iam_instance_profile" "pf2_ec2" {
  name = "physarum-pf2-ec2-profile"
  role = aws_iam_role.pf2_ec2.name
}

resource "aws_iam_role_policy" "pf2_s3_artifact" {
  name = "physarum-pf2-s3-artifact"
  role = aws_iam_role.pf2_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.artifact_bucket}/${var.artifact_prefix}/*"
    }]
  })
}
