resource "aws_iam_role" "seed_ec2" {
  name = "${var.name_prefix}-seed-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${var.name_prefix}-seed-ec2-role"
  }

  lifecycle {
    precondition {
      condition     = !(var.enable_seed_artifact_download && var.artifact_bucket == "")
      error_message = "artifact_bucket must be set when enable_seed_artifact_download is true."
    }
  }
}

resource "aws_iam_instance_profile" "seed_ec2" {
  name = "${var.name_prefix}-seed-ec2-profile"
  role = aws_iam_role.seed_ec2.name
}

resource "aws_iam_role_policy" "seed_s3_artifact" {
  count = (var.enable_seed_artifact_download && var.artifact_bucket != "") ? 1 : 0

  name = "${var.name_prefix}-seed-s3-artifact"
  role = aws_iam_role.seed_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.artifact_bucket}/${var.artifact_prefix}/*"
    }]
  })
}
