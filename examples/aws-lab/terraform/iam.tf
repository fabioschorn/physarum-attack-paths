resource "aws_iam_role" "physarum_ec2" {
  name = "${var.name_prefix}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${var.name_prefix}-ec2-role"
  }
}

resource "aws_iam_instance_profile" "physarum_ec2" {
  name = "${var.name_prefix}-ec2-profile"
  role = aws_iam_role.physarum_ec2.name
}

# Least-privilege s3:GetObject on the artifact prefix only.
# Created only when artifact download is enabled and a bucket name is provided.
resource "aws_iam_role_policy" "physarum_s3_artifact" {
  count = (var.enable_artifact_download && var.artifact_bucket != "") ? 1 : 0

  name = "${var.name_prefix}-s3-artifact"
  role = aws_iam_role.physarum_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.artifact_bucket}/${var.artifact_prefix}/*"
    }]
  })
}
