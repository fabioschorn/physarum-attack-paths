#!/usr/bin/env bash
set -euxo pipefail

# AWS Path Invariants Lab — seed bootstrap.
#
# Installs base tools and, when enabled, downloads physarum-maze from S3 using
# the instance profile attached by Terraform. No static AWS credentials are
# written to the instance.

ENABLE_SEED_ARTIFACT_DOWNLOAD="${enable_seed_artifact_download}"
ARTIFACT_BUCKET="${artifact_bucket}"
ARTIFACT_PREFIX="${artifact_prefix}"
ARTIFACT_REGION="${artifact_region}"
VPC_CIDR="${vpc_cidr}"

dnf update -y
dnf install -y jq python3

echo "physarum path-invariants seed bootstrap"
echo "enable_seed_artifact_download=$ENABLE_SEED_ARTIFACT_DOWNLOAD"
echo "artifact_bucket_set=$([ -n "$ARTIFACT_BUCKET" ] && echo yes || echo no)"
echo "artifact_prefix=$ARTIFACT_PREFIX"
echo "artifact_region=$ARTIFACT_REGION"

if [ "$ENABLE_SEED_ARTIFACT_DOWNLOAD" = "true" ]; then
  if ! command -v aws &>/dev/null; then
    dnf install -y awscli2 || \
    dnf install -y aws-cli2 || \
    dnf install -y awscli
  fi

  if ! command -v aws &>/dev/null; then
    echo "ERROR: AWS CLI unavailable — physarum-maze not installed" >&2
    exit 1
  fi

  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-maze" \
    /usr/local/bin/physarum-maze \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-maze
  /usr/local/bin/physarum-maze --version || true
fi

cat > /etc/physarum-path-invariants.json <<EOF
{
  "lab": "aws-path-invariants",
  "role": "seed",
  "vpc_cidr": "$VPC_CIDR",
  "physarum_maze": "/usr/local/bin/physarum-maze",
  "suggested_launch": "sudo --preserve-env=LLM_API_KEY /usr/local/bin/physarum-maze --llm-endpoint https://api.openai.com --llm-model gpt-4o-mini --llm-allowed-cidr $VPC_CIDR --exploit-enabled --server 8443 --tls"
}
EOF

echo "aws-path-invariants seed bootstrap complete" > /etc/physarum-lab-bootstrap.txt
