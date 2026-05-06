#!/usr/bin/env bash
set -euxo pipefail

# Bootstrap script for physarum-server (coordinator, node A).
# Runs on Amazon Linux 2023.
#
# Terraform-injected variables (substituted by templatefile() at apply time):
#   name_prefix              = ${name_prefix}
#   enable_artifact_download = ${enable_artifact_download}
#   artifact_bucket          = ${artifact_bucket}
#   artifact_prefix          = ${artifact_prefix}
#   artifact_region          = ${artifact_region}

NAME_PREFIX="${name_prefix}"
ENABLE_ARTIFACT_DOWNLOAD="${enable_artifact_download}"
ARTIFACT_BUCKET="${artifact_bucket}"
ARTIFACT_PREFIX="${artifact_prefix}"
ARTIFACT_REGION="${artifact_region}"

# Install dependencies
dnf update -y
dnf install -y jq curl

if [ "$ENABLE_ARTIFACT_DOWNLOAD" = "true" ]; then
  # Download physarum-server binary from S3 using the attached IAM Instance Profile.
  # No static AWS credentials required or permitted.
  if ! command -v aws &>/dev/null; then
    dnf install -y awscli2
  fi

  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-server" \
    /usr/local/bin/physarum-server \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-server

  # Verified ExecStart flags: cargo run -p physarum-server -- --help
  #   --listen <LISTEN>  [default: 0.0.0.0:8080]
  cat > /etc/systemd/system/physarum-server.service << 'UNIT'
[Unit]
Description=physarum-server (coordinator)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/physarum-server --listen 0.0.0.0:8080
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

else
  # Placeholder mode — enable_artifact_download = false.
  # Binary not installed. Systemd unit logs reason and keeps the service visible.
  cat > /etc/systemd/system/physarum-server.service << 'UNIT'
[Unit]
Description=physarum-server (coordinator)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-server binary not installed — artifact download disabled (enable_artifact_download=false)" && sleep infinity'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable physarum-server
systemctl start physarum-server
