#!/usr/bin/env bash
set -euxo pipefail

# Bootstrap script for physarum-agent (nodes B, C, D, E).
# Parameterized via Terraform templatefile — variables injected at apply time.
# Runs on Amazon Linux 2023.
#
# Terraform-injected variables (substituted by templatefile() at apply time):
#   agent_id                 = ${agent_id}
#   listen_port              = ${listen_port}
#   coordinator_ip           = ${coordinator_ip}
#   advertise_address        = ${advertise_address}
#   probe_targets            = ${probe_targets}   (empty = probe all peers)
#   name_prefix              = ${name_prefix}
#   enable_artifact_download = ${enable_artifact_download}
#   artifact_bucket          = ${artifact_bucket}
#   artifact_prefix          = ${artifact_prefix}
#   artifact_region          = ${artifact_region}

AGENT_ID="${agent_id}"
LISTEN_PORT="${listen_port}"
COORDINATOR_IP="${coordinator_ip}"
ADVERTISE_ADDRESS="${advertise_address}"
PROBE_TARGETS="${probe_targets}"
NAME_PREFIX="${name_prefix}"
ENABLE_ARTIFACT_DOWNLOAD="${enable_artifact_download}"
ARTIFACT_BUCKET="${artifact_bucket}"
ARTIFACT_PREFIX="${artifact_prefix}"
ARTIFACT_REGION="${artifact_region}"

# Build optional --probe-targets flag (lab-only topology control; empty = probe all)
PROBE_TARGETS_FLAG=""
if [ -n "$PROBE_TARGETS" ]; then
  PROBE_TARGETS_FLAG="--probe-targets $PROBE_TARGETS"
fi

# Install dependencies
dnf update -y
dnf install -y jq iproute-tc

# Log bootstrap configuration for cloud-init diagnostics (no secrets logged)
echo "physarum bootstrap: enable_artifact_download=$ENABLE_ARTIFACT_DOWNLOAD"
echo "physarum bootstrap: artifact_bucket_set=$([ -n "$ARTIFACT_BUCKET" ] && echo yes || echo no)"
echo "physarum bootstrap: artifact_prefix=$ARTIFACT_PREFIX"
echo "physarum bootstrap: artifact_region=$ARTIFACT_REGION"

if [ "$ENABLE_ARTIFACT_DOWNLOAD" = "true" ]; then
  # Download physarum-agent binary from S3 using the attached IAM Instance Profile.
  # No static AWS credentials required or permitted.
  if ! command -v aws &>/dev/null; then
    dnf install -y awscli2 || \
    dnf install -y aws-cli2 || \
    dnf install -y awscli
  fi
  if ! command -v aws &>/dev/null; then
    echo "ERROR: AWS CLI not available after install attempt — cannot download artifacts"
    exit 1
  fi

  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-agent" \
    /usr/local/bin/physarum-agent \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-agent

  # Verified ExecStart flags: cargo run -p physarum-agent -- --help
  #   --id <ID>                          (required)
  #   --coordinator <COORDINATOR>        (required)
  #   --listen <LISTEN>                  (required)
  #   --advertise-address <ADDR>         (required)
  #   --probe-interval-seconds <N>       [default: 10]
  #   --probe-targets <IDS>              [default: probe all; lab-only]
  cat > /etc/systemd/system/physarum-agent.service << UNIT
[Unit]
Description=physarum-agent ($AGENT_ID)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/physarum-agent --id $AGENT_ID --coordinator http://$COORDINATOR_IP:8080 --listen 0.0.0.0:$LISTEN_PORT --advertise-address $ADVERTISE_ADDRESS --probe-interval-seconds 10 $PROBE_TARGETS_FLAG
Restart=on-failure
RestartSec=10
Environment=AGENT_ID=$AGENT_ID

[Install]
WantedBy=multi-user.target
UNIT

else
  # Placeholder mode — enable_artifact_download = false.
  # Binary not installed. Systemd unit logs the intended command and keeps the service visible.
  cat > /etc/systemd/system/physarum-agent.service << UNIT
[Unit]
Description=physarum-agent ($AGENT_ID)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-agent binary not installed — artifact download disabled (enable_artifact_download=false) — would run: physarum-agent --id $AGENT_ID --coordinator http://$COORDINATOR_IP:8080 --listen 0.0.0.0:$LISTEN_PORT --advertise-address $ADVERTISE_ADDRESS --probe-interval-seconds 10 $PROBE_TARGETS_FLAG" && sleep infinity'
Restart=on-failure
RestartSec=10
Environment=AGENT_ID=$AGENT_ID

[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable physarum-agent
systemctl start physarum-agent
