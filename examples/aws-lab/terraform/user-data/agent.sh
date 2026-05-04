#!/usr/bin/env bash
set -euxo pipefail

# Bootstrap script for physarum-agent (nodes B, C, D).
# Parameterized via Terraform templatefile — variables injected at apply time.
# Runs on Amazon Linux 2023.

AGENT_ID="${agent_id}"
LISTEN_PORT="${listen_port}"
COORDINATOR_IP="${coordinator_ip}"
ADVERTISE_ADDRESS="${advertise_address}"
NAME_PREFIX="${name_prefix}"

# Install dependencies
dnf update -y
dnf install -y jq curl

# PLACEHOLDER: physarum-agent binary installation.
#
# The physarum-agent binary is not yet distributed via a package registry or
# S3 artifact bucket. To deploy a real lab:
#
#   Option 1 — build on instance:
#     dnf install -y rust cargo
#     git clone <repo-url> /opt/physarum-attack-paths
#     cd /opt/physarum-attack-paths && cargo build --release
#     cp target/release/physarum-agent /usr/local/bin/physarum-agent
#
#   Option 2 — upload binary to S3 and download here:
#     aws s3 cp s3://<bucket>/physarum-agent /usr/local/bin/physarum-agent
#     chmod +x /usr/local/bin/physarum-agent
#
# Until one of the above is in place, this script installs dependencies only
# and writes a placeholder systemd unit that logs the intended command.

cat > /etc/systemd/system/physarum-agent.service << UNIT
[Unit]
Description=physarum-agent ($AGENT_ID)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-agent binary not installed — would run: physarum-agent --id $AGENT_ID --coordinator http://$COORDINATOR_IP:8080 --listen 0.0.0.0:$LISTEN_PORT --advertise-address $ADVERTISE_ADDRESS --probe-interval-seconds 5" && sleep infinity'
Restart=on-failure
RestartSec=10
Environment=AGENT_ID=$AGENT_ID

[Install]
WantedBy=multi-user.target
UNIT

# Uncomment and replace ExecStart above with this once the binary is installed:
# ExecStart=/usr/local/bin/physarum-agent \
#   --id $AGENT_ID \
#   --coordinator http://$COORDINATOR_IP:8080 \
#   --listen 0.0.0.0:$LISTEN_PORT \
#   --advertise-address $ADVERTISE_ADDRESS \
#   --probe-interval-seconds 5

systemctl daemon-reload
systemctl enable physarum-agent
systemctl start physarum-agent
