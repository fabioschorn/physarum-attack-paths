#!/usr/bin/env bash
set -euxo pipefail

# Bootstrap script for physarum-server (coordinator, node A).
# Runs on Amazon Linux 2023.

NAME_PREFIX="${name_prefix}"

# Install dependencies
dnf update -y
dnf install -y jq curl

# PLACEHOLDER: physarum-server binary installation.
#
# The physarum-server binary is not yet distributed via a package registry or
# S3 artifact bucket. To deploy a real lab:
#
#   Option 1 — build on instance:
#     dnf install -y rust cargo
#     git clone <repo-url> /opt/physarum-attack-paths
#     cd /opt/physarum-attack-paths && cargo build --release
#     cp target/release/physarum-server /usr/local/bin/physarum-server
#
#   Option 2 — upload binary to S3 and download here:
#     aws s3 cp s3://<bucket>/physarum-server /usr/local/bin/physarum-server
#     chmod +x /usr/local/bin/physarum-server
#
# Until one of the above is in place, this script installs dependencies only
# and writes a placeholder systemd unit that logs the missing binary.

cat > /etc/systemd/system/physarum-server.service << 'UNIT'
[Unit]
Description=physarum-server (coordinator)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-server binary not installed — see user-data/server.sh for installation options" && sleep infinity'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

# Uncomment and update the ExecStart line above with the real binary once installed:
# ExecStart=/usr/local/bin/physarum-server --listen 0.0.0.0:8080

systemctl daemon-reload
systemctl enable physarum-server
systemctl start physarum-server
