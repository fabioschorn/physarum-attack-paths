#!/usr/bin/env bash
set -euxo pipefail

# Gate M.3 bootstrap — combined coordinator + physarum-node capability supervisor on node A.
# physarum-server starts first; physarum-node connects to localhost:8080 and supervises
# physarum-agent (probe) and physarum-ebpf-observer (observe-flow) as child processes.
# No separate physarum-agent.service or physarum-ebpf-observer.service are created —
# lifecycle management is delegated to physarum-node.
#
# Terraform-injected variables (substituted by templatefile() at apply time):
#   agent_id                 = ${agent_id}
#   listen_port              = ${listen_port}
#   advertise_address        = ${advertise_address}
#   capabilities             = ${capabilities}
#   name_prefix              = ${name_prefix}
#   enable_artifact_download = ${enable_artifact_download}
#   artifact_bucket          = ${artifact_bucket}
#   artifact_prefix          = ${artifact_prefix}
#   artifact_region          = ${artifact_region}

AGENT_ID="${agent_id}"
LISTEN_PORT="${listen_port}"
ADVERTISE_ADDRESS="${advertise_address}"
CAPABILITIES="${capabilities}"
NAME_PREFIX="${name_prefix}"
ENABLE_ARTIFACT_DOWNLOAD="${enable_artifact_download}"
ARTIFACT_BUCKET="${artifact_bucket}"
ARTIFACT_PREFIX="${artifact_prefix}"
ARTIFACT_REGION="${artifact_region}"

dnf update -y
dnf install -y jq iproute-tc

echo "physarum bootstrap: enable_artifact_download=$ENABLE_ARTIFACT_DOWNLOAD"
echo "physarum bootstrap: capabilities=$CAPABILITIES"

if [ "$ENABLE_ARTIFACT_DOWNLOAD" = "true" ]; then
  if ! command -v aws &>/dev/null; then
    dnf install -y awscli2 || \
    dnf install -y aws-cli2 || \
    dnf install -y awscli
  fi
  if ! command -v aws &>/dev/null; then
    echo "ERROR: AWS CLI not available after install attempt — cannot download artifacts"
    exit 1
  fi

  # ── 1. physarum-server (coordinator — runs independently) ────────────────────
  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-server" \
    /usr/local/bin/physarum-server \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-server

  # ── 2. physarum-node (capability supervisor) ─────────────────────────────────
  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-node" \
    /usr/local/bin/physarum-node \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-node

  # ── 3. Sibling binaries (located by physarum-node via current_exe().parent()) ─
  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-agent" \
    /usr/local/bin/physarum-agent \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-agent

  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-ebpf-observer" \
    /usr/local/bin/physarum-ebpf-observer \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-ebpf-observer

  # ── 4. eBPF bytecode for observe-flow (TCP tracepoint) ───────────────────────
  mkdir -p /usr/local/lib/physarum
  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-ebpf-observer-ebpf" \
    /usr/local/lib/physarum/physarum-ebpf-observer-ebpf \
    --region "$ARTIFACT_REGION"

  # ── 5. Mount tracefs (required for eBPF tracepoints) ────────────────────────
  mount | grep -q tracefs || mount -t tracefs tracefs /sys/kernel/tracing || true

  cat > /etc/systemd/system/physarum-server.service << 'UNIT'
[Unit]
Description=physarum-server (coordinator, co-located with node A — Gate M.3)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/physarum-server --listen 0.0.0.0:8080
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

  # physarum-node supervises all capabilities — no separate agent/observer services.
  cat > /etc/systemd/system/physarum-node.service << UNIT
[Unit]
Description=physarum-node ($AGENT_ID) — capability supervisor ($CAPABILITIES) — Gate M.3
After=network-online.target physarum-server.service
Wants=network-online.target
Requires=physarum-server.service

[Service]
User=root
ExecStart=/usr/local/bin/physarum-node \
  --capabilities $CAPABILITIES \
  --id $AGENT_ID \
  --coordinator http://127.0.0.1:8080 \
  --listen 0.0.0.0:$LISTEN_PORT \
  --advertise-address $ADVERTISE_ADDRESS \
  --probe-interval-seconds 10 \
  --flow-bpf-bytecode /usr/local/lib/physarum/physarum-ebpf-observer-ebpf
Restart=on-failure
RestartSec=10
Environment=AGENT_ID=$AGENT_ID

[Install]
WantedBy=multi-user.target
UNIT

else
  # Placeholder mode — enable_artifact_download = false.
  cat > /etc/systemd/system/physarum-server.service << 'UNIT'
[Unit]
Description=physarum-server (coordinator, co-located with node A — Gate M.3)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-server binary not installed (enable_artifact_download=false)" && sleep infinity'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

  cat > /etc/systemd/system/physarum-node.service << UNIT
[Unit]
Description=physarum-node ($AGENT_ID) — capability supervisor (Gate M.3)
After=network-online.target physarum-server.service
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-node binary not installed (enable_artifact_download=false)" && sleep infinity'
Restart=on-failure
RestartSec=10
Environment=AGENT_ID=$AGENT_ID

[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable physarum-server
systemctl start physarum-server
systemctl enable physarum-node
systemctl start physarum-node
