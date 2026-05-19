#!/usr/bin/env bash
set -euxo pipefail

# Gate L.3 bootstrap — combined coordinator + agent + packet observer on node A.
# physarum-server starts first; physarum-agent connects to localhost:8080.
# physarum-packet-observer runs as root when enable_packet_observer=true,
# attaching tc ingress on eth0 to capture inbound ICMP echo requests.
#
# Terraform-injected variables (substituted by templatefile() at apply time):
#   agent_id                 = ${agent_id}
#   listen_port              = ${listen_port}
#   advertise_address        = ${advertise_address}
#   probe_targets            = ${probe_targets}
#   name_prefix              = ${name_prefix}
#   enable_artifact_download = ${enable_artifact_download}
#   artifact_bucket          = ${artifact_bucket}
#   artifact_prefix          = ${artifact_prefix}
#   artifact_region          = ${artifact_region}
#   enable_observer          = ${enable_observer}
#   enable_packet_observer   = ${enable_packet_observer}
#   enable_discovery         = ${enable_discovery}
#   discovery_cidrs          = ${discovery_cidrs}
#   discovery_scope_mode     = ${discovery_scope_mode}

AGENT_ID="${agent_id}"
LISTEN_PORT="${listen_port}"
ADVERTISE_ADDRESS="${advertise_address}"
PROBE_TARGETS="${probe_targets}"
NAME_PREFIX="${name_prefix}"
ENABLE_ARTIFACT_DOWNLOAD="${enable_artifact_download}"
ARTIFACT_BUCKET="${artifact_bucket}"
ARTIFACT_PREFIX="${artifact_prefix}"
ARTIFACT_REGION="${artifact_region}"
ENABLE_OBSERVER="${enable_observer}"
ENABLE_PACKET_OBSERVER="${enable_packet_observer}"
ENABLE_DISCOVERY="${enable_discovery}"
DISCOVERY_CIDRS="${discovery_cidrs}"
DISCOVERY_SCOPE_MODE="${discovery_scope_mode}"

PROBE_TARGETS_FLAG=""
if [ -n "$PROBE_TARGETS" ]; then
  PROBE_TARGETS_FLAG="--probe-targets $PROBE_TARGETS"
fi

DISCOVERY_FLAGS=""
if [ "$ENABLE_DISCOVERY" = "true" ]; then
  BASE_FLAGS="--discovery-enabled --discovery-ports 9001,9002,9003,9004 --discovery-interval-secs 300 --discovery-timeout-ms 1500 --discovery-max-candidates 50 --discovery-seed-cooldown-secs 30"
  if [ "$DISCOVERY_SCOPE_MODE" = "local-interfaces" ]; then
    DISCOVERY_FLAGS="$BASE_FLAGS --discovery-scope-mode local-interfaces"
  elif [ "$DISCOVERY_SCOPE_MODE" = "merged" ]; then
    DISCOVERY_FLAGS="$BASE_FLAGS --discovery-scope-mode merged --discovery-cidrs $DISCOVERY_CIDRS"
  elif [ -n "$DISCOVERY_CIDRS" ]; then
    DISCOVERY_FLAGS="$BASE_FLAGS --discovery-cidrs $DISCOVERY_CIDRS"
  fi
fi

# Gate L.3: ICMP packet sensing enabled, TCP socket-state sensing disabled.
# Both can be enabled together; for the gate-l3 lab we isolate ICMP-only.
SENSE_FLAGS="--sense-tcp-socket-state false --sense-icmp-packet true"

dnf update -y
dnf install -y jq iproute-tc

echo "physarum bootstrap: enable_artifact_download=$ENABLE_ARTIFACT_DOWNLOAD"
echo "physarum bootstrap: artifact_bucket_set=$([ -n "$ARTIFACT_BUCKET" ] && echo yes || echo no)"
echo "physarum bootstrap: artifact_prefix=$ARTIFACT_PREFIX"
echo "physarum bootstrap: artifact_region=$ARTIFACT_REGION"

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

  # ── 1. physarum-server (coordinator) ─────────────────────────────────────────
  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-server" \
    /usr/local/bin/physarum-server \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-server

  cat > /etc/systemd/system/physarum-server.service << 'UNIT'
[Unit]
Description=physarum-server (coordinator, co-located with node A)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/physarum-server --listen 0.0.0.0:8080
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

  # ── 2. physarum-agent (node A — Gate L.3: ICMP sense only) ──────────────────
  aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-agent" \
    /usr/local/bin/physarum-agent \
    --region "$ARTIFACT_REGION"
  chmod +x /usr/local/bin/physarum-agent

  cat > /etc/systemd/system/physarum-agent.service << UNIT
[Unit]
Description=physarum-agent ($AGENT_ID) — co-located with coordinator (Gate L.3)
After=network-online.target physarum-server.service
Wants=network-online.target
Requires=physarum-server.service

[Service]
ExecStart=/usr/local/bin/physarum-agent \
  --id $AGENT_ID \
  --coordinator http://127.0.0.1:8080 \
  --listen 0.0.0.0:$LISTEN_PORT \
  --advertise-address $ADVERTISE_ADDRESS \
  --probe-interval-seconds 10 \
  $PROBE_TARGETS_FLAG \
  $DISCOVERY_FLAGS \
  $SENSE_FLAGS
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
Description=physarum-server (coordinator, co-located with node A)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-server binary not installed (enable_artifact_download=false)" && sleep infinity'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

  cat > /etc/systemd/system/physarum-agent.service << UNIT
[Unit]
Description=physarum-agent ($AGENT_ID) — co-located with coordinator (Gate L.3)
After=network-online.target physarum-server.service
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c 'echo "physarum-agent binary not installed (enable_artifact_download=false)" && sleep infinity'
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
systemctl enable physarum-agent
systemctl start physarum-agent

# ── Gate J: physarum-ebpf-observer (TCP tracepoint — optional) ───────────────

if [ "$ENABLE_OBSERVER" = "true" ]; then
  if [ "$ENABLE_ARTIFACT_DOWNLOAD" = "true" ]; then
    echo "physarum bootstrap: downloading physarum-ebpf-observer artifacts"
    mkdir -p /usr/local/lib/physarum

    aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-ebpf-observer" \
      /usr/local/bin/physarum-ebpf-observer \
      --region "$ARTIFACT_REGION"
    chmod +x /usr/local/bin/physarum-ebpf-observer

    aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-ebpf-observer-ebpf" \
      /usr/local/lib/physarum/physarum-ebpf-observer-ebpf \
      --region "$ARTIFACT_REGION"

    mount | grep -q tracefs || mount -t tracefs tracefs /sys/kernel/tracing || true

    cat > /etc/systemd/system/physarum-ebpf-observer.service << UNIT
[Unit]
Description=physarum-ebpf-observer ($AGENT_ID) — eBPF TCP flow observer
After=physarum-agent.service physarum-server.service
Wants=physarum-agent.service physarum-server.service

[Service]
User=root
ExecStart=/usr/local/bin/physarum-ebpf-observer \
  --agent-id $AGENT_ID \
  --coordinator-url http://127.0.0.1:8080 \
  --bpf-bytecode /usr/local/lib/physarum/physarum-ebpf-observer-ebpf \
  --log-level info
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable physarum-ebpf-observer
    systemctl start physarum-ebpf-observer
    echo "physarum bootstrap: physarum-ebpf-observer started"
  else
    echo "physarum bootstrap: enable_observer=true but enable_artifact_download=false — observer not started"
  fi
fi

# ── Gate L.3: physarum-packet-observer (ICMP tc ingress) ─────────────────────

if [ "$ENABLE_PACKET_OBSERVER" = "true" ]; then
  if [ "$ENABLE_ARTIFACT_DOWNLOAD" = "true" ]; then
    echo "physarum bootstrap: downloading physarum-packet-observer artifacts"
    mkdir -p /usr/local/lib/physarum

    aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-packet-observer" \
      /usr/local/bin/physarum-packet-observer \
      --region "$ARTIFACT_REGION"
    chmod +x /usr/local/bin/physarum-packet-observer

    aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-packet-observer-ebpf" \
      /usr/local/lib/physarum/physarum-packet-observer-ebpf \
      --region "$ARTIFACT_REGION"

    cat > /etc/systemd/system/physarum-packet-observer.service << UNIT
[Unit]
Description=physarum-packet-observer ($AGENT_ID) — eBPF ICMP tc ingress observer
After=physarum-agent.service physarum-server.service
Wants=physarum-agent.service physarum-server.service

[Service]
User=root
ExecStart=/usr/local/bin/physarum-packet-observer \
  --agent-id $AGENT_ID \
  --coordinator-url http://127.0.0.1:8080 \
  --bpf-bytecode /usr/local/lib/physarum/physarum-packet-observer-ebpf \
  --interface eth0 \
  --log-level info
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable physarum-packet-observer
    systemctl start physarum-packet-observer
    echo "physarum bootstrap: physarum-packet-observer started (tc ingress on eth0)"
  else
    echo "physarum bootstrap: enable_packet_observer=true but enable_artifact_download=false — packet observer not started"
  fi
fi
