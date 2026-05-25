#!/bin/bash
# PF-2 — Host A (seed) user-data
# Role: front subnet, organism entry point.
# No SSH key is held here — propagation uses IP-based trust only.
set -euo pipefail

# ── Hostname ──────────────────────────────────────────────────────────────────
hostnamectl set-hostname ${hostname}

# ── /etc/hosts — maze name resolution ────────────────────────────────────────
cat >> /etc/hosts <<'HOSTS'
${maze_hosts_entries}
HOSTS

# ── System tools ──────────────────────────────────────────────────────────────
dnf install -y traceroute iputils jq curl 2>&1 || true
dnf install -y sshpass 2>&1 || { echo "WARNING: sshpass install failed — propagation will not work" >&2; }

# ── physarum-maze binary — download from S3 via IAM Instance Profile ──────────
ARTIFACT_BUCKET="${artifact_bucket}"
ARTIFACT_PREFIX="${artifact_prefix}"
ARTIFACT_REGION="${artifact_region}"

if ! command -v aws &>/dev/null; then
    dnf install -y awscli2 2>/dev/null || dnf install -y aws-cli2 2>/dev/null || dnf install -y awscli 2>/dev/null || true
fi

if command -v aws &>/dev/null; then
    aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-maze" \
        /usr/local/bin/physarum-maze \
        --region "$ARTIFACT_REGION"
    chmod +x /usr/local/bin/physarum-maze
    echo "physarum-maze downloaded OK"

    # eBPF bytecode — optional, enables the 5th stimulus arm in physarum-maze.
    # If not present in S3 the agent runs with 4 stimuli (ICMP, TCP-SYN,
    # periodic /24 discovery, dormancy timer).
    if aws s3 cp "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/physarum-ebpf-observer-ebpf" \
        /usr/local/lib/physarum-ebpf-observer-ebpf \
        --region "$ARTIFACT_REGION" 2>/dev/null; then
        chmod 644 /usr/local/lib/physarum-ebpf-observer-ebpf
        echo "physarum-ebpf-observer-ebpf downloaded OK"
    else
        echo "physarum-ebpf-observer-ebpf not in S3 — eBPF stimulus disabled" >&2
    fi
else
    echo "ERROR: AWS CLI unavailable — physarum-maze not installed" >&2
fi

# ── ec2-user — empty password for IP-based SSH propagation ───────────────────
passwd -d ec2-user

# ── SSH hardening — operator (key) only, password auth off ───────────────────
cat > /etc/ssh/sshd_config.d/99-maze.conf <<EOF
AllowUsers ec2-user@${operator_ip}
PasswordAuthentication no
PermitEmptyPasswords no
EOF
systemctl restart sshd

# ── SSH client config — keyless propagation to internal hosts ─────────────────
install -d -m 700 -o ec2-user -g ec2-user /home/ec2-user/.ssh
cat > /home/ec2-user/.ssh/config <<'SSHCFG'
Host 10.60.*
    User ec2-user
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 5
    PasswordAuthentication yes
    PreferredAuthentications password
SSHCFG
chmod 600 /home/ec2-user/.ssh/config
chown ec2-user:ec2-user /home/ec2-user/.ssh/config

# ── Maze marker ───────────────────────────────────────────────────────────────
# Host A only RECEIVES ICMP (from B and C pinging inbound).
# No outbound ping timer here — A's raw ICMP socket captures incoming echo
# requests and uses the source IP as the discovery stimulus.
# eBPF (5th stimulus) is active when --bpf-bytecode is passed at agent launch.
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "seed",
  "maze_layer": "front",
  "host": "${hostname}",
  "propagation": "ip-based — no SSH key, source IP is the credential",
  "icmp_stimulus": "inbound — B and C ping A; raw ICMP socket captures source IPs",
  "ebpf_stimulus": "inbound TCP accepts from 10.60/16 via tracepoint/sock/inet_sock_set_state",
  "bpf_bytecode": "/usr/local/lib/physarum-ebpf-observer-ebpf",
  "note": "PF-2 organism entry point. Launch: sudo physarum-maze --mode seed --interface <iface> --bpf-bytecode /usr/local/lib/physarum-ebpf-observer-ebpf"
}
EOF

echo "PF-1 host-a user-data complete"
