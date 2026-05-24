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
dnf install -y traceroute iputils jq curl nmap 2>&1 || true
dnf install -y sshpass 2>&1 || { echo "WARNING: sshpass install failed — propagation will not work" >&2; }

# ── RustScan v2.4.1 — /24 subnet discovery for the physarum organism ──────────
RUSTSCAN_VERSION="2.4.1"
RUSTSCAN_URL="https://github.com/RustScan/RustScan/releases/download/${RUSTSCAN_VERSION}/rustscan_${RUSTSCAN_VERSION}_amd64.deb"
RUSTSCAN_DEB="/tmp/rustscan.deb"
if curl -fsSL -o "$RUSTSCAN_DEB" "$RUSTSCAN_URL" 2>/dev/null; then
    dnf install -y alien 2>/dev/null || true
    if command -v alien &>/dev/null; then
        alien -r "$RUSTSCAN_DEB" -o /tmp/ 2>/dev/null && dnf install -y /tmp/rustscan-*.rpm 2>/dev/null || true
    fi
    if ! command -v rustscan &>/dev/null; then
        cd /tmp && ar x rustscan.deb && tar -xf data.tar.* ./usr/bin/rustscan 2>/dev/null || true
        [ -f /tmp/usr/bin/rustscan ] && install -m 755 /tmp/usr/bin/rustscan /usr/local/bin/rustscan
    fi
else
    echo "WARNING: rustscan download failed — /24 discovery will be skipped" >&2
fi
command -v rustscan &>/dev/null && echo "rustscan installed OK" || echo "WARNING: rustscan not available" >&2

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
# No outbound ping timer here — A's eBPF captures incoming echo requests
# and uses the source IP as the discovery stimulus.
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "seed",
  "maze_layer": "front",
  "host": "${hostname}",
  "propagation": "ip-based — no SSH key, source IP 10.60.10.10 is the credential",
  "icmp_stimulus": "inbound — B and C ping A; eBPF captures source IPs",
  "note": "PF-1 organism entry point. Only this host receives physarum-node at lab start."
}
EOF

echo "PF-1 host-a user-data complete"
