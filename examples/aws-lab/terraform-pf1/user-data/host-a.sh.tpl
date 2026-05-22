#!/bin/bash
# PF-1 — Host A (seed) user-data
# Role: front subnet, organism entry point, holds propagation key.
# No physarum services — pure maze infrastructure.
set -euo pipefail

# ── Hostname ──────────────────────────────────────────────────────────────────
hostnamectl set-hostname ${hostname}

# ── /etc/hosts — maze name resolution ────────────────────────────────────────
cat >> /etc/hosts <<'HOSTS'
${maze_hosts_entries}
HOSTS

# ── System tools ──────────────────────────────────────────────────────────────
dnf install -y nmap-ncat traceroute iputils jq curl 2>/dev/null || true

# ── SSH hardening — operator access only from public internet ─────────────────
# Host A is in the front subnet. Only the operator can SSH in.
# The organism on A uses the propagation key (below) for internal SCP.
cat > /etc/ssh/sshd_config.d/99-maze.conf <<EOF
AllowUsers ec2-user@${operator_ip}
EOF
systemctl restart sshd

# ── Propagation key — written to ec2-user home ────────────────────────────────
# The physarum organism on this host uses this key to SCP itself to discovered
# corridor hosts (B, C, ...) after RustScan finds port 22 open and AllowUsers
# on the target host permits this host's IP.
#
# Security note: this private key is visible in EC2 instance metadata during
# launch. Acceptable for a lab destroyed immediately after evidence collection.
install -d -m 700 -o ec2-user -g ec2-user /home/ec2-user/.ssh

cat > /home/ec2-user/.ssh/physarum-propagation <<'KEY'
${propagation_priv_key}
KEY
chmod 600 /home/ec2-user/.ssh/physarum-propagation
chown ec2-user:ec2-user /home/ec2-user/.ssh/physarum-propagation

# The propagation public key is also stored for reference.
cat > /home/ec2-user/.ssh/physarum-propagation.pub <<'PUBKEY'
${propagation_pub_key}
PUBKEY
chmod 644 /home/ec2-user/.ssh/physarum-propagation.pub
chown ec2-user:ec2-user /home/ec2-user/.ssh/physarum-propagation.pub

# ── SSH client config for propagation ────────────────────────────────────────
# When the organism SSHs/SCPs to internal maze hosts, use the propagation key
# and skip host key checking (hosts are freshly provisioned, keys unknown).
cat > /home/ec2-user/.ssh/config <<'SSHCFG'
Host 10.60.*
    User ec2-user
    IdentityFile ~/.ssh/physarum-propagation
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 5
SSHCFG
chmod 600 /home/ec2-user/.ssh/config
chown ec2-user:ec2-user /home/ec2-user/.ssh/config

# ── Maze marker ───────────────────────────────────────────────────────────────
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "seed",
  "maze_layer": "front",
  "host": "${hostname}",
  "note": "PF-1 organism entry point. Only this host receives physarum-node at lab start.",
  "propagation_key": "/home/ec2-user/.ssh/physarum-propagation"
}
EOF

echo "PF-1 host-a user-data complete"
