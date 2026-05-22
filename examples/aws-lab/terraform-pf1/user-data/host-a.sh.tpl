#!/bin/bash
# PF-1 — Host A (seed) user-data
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
dnf install -y traceroute iputils jq curl 2>/dev/null || true

# ── ec2-user — empty password for IP-based SSH propagation ───────────────────
# The organism propagates by SSH from A to B/C using only the source IP as
# identity. No private key is involved. ec2-user must have an empty password
# so that sshd (with PermitEmptyPasswords yes on the target) accepts the
# connection when the source IP is in AllowUsers.
passwd -d ec2-user

# ── SSH hardening — operator (key) + restrict password auth ──────────────────
# Operator reaches A with their key from the public internet.
# Password auth is off globally — A does not accept inbound empty passwords
# since nothing propagates back to A.
cat > /etc/ssh/sshd_config.d/99-maze.conf <<EOF
AllowUsers ec2-user@${operator_ip}
PasswordAuthentication no
PermitEmptyPasswords no
EOF
systemctl restart sshd

# ── SSH client config — keyless propagation to internal hosts ─────────────────
# When the organism (running as ec2-user on A) SSHes/SCPs to B or C, it uses
# empty-password auth. The source IP 10.60.10.10 is in their AllowUsers.
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
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "seed",
  "maze_layer": "front",
  "host": "${hostname}",
  "propagation": "ip-based — no SSH key, source IP 10.60.10.10 is the credential",
  "note": "PF-1 organism entry point. Only this host receives physarum-node at lab start."
}
EOF

echo "PF-1 host-a user-data complete"
