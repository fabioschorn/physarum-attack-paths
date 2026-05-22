#!/bin/bash
# PF-1 — maze node user-data (hosts B through G)
# Role: ${maze_role}
# Note: ${maze_note}
# No physarum services — pure maze infrastructure.
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
# The physarum organism propagates without any SSH key. The source IP is the
# credential. ec2-user needs an empty (not locked) password so that sshd with
# PermitEmptyPasswords accepts the connection from authorized IPs.
passwd -d ec2-user

# ── SSH hardening — AllowUsers + IP-based PermitEmptyPasswords ───────────────
#
# Two-layer access control:
#   SG (network level):  controls which subnets can reach port 22
#   sshd (OS level):     AllowUsers controls which source IPs can authenticate
#
# Global: only operator (key-based) and allowed propagation IPs are accepted.
# Match Address block: enables empty-password auth for the allowed source IPs.
#   Without this block, AllowUsers alone is not enough — password auth would
#   still require a non-empty password.
#
# Allowed propagation sources: ${allowed_source_ips}
# (empty = dead end — no organism can propagate to this host)

cat > /etc/ssh/sshd_config.d/99-maze.conf <<'SSHDCONF'
# Global defaults
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
AllowUsers ec2-user@${operator_ip}%{ if allowed_source_ips != "" } ${allow_users_entries}%{ endif }
SSHDCONF

%{ if allowed_source_ips != "" }
# Match block: allow empty-password SSH from authorized propagation source IPs
cat >> /etc/ssh/sshd_config.d/99-maze.conf <<'MATCHBLOCK'

Match Address ${allowed_source_ips}
    PasswordAuthentication yes
    PermitEmptyPasswords yes
    AllowUsers ec2-user
MATCHBLOCK
%{ endif }

systemctl restart sshd

# ── SSH client config — keyless forward propagation ───────────────────────────
# When the organism propagates here and needs to SCP further, no key is used.
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
  "maze_role": "${maze_role}",
  "host": "${hostname}",
  "propagation": "ip-based — no SSH key",
  "allowed_source_ips": "${allowed_source_ips}",
  "note": "${maze_note}"
}
EOF

echo "PF-1 ${hostname} (${maze_role}) user-data complete"
