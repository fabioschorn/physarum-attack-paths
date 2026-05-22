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
dnf install -y nmap-ncat traceroute iputils jq curl 2>/dev/null || true

# ── Propagation key — authorized for organism SCP propagation ─────────────────
# The physarum organism on Host A (and later on propagated instances) uses
# this key to SCP the physarum-node binary to this host after RustScan
# discovers port 22 open and AllowUsers (below) permits the source IP.
install -d -m 700 -o ec2-user -g ec2-user /home/ec2-user/.ssh
cat >> /home/ec2-user/.ssh/authorized_keys <<'PUBKEY'
${propagation_pub_key}
PUBKEY
chmod 600 /home/ec2-user/.ssh/authorized_keys
chown ec2-user:ec2-user /home/ec2-user/.ssh/authorized_keys

# ── SSH hardening — AllowUsers enforces maze corridor rules ───────────────────
# The Security Group controls which subnets can reach port 22 at the network
# level (coarse). AllowUsers here enforces fine-grained per-host corridor
# rules at the sshd level (fine).
#
# The organism discovers port 22 open via RustScan (SG allows the subnet).
# It then attempts SCP propagation. sshd accepts or rejects based on AllowUsers:
#   - Accepted: source IP is in the allowed list → valid corridor
#   - Rejected: source IP not in allowed list → dead end or blocked path
#
# Allowed propagation sources for this host:
#   ${allowed_ssh_users}
cat > /etc/ssh/sshd_config.d/99-maze.conf <<EOF
AllowUsers ${allowed_ssh_users}
EOF
systemctl restart sshd

# ── SSH client config for forward propagation ─────────────────────────────────
# If the organism propagates to this host, it will need to SCP further.
# Provide the same SSH client config so propagated instances work correctly.
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
  "maze_role": "${maze_role}",
  "host": "${hostname}",
  "allowed_ssh_from": "${allowed_ssh_users}",
  "note": "${maze_note}"
}
EOF

echo "PF-1 ${hostname} (${maze_role}) user-data complete"
