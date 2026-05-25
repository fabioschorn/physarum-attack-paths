#!/bin/bash
# PF-2 — maze node user-data (hosts B through G and A.1)
# Role: ${maze_role}
# Note: ${maze_note}
set -euo pipefail

# ── Hostname ──────────────────────────────────────────────────────────────────
hostnamectl set-hostname ${hostname}

# ── /etc/hosts — maze name resolution ────────────────────────────────────────
cat >> /etc/hosts <<'HOSTS'
${maze_hosts_entries}
HOSTS

# ── System tools ──────────────────────────────────────────────────────────────
dnf install -y traceroute iputils jq curl 2>&1 || true
# sshpass is critical for the organism propagation — install explicitly
dnf install -y sshpass 2>&1 || { echo "WARNING: sshpass install failed — propagation will not work" >&2; }

# ── ec2-user — empty password for IP-based SSH propagation ───────────────────
# The physarum organism propagates without any SSH key. Source IP is the
# credential. Empty password lets sshd (PermitEmptyPasswords) accept it.
passwd -d ec2-user

# ── SSH hardening — AllowUsers + IP-based PermitEmptyPasswords ───────────────
#
# Global: only operator (key) + authorized propagation IPs accepted.
# Match Address: enables empty-password auth for those source IPs only.
#
# Allowed propagation sources: ${allowed_source_ips}
cat > /etc/ssh/sshd_config.d/99-maze.conf <<SSHDCONF
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
AllowUsers ec2-user@${operator_ip}%{ if allowed_source_ips != "" } ${allow_users_entries}%{ endif }
SSHDCONF

%{ if allowed_source_ips != "" }
cat >> /etc/ssh/sshd_config.d/99-maze.conf <<MATCHBLOCK

Match Address ${allowed_source_ips}
    PasswordAuthentication yes
    PermitEmptyPasswords yes
    AllowUsers ec2-user
MATCHBLOCK
%{ endif }

systemctl restart sshd

# ── SSH client config — keyless forward propagation ───────────────────────────
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

# ── ICMP stimulus — pings next-layer hosts so eBPF captures the flow ──────────
# Each host pings the hosts visible to it via SG rules.
# The timer fires every 30s — echo replies are the eBPF discovery stimulus.
# ping_targets is empty for host-g (layer-3 milestone, no next layer).
%{ if ping_targets != "" }
cat > /usr/local/bin/physarum-icmp-stimulus.sh <<'SCRIPT'
#!/bin/bash
for target in ${ping_targets}; do
    ping -c1 -W2 "$target" >/dev/null 2>&1 || true
done
SCRIPT
chmod +x /usr/local/bin/physarum-icmp-stimulus.sh

cat > /etc/systemd/system/physarum-icmp-stimulus.service <<'SVC'
[Unit]
Description=Physarum ICMP stimulus — pings next-layer hosts for eBPF discovery

[Service]
Type=oneshot
ExecStart=/usr/local/bin/physarum-icmp-stimulus.sh
SVC

cat > /etc/systemd/system/physarum-icmp-stimulus.timer <<'TMR'
[Unit]
Description=Physarum ICMP stimulus timer (30s interval)

[Timer]
OnBootSec=15s
OnUnitActiveSec=30s

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now physarum-icmp-stimulus.timer
%{ endif }

# ── Maze marker ───────────────────────────────────────────────────────────────
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "${maze_role}",
  "host": "${hostname}",
  "propagation": "ip-based — no SSH key",
  "allowed_source_ips": "${allowed_source_ips}",
  "icmp_stimulus_targets": "${ping_targets}",
  "note": "${maze_note}"
}
EOF

echo "PF-1 ${hostname} (${maze_role}) user-data complete"
