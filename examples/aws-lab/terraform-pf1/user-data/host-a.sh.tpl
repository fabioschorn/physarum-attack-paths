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

# ── ICMP stimulus — pings next-layer hosts so eBPF captures the flow ──────────
# Host A can reach layer-1 (B, C) via ICMP per SG rules.
# A timer fires every 30s — each ping generates an echo reply that the
# physarum organism's eBPF sensor captures as a discovery stimulus.
cat > /usr/local/bin/physarum-icmp-stimulus.sh <<'SCRIPT'
#!/bin/bash
for target in host-b host-c; do
    ping -c1 -W2 "$target" >/dev/null 2>&1 || true
done
SCRIPT
chmod +x /usr/local/bin/physarum-icmp-stimulus.sh

cat > /etc/systemd/system/physarum-icmp-stimulus.service <<'SVC'
[Unit]
Description=Physarum ICMP stimulus — pings layer-1 hosts for eBPF discovery

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

# ── Maze marker ───────────────────────────────────────────────────────────────
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "seed",
  "maze_layer": "front",
  "host": "${hostname}",
  "propagation": "ip-based — no SSH key, source IP 10.60.10.10 is the credential",
  "icmp_stimulus_targets": ["host-b", "host-c"],
  "note": "PF-1 organism entry point. Only this host receives physarum-node at lab start."
}
EOF

echo "PF-1 host-a user-data complete"
