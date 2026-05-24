#!/bin/bash
# PF-2 — Host X (cross-subnet adaptive probe) user-data
#
# Role: cross subnet (10.60.50.0/24), appears ~5 minutes into PF-2 run.
# Behaviour:
#   - Receives ICMP from G → X's agent discovers G → AlreadyColonized → secondary conduit
#   - Sends TCP SYN to A.1:22 every 30s (timer starts at T+5min from boot)
#   - Accepts propagation from A.1 via empty-password SSH
#
# TCP stimulus: the timer issues `nc -z <A1_IP> 22` which creates a TCP SYN
# to A.1's sshd port.  A.1's raw TCP socket listener (tcp.rs) captures the SYN
# and uses X's source IP as a stimulus to discover X.  No actual SSH auth is
# performed by the timer — the SYN alone is sufficient.
set -euo pipefail

# ── Hostname ──────────────────────────────────────────────────────────────────
hostnamectl set-hostname ${hostname}

# ── /etc/hosts — maze name resolution ────────────────────────────────────────
cat >> /etc/hosts <<'HOSTS'
${maze_hosts_entries}
HOSTS

# ── System tools ──────────────────────────────────────────────────────────────
dnf install -y traceroute iputils jq curl nmap nmap-ncat 2>&1 || true
dnf install -y sshpass 2>&1 || { echo "WARNING: sshpass install failed — propagation will not work" >&2; }

# ── RustScan v2.4.1 — port discovery for the physarum organism ────────────────
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

# ── ec2-user — empty password for IP-based SSH propagation ───────────────────
passwd -d ec2-user

# ── SSH hardening — AllowUsers + IP-based PermitEmptyPasswords ───────────────
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

# ── TCP stimulus — X connects to A.1:22 every 30s to signal its presence ──────
# The 5-minute delay before X appears is enforced by Terraform (time_sleep).
# The boot timer starts 60s after X's own boot, by which point sshd is ready.
%{ if tcp_stimulus_target != "" }
cat > /usr/local/bin/physarum-tcp-stimulus.sh <<'SCRIPT'
#!/bin/bash
# TCP SYN to A.1:22 — physarum-maze on A.1 captures the SYN via raw socket
# and treats X's IP as a new discovery candidate.
nc -z -w2 ${tcp_stimulus_target} 22 >/dev/null 2>&1 || true
SCRIPT
chmod +x /usr/local/bin/physarum-tcp-stimulus.sh

cat > /etc/systemd/system/physarum-tcp-stimulus.service <<'SVC'
[Unit]
Description=Physarum TCP stimulus — connects to A.1:22 so A.1 discovers X

[Service]
Type=oneshot
ExecStart=/usr/local/bin/physarum-tcp-stimulus.sh
SVC

cat > /etc/systemd/system/physarum-tcp-stimulus.timer <<'TMR'
[Unit]
Description=Physarum TCP stimulus timer (30s interval, starts 60s after boot)

[Timer]
OnBootSec=60s
OnUnitActiveSec=30s

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now physarum-tcp-stimulus.timer
%{ endif }

# ── Maze marker ───────────────────────────────────────────────────────────────
cat > /etc/physarum-maze.json <<EOF
{
  "maze_role": "cross-probe",
  "maze_layer": "cross",
  "host": "${hostname}",
  "propagation": "ip-based — allowed from ${allowed_source_ips}",
  "tcp_stimulus_target": "${tcp_stimulus_target}",
  "note": "PF-2: X created 5min after primary hosts (Terraform gate); sends TCP SYN to A.1:22 every 30s from T+60s boot; G pings X via ICMP"
}
EOF

echo "PF-2 host-x user-data complete"
