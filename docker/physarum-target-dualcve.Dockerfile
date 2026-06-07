FROM debian:bookworm-slim

# Dual-CVE lab target for physarum-attack-paths PF-6.
#
# Simulates a host exposing two concurrent RCE surfaces:
#   :21  FTP — ProFTPD 1.3.5 banner + mod_copy behaviour (CVE-2015-3306)
#   :80  HTTP — Wing FTP Server 7.4.3 web admin (CVE-2025-47812)
#   :22  sshd — ephemeral pubkey delivery point for Phase 2 propagation
#
# The mock server (mock-wingftp-server.py) handles both services in a single
# Python process. No compilation needed — lightweight and fast to build.
#
# Build (mandatory — cloud builder law):
#   docker buildx build \
#     --builder cloud-expertsonline-physarum-attack-paths \
#     --platform linux/amd64 \
#     -f docker/physarum-target-dualcve.Dockerfile \
#     -t physarum-target-dualcve:lab --load .

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Configure sshd for pubkey-only root login (Phase 2 delivery gate)
RUN mkdir -p /var/run/sshd /root/.ssh && \
    chmod 700 /root/.ssh && \
    sed -i 's|#*PermitRootLogin.*|PermitRootLogin yes|'           /etc/ssh/sshd_config && \
    sed -i 's|#*PubkeyAuthentication.*|PubkeyAuthentication yes|' /etc/ssh/sshd_config && \
    sed -i 's|#*PasswordAuthentication.*|PasswordAuthentication no|' /etc/ssh/sshd_config && \
    sed -i 's|#*AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' /etc/ssh/sshd_config

COPY docker/mock-wingftp-server.py /usr/local/bin/mock-wingftp-server.py
RUN chmod +x /usr/local/bin/mock-wingftp-server.py

EXPOSE 21 22 80

CMD ["/bin/sh", "-c", "/usr/sbin/sshd && python3 /usr/local/bin/mock-wingftp-server.py"]
