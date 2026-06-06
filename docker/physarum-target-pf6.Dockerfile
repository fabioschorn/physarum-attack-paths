# PF-6 target: Apache Struts 2.5.25 (CVE-2020-17530 surface) + sshd
#
# sshd runs alongside Struts on port 22. No keys are pre-planted — the
# ephemeral pubkey is injected at runtime via the OGNL RCE exploit (Phase 2).
# This models a realistic server: SSH always open, but only accessible after
# the organism plants its own key via the vulnerability.
#
# Build (cloud builder — law):
#   docker buildx build --builder cloud-expertsonline-physarum-attack-paths \
#     --platform linux/amd64 \
#     -f docker/physarum-target-pf6.Dockerfile \
#     -t physarum-target-pf6:lab --load .

FROM vulhub/struts2:2.5.25

# Debian Buster reached EOL — redirect to archive mirrors before any apt-get
RUN sed -i \
      -e 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' \
      -e 's|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' \
      -e '/buster-updates/d' \
    /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends openssh-server && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh && \
    # Allow root login — key is planted at runtime via exploit, not pre-configured
    sed -i 's|#*PermitRootLogin.*|PermitRootLogin yes|' /etc/ssh/sshd_config && \
    # Pubkey auth on (usually default, explicit for clarity)
    sed -i 's|#*PubkeyAuthentication.*|PubkeyAuthentication yes|' /etc/ssh/sshd_config && \
    # Disable password auth — forces key-only access (models a hardened server)
    sed -i 's|#*PasswordAuthentication.*|PasswordAuthentication no|' /etc/ssh/sshd_config && \
    # Use standard authorized_keys path
    sed -i 's|#*AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' /etc/ssh/sshd_config

EXPOSE 22 8080

# Start sshd first (background), then hand off to Struts/Tomcat
# vulhub/struts2:2.5.25 uses Maven + Jetty (not Tomcat). ENTRYPOINT is mvn-entrypoint.sh which execs "$@".
CMD ["/bin/sh", "-c", "/usr/sbin/sshd && exec mvn jetty:run"]
